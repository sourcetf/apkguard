package dex

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"sort"
	"testing"
)

// encodedValueTypes 解析一个 encoded_array，返回每个值的类型码。
//
// 只关心「值类型」这一个字节：ART 的结构校验器用它来对照静态字段的类型，
// 不匹配即拒绝整个 DEX（"unexpected static field initial value type"）。
func encodedValueTypes(d []byte, off uint32) ([]byte, error) {
	p := int(off)
	size, np, err := ULEB128(d, p)
	if err != nil {
		return nil, err
	}
	p = np
	out := make([]byte, 0, size)
	for i := uint32(0); i < size; i++ {
		if p >= len(d) {
			return nil, fmt.Errorf("encoded_array 越界")
		}
		at := d[p]
		out = append(out, at&0x1f)
		p++
		vt := at & 0x1f
		va := (at >> 5) & 0x7
		switch vt {
		case 0x1c: // array：递归
			sub, err := encodedValueTypes(d, uint32(p))
			if err != nil {
				return nil, err
			}
			// 跳过该数组的全部内容
			q := int(uint32(p))
			n, nq, err := ULEB128(d, q)
			if err != nil {
				return nil, err
			}
			q = nq
			for k := uint32(0); k < n; k++ {
				_, qq, err := skipEncodedValue(d, q)
				if err != nil {
					return nil, err
				}
				q = qq
			}
			_ = sub
			p = q
		case 0x1d: // annotation
			_, q, err := skipEncodedValue(d, int(uint32(p))-1)
			if err != nil {
				return nil, err
			}
			p = q
		case 0x1e, 0x1f: // null / boolean：无载荷
		case 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b: // 含索引
			p += int(va) + 1
		default: // 数值型
			p += int(va) + 1
		}
	}
	return out, nil
}

// skipEncodedValue 返回跳过该 encoded_value 后的位置。
func skipEncodedValue(d []byte, p int) (byte, int, error) {
	if p >= len(d) {
		return 0, p, fmt.Errorf("encoded_value 越界")
	}
	at := d[p]
	p++
	vt := at & 0x1f
	va := (at >> 5) & 0x7
	switch vt {
	case 0x1c:
		n, np, err := ULEB128(d, p)
		if err != nil {
			return at, p, err
		}
		p = np
		for k := uint32(0); k < n; k++ {
			_, q, err := skipEncodedValue(d, p)
			if err != nil {
				return at, p, err
			}
			p = q
		}
	case 0x1d:
		_, q, err := skipEncodedAnnotation(d, p)
		if err != nil {
			return at, p, err
		}
		p = q
	case 0x1e, 0x1f:
	default:
		p += int(va) + 1
	}
	return at, p, nil
}

func skipEncodedAnnotation(d []byte, p int) (byte, int, error) {
	_, p, err := ULEB128(d, p) // type_idx
	if err != nil {
		return 0, p, err
	}
	n, p, err := ULEB128(d, p)
	if err != nil {
		return 0, p, err
	}
	for i := uint32(0); i < n; i++ {
		_, p, err = ULEB128(d, p) // name_idx
		if err != nil {
			return 0, p, err
		}
		_, p, err = skipEncodedValue(d, p)
		if err != nil {
			return 0, p, err
		}
	}
	return 0, p, nil
}

// valueIsReference 判断 encoded_value 的类型码是否属于「引用类」。
func valueIsReference(vt byte) bool {
	switch vt {
	case 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e:
		return true
	}
	return false
}

// checkStaticValues 校验 static_values 与静态字段的类型/数量是否对齐。
//
// 这是 ART 结构校验器的规则："unexpected static field initial value type"。
// static_values 的第 i 个值必须对应按 field_idx 升序的第 i 个静态字段——
// 字段被重排（改名会改变 field_idx 顺序）而值未同步重排时就会被拒绝。
func checkStaticValues(t *testing.T, tag string, f *File) int {
	t.Helper()
	checked := 0
	if err := f.Classes(func(i uint32, cd ClassDef, name string) error {
		if cd.StaticValuesOff == 0 || cd.ClassDataOff == 0 {
			return nil
		}
		pcd, err := f.ParseClassData(cd.ClassDataOff)
		if err != nil {
			return nil
		}
		if len(pcd.StaticFields) == 0 {
			return nil
		}
		types, err := encodedValueTypes(f.data, cd.StaticValuesOff)
		if err != nil {
			t.Errorf("%s：类 %s 的 static_values 解析失败: %v", tag, name, err)
			return nil
		}
		if len(types) > len(pcd.StaticFields) {
			t.Errorf("%s：类 %s 的 static_values 有 %d 个值，但只有 %d 个静态字段"+
				"（ART 会拒绝整个 DEX）", tag, name, len(types), len(pcd.StaticFields))
			return nil
		}
		checked++
		for k, vt := range types {
			_, typeIdx, _, err := f.FieldRefAt(pcd.StaticFields[k].Idx)
			if err != nil {
				continue
			}
			ft, err := f.Type(uint32(typeIdx))
			if err != nil {
				continue
			}
			ref := len(ft) > 0 && (ft[0] == 'L' || ft[0] == '[')
			if ref != valueIsReference(vt) {
				t.Errorf("%s：类 %s 第 %d 个静态字段（类型 %s）与 static_values 的值类型 0x%02x 不匹配"+
					"（ART 会判 unexpected static field initial value type 并拒绝整个 DEX）",
					tag, name, k, ft, vt)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("%s 遍历类失败: %v", tag, err)
	}
	return checked
}

// TestArtifactStaticValues 对全部交付包（含解密后的载荷）检查静态值对齐。
func TestArtifactStaticValues(t *testing.T) {
	files, err := filepath.Glob("../../../deliver/*.apk")
	if err != nil || len(files) == 0 {
		t.Skip("交付包不在本机，跳过")
	}
	sort.Strings(files)
	total := 0
	for _, apk := range files {
		g, assets := apkShellDex(t, apk)
		total += checkStaticValues(t, filepath.Base(apk), g)
		if len(assets) == 0 || !hasLoaderClass(g) {
			continue
		}
		env := &loaderEnv{assets: assets, fs: map[string][]byte{}}
		restore := installLoaderMocks(env)
		installActivityThreadMock()
		fakeCode = map[string]uint32{}
		registerFakeCode(t, g, allClassNames(t, g)...)
		for k, h := range crashHandlerDeps() {
			fakeCalls[k] = h
		}
		if idx, off := findMethod(t, g, "Lcom/apkguard/shell/Loader;", "->"+LoaderEntry+"("); off != 0 {
			if _, rerr := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); rerr == nil {
				for name, blob := range env.fs {
					if pg, perr := Parse(blob); perr == nil {
						total += checkStaticValues(t, filepath.Base(apk)+" 载荷 "+filepath.Base(name), pg)
					}
				}
			}
		}
		restore()
		clearActivityThreadMock()
		fakeCode = map[string]uint32{}
	}
	t.Logf("检查了 %d 个类的 static_values", total)
}

// TestRealWorldStaticValues 检查真实应用载荷的静态值（自研样本覆盖不到）。
func TestRealWorldStaticValues(t *testing.T) {
	apk, isRealApp := realAppAPK(t)
	g, assets := apkShellDex(t, apk)
	env := &loaderEnv{assets: assets, fs: map[string][]byte{}}
	restore := installLoaderMocks(env)
	defer restore()
	installActivityThreadMock()
	defer clearActivityThreadMock()
	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, allClassNames(t, g)...)
	idx, off := findMethod(t, g, "Lcom/apkguard/shell/Loader;", "->"+LoaderEntry+"(")
	if _, err := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); err != nil {
		t.Fatalf("壳链路执行失败: %v", err)
	}
	total := 0
	for name, blob := range env.fs {
		pg, err := Parse(blob)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", name, err)
		}
		total += checkStaticValues(t, filepath.Base(apk)+" "+filepath.Base(name), pg)
	}
	t.Logf("RustDesk 载荷共检查 %d 个类的 static_values", total)
	// 规模断言只在**真实应用产物**上生效：交付包（testapp）规模小得多，
	// 用它去比"应有上千个原型"必然失败，但那不是缺陷。
	// 结构体检（上面 checkXxx 的合法性断言）在任何产物上都已执行。
	if isRealApp && total < 20 {
		t.Fatalf("真实应用带静态值的类数量异常（只检查到 %d 个）", total)
	}
	_ = binary.LittleEndian
}
