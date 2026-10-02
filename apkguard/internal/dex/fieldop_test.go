package dex

import (
	"path/filepath"
	"sort"
	"testing"
)

// checkFieldOps 校验字段读写指令的操作码与字段类型是否匹配。
//
// Dalvik 为字段访问按「值的宽度」分了不同操作码：对象用 sget-object /
// sput-object（0x62/0x69），宽值（long/double）用 -wide（0x61/0x68），
// 其余基本类型用 0x60/0x67 及布尔/字节/字符/短整型变体。用错操作码时
// ART 的校验器会直接判 VerifyError（「寄存器里是对象，字段却要宽类型」），
// 而本地结构校验完全看不出来——本项目就因此踩过一次坑。
func checkFieldOps(t *testing.T, tag string, f *File) int {
	t.Helper()
	checked := 0
	if err := f.walkAllCode(func(codeOff uint32) error {
		ci, err := f.ParseCodeItem(codeOff)
		if err != nil {
			return err
		}
		return walkInsns(ci.Insns, func(op byte, pos int, w []uint16) error {
			ref, ok := insnRefs[op]
			if !ok || ref.kind != refField || pos+ref.word >= len(w) {
				return nil
			}
			fi := uint32(w[pos+ref.word])
			_, typeIdx, _, err := f.FieldRefAt(fi)
			if err != nil {
				return nil
			}
			ft, err := f.Type(uint32(typeIdx))
			if err != nil {
				return nil
			}
			wide := ft == "J" || ft == "D"
			obj := len(ft) > 0 && (ft[0] == 'L' || ft[0] == '[')
			checked++
			// 按 Dalvik 的字段操作码分类判定宽度是否匹配。
			//
			// 每类宽度各有 iget/iput（0x44..0x51 与 0x52..0x5f）与 sget/sput
			// （0x60..0x6d）两组，漏列一组就会把合法指令误报成错误。
			objOps := map[byte]bool{0x48: true, 0x49: true, 0x54: true, 0x5b: true, 0x62: true, 0x69: true}
			wideOps := map[byte]bool{0x46: true, 0x47: true, 0x53: true, 0x5a: true, 0x61: true, 0x68: true}
			switch {
			case objOps[op]:
				if !obj {
					t.Errorf("%s：code@%d 偏移 %d 用对象类操作码 0x%02x 访问字段 %s（ART 会判 VerifyError）",
						tag, codeOff, pos, op, ft)
				}
			case wideOps[op]:
				if !wide {
					t.Errorf("%s：code@%d 偏移 %d 用 wide 操作码 0x%02x 访问非宽字段 %s（ART 会判 VerifyError）",
						tag, codeOff, pos, op, ft)
				}
			default:
				if obj || wide {
					t.Errorf("%s：code@%d 偏移 %d 用 op=0x%02x 访问字段 %s，宽度不匹配（ART 会判 VerifyError）",
						tag, codeOff, pos, op, ft)
				}
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("%s 遍历失败: %v", tag, err)
	}
	return checked
}

// TestArtifactFieldOps 对全部交付包（含解密后的载荷）做字段操作码体检。
func TestArtifactFieldOps(t *testing.T) {
	files, err := filepath.Glob("../../../deliver/*.apk")
	if err != nil || len(files) == 0 {
		t.Skip("交付包不在本机，跳过")
	}
	sort.Strings(files)
	total := 0
	for _, apk := range files {
		g, assets := apkShellDex(t, apk)
		total += checkFieldOps(t, filepath.Base(apk), g)
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
						total += checkFieldOps(t, filepath.Base(apk)+" 载荷 "+filepath.Base(name), pg)
					}
				}
			}
		}
		restore()
		clearActivityThreadMock()
		fakeCode = map[string]uint32{}
	}
	t.Logf("体检了 %d 条字段访问指令", total)
}

// TestSPutObjectOpcode 直接断言汇编器发出的操作码。
//
// 这是上一条体检的「源头防线」：曾经 SPutObject 发的是 0x68（sput-wide），
// 而解释器也把 0x68 当 sput-object，两边一起错，于是本地全绿、真机崩。
func TestSPutObjectOpcode(t *testing.T) {
	f := FieldSpec{Class: "Lx/C;", Name: "o", Type: "Ljava/lang/Object;"}
	a := NewAsm()
	a.SPutObject(3, f)
	insns, _, err := a.Assemble()
	if err != nil {
		t.Fatalf("汇编失败: %v", err)
	}
	if got := byte(insns[0] & 0xff); got != 0x69 {
		t.Fatalf("sput-object 的操作码应为 0x69，实际 0x%02x", got)
	}
	if got := int(insns[0] >> 8); got != 3 {
		t.Fatalf("寄存器应为 v3，实际 v%d", got)
	}
	// sget-object 同样断言（0x62），避免同类错误再现。
	a2 := NewAsm()
	a2.SGetObject(2, f)
	insns2, _, err := a2.Assemble()
	if err != nil {
		t.Fatalf("汇编失败: %v", err)
	}
	if got := byte(insns2[0] & 0xff); got != 0x62 {
		t.Fatalf("sget-object 的操作码应为 0x62，实际 0x%02x", got)
	}
}

// TestReturnOpcodes 断言 return 家族的操作码。
//
// 与 sput-object 那次同源：操作码的宽度选错（0x10 return-wide 当成
// return-object）时，本地解释器会跟着错认，于是测试全绿而 ART 拒绝整个类。
func TestReturnOpcodes(t *testing.T) {
	cases := []struct {
		name string
		emit func(a *Asm)
		want byte
	}{
		{"return-void", func(a *Asm) { a.ReturnVoid() }, 0x0e},
		{"return", func(a *Asm) { a.Return(2) }, 0x0f},
		{"return-object", func(a *Asm) { a.ReturnObject(3) }, 0x11},
	}
	for _, c := range cases {
		a := NewAsm()
		c.emit(a)
		insns, _, err := a.Assemble()
		if err != nil {
			t.Fatalf("%s 汇编失败: %v", c.name, err)
		}
		if got := byte(insns[0] & 0xff); got != c.want {
			t.Errorf("%s 的操作码应为 0x%02x，实际 0x%02x", c.name, c.want, got)
		}
	}
}
