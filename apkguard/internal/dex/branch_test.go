package dex

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// checkBranchTargets 校验 DEX 中所有分支的目标都落在指令边界上。
//
// ART 的校验器要求分支目标必须是某条指令的起始字；落在指令中间（或越界）
// 会直接判 VerifyError。A2/A3 的改写会整体平移指令，一旦某个分支偏移算错，
// 就会出现这种「跳进指令中间」的文件——而它在本地的结构校验里完全看不出来。
func checkBranchTargets(t *testing.T, tag string, f *File) int {
	t.Helper()
	checked := 0
	if err := f.walkAllCode(func(codeOff uint32) error {
		ci, err := f.ParseCodeItem(codeOff)
		if err != nil {
			return err
		}
		// 用 ParseInsns 而不是顺序遍历：switch / fill-array-data 的 payload
		// 就嵌在指令流里，顺序遍历会把 payload 的数据当成指令解析，
		// 从而算错「指令边界」集合，产生大量误报。
		l, err := ParseInsns(ci.Insns)
		if err != nil {
			return err
		}
		// 合法分支目标 = 指令起始 ∪ payload 起始。
		//
		// switch / fill-array-data 的 payload 通常排在全部指令之后，
		// 而指向它的 31t 分支是合法的——把 payload 当成「越界」会误报。
		starts := map[int]bool{}
		for i := 0; i < l.ItemCount(); i++ {
			if !l.ItemIsInsn(i) {
				continue
			}
			starts[l.ItemOldOffset(i)] = true
		}
		for i := 0; i < l.ItemCount(); i++ {
			if l.ItemIsInsn(i) {
				continue
			}
			starts[l.ItemOldOffset(i)] = true // payload 自身也是合法目标
		}
		total := len(ci.Insns)
		for i := 0; i < l.ItemCount(); i++ {
			if !l.ItemIsInsn(i) {
				continue
			}
			w := l.ItemWords(i)
			pos := l.ItemOldOffset(i)
			op := byte(w[0] & 0xff)
			var rel int
			var isBranch bool
			switch op {
			case 0x28:
				isBranch, rel = true, int(int8(w[0]>>8))
			case 0x29:
				isBranch, rel = true, int(int16(w[1]))
			case 0x2a:
				isBranch = true
				rel = int(int32(uint32(w[1]) | uint32(w[2])<<16))
			case 0x32, 0x33, 0x34, 0x35, 0x36, 0x37:
				isBranch, rel = true, int(int16(w[1]))
			case 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d:
				isBranch, rel = true, int(int16(w[1]))
			case 0x26, 0x2b, 0x2c:
				isBranch = true
				rel = int(int32(uint32(w[1]) | uint32(w[2])<<16))
			}
			if !isBranch {
				continue
			}
			checked++
			target := pos + rel
			if target < 0 || target > total {
				t.Errorf("%s：code@%d 偏移 %d(op=0x%02x) 的分支跳到 %d，越出方法体 [0,%d)",
					tag, codeOff, pos, op, target, total)
				continue
			}
			if !starts[target] {
				t.Errorf("%s：code@%d 偏移 %d(op=0x%02x) 的分支跳到 %d，那不是指令边界（ART 会判 VerifyError）",
					tag, codeOff, pos, op, target)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("%s 遍历失败: %v", tag, err)
	}
	return checked
}

// TestArtifactBranchTargets 对全部交付包（含解密后的载荷）检查分支目标。
func TestArtifactBranchTargets(t *testing.T) {
	files, err := filepath.Glob("../../../deliver/*.apk")
	if err != nil || len(files) == 0 {
		t.Skip("交付包不在本机，跳过")
	}
	sort.Strings(files)
	total := 0
	for _, apk := range files {
		g, assets := apkShellDex(t, apk)
		total += checkBranchTargets(t, filepath.Base(apk), g)
		if len(assets) == 0 {
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
						total += checkBranchTargets(t, filepath.Base(apk)+" 载荷 "+filepath.Base(name), pg)
					}
				}
			}
		}
		restore()
		clearActivityThreadMock()
		fakeCode = map[string]uint32{}
	}
	if total == 0 {
		t.Log("没有扫描到分支（样本过小）")
	}
	t.Logf("检查了 %d 条分支的目标", total)
}

// TestRealWorldBranchTargets 检查真实应用载荷的分支目标。
//
// 改写会平移指令，分支目标必须重算；算错时 ART 报
//
//	"invalid branch target" 并拒绝整个类。
func TestRealWorldBranchTargets(t *testing.T) {
	apk := os.Getenv("RD_APK")
	if apk == "" {
		apk = "../../../realworld/rd-v20.apk"
	}
	if _, err := os.Stat(apk); err != nil {
		t.Skipf("未找到 %s，跳过", apk)
	}
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
		total += checkBranchTargets(t, filepath.Base(apk)+" "+filepath.Base(name), pg)
	}
	t.Logf("RustDesk 载荷共检查 %d 条分支", total)
}
