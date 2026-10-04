package passes

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// strJunkFixture 构造一个最小 DEX：含一个返回字符串常量的方法（用于验证
// 「新增字符串不被任何指令引用」）与一个算术方法。
func strJunkFixture(t *testing.T) []byte {
	t.Helper()
	protoS := dex.ProtoSpec{Ret: "Ljava/lang/String;"}
	protoAdd := dex.ProtoSpec{Ret: "I", Params: []string{"I", "I"}}

	mustAsm := func(fn func(*dex.Asm)) *dex.CodeBlob {
		a := dex.NewAsm()
		fn(a)
		insns, patches, err := a.Assemble()
		if err != nil {
			t.Fatalf("汇编测试方法失败: %v", err)
		}
		return &dex.CodeBlob{Insns: insns, Patches: patches}
	}
	codeS := mustAsm(func(a *dex.Asm) {
		a.ConstString(0, "hello-world")
		a.ReturnObject(0)
	})
	codeS.Registers, codeS.Ins, codeS.Outs = 2, 0, 0

	codeAdd := mustAsm(func(a *dex.Asm) {
		a.AddInt(0, 2, 3)
		a.Return(0)
	})
	codeAdd.Registers, codeAdd.Ins, codeAdd.Outs = 4, 2, 0

	const accPublic = 0x0001
	const accStatic = 0x0008
	add := dex.Addition{Classes: []dex.ClassSpec{{
		Name:  "Lstr/T;",
		Super: "Ljava/lang/Object;",
		// 类级标志不含 STATIC。
		Access: accPublic,
		Methods: []dex.ClassMethod{
			{Name: "s", Proto: protoS, Access: accPublic | accStatic, Code: codeS},
			{Name: "add", Proto: protoAdd, Access: accPublic | accStatic, Code: codeAdd},
		},
	}}}
	data, err := dex.Build(add)
	if err != nil {
		t.Fatalf("构造测试 DEX 失败: %v", err)
	}
	return data
}

// referencedStringValues 返回全部 const-string / const-string/jumbo 引用的字符串值集合。
//
// 通过 ParseInsns 按指令边界遍历，避免逐字扫描把操作数字节误当成操作码。
func referencedStringValues(t *testing.T, f *dex.File) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	if err := f.AllMethods(func(_, _ string, m dex.EncodedMethod) error {
		if m.CodeOff == 0 {
			return nil
		}
		ci, err := f.ParseCodeItem(m.CodeOff)
		if err != nil {
			return err
		}
		l, err := dex.ParseInsns(ci.Insns)
		if err != nil {
			return err
		}
		for i := 0; i < l.ItemCount(); i++ {
			if !l.ItemIsInsn(i) {
				continue
			}
			w := l.ItemWords(i)
			var idx uint32
			switch byte(w[0] & 0xff) {
			case 0x1a:
				if len(w) < 2 {
					continue
				}
				idx = uint32(w[1])
			case 0x1b:
				if len(w) < 3 {
					continue
				}
				idx = uint32(w[1]) | uint32(w[2])<<16
			default:
				continue
			}
			if s, err := f.String(idx); err == nil {
				out[s] = true
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("遍历方法失败: %v", err)
	}
	return out
}

// TestStrJunkInjection 验证 A19 注入后池确实变大、结构合法、且新增字符串无人引用。
func TestStrJunkInjection(t *testing.T) {
	data := strJunkFixture(t)
	f0, err := dex.Parse(data)
	if err != nil {
		t.Fatalf("解析 fixture 失败: %v", err)
	}
	beforeRefs := referencedStringValues(t, f0)

	art := newArtifact(zipx.NewStored("classes.dex", data))
	p := &strJunk{}
	if err := p.Run(context.Background(), art, &config.Options{Seed: "sj-1", StrJunkCount: 50}); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	e := pipeline.Find(art, "classes.dex")
	if e == nil {
		t.Fatal("classes.dex 丢失")
	}
	out, err := e.Data()
	if err != nil {
		t.Fatal(err)
	}
	if err := dex.Verify(out); err != nil {
		t.Fatalf("A19 产物校验失败: %v", err)
	}
	if err := dex.ValidateDescriptors(out); err != nil {
		t.Fatalf("A19 产物描述符非法: %v", err)
	}
	f1, err := dex.Parse(out)
	if err != nil {
		t.Fatal(err)
	}

	added := int(f1.NString) - int(f0.NString)
	if added <= 0 {
		t.Fatalf("字符串池未增加：%d → %d", f0.NString, f1.NString)
	}
	if got := art.Stats["A19.added"]; got != fmt.Sprint(added) {
		t.Fatalf("A19.added 统计不符：%s vs 实际 %d", got, added)
	}
	if art.Stats["A19.requested"] == "" || art.Stats["A19.requested"] == "0" {
		t.Fatalf("A19.requested 统计缺失: %v", art.Stats)
	}
	if art.Stats["A19.skipped"] != "0" {
		t.Fatalf("小池不应跳过，实际 A19.skipped=%s", art.Stats["A19.skipped"])
	}

	// 池必须保持 UTF-16 升序（ART 会校验 Out-of-order string_ids）。
	prev := ""
	for i := uint32(0); i < f1.NString; i++ {
		s, err := f1.String(i)
		if err != nil {
			t.Fatalf("读取字符串 %d 失败: %v", i, err)
		}
		if i > 0 && dex.CompareUTF16(prev, s) >= 0 {
			t.Fatalf("字符串池顺序错误 @%d: %q >= %q", i, prev, s)
		}
		prev = s
	}

	// 核心断言：没有任何指令引用新增字符串——const-string 的目标值集合不变。
	afterRefs := referencedStringValues(t, f1)
	for s := range beforeRefs {
		if !afterRefs[s] {
			t.Errorf("原有 const-string 引用 %q 丢失", s)
		}
	}
	for s := range afterRefs {
		if !beforeRefs[s] {
			t.Errorf("新增字符串 %q 竟被指令引用（ExtraStrings 应无人引用）", s)
		}
	}

	// 形态多样性抽查：至少出现 URL 形态与非 ASCII（中文/emoji）文本。
	hasURL, hasNonASCII := false, false
	for i := uint32(0); i < f1.NString; i++ {
		s, err := f1.String(i)
		if err != nil {
			continue
		}
		if strings.Contains(s, "://") {
			hasURL = true
		}
		for _, r := range s {
			if r > 127 {
				hasNonASCII = true
				break
			}
		}
	}
	if !hasURL {
		t.Error("垃圾字符串中未出现 URL 形态")
	}
	if !hasNonASCII {
		t.Error("垃圾字符串中未出现中文/emoji 文本")
	}
	t.Logf("A19 fixture：池 %d → %d（requested=%s added=%s bytes=%s skipped=%s）",
		f0.NString, f1.NString, art.Stats["A19.requested"], art.Stats["A19.added"],
		art.Stats["A19.bytes"], art.Stats["A19.skipped"])
}

// TestStrJunkDeterministic 验证同一 seed 下两次注入结果完全一致。
func TestStrJunkDeterministic(t *testing.T) {
	run := func() []byte {
		t.Helper()
		art := newArtifact(zipx.NewStored("classes.dex", strJunkFixture(t)))
		if err := (&strJunk{}).Run(context.Background(), art,
			&config.Options{Seed: "fixed", StrJunkCount: 40}); err != nil {
			t.Fatalf("执行失败: %v", err)
		}
		e := pipeline.Find(art, "classes.dex")
		out, err := e.Data()
		if err != nil {
			t.Fatal(err)
		}
		return append([]byte(nil), out...)
	}
	if a, b := run(), run(); !bytes.Equal(a, b) {
		t.Fatal("相同 seed 下两次加固结果不一致，说明存在未受控随机性")
	}
}

// TestStrJunkSkipsOversizePool 验证「池接近 16 位上限即跳过并记账」的判据与路径。
//
// 端到端构造 6.5 万条字符串的 DEX 不现实，因此直接命中 strJunkUnit 的跳过分支
// （该分支在触碰任何文件数据之前返回，可用仅含 NString 的合成 File 驱动）。
func TestStrJunkSkipsOversizePool(t *testing.T) {
	if strJunkPoolTooBig(1000) {
		t.Error("小池不应判定为过大")
	}
	if strJunkPoolTooBig(strJunkPoolLimit) {
		t.Error("恰好等于阈值不应跳过")
	}
	if !strJunkPoolTooBig(strJunkPoolLimit + 1) {
		t.Error("超过阈值应跳过")
	}
	if !strJunkPoolTooBig(0xFFFF) {
		t.Error("65535 应判定为过大")
	}
	// Termux 的 classes.dex 实测有 65866 个字符串，是真实触发点。
	if !strJunkPoolTooBig(65866) {
		t.Error("65866（Termux 实测规模）应判定为过大")
	}

	u := &dexUnit{file: &dex.File{NString: 70000}}
	req, add, byt, skipped, err := strJunkUnit(u, newRand("x"), 10)
	if err != nil {
		t.Fatalf("跳过路径不应报错: %v", err)
	}
	if !skipped {
		t.Fatalf("池 70000 的 DEX 应被跳过")
	}
	if req != 0 || add != 0 || byt != 0 {
		t.Fatalf("跳过时统计应全 0，实际 req=%d add=%d bytes=%d", req, add, byt)
	}
}

// ---- A20 无害花指令填充（Pass 层） ----

// TestNopFillPass 验证 nopFill Pass 确实通过 JunkFill 驱动花指令、统计齐备，
// 且**没有偷偷开启 A6**（不得出现不透明谓词特征序列，也不得新增写寄存器的指令）。
func TestNopFillPass(t *testing.T) {
	orig := strJunkFixture(t)
	f0, err := dex.Parse(orig)
	if err != nil {
		t.Fatal(err)
	}
	beforeOps := map[string]map[byte]int{}
	if err := f0.AllMethods(func(_, desc string, m dex.EncodedMethod) error {
		if m.CodeOff == 0 {
			return nil
		}
		ci, err := f0.ParseCodeItem(m.CodeOff)
		if err != nil {
			return err
		}
		l, err := dex.ParseInsns(ci.Insns)
		if err != nil {
			return err
		}
		h := map[byte]int{}
		for i := 0; i < l.ItemCount(); i++ {
			if l.ItemIsInsn(i) {
				h[byte(l.ItemWords(i)[0]&0xff)]++
			}
		}
		beforeOps[desc] = h
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	art := newArtifact(zipx.NewStored("classes.dex", orig))
	p := &nopFill{}
	if err := p.Run(context.Background(), art, &config.Options{Seed: "np-1", JunkInsnCount: 5}); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	e := pipeline.Find(art, "classes.dex")
	out, err := e.Data()
	if err != nil {
		t.Fatal(err)
	}
	if err := dex.Verify(out); err != nil {
		t.Fatalf("A20 产物校验失败: %v", err)
	}
	if err := dex.ValidateDescriptors(out); err != nil {
		t.Fatalf("A20 产物描述符非法: %v", err)
	}
	if art.Stats["A20.dex"] != "1" {
		t.Fatalf("A20.dex 应为 1，实际 %v", art.Stats)
	}
	if art.Stats["A20.methods"] == "" || art.Stats["A20.methods"] == "0" {
		t.Fatalf("A20.methods 应 >0，实际 %v", art.Stats)
	}
	if art.Stats["A20.nops"] == "" || art.Stats["A20.nops"] == "0" {
		t.Fatalf("A20.nops 应 >0，实际 %v", art.Stats)
	}
	if art.Stats["A20.fake_jumps"] == "" || art.Stats["A20.fake_jumps"] == "0" {
		t.Fatalf("A20.fake_jumps 应 >0，实际 %v", art.Stats)
	}
	if art.Stats["A20.skipped"] != "0" {
		t.Fatalf("fixture 无 try/payload，A20.skipped 应为 0，实际 %s", art.Stats["A20.skipped"])
	}

	f1, err := dex.Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	// A6 的不透明谓词特征序列：const/16,const/16,mul-int,sub-int,const/16,and-int,if-eqz。
	predSeq := []byte{0x13, 0x13, 0x92, 0x91, 0x13, 0x95, 0x38}
	sawNop, sawGoto16 := false, false
	if err := f1.AllMethods(func(_, desc string, m dex.EncodedMethod) error {
		if m.CodeOff == 0 {
			return nil
		}
		ci, err := f1.ParseCodeItem(m.CodeOff)
		if err != nil {
			return err
		}
		l, err := dex.ParseInsns(ci.Insns)
		if err != nil {
			return err
		}
		var ops []byte
		hist := map[byte]int{}
		for i := 0; i < l.ItemCount(); i++ {
			if !l.ItemIsInsn(i) {
				continue
			}
			op := byte(l.ItemWords(i)[0] & 0xff)
			ops = append(ops, op)
			hist[op]++
			if op == 0x00 {
				sawNop = true
			}
			if op == 0x29 {
				sawGoto16 = true
			}
		}
		if bytes.Contains(ops, predSeq) {
			t.Errorf("方法 %s 出现不透明谓词特征序列，A20 偷偷开了 A6", desc)
		}
		for op, n := range hist {
			if op == 0x00 || op == 0x29 {
				continue
			}
			if n > beforeOps[desc][op] {
				t.Errorf("方法 %s 新增了非 nop/goto16 指令 0x%02x（+%d）", desc, op, n-beforeOps[desc][op])
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !sawNop || !sawGoto16 {
		t.Fatalf("A20 产物缺少 nop/goto16：nop=%v goto16=%v", sawNop, sawGoto16)
	}
	t.Logf("A20 fixture：methods=%s nops=%s fake_jumps=%s skipped=%s",
		art.Stats["A20.methods"], art.Stats["A20.nops"],
		art.Stats["A20.fake_jumps"], art.Stats["A20.skipped"])
}

// TestNopFillReturnNopsOption 验证 A20 的 ReturnNops 选项在 Pass 层真的接线：
// 开启后每条 return 前有 nop 且统计 >0；未开启时统计为 0（零回归）。
func TestNopFillReturnNopsOption(t *testing.T) {
	orig := strJunkFixture(t)
	run := func(returnNops bool) (*pipeline.Artifact, []byte) {
		t.Helper()
		art := newArtifact(zipx.NewStored("classes.dex", orig))
		p := &nopFill{}
		if err := p.Run(context.Background(), art, &config.Options{Seed: "np-2", ReturnNops: returnNops}); err != nil {
			t.Fatalf("A20 执行失败: %v", err)
		}
		out, err := pipeline.Find(art, "classes.dex").Data()
		if err != nil {
			t.Fatal(err)
		}
		if err := dex.Verify(out); err != nil {
			t.Fatalf("A20 产物校验失败: %v", err)
		}
		return art, out
	}

	artOn, outOn := run(true)
	if artOn.Stats["A20.return_nops"] == "" || artOn.Stats["A20.return_nops"] == "0" {
		t.Fatalf("开启 ReturnNops 后 A20.return_nops 应 >0，实际 %v", artOn.Stats)
	}
	artOff, _ := run(false)
	if artOff.Stats["A20.return_nops"] != "0" {
		t.Fatalf("未开启 ReturnNops 时 A20.return_nops 应为 0，实际 %s", artOff.Stats["A20.return_nops"])
	}

	f, err := dex.Parse(outOn)
	if err != nil {
		t.Fatal(err)
	}
	covered, returns := 0, 0
	if err := f.AllMethods(func(_, desc string, m dex.EncodedMethod) error {
		if m.CodeOff == 0 {
			return nil
		}
		ci, err := f.ParseCodeItem(m.CodeOff)
		if err != nil {
			return nil
		}
		l, err := dex.ParseInsns(ci.Insns)
		if err != nil {
			return nil
		}
		for i := 0; i < l.ItemCount(); i++ {
			if !l.ItemIsInsn(i) {
				continue
			}
			op := byte(l.ItemWords(i)[0] & 0xff)
			if op < 0x0e || op > 0x11 {
				continue
			}
			returns++
			if i > 0 && l.ItemIsInsn(i-1) && byte(l.ItemWords(i - 1)[0]&0xff) == 0x00 {
				covered++
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if returns == 0 {
		t.Fatalf("fixture 中没有 return，测试样本失效")
	}
	if covered != returns {
		t.Fatalf("%d 条 return 中只有 %d 条前面有 nop（预算足够时应全覆盖）", returns, covered)
	}
}
