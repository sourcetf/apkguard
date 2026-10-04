package passes

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pack"
	"apkguard/internal/pipeline"
	"apkguard/internal/vmp"
	"apkguard/internal/zipx"
)

// 本文件是 B6 的产物级测试：翻译数量、跳过原因、载荷可解密/可反汇编、
// 关闭时零改动、同 seed 可复现，以及 B8 同时启用时的容器目录一致性。
//
// 方法体由 dex.Build 现造（不依赖 sample.apk），因此每条断言都可精确预期。

// vmpInsnsBlob 由指令字构造一个最简 code_item。
func vmpInsnsBlob(regs, ins int, words ...uint16) *dex.CodeBlob {
	return &dex.CodeBlob{Registers: uint16(regs), Ins: uint16(ins), Insns: words}
}

// vmpTestDEX 构造一个只含测试方法的 DEX。
func vmpTestDEX(t *testing.T, methods []dex.ClassMethod) []byte {
	t.Helper()
	const cls = "Ltest/A;"
	add := dex.Addition{Classes: []dex.ClassSpec{{
		Name: cls, Super: "Ljava/lang/Object;", Access: 0x1, Methods: methods,
	}}}
	for _, m := range methods {
		add.Methods = append(add.Methods, dex.MethodSpec{Class: cls, Name: m.Name, Proto: m.Proto})
	}
	data, err := dex.Build(add)
	if err != nil {
		t.Fatalf("构造测试 DEX 失败: %v", err)
	}
	if err := dex.ValidateDescriptors(data); err != nil {
		t.Fatalf("测试 DEX 描述符非法: %v", err)
	}
	return data
}

// vmpEligibleMethods 是两个可翻译方法（int 二元运算 + long 运算）。
func vmpEligibleMethods() []dex.ClassMethod {
	return []dex.ClassMethod{
		{ // static int addsub(int a, int b)：v0 = a - (a + b) 的反向小算式
			Name: "addsub", Access: 0x9, Proto: dex.ProtoSpec{Ret: "I", Params: []string{"I", "I"}},
			Code: vmpInsnsBlob(2, 2,
				0x0090, 0x0100, // add-int v0, v0, v1
				0x0091, 0x0100, // sub-int v0, v0, v1
				0x000f, // return v0
			),
		},
		{ // static long lops(long a, long b)：v0 = a + b
			Name: "lops", Access: 0x9, Proto: dex.ProtoSpec{Ret: "J", Params: []string{"J", "J"}},
			Code: vmpInsnsBlob(4, 4,
				0x009b, 0x0200, // add-long v0, v0, v2
				0x0010, // return-wide v0
			),
		},
	}
}

// vmpIneligibleMethods 是四类必须被跳过的结构。
func vmpIneligibleMethods() []dex.ClassMethod {
	return []dex.ClassMethod{
		{ // 不支持指令：throw
			Name: "throwm", Access: 0x9, Proto: dex.ProtoSpec{Ret: "V"},
			Code: vmpInsnsBlob(1, 0, 0x0027),
		},
		{ // 不支持指令：packed-switch
			Name: "switchm", Access: 0x9, Proto: dex.ProtoSpec{Ret: "V"},
			Code: vmpInsnsBlob(1, 0, 0x002b, 0x0001, 0x0000),
		},
		{ // 不支持指令：fill-array-data
			Name: "fillm", Access: 0x9, Proto: dex.ProtoSpec{Ret: "V"},
			Code: vmpInsnsBlob(1, 0, 0x0026, 0x0001, 0x0000),
		},
		{ // synchronized 方法
			Name: "syncm", Access: 0x21, Proto: dex.ProtoSpec{Ret: "V"},
			Code: vmpInsnsBlob(0, 0, 0x000e),
		},
	}
}

// vmpFindCodeOff 在 DEX 中定位指定方法的 code_item 偏移。
func vmpFindCodeOff(t *testing.T, f *dex.File, classDesc, name string) uint32 {
	t.Helper()
	for i := uint32(0); i < f.NClass; i++ {
		cd, err := f.ClassDefAt(i)
		if err != nil {
			t.Fatal(err)
		}
		d, err := f.Type(cd.ClassIdx)
		if err != nil {
			t.Fatal(err)
		}
		if d != classDesc || cd.ClassDataOff == 0 {
			continue
		}
		pcd, err := f.ParseClassData(cd.ClassDataOff)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range append(append([]dex.EncodedMethod{}, pcd.DirectMethods...), pcd.VirtualMethods...) {
			ref, err := f.MethodRefAt(m.Idx)
			if err != nil {
				t.Fatal(err)
			}
			n, err := f.String(ref.NameIdx)
			if err != nil {
				t.Fatal(err)
			}
			if n == name {
				return m.CodeOff
			}
		}
	}
	t.Fatalf("找不到方法 %s.%s", classDesc, name)
	return 0
}

// vmpReplaceWithTry 把 dexData 中某方法的 code_item 替换为带 try/catch 的版本。
func vmpReplaceWithTry(t *testing.T, dexData []byte, classDesc, name string) []byte {
	t.Helper()
	f, err := dex.Parse(dexData)
	if err != nil {
		t.Fatalf("解析测试 DEX 失败: %v", err)
	}
	off := vmpFindCodeOff(t, f, classDesc, name)
	ci := &dex.CodeItemFull{
		Registers: 1,
		Insns:     []uint16{0x0e},
		Tries:     []dex.TryItem{{StartAddr: 0, InsnCount: 1, HandlerOff: 1}},
		Handlers:  []dex.CatchHandler{{CatchAll: true, AllAddr: 0}},
	}
	blob, err := ci.EncodeChecked(nil)
	if err != nil {
		t.Fatalf("构造带异常表的 code_item 失败: %v", err)
	}
	out, err := dex.Rebuild(f, dex.RebuildOptions{CodeReplacements: map[uint32][]byte{off: blob}})
	if err != nil {
		t.Fatalf("替换方法体失败: %v", err)
	}
	// 自证替换生效：重建后的 code_item 必须真的带异常表。
	f2, err := dex.Parse(out)
	if err != nil {
		t.Fatalf("重建后的 DEX 解析失败: %v", err)
	}
	ci2, err := f2.ParseCodeItem(off)
	if err != nil {
		t.Fatalf("重建后的 code_item 解析失败: %v", err)
	}
	if len(ci2.Tries) != 1 {
		t.Fatalf("替换后应含 1 条 try 记录，实际 %d", len(ci2.Tries))
	}
	return out
}

// vmpTestArtifact 构造含测试 DEX 的产物。
func vmpTestArtifact(t *testing.T, methods []dex.ClassMethod) (*pipeline.Artifact, []byte) {
	t.Helper()
	data := vmpTestDEX(t, methods)
	art := newArtifact(zipx.NewStored("classes.dex", data))
	return art, data
}

// vmpBaseOpts 返回启用 B6 所需的最小选项（B1/B2/B3 依赖 + 固定密钥便于对比）。
func vmpBaseOpts(n int) *config.Options {
	opts := &config.Options{Seed: "b6-seed", DexKey: "b6-dex-key", VMPMethods: n}
	opts.SetEnabled("B1", true)
	opts.SetEnabled("B2", true)
	opts.SetEnabled("B3", true)
	return opts
}

// vmpEntriesSnapshot 记录全部条目的名字与原始字节。
func vmpEntriesSnapshot(art *pipeline.Artifact) map[string][]byte {
	out := map[string][]byte{}
	for _, e := range art.Entries() {
		out[e.NameString()] = append([]byte(nil), e.Raw...)
	}
	return out
}

func TestVMPZeroMethodsIsNoop(t *testing.T) {
	methods := append(vmpEligibleMethods(), vmpIneligibleMethods()...)
	art, _ := vmpTestArtifact(t, methods)
	before := vmpEntriesSnapshot(art)

	// VMPMethods=0 是关闭开关：不得新增条目、不得改任何字节。
	if err := (&vmpMethods{}).Run(context.Background(), art, &config.Options{Seed: "s"}); err != nil {
		t.Fatalf("关闭状态执行失败: %v", err)
	}
	after := vmpEntriesSnapshot(art)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("VMPMethods=0 时产物被改动：条目 %d -> %d", len(before), len(after))
	}
	for k := range art.Stats {
		if strings.HasPrefix(k, "B6.") {
			t.Fatalf("VMPMethods=0 不应产生 B6 统计项 %s", k)
		}
	}
	if art.Get(sharedKeyVMP) != nil {
		t.Fatal("VMPMethods=0 不应写入 B6 摘要")
	}

	// 端到端零影响：与 B1 同链跑一遍，VMPMethods=0 的产物必须与
	// 「B6 根本没有执行过」逐字节一致（含 B1 生成的加密载荷）。
	runChain := func(withB6 bool) map[string][]byte {
		a, _ := vmpTestArtifact(t, vmpEligibleMethods())
		o := vmpBaseOpts(0)
		if withB6 {
			if err := (&vmpMethods{}).Run(context.Background(), a, o); err != nil {
				t.Fatalf("B6(VMPMethods=0) 执行失败: %v", err)
			}
		}
		if err := (&encryptDex{}).Run(context.Background(), a, o); err != nil {
			t.Fatalf("B1 执行失败: %v", err)
		}
		return vmpEntriesSnapshot(a)
	}
	without := runChain(false)
	with := runChain(true)
	if !reflect.DeepEqual(without, with) {
		t.Fatalf("VMPMethods=0 时产物与未启用 B6 不一致：条目数 %d vs %d", len(without), len(with))
	}
}

func TestVMPDependencyErrors(t *testing.T) {
	art, _ := vmpTestArtifact(t, vmpEligibleMethods())
	pass := &vmpMethods{}
	cases := []struct {
		name string
		opts *config.Options
		want string
	}{
		{"缺 B1", &config.Options{VMPMethods: 1}, "B1"},
		{"缺 B3", func() *config.Options {
			o := &config.Options{VMPMethods: 1}
			o.SetEnabled("B1", true)
			o.SetEnabled("B2", true)
			return o
		}(), "B3"},
		{"与 B5 互斥", func() *config.Options {
			o := vmpBaseOpts(1)
			o.ExtractMethods = 5
			return o
		}(), "B5"},
		{"与 B7 互斥", func() *config.Options {
			o := vmpBaseOpts(1)
			o.Dex2CMethods = 5
			return o
		}(), "B7"},
	}
	for _, c := range cases {
		err := pass.Run(context.Background(), art, c.opts)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: 应报包含 %q 的错误，实际 %v", c.name, c.want, err)
		}
	}
}

func TestVMPTranslateAndPack(t *testing.T) {
	methods := append(vmpEligibleMethods(), vmpIneligibleMethods()...)
	art, dexBefore := vmpTestArtifact(t, methods)
	// 把 throwm 换成带 try/catch 的版本：pass 与 vmp 选择器都必须拒绝它。
	dexReplaced := vmpReplaceWithTry(t, dexBefore, "Ltest/A;", "throwm")
	if err := pipeline.Find(art, "classes.dex").SetData(dexReplaced, true); err != nil {
		t.Fatalf("写回测试 DEX 失败: %v", err)
	}

	opts := vmpBaseOpts(10)
	if err := (&vmpMethods{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("执行失败: %v", err)
	}

	sum, _ := art.Get(sharedKeyVMP).(*vmpSummary)
	if sum == nil {
		t.Fatal("未写入 B6 摘要")
	}
	if sum.Selected != 2 {
		t.Fatalf("应虚拟化 2 个方法（addsub/lops），实际 %d；跳过明细: %s", sum.Selected, reasonReport(sum.Skip))
	}
	if len(sum.Methods) != 2 || !strings.Contains(sum.Methods[0], "addsub") || !strings.Contains(sum.Methods[1], "lops") {
		t.Fatalf("方法明细不符: %v", sum.Methods)
	}
	if sum.Payload == "" {
		t.Fatal("摘要未记录载荷条目名")
	}
	for _, want := range []string{"含 try/catch", "不支持指令 packed-switch", "不支持指令 fill-array-data",
		"synchronized"} {
		found := false
		for reason := range sum.Skip {
			if strings.Contains(reason, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("跳过原因应含 %q，实际: %s", want, reasonReport(sum.Skip))
		}
	}
	if art.Stats["B6.selected"] != "2" {
		t.Fatalf("B6.selected 统计不符: %v", art.Stats)
	}

	// 载荷必须存在、Stored、可解密、可反汇编、无未知操作码。
	en := pipeline.Find(art, sum.Payload)
	if en == nil {
		t.Fatalf("载荷条目 %s 不存在", sum.Payload)
	}
	if !en.IsStored() {
		t.Fatal("载荷必须未压缩存储")
	}
	key, ok := art.Get(sharedKeyPayloadKey).([pack.KeySize]byte)
	if !ok {
		t.Fatal("artifact 中缺少共享载荷密钥")
	}
	plain, err := pack.Decrypt(en.Raw, key)
	if err != nil {
		t.Fatalf("载荷解密失败: %v", err)
	}
	blob, err := vmp.DecodeBlob(plain)
	if err != nil {
		t.Fatalf("载荷解码失败: %v", err)
	}
	if len(blob.Methods) != 2 {
		t.Fatalf("载荷内方法数 %d != 2", len(blob.Methods))
	}
	for i, p := range blob.Methods {
		if p.VMID != uint32(i) {
			t.Fatalf("VMID 必须全局连续编号：第 %d 个为 %d", i, p.VMID)
		}
		for _, ln := range vmp.Disasm(p) {
			if strings.Contains(ln, "非法") {
				t.Fatalf("反汇编出现非法指令: %s", ln)
			}
		}
	}
	if blob.Methods[0].Class != "Ltest/A;" {
		t.Fatalf("方法类描述符不符: %s", blob.Methods[0].Class)
	}

	// 本次交付的 DEX 侧边界：DEX 字节不得被改动（改写 ACC_NATIVE/stub 是后续切片）。
	// 用 Data() 取解压后的明文比较：SetData(...,true) 后 Raw 可能是 deflate 流。
	gotDex, err := pipeline.Find(art, "classes.dex").Data()
	if err != nil {
		t.Fatalf("读取 DEX 失败: %v", err)
	}
	if !bytes.Equal(gotDex, dexReplaced) {
		t.Fatal("B6 最小子集不应改动 DEX 字节（ACC_NATIVE/stub 改写尚未接线）")
	}
}

func TestVMPDeterministic(t *testing.T) {
	methods := vmpEligibleMethods()
	run := func() (string, []byte, *vmpSummary) {
		art, _ := vmpTestArtifact(t, methods)
		if err := (&vmpMethods{}).Run(context.Background(), art, vmpBaseOpts(10)); err != nil {
			t.Fatalf("执行失败: %v", err)
		}
		sum, _ := art.Get(sharedKeyVMP).(*vmpSummary)
		en := pipeline.Find(art, sum.Payload)
		return sum.Payload, append([]byte(nil), en.Raw...), sum
	}
	name1, blob1, sum1 := run()
	name2, blob2, sum2 := run()
	if name1 != name2 || !bytes.Equal(blob1, blob2) {
		t.Fatal("相同 seed/密钥应产生逐字节一致的载荷与条目名")
	}
	if !reflect.DeepEqual(sum1, sum2) {
		t.Fatal("相同 seed 的摘要应一致")
	}
}

func TestVMPPayloadLandsInB8Container(t *testing.T) {
	art, _ := vmpTestArtifact(t, vmpEligibleMethods())
	opts := vmpBaseOpts(10)
	opts.SetEnabled("B8", true)

	if err := (&vmpMethods{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("B6 执行失败: %v", err)
	}
	sum, _ := art.Get(sharedKeyVMP).(*vmpSummary)
	if sum == nil || sum.Payload == "" {
		t.Fatal("B6 未产生载荷")
	}
	// 依次跑 B1 与 B8，确认 B6 载荷与 B1 载荷落在同一容器目录树。
	if err := (&encryptDex{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("B1 执行失败: %v", err)
	}
	if err := (&payloadContainer{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("B8 执行失败: %v", err)
	}
	sp := payloadsOf(art)
	if sp == nil || len(sp.Items) == 0 {
		t.Fatal("B1 载荷清单缺失")
	}
	b6dir := sum.Payload[:strings.LastIndex(sum.Payload, "/")]
	b1dir := sp.Items[0].Asset[:strings.LastIndex(sp.Items[0].Asset, "/")]
	if b6dir != b1dir {
		t.Fatalf("B6 载荷目录 %s 与 B8 容器目录 %s 不一致（派生公式漂移）", b6dir, b1dir)
	}
	if pipeline.Find(art, sum.Payload) == nil {
		t.Fatal("B6 载荷在 B8 之后应仍存在")
	}
}
