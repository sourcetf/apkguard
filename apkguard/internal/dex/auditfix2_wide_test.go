package dex

import (
	"strings"
	"testing"
)

// 本文件覆盖 auditfix2 的第 6 条：语义等价解释器不支持宽值（long/double）。
//
// A6 有一条硬保护：cffRegs 只报告指令显式写出的那一个寄存器，而 DEX 里长整型
// 占**两个**相邻寄存器（低半 r、高半 r+1），因此扫描活跃寄存器时把 r+1 也算作
// 占用，避免谓词选到某个宽值的高半、写入 int 常量后真机 VerifyError：
//
//	VerifyError: ... [0x6D] wide register v7 has type Low-half Constant/Conflict
//
// 但解释器此前只有 regs []int32（每个寄存器一个槽位、没有低/高半概念），
// 遇到 const-wide/move-wide 直接报「不支持的操作码」——这条保护没有任何测试
// 能验证。现在解释器补上宽值支持（低/高半两个槽位 + 类型标记），并用本
// fixture 做起改写前/后的语义等价回归：返回值一致，且不出现宽值类型冲突。

// audit2WideBody 构造一个含 const-wide / move-wide / return-wide 的方法体。
//
// 布局（registers=7、ins=0）：
//
//	word0-4: const-wide v0, #0x0000000200000001   ; v0=低半, v1=高半
//	word5:   const/4 v3, 1
//	word6:   if-eqz v3, :real                     ; v3!=0 → 不跳，继续往下
//	word7:   nop                                  ; 落到锚点前
//	word8:   move-wide v4, v0                     ; 读 v0 的宽值（校验 v1 类型）
//	word9:   return-wide v4
//
// if-eqz 的分支目标是 word8（使它成为 A6 的插入锚点），但恒不跳；执行沿
// word7 直落到锚点前插入的谓词、再执行 move-wide。这样锚点谓词**真的会执行**，
// 而不是像「恒跳」布局那样成为不可达死代码——后者只能被校验器看到，
// 本地解释器验证不了。
//
// 关键点：v1（宽值高半）在任何指令里都不被显式引用。只按显式寄存器判空闲时，
// v1 会成为「最空闲」的寄存器而被谓词选中；保护生效时它必须被排除。
func audit2WideBody(t *testing.T) *CodeBlob {
	t.Helper()
	a := NewAsm()
	// const-wide（0x18，51l）：word0 操作码+vAA，word1-4 是 64 位小端立即数。
	a.emit(0x0018, 0x0001, 0x0000, 0x0002, 0x0000)
	a.Const4(3, 1)
	a.IfEqz(3, "real") // v3=1，恒不跳
	a.emit(0x0000)     // nop：fallthrough 进入锚点谓词
	a.Label("real")
	// move-wide v4, v0（12x：0x04 | A<<8 | B<<12）
	a.emit(0x0004 | 4<<8)
	// return-wide v4（11x：0x10 | AA<<8）
	a.emit(0x0010 | 4<<8)
	insns, patches, err := a.Assemble()
	if err != nil {
		t.Fatalf("汇编宽值方法失败: %v", err)
	}
	return &CodeBlob{Registers: 7, Ins: 0, Outs: 0, Insns: insns, Patches: patches}
}

// TestAuditFix2WideSemanticEquivalence 验证含宽值的方法经 A6 改写后语义不变，
// 且谓词寄存器没有写坏宽值的高半。
func TestAuditFix2WideSemanticEquivalence(t *testing.T) {
	d, err := Build(Addition{Classes: []ClassSpec{{
		Name:   "Lcff2/W;",
		Super:  "Ljava/lang/Object;",
		Access: accPublic,
		Methods: []ClassMethod{
			{Name: "wide", Proto: ProtoSpec{Ret: "J"}, Access: accPublic | accStatic, Code: audit2WideBody(t)},
		},
	}}})
	if err != nil {
		t.Fatalf("构造宽值测试 DEX 失败: %v", err)
	}
	f0, err := Parse(d)
	if err != nil {
		t.Fatalf("解析测试 DEX 失败: %v", err)
	}

	idx, off := findMethod(t, f0, "Lcff2/W;", "->wide(")
	before, err := runPadMethod(f0, idx, off)
	if err != nil {
		t.Fatalf("改写前执行宽值方法失败（解释器不支持宽值就说明本回归失效）: %v", err)
	}
	const want = int64(0x0000000200000001)
	if got, ok := before.(int64); !ok || got != want {
		t.Fatalf("改写前返回值错误: %#v（期望 int64 %#x）", before, want)
	}

	// MaxPredicates=2 让锚点包含 if-eqz 的分支目标（word8），即 move-wide 之前——
	// 谓词若选到 v1（宽值高半），就会在宽值仍活跃时写坏它。
	out, st, err := RebuildWithStats(f0, RebuildOptions{
		ControlFlow: &ControlFlow{Seed: 4242, MaxPredicates: 2, Substitute: true},
	})
	if err != nil {
		t.Fatalf("A6 重建失败: %v", err)
	}
	if st.ControlFlow.MethodsRewritten < 1 {
		t.Fatalf("含宽值的方法未被 A6 改写，测试前提不成立（跳过原因统计: %+v）", st.ControlFlow)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("A6 产物 Verify 失败: %v", err)
	}
	if err := ValidateDescriptors(out); err != nil {
		t.Fatalf("A6 产物描述符非法: %v", err)
	}

	f1, err := Parse(out)
	if err != nil {
		t.Fatalf("解析 A6 产物失败: %v", err)
	}
	idx1, off1 := findMethod(t, f1, "Lcff2/W;", "->wide(")
	after, err := runPadMethod(f1, idx1, off1)
	if err != nil {
		if strings.Contains(err.Error(), "宽值类型冲突") {
			t.Fatalf("A6 谓词写坏了宽值高半（cffRegs 的 r+1 保护失效）: %v", err)
		}
		t.Fatalf("改写后执行宽值方法失败: %v", err)
	}
	if after != before {
		t.Fatalf("宽值方法改写前后返回值不同: %#v → %#v（谓词非恒真或宽值被写坏）", before, after)
	}
	t.Logf("宽值语义等价: %#v（谓词 %d、替换 %d、改写 %d 个方法）",
		after, st.ControlFlow.Predicates, st.ControlFlow.Substitutions, st.ControlFlow.MethodsRewritten)
}
