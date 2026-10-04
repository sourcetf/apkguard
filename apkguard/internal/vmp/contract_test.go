package vmp_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"apkguard/internal/vmp"
)

// TestOpcodeContractWithC 把「私有指令集数值」这份跨语言二进制契约钉死。
//
// C 侧解释器（internal/native/csrc/agvm.h）里有一份同名枚举 AG_OP_*。
// 任何一侧悄悄改号、增删操作码，都会让设备上的解释器把 A 指令执行成 B
// 指令——而 Go 单测全绿。这里解析 C 源码逐值比对，是唯一能在 CI 拦下
// 这类事故的守卫（本地无法跑真机）。
func TestOpcodeContractWithC(t *testing.T) {
	path := filepath.Join("..", "native", "csrc", "agvm.h")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 C 源码失败（%s）: %v", path, err)
	}
	re := regexp.MustCompile(`AG_OP_([A-Z0-9]+)\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)`)
	got := map[string]uint8{}
	for _, m := range re.FindAllStringSubmatch(string(data), -1) {
		v, err := strconv.ParseUint(m[2], 0, 16)
		if err != nil {
			t.Fatalf("解析 %s 的取值 %q 失败: %v", m[1], m[2], err)
		}
		if _, dup := got[m[1]]; dup {
			t.Fatalf("C 侧枚举 %s 重复定义", m[1])
		}
		got[m[1]] = uint8(v)
	}
	if len(got) == 0 {
		t.Fatal("C 源码里没有解析到任何 AG_OP_*（枚举被改名或删除？）")
	}

	want := []struct {
		name string
		op   uint8
	}{
		{"NOP", vmp.OpNop},
		{"MOVE", vmp.OpMove}, {"MOVEWIDE", vmp.OpMoveWide}, {"MOVEOBJECT", vmp.OpMoveObject},
		{"CONST", vmp.OpConst}, {"CONSTWIDE", vmp.OpConstWide}, {"CONSTSTRING", vmp.OpConstString},
		{"MOVERESULT", vmp.OpMoveResult}, {"MOVERESULTWIDE", vmp.OpMoveResultWide},
		{"MOVERESULTOBJECT", vmp.OpMoveResultObject},
		{"NEGINT", vmp.OpNegInt}, {"NOTINT", vmp.OpNotInt}, {"NEGLONG", vmp.OpNegLong},
		{"NOTLONG", vmp.OpNotLong}, {"I2B", vmp.OpI2B}, {"I2C", vmp.OpI2C},
		{"I2S", vmp.OpI2S}, {"I2L", vmp.OpI2L}, {"L2I", vmp.OpL2I},
		{"ADDINT", vmp.OpAddInt}, {"SUBINT", vmp.OpSubInt}, {"MULINT", vmp.OpMulInt},
		{"DIVINT", vmp.OpDivInt}, {"REMINT", vmp.OpRemInt}, {"ANDINT", vmp.OpAndInt},
		{"ORINT", vmp.OpOrInt}, {"XORINT", vmp.OpXorInt}, {"SHLINT", vmp.OpShlInt},
		{"SHRINT", vmp.OpShrInt}, {"USHRINT", vmp.OpUshrInt}, {"ADDLONG", vmp.OpAddLong},
		{"SUBLONG", vmp.OpSubLong}, {"MULLONG", vmp.OpMulLong}, {"DIVLONG", vmp.OpDivLong},
		{"REMLONG", vmp.OpRemLong}, {"ANDLONG", vmp.OpAndLong}, {"ORLONG", vmp.OpOrLong},
		{"XORLONG", vmp.OpXorLong}, {"SHLLONG", vmp.OpShlLong}, {"SHRLONG", vmp.OpShrLong},
		{"USHRLONG", vmp.OpUshrLong}, {"CMPLONG", vmp.OpCmpLong},
		{"ADDINTIMM", vmp.OpAddIntImm}, {"MULINTIMM", vmp.OpMulIntImm},
		{"DIVINTIMM", vmp.OpDivIntImm}, {"REMINTIMM", vmp.OpRemIntImm},
		{"ANDINTIMM", vmp.OpAndIntImm}, {"ORINTIMM", vmp.OpOrIntImm},
		{"XORINTIMM", vmp.OpXorIntImm}, {"SHLINTIMM", vmp.OpShlIntImm},
		{"SHRINTIMM", vmp.OpShrIntImm}, {"USHRINTIMM", vmp.OpUshrIntImm},
		{"GOTO", vmp.OpGoto}, {"IFEQ", vmp.OpIfEq}, {"IFNE", vmp.OpIfNe},
		{"IFLT", vmp.OpIfLt}, {"IFGE", vmp.OpIfGe}, {"IFGT", vmp.OpIfGt}, {"IFLE", vmp.OpIfLe},
		{"IFEQZ", vmp.OpIfEqz}, {"IFNEZ", vmp.OpIfNez}, {"IFLTZ", vmp.OpIfLtz},
		{"IFGEZ", vmp.OpIfGez}, {"IFGTZ", vmp.OpIfGtz}, {"IFLEZ", vmp.OpIfLez},
		{"IGET", vmp.OpIGet}, {"IPUT", vmp.OpIPut}, {"SGET", vmp.OpSGet}, {"SPUT", vmp.OpSPut},
		{"IGETWIDE", vmp.OpIGetWide}, {"IPUTWIDE", vmp.OpIPutWide},
		{"SGETWIDE", vmp.OpSGetWide}, {"SPUTWIDE", vmp.OpSPutWide},
		{"IGETOBJECT", vmp.OpIGetObject}, {"IPUTOBJECT", vmp.OpIPutObject},
		{"SGETOBJECT", vmp.OpSGetObject}, {"SPUTOBJECT", vmp.OpSPutObject},
		{"INVOKESTATIC", vmp.OpInvokeStatic}, {"INVOKEVIRTUAL", vmp.OpInvokeVirtual},
		{"INVOKEDIRECT", vmp.OpInvokeDirect}, {"INVOKESUPER", vmp.OpInvokeSuper},
		{"INVOKEINTERFACE", vmp.OpInvokeInterface},
		{"RETURNVOID", vmp.OpReturnVoid}, {"RETURN", vmp.OpReturn},
		{"RETURNWIDE", vmp.OpReturnWide}, {"RETURNOBJECT", vmp.OpReturnObject},
	}
	if len(got) != len(want) {
		t.Fatalf("C 侧枚举数量 %d 与 Go 侧声明 %d 不一致（一侧增删了操作码）", len(got), len(want))
	}
	for _, w := range want {
		v, ok := got[w.name]
		if !ok {
			t.Errorf("C 侧缺少 AG_OP_%s", w.name)
			continue
		}
		if v != w.op {
			t.Errorf("操作码 AG_OP_%s 两侧不一致：C=0x%02x Go=0x%02x", w.name, v, w.op)
		}
	}
}
