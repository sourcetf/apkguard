package dex2c

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"unicode/utf16"
)

// skipErr 是「该方法不可翻译」的原因，reason 用于统计，detail 用于定位。
type skipErr struct {
	reason string
	detail string
}

func (e *skipErr) Error() string { return e.reason + ": " + e.detail }

func skipf(reason, format string, args ...any) error {
	return &skipErr{reason: reason, detail: fmt.Sprintf(format, args...)}
}

// invokeWhitelist 是允许出现在被翻译方法里的调用目标类。
//
// 白名单而不是黑名单：Dex2C 的调用要经 JNI 反射式解析（FindClass + GetMethodID），
// 未列出的类一旦参与，运行期解析失败就是 UnsatisfiedLink/NoSuchMethod 级别的事故；
// 第一版只放开纯 JDK 且语义稳定的类。
var invokeWhitelist = map[string]bool{
	"Ljava/lang/Math;":         true,
	"Ljava/lang/String;":       true,
	"Ljava/lang/Integer;":      true,
	"Ljava/lang/Object;":       true,
	"Ljava/lang/Character;":    true,
	"Ljava/lang/Boolean;":      true,
	"Ljava/lang/System;":       true,
	"Ljava/lang/CharSequence;": true,
	"Ljava/lang/Comparable;":   true,
}

// prepare 解码并校验方法体，做引用解析与类型推断。
func (m *Method) prepare() error {
	ins, err := decodeInsns(m.words)
	if err != nil {
		return skipf("insn", "%s: %v", m.Source, err)
	}
	m.ins = ins
	m.strRefs = make([]string, len(ins))
	m.fldRefs = make([]*fieldRef, len(ins))
	m.mthRefs = make([]*methodRef, len(ins))

	for i := range ins {
		it := &ins[i]
		switch {
		case it.op == 0x1a || it.op == 0x1b: // const-string
			s, err := m.file.String(it.ref)
			if err != nil {
				return skipf("decode", "%s: 字符串 %d 读取失败", m.Source, it.ref)
			}
			m.strRefs[i] = s
			m.needsJni = true
		case it.op >= 0x52 && it.op <= 0x5f:
			classIdx, typeIdx, nameIdx, err := m.file.FieldRefAt(it.ref)
			if err != nil {
				return skipf("decode", "%s: 字段引用读取失败", m.Source)
			}
			class, err := m.file.Type(uint32(classIdx))
			if err != nil {
				return skipf("decode", "%s: 字段类读取失败", m.Source)
			}
			typ, err := m.file.Type(uint32(typeIdx))
			if err != nil {
				return skipf("decode", "%s: 字段类型读取失败", m.Source)
			}
			name, err := m.file.String(nameIdx)
			if err != nil {
				return skipf("decode", "%s: 字段名读取失败", m.Source)
			}
			if _, ok := typeKind(typ); !ok {
				return skipf("wide", "%s: 字段 %s 类型 %s 不支持", m.Source, name, typ)
			}
			m.fldRefs[i] = &fieldRef{class: class, name: name, typ: typ}
			m.needsJni = true
		case it.op >= 0x60 && it.op <= 0x6d:
			classIdx, typeIdx, nameIdx, err := m.file.FieldRefAt(it.ref)
			if err != nil {
				return skipf("decode", "%s: 静态字段引用读取失败", m.Source)
			}
			class, err := m.file.Type(uint32(classIdx))
			if err != nil {
				return skipf("decode", "%s: 字段类读取失败", m.Source)
			}
			typ, err := m.file.Type(uint32(typeIdx))
			if err != nil {
				return skipf("decode", "%s: 字段类型读取失败", m.Source)
			}
			name, err := m.file.String(nameIdx)
			if err != nil {
				return skipf("decode", "%s: 字段名读取失败", m.Source)
			}
			if _, ok := typeKind(typ); !ok {
				return skipf("wide", "%s: 静态字段 %s 类型 %s 不支持", m.Source, name, typ)
			}
			m.fldRefs[i] = &fieldRef{class: class, name: name, typ: typ}
			m.needsJni = true
		case opIsInvoke(it.op):
			class, name, ret, params, err := m.file.MethodFull(it.ref)
			if err != nil {
				return skipf("decode", "%s: 方法引用读取失败", m.Source)
			}
			kind, _ := opInvokeKind(it.op)
			if !invokeWhitelist[class] {
				return skipf("invoke", "%s: 调用目标类 %s 不在白名单", m.Source, class)
			}
			if ret != "V" {
				if _, ok := typeKind(ret); !ok {
					return skipf("wide", "%s: 调用 %s.%s 返回类型 %s 不支持", m.Source, class, name, ret)
				}
			}
			for _, p := range params {
				if _, ok := typeKind(p); !ok {
					return skipf("wide", "%s: 调用 %s.%s 参数类型 %s 不支持", m.Source, class, name, p)
				}
			}
			m.mthRefs[i] = &methodRef{
				class: class, name: name, proto: dexBuildProto(ret, params),
				ret: ret, params: params, kind: kind, cls: class,
			}
			m.needsJni = true
		}
		switch it.op {
		case 0x93, 0xb3, 0xd3, 0xdb:
			m.needsDiv = true
		case 0x94, 0xb4, 0xd4, 0xdc:
			m.needsRem = true
		}
		m.needsArith = true
	}
	return m.infer()
}

// dexBuildProto 拼接描述符（与 dex.BuildProtoDesc 同构；避免本文件依赖太多）。
func dexBuildProto(ret string, params []string) string {
	var b strings.Builder
	b.WriteByte('(')
	for _, p := range params {
		b.WriteString(p)
	}
	b.WriteByte(')')
	b.WriteString(ret)
	return b.String()
}

// succIdx 返回指令的全部后继指令下标（-1 不存在）。
func (m *Method) succIdx(idx int) ([]int, error) {
	it := m.ins[idx]
	next := -1
	if idx+1 < len(m.ins) {
		next = idx + 1
	}
	switch {
	case it.op == 0x28 || it.op == 0x29 || it.op == 0x2a:
		t, err := m.targetIdx(it)
		if err != nil {
			return nil, err
		}
		return []int{t}, nil
	case it.op >= 0x32 && it.op <= 0x3d:
		t, err := m.targetIdx(it)
		if err != nil {
			return nil, err
		}
		out := []int{t}
		if next >= 0 {
			out = append(out, next)
		}
		return out, nil
	case it.op == 0x0e || it.op == 0x0f || it.op == 0x11:
		return nil, nil
	default:
		if next < 0 {
			return nil, nil
		}
		return []int{next}, nil
	}
}

// targetIdx 把分支目标字偏移换算成指令下标。
func (m *Method) targetIdx(it insn) (int, error) {
	if m.pcIdx == nil {
		m.pcIdx = make(map[int]int, len(m.ins))
		for i := range m.ins {
			m.pcIdx[m.ins[i].pc] = i
		}
	}
	i, ok := m.pcIdx[it.target]
	if !ok {
		return 0, skipf("decode", "%s: 分支目标 %d 不是指令边界", m.Source, it.target)
	}
	return i, nil
}

// mergeKind 合并两条路径上的寄存器种类；任何冲突/未定都取保守值。
func mergeKind(a, b valKind) valKind {
	if a == b {
		return a
	}
	if a == kindBad || b == kindBad {
		return kindBad
	}
	if a == kindUnknown || b == kindUnknown {
		return kindUnknown
	}
	return kindBad
}

// infer 做前向数据流类型推断，并在推断过程中完成全部语义校验。
func (m *Method) infer() error {
	n := len(m.ins)
	if n == 0 {
		return skipf("insn", "%s: 空方法体", m.Source)
	}
	entry := make([]valKind, m.Registers)
	for i := range entry {
		entry[i] = kindUnknown
	}

	// 入参寄存器种类来自方法原型。
	base := m.Registers - m.Ins
	if base < 0 {
		return skipf("decode", "%s: ins 数超过寄存器数", m.Source)
	}
	params := m.params
	if m.Static {
		if len(params) != m.Ins {
			return skipf("decode", "%s: ins=%d 与参数个数 %d 不符", m.Source, m.Ins, len(params))
		}
		for i, p := range params {
			k, _ := typeKind(p)
			entry[base+i] = k
		}
	} else {
		if len(params) != m.Ins-1 {
			return skipf("decode", "%s: ins=%d 与参数个数 %d+1 不符", m.Source, m.Ins, len(params))
		}
		entry[base] = kindRef
		for i, p := range params {
			k, _ := typeKind(p)
			entry[base+1+i] = k
		}
	}

	states := make([][]valKind, n)
	states[0] = entry
	queue := []int{0}
	iter := 0
	for len(queue) > 0 {
		iter++
		if iter > 16384 {
			return skipf("decode", "%s: 类型推断不收敛", m.Source)
		}
		idx := queue[0]
		queue = queue[1:]
		out, err := m.transfer(idx, states[idx])
		if err != nil {
			return err
		}
		succs, err := m.succIdx(idx)
		if err != nil {
			return err
		}
		for _, s := range succs {
			if states[s] == nil {
				states[s] = cloneKinds(out)
				queue = append(queue, s)
				continue
			}
			changed := false
			for r := range out {
				mg := mergeKind(states[s][r], out[r])
				if mg != states[s][r] {
					states[s][r] = mg
					changed = true
				}
			}
			if changed {
				queue = append(queue, s)
			}
		}
	}
	m.states = states
	return nil
}

func cloneKinds(in []valKind) []valKind {
	out := make([]valKind, len(in))
	copy(out, in)
	return out
}

// transfer 校验并计算一条指令执行后的寄存器种类。
func (m *Method) transfer(idx int, in []valKind) ([]valKind, error) {
	it := m.ins[idx]
	out := cloneKinds(in)
	req := func(r int, k valKind, what string) error {
		if r < 0 || r >= m.Registers {
			return skipf("decode", "%s: %s 引用越界寄存器 v%d", m.Source, what, r)
		}
		got := in[r]
		switch got {
		case kindBad:
			return skipf("type", "%s: %s 的 v%d 类型冲突", m.Source, what, r)
		case kindUnknown:
			return skipf("type", "%s: %s 的 v%d 类型推断不足（可能未初始化）", m.Source, what, r)
		}
		if k != kindUnknown && got != k {
			return skipf("type", "%s: %s 需要 %s，实际 %s", m.Source, what, kindName(k), kindName(got))
		}
		return nil
	}
	set := func(r int, k valKind) error {
		if r < 0 || r >= m.Registers {
			return skipf("decode", "%s: 目标寄存器越界 v%d", m.Source, r)
		}
		out[r] = k
		return nil
	}

	switch it.op {
	case 0x00: // nop
		return out, nil
	case 0x01, 0x02, 0x03, 0x07, 0x08, 0x09: // move 家族
		if err := req(it.b, kindUnknown, it.name); err != nil {
			return nil, err
		}
		src := in[it.b]
		if it.op >= 0x07 && src != kindRef {
			return nil, skipf("type", "%s: %s 的源寄存器不是引用", m.Source, it.name)
		}
		return out, set(it.a, src)
	case 0x12, 0x13, 0x14, 0x15: // const*
		return out, set(it.a, kindInt)
	case 0x1a, 0x1b: // const-string
		return out, set(it.a, kindRef)
	case 0x0a, 0x0c: // move-result / move-result-object
		if idx == 0 || !opIsInvoke(m.ins[idx-1].op) {
			return nil, skipf("decode", "%s: move-result 前不是 invoke", m.Source)
		}
		ref := m.mthRefs[idx-1]
		if ref == nil {
			return nil, skipf("decode", "%s: move-result 前 invoke 未解析", m.Source)
		}
		if it.op == 0x0a {
			if ref.ret == "V" {
				return nil, skipf("type", "%s: move-result 对应 void 调用", m.Source)
			}
			if k, _ := typeKind(ref.ret); k != kindInt {
				return nil, skipf("type", "%s: move-result 对应引用返回", m.Source)
			}
			return out, set(it.a, kindInt)
		}
		if ref.ret == "V" {
			return nil, skipf("type", "%s: move-result-object 对应 void 调用", m.Source)
		}
		if k, _ := typeKind(ref.ret); k != kindRef {
			return nil, skipf("type", "%s: move-result-object 对应非引用返回", m.Source)
		}
		return out, set(it.a, kindRef)
	case 0x0e: // return-void
		return out, nil
	case 0x0f: // return
		return out, req(it.a, kindInt, it.name)
	case 0x11: // return-object
		return out, req(it.a, kindRef, it.name)
	case 0x7b, 0x7c, 0x8d, 0x8e, 0x8f: // neg/not/int-to-*
		if err := req(it.b, kindInt, it.name); err != nil {
			return nil, err
		}
		return out, set(it.a, kindInt)
	case 0x90, 0x91, 0x92, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a: // 23x 整型
		for _, r := range []int{it.b, it.c} {
			if err := req(r, kindInt, it.name); err != nil {
				return nil, err
			}
		}
		return out, set(it.a, kindInt)
	case 0x93, 0x94: // div/rem-int
		for _, r := range []int{it.b, it.c} {
			if err := req(r, kindInt, it.name); err != nil {
				return nil, err
			}
		}
		return out, set(it.a, kindInt)
	case 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba: // /2addr
		if err := req(it.b, kindInt, it.name); err != nil {
			return nil, err
		}
		return out, set(it.a, kindInt)
	case 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7: // lit16
		if err := req(it.b, kindInt, it.name); err != nil {
			return nil, err
		}
		return out, set(it.a, kindInt)
	case 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2: // lit8
		if err := req(it.b, kindInt, it.name); err != nil {
			return nil, err
		}
		return out, set(it.a, kindInt)
	case 0x28, 0x29, 0x2a: // goto
		return out, nil
	case 0x32, 0x33: // if-eq / if-ne（int 或引用）
		ka, kb := in[it.a], in[it.b]
		if ka == kindBad || kb == kindBad || ka == kindUnknown || kb == kindUnknown {
			return nil, skipf("type", "%s: %s 的寄存器类型未定", m.Source, it.name)
		}
		if ka != kb {
			return nil, skipf("type", "%s: %s 的两个寄存器种类不一致", m.Source, it.name)
		}
		return out, nil
	case 0x34, 0x35, 0x36, 0x37: // if-lt/ge/gt/le
		for _, r := range []int{it.a, it.b} {
			if err := req(r, kindInt, it.name); err != nil {
				return nil, err
			}
		}
		return out, nil
	case 0x38, 0x39: // if-eqz / if-nez（int 或引用）
		if err := req(it.a, kindUnknown, it.name); err != nil {
			return nil, err
		}
		return out, nil
	case 0x3a, 0x3b, 0x3c, 0x3d: // if-ltz/gez/gtz/lez
		return out, req(it.a, kindInt, it.name)
	case 0x52, 0x54, 0x55, 0x56, 0x57, 0x58: // iget*
		if err := req(it.b, kindRef, it.name); err != nil {
			return nil, err
		}
		if it.op == 0x54 {
			return out, set(it.a, kindRef)
		}
		return out, set(it.a, kindInt)
	case 0x59, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f: // iput*
		if err := req(it.b, kindRef, it.name); err != nil {
			return nil, err
		}
		if it.op == 0x5b {
			return out, req(it.a, kindRef, it.name)
		}
		return out, req(it.a, kindInt, it.name)
	case 0x60, 0x62, 0x63, 0x64, 0x65, 0x66: // sget*
		if it.op == 0x62 {
			return out, set(it.a, kindRef)
		}
		return out, set(it.a, kindInt)
	case 0x67, 0x69, 0x6a, 0x6b, 0x6c, 0x6d: // sput*
		if it.op == 0x69 {
			return out, req(it.a, kindRef, it.name)
		}
		return out, req(it.a, kindInt, it.name)
	default:
		if opIsInvoke(it.op) {
			return m.transferInvoke(idx, it, in, out)
		}
		return nil, skipf("insn", "%s: 未处理指令 %s", m.Source, it.name)
	}
}

// transferInvoke 校验 invoke 的接收者与实参种类。
func (m *Method) transferInvoke(idx int, it insn, in, out []valKind) ([]valKind, error) {
	ref := m.mthRefs[idx]
	if ref == nil {
		return nil, skipf("decode", "%s: invoke 引用未解析", m.Source)
	}
	want := ref.params
	if ref.kind != 0 {
		want = append([]string{ref.class}, ref.params...)
	}
	if len(it.args) != len(want) {
		return nil, skipf("decode", "%s: %s 实参数 %d 与原型 %d 不符", m.Source, it.name, len(it.args), len(want))
	}
	for i, r := range it.args {
		k, ok := typeKind(want[i])
		if !ok {
			return nil, skipf("wide", "%s: %s 参数类型 %s 不支持", m.Source, it.name, want[i])
		}
		if r < 0 || r >= m.Registers {
			return nil, skipf("decode", "%s: %s 实参寄存器越界", m.Source, it.name)
		}
		got := in[r]
		if got == kindBad || got == kindUnknown || got != k {
			return nil, skipf("type", "%s: %s 的实参 v%d 类型不符（需要 %s）", m.Source, it.name, r, kindName(k))
		}
	}
	return out, nil
}

func kindName(k valKind) string {
	switch k {
	case kindInt:
		return "int"
	case kindRef:
		return "ref"
	case kindVoid:
		return "void"
	case kindBad:
		return "conflict"
	}
	return "unknown"
}

// ---- C 代码生成 ----

// cType 返回 DEX 类型对应的 JNI C 类型。
func cType(t string) string {
	if t == "" {
		return "void"
	}
	switch t[0] {
	case 'V':
		return "void"
	case 'Z':
		return "jboolean"
	case 'B':
		return "jbyte"
	case 'S':
		return "jshort"
	case 'C':
		return "jchar"
	case 'I':
		return "jint"
	case 'L', '[':
		return "jobject"
	}
	return "jint"
}

// isRefType 报告描述符是否为引用类型。
func isRefType(t string) bool {
	if t == "" {
		return false
	}
	return t[0] == 'L' || t[0] == '['
}

// javaName 把类描述符转成 FindClass 需要的点分/斜杠名（JNI 用 '/' 分隔）。
func javaName(desc string) string {
	if strings.HasPrefix(desc, "L") && strings.HasSuffix(desc, ";") {
		return desc[1 : len(desc)-1]
	}
	return desc
}

// cQuote 把 Go 字符串转成 C 字符串字面量（含转义）。
func cQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c == '\n':
			b.WriteString("\\n")
		case c == '\r':
			b.WriteString("\\r")
		case c == '\t':
			b.WriteString("\\t")
		case c >= 0x20 && c < 0x7f:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "\\%03o", c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// libNameOf 由 seed + 被翻译方法集合派生库名（长度固定、全小写十六进制）。
//
// 不含产品名与方法名：库名本身不应成为「这是 apkguard 产物」的指纹；
// 混入方法集合使不同应用（即使 seed 都为空）得到不同库名。
func libNameOf(seed string, methods []*Method) string {
	h := fnv.New64a()
	h.Write([]byte("apkguard-b7|"))
	h.Write([]byte(seed))
	for _, m := range methods {
		h.Write([]byte{0})
		h.Write([]byte(m.Entry))
		h.Write([]byte{0})
		h.Write([]byte(m.Class))
		h.Write([]byte{0})
		h.Write([]byte(m.Name))
		h.Write([]byte{0})
		h.Write([]byte(m.Proto))
	}
	return fmt.Sprintf("lib%08x.so", uint32(h.Sum64()))
}

// funcNameOf 由 seed 与方法身份派生 C 函数名（同一方法在任何两次运行中稳定）。
func funcNameOf(seed string, m *Method) string {
	h := fnv.New64a()
	h.Write([]byte(seed))
	h.Write([]byte{0})
	h.Write([]byte(m.Entry))
	h.Write([]byte{0})
	h.Write([]byte(m.Class))
	h.Write([]byte{0})
	h.Write([]byte(m.Name))
	h.Write([]byte{0})
	h.Write([]byte(m.Proto))
	return fmt.Sprintf("b7_fn_%08x", uint32(h.Sum64()))
}

// cgen 是一次 C 生成的状态。
type cgen struct {
	buf    bytes.Buffer
	strs   [][]uint16
	strIdx map[string]int
	seed   string
}

// generateC 为全部选中方法生成一个确定性的 C 源文件。
//
// 相同输入（方法集合、seed）必须产生逐字节相同的输出：全部命名由内容哈希
// 派生，不使用时间、随机数与 map 遍历序。
func generateC(methods []*Method, seed string) ([]byte, error) {
	g := &cgen{strIdx: map[string]int{}, seed: seed}
	g.buf.WriteString("/* 由 apkguard B7 (Dex2C) 生成，请勿手工修改。\n")
	g.buf.WriteString(" * 本文件与 APK 一一对应；相同输入与 seed 产生逐字节相同的输出。\n")
	g.buf.WriteString(" * 编译：<ndk>/toolchains/llvm/prebuilt/<host>/bin/clang --target=<triple> \\\n")
	g.buf.WriteString(" *        -shared -O2 -fPIC -fvisibility=hidden -Wl,-z,max-page-size=16384 ...\n */\n")
	g.buf.WriteString("#include <jni.h>\n#include <stdint.h>\n\n")
	g.buf.WriteString("_Static_assert(sizeof(jint) == 4, \"jint must be 32-bit\");\n")
	g.buf.WriteString("_Static_assert(sizeof(jchar) == 2, \"jchar must be 16-bit\");\n\n")

	// 先收集字符串常量（方法体生成前完成，索引才能稳定）。
	// 只收集真正的 const-string 指令：m.strRefs 对非字符串指令是空串，
	// 若照单全收会白白多出一个空串常量。
	for _, m := range methods {
		for i := range m.ins {
			if m.ins[i].op == 0x1a || m.ins[i].op == 0x1b {
				g.intern(m.strRefs[i])
			}
		}
	}

	needDiv, needRem := false, false
	for _, m := range methods {
		needDiv = needDiv || m.needsDiv
		needRem = needRem || m.needsRem
	}
	if needDiv || needRem {
		g.buf.WriteString("static void b7_throw_arithmetic(JNIEnv *env, const char *msg) {\n")
		g.buf.WriteString("  jclass c = (*env)->FindClass(env, \"java/lang/ArithmeticException\");\n")
		g.buf.WriteString("  if (c != NULL) {\n")
		g.buf.WriteString("    (*env)->ThrowNew(env, c, msg);\n")
		g.buf.WriteString("    (*env)->DeleteLocalRef(env, c);\n")
		g.buf.WriteString("  }\n}\n\n")
	}
	if needDiv {
		g.buf.WriteString("static int32_t b7_div(JNIEnv *env, int32_t a, int32_t b) {\n")
		g.buf.WriteString("  if (b == 0) { b7_throw_arithmetic(env, \"/ by zero\"); return 0; }\n")
		g.buf.WriteString("  if (b == -1) return (int32_t)(0u - (uint32_t)a);\n")
		g.buf.WriteString("  return a / b;\n}\n\n")
	}
	if needRem {
		g.buf.WriteString("static int32_t b7_rem(JNIEnv *env, int32_t a, int32_t b) {\n")
		g.buf.WriteString("  if (b == 0) { b7_throw_arithmetic(env, \"/ by zero\"); return 0; }\n")
		g.buf.WriteString("  if (b == -1) return 0;\n")
		g.buf.WriteString("  return a % b;\n}\n\n")
	}

	// UTF-16 字符串常量。
	for i, s := range g.strs {
		fmt.Fprintf(&g.buf, "static const uint16_t b7_str_%d[] = {", i)
		if len(s) == 0 {
			g.buf.WriteString("0")
		}
		for j, u := range s {
			if j > 0 {
				g.buf.WriteString(", ")
			}
			fmt.Fprintf(&g.buf, "0x%04x", u)
		}
		g.buf.WriteString("};\n")
	}
	if len(g.strs) > 0 {
		g.buf.WriteString("\n")
	}

	for _, m := range methods {
		if err := g.emitMethod(m); err != nil {
			return nil, err
		}
	}
	g.emitBindings(methods)
	return g.buf.Bytes(), nil
}

// intern 把字符串转换为 UTF-16 码元序列并返回常量下标。
func (g *cgen) intern(s string) int {
	if i, ok := g.strIdx[s]; ok {
		return i
	}
	units := utf16.Encode([]rune(s))
	i := len(g.strs)
	g.strs = append(g.strs, units)
	g.strIdx[s] = i
	return i
}

// emitMethod 生成一个 native 方法实现。
func (g *cgen) emitMethod(m *Method) error {
	retType := cType(m.retType())
	g.buf.WriteString("/* " + m.Class + "->" + m.Name + m.Proto + " (" + m.Source + ") */\n")
	// 非 static：JNINativeMethod 的函数指针可以指向 static 函数，但宿主差分测试
	// 与将来可能的符号绑定都要求外部链接；产物用 -fvisibility=hidden 保证不导出。
	fmt.Fprintf(&g.buf, "%s %s(JNIEnv *env, %s", retType, m.FnName, m.secondParam())
	// 形参：按方法描述符映射成精确的 JNI 类型。
	base := m.Registers - m.Ins
	pi := 0
	if !m.Static {
		pi++
	}
	params := m.paramTypes()
	for i, p := range params {
		fmt.Fprintf(&g.buf, ", %s p%d", cType(p), i)
	}
	g.buf.WriteString(") {\n")
	fmt.Fprintf(&g.buf, "  uint32_t v[%d];\n", maxInt(m.Registers, 1))
	fmt.Fprintf(&g.buf, "  jobject o[%d];\n", maxInt(m.Registers, 1))
	g.buf.WriteString("  (void)v; (void)o;\n")
	if !m.Static {
		fmt.Fprintf(&g.buf, "  o[%d] = self;\n", base)
	}
	for i, p := range params {
		reg := base + pi + i
		if isRefType(p) {
			fmt.Fprintf(&g.buf, "  o[%d] = p%d;\n", reg, i)
		} else {
			fmt.Fprintf(&g.buf, "  v[%d] = (uint32_t)p%d;\n", reg, i)
		}
	}

	// 消费掉紧随 invoke 的 move-result（结果在 invoke 处直接赋值）。
	// 只消费可达的 invoke（状态为 nil 的不可达指令不会生成代码）。
	consumed := make(map[int]bool)
	for i, it := range m.ins {
		if m.states[i] == nil {
			continue
		}
		if opIsInvoke(it.op) && i+1 < len(m.ins) && opIsMoveResult(m.ins[i+1].op) {
			consumed[i+1] = true
		}
	}

	for i := range m.ins {
		if m.states[i] == nil {
			continue // 不可达指令，不生成
		}
		// 标签必须在 consumed 判断之前输出：分支可以落在 move-result 上，
		// 此时该指令本身不生成语句，但跳转目标必须存在。
		if target, ok := m.branchLabel(i); ok {
			fmt.Fprintf(&g.buf, "L%d: ;\n", target)
		}
		if consumed[i] {
			continue
		}
		if err := g.emitInsn(m, i); err != nil {
			return err
		}
	}
	if m.retType() == "V" {
		g.buf.WriteString("  return;\n}\n\n")
	} else {
		fmt.Fprintf(&g.buf, "  return %s;\n}\n\n", zeroValue(m.retType()))
	}
	return nil
}

// paramTypes 返回方法形参类型（不含 this）。
func (m *Method) paramTypes() []string {
	return m.params
}

// retType 返回方法返回类型。
func (m *Method) retType() string {
	return m.ret
}

// secondParam 返回 JNI 第二参数类型。
func (m *Method) secondParam() string {
	if m.Static {
		return "jclass cls"
	}
	return "jobject self"
}

// branchLabel 报告指令下标是否是某个分支的目标；是则返回其 PC 标签号。
func (m *Method) branchLabel(idx int) (int, bool) {
	if m.labels == nil {
		m.labels = map[int]bool{}
		for i := range m.ins {
			switch {
			case m.ins[i].op == 0x28 || m.ins[i].op == 0x29 || m.ins[i].op == 0x2a:
				if t, err := m.targetIdx(m.ins[i]); err == nil {
					m.labels[t] = true
				}
			case m.ins[i].op >= 0x32 && m.ins[i].op <= 0x3d:
				if t, err := m.targetIdx(m.ins[i]); err == nil {
					m.labels[t] = true
				}
			}
		}
	}
	if !m.labels[idx] {
		return 0, false
	}
	return m.ins[idx].pc, true
}

// zeroValue 返回返回类型的 C 默认值（异常中止路径使用）；void 返回空串，
// 使调用点生成合法的 `return ;`。
func zeroValue(t string) string {
	if t == "V" {
		return ""
	}
	if isRefType(t) {
		return "NULL"
	}
	return "0"
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// emitInsn 生成一条指令的 C 语句。
func (g *cgen) emitInsn(m *Method, idx int) error {
	it := m.ins[idx]
	st := m.states[idx]
	rv := func(r int) string { return fmt.Sprintf("v[%d]", r) }
	ro := func(r int) string { return fmt.Sprintf("o[%d]", r) }
	w := func(format string, args ...any) { fmt.Fprintf(&g.buf, "  "+format+"\n", args...) }
	def := zeroValue(m.retType())

	switch {
	case it.op == 0x00:
		w("/* nop */")
	case it.op >= 0x01 && it.op <= 0x03 || it.op >= 0x07 && it.op <= 0x09:
		if st[it.b] == kindRef {
			w("%s = %s;", ro(it.a), ro(it.b))
		} else {
			w("%s = %s;", rv(it.a), rv(it.b))
		}
	case it.op == 0x12 || it.op == 0x13 || it.op == 0x14 || it.op == 0x15:
		w("%s = (uint32_t)0x%08xu; /* %s */", rv(it.a), uint32(it.lit), it.name)
	case it.op == 0x1a || it.op == 0x1b:
		si := g.strIdx[m.strRefs[idx]]
		w("%s = (*env)->NewString(env, (const jchar *)b7_str_%d, %d);", ro(it.a), si, len(g.strs[si]))
		w("if (%s == NULL && (*env)->ExceptionCheck(env)) return %s;", ro(it.a), def)
	case it.op == 0x0a || it.op == 0x0c:
		// 结果已在 invoke 处直接赋值；只有「被分支单独命中」的畸形输入会走到
		// 这里，按无操作处理（infer 已保证正常路径一定被 invoke 消费）。
		w("/* move-result 由前置 invoke 直接赋值 */")
	case it.op == 0x0e:
		w("return;")
	case it.op == 0x0f:
		w("return (%s)%s;", cType(m.retType()), rv(it.a))
	case it.op == 0x11:
		w("return %s;", ro(it.a))
	case it.op == 0x7b:
		w("%s = (uint32_t)(-(int32_t)%s);", rv(it.a), rv(it.b))
	case it.op == 0x7c:
		w("%s = ~%s;", rv(it.a), rv(it.b))
	case it.op == 0x8d:
		w("%s = (uint32_t)(int8_t)%s;", rv(it.a), rv(it.b))
	case it.op == 0x8e:
		w("%s = (uint32_t)(uint16_t)%s;", rv(it.a), rv(it.b))
	case it.op == 0x8f:
		w("%s = (uint32_t)(int16_t)%s;", rv(it.a), rv(it.b))
	case it.op >= 0x90 && it.op <= 0x9a:
		g.emitBin(m, it.op, it.a, rv(it.b), rv(it.c), def)
	case it.op >= 0xb0 && it.op <= 0xba:
		base := int2addrOp(it.op)
		g.emitBin(m, base, it.a, rv(it.a), rv(it.b), def)
	case it.op >= 0xd0 && it.op <= 0xd7:
		lit := fmt.Sprintf("(uint32_t)0x%08xu", uint32(int32(it.lit)))
		if it.op == 0xd1 { // rsub-int: lit - v[b]
			w("%s = (uint32_t)((int32_t)0x%08xu - (int32_t)%s);", rv(it.a), uint32(int32(it.lit)), rv(it.b))
		} else {
			g.emitBin(m, 0x90+(it.op-0xd0), it.a, rv(it.b), lit, def)
		}
	case it.op >= 0xd8 && it.op <= 0xe2:
		lit := fmt.Sprintf("(uint32_t)0x%08xu", uint32(int32(it.lit)))
		if it.op == 0xd9 { // rsub-int/lit8
			w("%s = (uint32_t)((int32_t)0x%08xu - (int32_t)%s);", rv(it.a), uint32(int32(it.lit)), rv(it.b))
		} else {
			g.emitBin(m, 0x90+(it.op-0xd8), it.a, rv(it.b), lit, def)
		}
	case it.op == 0x28 || it.op == 0x29 || it.op == 0x2a:
		t, err := m.targetIdx(it)
		if err != nil {
			return err
		}
		w("goto L%d;", m.ins[t].pc)
	case it.op >= 0x32 && it.op <= 0x37:
		t, err := m.targetIdx(it)
		if err != nil {
			return err
		}
		var cond string
		if it.op == 0x32 || it.op == 0x33 {
			if st[it.a] == kindRef {
				op := "=="
				if it.op == 0x33 {
					op = "!="
				}
				cond = fmt.Sprintf("%s %s %s", ro(it.a), op, ro(it.b))
			} else {
				op := "=="
				if it.op == 0x33 {
					op = "!="
				}
				cond = fmt.Sprintf("%s %s %s", rv(it.a), op, rv(it.b))
			}
		} else {
			sign := map[byte]string{0x34: "<", 0x35: ">=", 0x36: ">", 0x37: "<="}
			cond = fmt.Sprintf("(int32_t)%s %s (int32_t)%s", rv(it.a), sign[it.op], rv(it.b))
		}
		w("if (%s) goto L%d;", cond, m.ins[t].pc)
	case it.op >= 0x38 && it.op <= 0x3d:
		t, err := m.targetIdx(it)
		if err != nil {
			return err
		}
		var cond string
		if it.op == 0x38 || it.op == 0x39 {
			op := "=="
			if it.op == 0x39 {
				op = "!="
			}
			if st[it.a] == kindRef {
				cond = fmt.Sprintf("%s %s NULL", ro(it.a), op)
			} else {
				cond = fmt.Sprintf("%s %s 0", rv(it.a), op)
			}
		} else {
			sign := map[byte]string{0x3a: "<", 0x3b: ">=", 0x3c: ">", 0x3d: "<="}
			cond = fmt.Sprintf("(int32_t)%s %s 0", rv(it.a), sign[it.op])
		}
		w("if (%s) goto L%d;", cond, m.ins[t].pc)
	case it.op >= 0x52 && it.op <= 0x5f:
		g.emitField(m, idx, it, def)
	case it.op >= 0x60 && it.op <= 0x6d:
		g.emitStaticField(m, idx, it, def)
	default:
		if opIsInvoke(it.op) {
			return g.emitInvoke(m, idx, it, def)
		}
		return skipf("insn", "%s: 代码生成遇到未处理指令 %s", m.Source, it.name)
	}
	return nil
}

// emitBin 生成一条整型二元运算（dst = op(x, y)）。
func (g *cgen) emitBin(m *Method, op byte, dst int, x, y, def string) {
	w := func(format string, args ...any) { fmt.Fprintf(&g.buf, "  "+format+"\n", args...) }
	d := fmt.Sprintf("v[%d]", dst)
	switch op {
	case 0x90:
		w("%s = %s + %s;", d, x, y)
	case 0x91:
		w("%s = %s - %s;", d, x, y)
	case 0x92:
		w("%s = %s * %s;", d, x, y)
	case 0x93:
		w("%s = (uint32_t)b7_div(env, (int32_t)%s, (int32_t)%s);", d, x, y)
		w("if ((*env)->ExceptionCheck(env)) return %s;", def)
	case 0x94:
		w("%s = (uint32_t)b7_rem(env, (int32_t)%s, (int32_t)%s);", d, x, y)
		w("if ((*env)->ExceptionCheck(env)) return %s;", def)
	case 0x95:
		w("%s = %s & %s;", d, x, y)
	case 0x96:
		w("%s = %s | %s;", d, x, y)
	case 0x97:
		w("%s = %s ^ %s;", d, x, y)
	case 0x98:
		w("%s = %s << (%s & 31u);", d, x, y)
	case 0x99:
		w("%s = (uint32_t)((int32_t)%s >> (%s & 31u));", d, x, y)
	case 0x9a:
		w("%s = %s >> (%s & 31u);", d, x, y)
	default:
		w("/* 未处理二元运算 0x%02x */", op)
	}
}

// jniGetField / jniSetField 返回字段读写的 JNI 函数名。
func jniGetField(t string) string {
	if isRefType(t) {
		return "GetObjectField"
	}
	switch t[0] {
	case 'Z':
		return "GetBooleanField"
	case 'B':
		return "GetByteField"
	case 'S':
		return "GetShortField"
	case 'C':
		return "GetCharField"
	}
	return "GetIntField"
}

func jniSetField(t string) string {
	if isRefType(t) {
		return "SetObjectField"
	}
	switch t[0] {
	case 'Z':
		return "SetBooleanField"
	case 'B':
		return "SetByteField"
	case 'S':
		return "SetShortField"
	case 'C':
		return "SetCharField"
	}
	return "SetIntField"
}

func jniGetStaticField(t string) string {
	return "GetStatic" + jniGetField(t)
}

func jniSetStaticField(t string) string {
	return "SetStatic" + jniSetField(t)
}

// jniCallStatic 返回静态调用的 JNI 函数名。
func jniCallStatic(ret string) string {
	if ret == "V" {
		return "CallStaticVoidMethod"
	}
	if isRefType(ret) {
		return "CallStaticObjectMethod"
	}
	return "CallStatic" + titleASCII(jniIntSuffix(ret)) + "Method"
}

// jniCallVirtual 返回虚/接口调用的 JNI 函数名。
func jniCallVirtual(ret string) string {
	if ret == "V" {
		return "CallVoidMethod"
	}
	if isRefType(ret) {
		return "CallObjectMethod"
	}
	return "Call" + titleASCII(jniIntSuffix(ret)) + "Method"
}

// titleASCII 把首字母大写（只用于固定的 JNI 后缀，不涉及 Unicode）。
func titleASCII(s string) string {
	if s == "" {
		return s
	}
	if s[0] >= 'a' && s[0] <= 'z' {
		return string(s[0]-'a'+'A') + s[1:]
	}
	return s
}

func jniIntSuffix(t string) string {
	switch t {
	case "Z":
		return "boolean"
	case "B":
		return "byte"
	case "S":
		return "short"
	case "C":
		return "char"
	}
	return "int"
}

// emitField 生成实例字段读写。
func (g *cgen) emitField(m *Method, idx int, it insn, def string) {
	f := m.fldRefs[idx]
	w := func(format string, args ...any) { fmt.Fprintf(&g.buf, "  "+format+"\n", args...) }
	w("{")
	w("  jclass k = (*env)->GetObjectClass(env, o[%d]);", it.b)
	w("  jfieldID fid;")
	w("  if (k == NULL) return %s;", def)
	w("  fid = (*env)->GetFieldID(env, k, %s, %s);", cQuote(f.name), cQuote(f.typ))
	w("  (*env)->DeleteLocalRef(env, k);")
	w("  if (fid == NULL) return %s;", def)
	if it.op >= 0x59 { // iput*
		val := fmt.Sprintf("(jint)v[%d]", it.a)
		if it.op == 0x5b {
			val = fmt.Sprintf("o[%d]", it.a)
		}
		w("  (*env)->%s(env, o[%d], fid, %s);", jniSetField(f.typ), it.b, val)
		w("  if ((*env)->ExceptionCheck(env)) return %s;", def)
	} else {
		dst := fmt.Sprintf("v[%d]", it.a)
		if it.op == 0x54 {
			dst = fmt.Sprintf("o[%d]", it.a)
		}
		w("  %s = (%s)(*env)->%s(env, o[%d], fid);", dst, cType(f.typ), jniGetField(f.typ), it.b)
		w("  if ((*env)->ExceptionCheck(env)) return %s;", def)
	}
	w("}")
}

// emitStaticField 生成静态字段读写。
func (g *cgen) emitStaticField(m *Method, idx int, it insn, def string) {
	f := m.fldRefs[idx]
	w := func(format string, args ...any) { fmt.Fprintf(&g.buf, "  "+format+"\n", args...) }
	w("{")
	w("  jclass k = (*env)->FindClass(env, %s);", cQuote(javaName(f.class)))
	w("  jfieldID fid;")
	w("  if (k == NULL) return %s;", def)
	w("  fid = (*env)->GetStaticFieldID(env, k, %s, %s);", cQuote(f.name), cQuote(f.typ))
	w("  if (fid == NULL) { (*env)->DeleteLocalRef(env, k); return %s; }", def)
	if it.op >= 0x67 { // sput*
		val := fmt.Sprintf("(jint)v[%d]", it.a)
		if it.op == 0x69 {
			val = fmt.Sprintf("o[%d]", it.a)
		}
		w("  (*env)->%s(env, k, fid, %s);", jniSetStaticField(f.typ), val)
	} else if it.op == 0x62 { // sget-object
		w("  o[%d] = (*env)->%s(env, k, fid);", it.a, jniGetStaticField(f.typ))
	} else {
		w("  v[%d] = (uint32_t)(*env)->%s(env, k, fid);", it.a, jniGetStaticField(f.typ))
	}
	w("  (*env)->DeleteLocalRef(env, k);")
	w("  if ((*env)->ExceptionCheck(env)) return %s;", def)
	w("}")
}

// emitInvoke 生成一次 JNI 调用（含紧随其后的 move-result 赋值）。
func (g *cgen) emitInvoke(m *Method, idx int, it insn, def string) error {
	ref := m.mthRefs[idx]
	if ref == nil {
		return skipf("decode", "%s: invoke 引用未解析", m.Source)
	}
	w := func(format string, args ...any) { fmt.Fprintf(&g.buf, "  "+format+"\n", args...) }

	// 实参列表（不含接收者）。
	var argExprs []string
	argStart := 0
	if ref.kind != 0 {
		argStart = 1
	}
	for i := argStart; i < len(it.args); i++ {
		t := ref.params[i-argStart]
		if isRefType(t) {
			argExprs = append(argExprs, fmt.Sprintf("o[%d]", it.args[i]))
		} else {
			argExprs = append(argExprs, fmt.Sprintf("(%s)v[%d]", cType(t), it.args[i]))
		}
	}
	argsStr := ""
	if len(argExprs) > 0 {
		argsStr = ", " + strings.Join(argExprs, ", ")
	}

	// 目标寄存器（move-result）。
	dst := ""
	if idx+1 < len(m.ins) && opIsMoveResult(m.ins[idx+1].op) {
		if m.ins[idx+1].op == 0x0c {
			dst = fmt.Sprintf("o[%d]", m.ins[idx+1].a)
		} else {
			dst = fmt.Sprintf("v[%d]", m.ins[idx+1].a)
		}
	}

	if ref.kind == 0 { // invoke-static
		w("{")
		w("  jclass k = (*env)->FindClass(env, %s);", cQuote(javaName(ref.class)))
		w("  jmethodID mid;")
		w("  if (k == NULL) return %s;", def)
		w("  mid = (*env)->GetStaticMethodID(env, k, %s, %s);", cQuote(ref.name), cQuote(ref.proto))
		w("  if (mid == NULL) { (*env)->DeleteLocalRef(env, k); return %s; }", def)
		call := fmt.Sprintf("(*env)->%s(env, k, mid%s)", jniCallStatic(ref.ret), argsStr)
		if ref.ret == "V" {
			w("  %s;", call)
		} else if dst == "" {
			w("  (void)%s;", call)
		} else {
			w("  %s = %s;", dst, call)
		}
		w("  (*env)->DeleteLocalRef(env, k);")
		w("  if ((*env)->ExceptionCheck(env)) return %s;", def)
		w("}")
		return nil
	}

	// invoke-virtual / invoke-interface：接收者来自实参表第一个寄存器。
	if len(it.args) < 1 {
		return skipf("decode", "%s: %s 缺少接收者", m.Source, it.name)
	}
	recv := it.args[0]
	w("{")
	if ref.kind == 2 {
		// invoke-interface：按 JNI 规范在**声明接口**上取 methodID（对
		// GetObjectClass 得到的实现类调用 GetMethodID 在部分实现上找不到
		// 未覆写的接口方法）。
		w("  jclass k = (*env)->FindClass(env, %s);", cQuote(javaName(ref.class)))
	} else {
		w("  jclass k = (*env)->GetObjectClass(env, o[%d]);", recv)
	}
	w("  jmethodID mid;")
	w("  if (k == NULL) return %s;", def)
	w("  mid = (*env)->GetMethodID(env, k, %s, %s);", cQuote(ref.name), cQuote(ref.proto))
	w("  if (mid == NULL) { (*env)->DeleteLocalRef(env, k); return %s; }", def)
	call := fmt.Sprintf("(*env)->%s(env, o[%d], mid%s)", jniCallVirtual(ref.ret), recv, argsStr)
	if ref.ret == "V" {
		w("  %s;", call)
	} else if dst == "" {
		w("  (void)%s;", call)
	} else {
		w("  %s = %s;", dst, call)
	}
	w("  (*env)->DeleteLocalRef(env, k);")
	w("  if ((*env)->ExceptionCheck(env)) return %s;", def)
	w("}")
	return nil
}

// emitBindings 生成 RegisterNatives 绑定表与注册入口。
func (g *cgen) emitBindings(methods []*Method) {
	// 按类分组（保持方法的确定性顺序）。
	type clsGroup struct {
		class   string
		methods []*Method
	}
	order := []string{}
	byClass := map[string]*clsGroup{}
	for _, m := range methods {
		grp, ok := byClass[m.Class]
		if !ok {
			grp = &clsGroup{class: m.Class}
			byClass[m.Class] = grp
			order = append(order, m.Class)
		}
		grp.methods = append(grp.methods, m)
	}
	sort.Strings(order)

	g.buf.WriteString("/* RegisterNatives 绑定表。 */\n")
	g.buf.WriteString("typedef struct { const char *name; const char *sig; void *fn; } b7_binding;\n")
	for gi, cls := range order {
		grp := byClass[cls]
		fmt.Fprintf(&g.buf, "static const b7_binding b7_bind_%d[] = {\n", gi)
		for _, m := range grp.methods {
			fmt.Fprintf(&g.buf, "  {%s, %s, (void *)&%s},\n", cQuote(m.Name), cQuote(m.Proto), m.FnName)
		}
		g.buf.WriteString("};\n")
	}
	g.buf.WriteString("\ntypedef struct { const char *cls; const b7_binding *b; int n; } b7_class_entry;\n")
	g.buf.WriteString("static const b7_class_entry b7_classes[] = {\n")
	for gi, cls := range order {
		fmt.Fprintf(&g.buf, "  {%s, b7_bind_%d, %d},\n", cQuote(javaName(cls)), gi, len(byClass[cls].methods))
	}
	g.buf.WriteString("};\n\n")
	g.buf.WriteString("/* 由壳在 ClassLoader 就绪后调用：注册全部翻译方法，返回成功注册数。 */\n")
	g.buf.WriteString("JNIEXPORT jint JNICALL b7_register_all(JNIEnv *env, jclass unused) {\n")
	g.buf.WriteString("  jint total = 0;\n")
	g.buf.WriteString("  size_t i;\n")
	g.buf.WriteString("  (void)unused;\n")
	g.buf.WriteString("  for (i = 0; i < sizeof(b7_classes) / sizeof(b7_classes[0]); i++) {\n")
	g.buf.WriteString("    jclass k = (*env)->FindClass(env, b7_classes[i].cls);\n")
	g.buf.WriteString("    if (k == NULL) {\n")
	g.buf.WriteString("      if ((*env)->ExceptionCheck(env)) return total;\n")
	g.buf.WriteString("      continue;\n")
	g.buf.WriteString("    }\n")
	g.buf.WriteString("    total += (*env)->RegisterNatives(env, k, (const JNINativeMethod *)b7_classes[i].b, b7_classes[i].n);\n")
	g.buf.WriteString("    (*env)->DeleteLocalRef(env, k);\n")
	g.buf.WriteString("  }\n")
	g.buf.WriteString("  return total;\n}\n")
}
