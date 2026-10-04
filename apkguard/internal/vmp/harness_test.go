package vmp_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"apkguard/internal/dex"
	"apkguard/internal/vmp"
)

// 本文件是 internal/vmp 的对拍基础设施：
//   - wa：一个只覆盖「受支持 DEX 指令子集」的极简汇编器（可表达任意原始字，
//     包含 switch/fill-array-data/try 等**不支持**指令，用于跳过规则测试）；
//   - mockRuntime：私有 VM 与 DEX 参考解释器共享的宿主语义（对象/字符串/字段/调用）；
//   - dexRunner：原始 Dalvik 方法体解释器（测试专用，独立实现，不复用实现代码）。
//
// 对拍的两条路径必须**语义独立**：DEX 侧直接解释原始指令，VM 侧解释翻译后的
// 私有指令；两侧共用同一 mock 宿主，因此结果差异只可能来自翻译/解释错误。

// ---- 极简 DEX 汇编器 ----

type waBranch struct {
	item  int    // 分支指令所在项
	word  int    // 回填位置（项内字偏移）
	form  int    // 10t/20t/22t/21t/30t/31t/payload
	label string // 目标标签（tgtItem < 0 时使用）
	tgt   int    // 已解析的目标项（-1 表示用 label）
	base  int    // 项内基准字偏移（分支相对基准）
	// baseItem >= 0 时基准取该 item 的起点（payload 相对 switch 指令）；
	// 否则基准为分支指令自身起点。
	baseItem int
}

type waPatch struct {
	item, word int
	ref        dex.RefSpec
}

type wa struct {
	items  [][]uint16
	brs    []waBranch
	pts    []waPatch
	labels map[string]int
}

func newWA() *wa { return &wa{labels: map[string]int{}} }

func (a *wa) emit(words ...uint16) int {
	a.items = append(a.items, append([]uint16(nil), words...))
	return len(a.items) - 1
}

func (a *wa) label(name string) { a.labels[name] = len(a.items) }

func (a *wa) patch(word int, ref dex.RefSpec, words ...uint16) {
	idx := len(a.items)
	a.items = append(a.items, append([]uint16(nil), words...))
	a.pts = append(a.pts, waPatch{item: idx, word: word, ref: ref})
}

// branch 追加分支指令；form 决定宽度与回填位置。
func (a *wa) branch(form int, label string, w0 uint16) int {
	width := 1
	word := 0
	switch form {
	case form20t, form22t, form21t:
		width, word = 2, 1
	case form30t, form31t:
		width, word = 3, 1
	case form10t:
		width, word = 1, 0
	}
	words := make([]uint16, width)
	words[0] = w0
	idx := len(a.items)
	a.items = append(a.items, words)
	a.brs = append(a.brs, waBranch{item: idx, form: form, label: label, word: word, tgt: -1, baseItem: -1})
	return idx
}

const (
	form10t     = 1
	form20t     = 2
	form22t     = 3
	form21t     = 4
	form30t     = 5
	form31t     = 6
	formPayload = 7
)

// assemble 解析标签、回填分支，返回可交给 dex.Build 的 CodeBlob。
//
// 标签未定义等编程错误直接 panic：测试基础设施出错时不应继续对拍。
func (a *wa) assemble(registers, ins, outs int) *dex.CodeBlob {
	start := make([]int, len(a.items))
	pos := 0
	for i, it := range a.items {
		start[i] = pos
		pos += len(it)
	}
	words := make([]uint16, 0, pos)
	for _, it := range a.items {
		words = append(words, it...)
	}
	for _, b := range a.brs {
		tgt := b.tgt
		if tgt < 0 {
			l, ok := a.labels[b.label]
			if !ok {
				panic("汇编器：未定义标签 " + b.label)
			}
			tgt = l
		}
		baseItem := b.item
		if b.baseItem >= 0 {
			baseItem = b.baseItem
		}
		rel := start[tgt] - (start[baseItem] + b.base)
		at := start[b.item] + b.word
		switch b.form {
		case form10t:
			if rel < -128 || rel > 127 {
				panic("汇编器：10t 偏移超范围")
			}
			words[at] = words[at]&0xff | uint16(byte(int8(rel)))<<8
		case form20t, form22t, form21t:
			if rel < -32768 || rel > 32767 {
				panic("汇编器：16 位分支偏移超范围")
			}
			words[at] = uint16(int16(rel))
		case form30t, form31t, formPayload:
			words[at] = uint16(rel & 0xffff)
			words[at+1] = uint16(uint32(int32(rel)) >> 16)
		}
	}
	var patches []dex.InsnPatch
	for _, p := range a.pts {
		r := p.ref
		r.Word = start[p.item] + p.word
		patches = append(patches, dex.InsnPatch{At: start[p.item] + p.word, Ref: r})
	}
	return &dex.CodeBlob{Registers: uint16(registers), Ins: uint16(ins), Outs: uint16(outs), Insns: words, Patches: patches}
}

// ---- 常用发射辅助 ----

func (a *wa) _mov(a1, b int)                { a.emit(0x01 | uint16(a1&0xf)<<8 | uint16(b&0xf)<<12) }
func (a *wa) moveFrom16(a1, b int)          { a.emit(0x02|uint16(a1)<<8, uint16(b)) }
func (a *wa) move16(a1, b int)              { a.emit(0x03, uint16(a1), uint16(b)) }
func (a *wa) moveWide(a1, b int)            { a.emit(0x04 | uint16(a1&0xf)<<8 | uint16(b&0xf)<<12) }
func (a *wa) moveWideFrom16(a1, b int)      { a.emit(0x05|uint16(a1)<<8, uint16(b)) }
func (a *wa) moveWide16(a1, b int)          { a.emit(0x06, uint16(a1), uint16(b)) }
func (a *wa) moveObject(a1, b int)          { a.emit(0x07 | uint16(a1&0xf)<<8 | uint16(b&0xf)<<12) }
func (a *wa) moveObjectFrom16(dst, src int) { a.emit(0x08|uint16(dst)<<8, uint16(src)) }
func (a *wa) moveObject16(dst, src int)     { a.emit(0x09, uint16(dst), uint16(src)) }
func (a *wa) moveResult(r int)              { a.emit(0x0a | uint16(r)<<8) }
func (a *wa) moveResultWide(r int)          { a.emit(0x0b | uint16(r)<<8) }
func (a *wa) moveResultObject(r int)        { a.emit(0x0c | uint16(r)<<8) }
func (a *wa) returnVoid()                   { a.emit(0x0e) }
func (a *wa) returnReg(r int)               { a.emit(0x0f | uint16(r)<<8) }
func (a *wa) returnWide(r int)              { a.emit(0x10 | uint16(r)<<8) }
func (a *wa) returnObject(r int)            { a.emit(0x11 | uint16(r)<<8) }
func (a *wa) const4(r int, v int8)          { a.emit(0x12 | uint16(r&0xf)<<8 | uint16(byte(v))<<12) }
func (a *wa) const16(r int, v int16)        { a.emit(0x13|uint16(r)<<8, uint16(v)) }
func (a *wa) const32(r int, v int32) {
	a.emit(0x14|uint16(r)<<8, uint16(v&0xffff), uint16(uint32(v)>>16))
}
func (a *wa) constWide16(r int, v int16) { a.emit(0x16|uint16(r)<<8, uint16(v)) }
func (a *wa) constWide32(r int, v int32) {
	a.emit(0x17|uint16(r)<<8, uint16(v&0xffff), uint16(uint32(v)>>16))
}
func (a *wa) constWide(r int, v int64) {
	a.emit(0x18|uint16(r)<<8, uint16(v&0xffff), uint16(uint64(v)>>16), uint16(uint64(v)>>32), uint16(uint64(v)>>48))
}
func (a *wa) constWideHigh16(r int, v int16) { a.emit(0x19|uint16(r)<<8, uint16(v)) }
func (a *wa) constString(r int, s string) {
	a.patch(1, dex.RefSpec{Kind: dex.RefString, Word: 1, Wide: true, String: s}, 0x1b|uint16(r)<<8, 0, 0)
}

// constStringShort 发射 21c 形态的 const-string（16 位索引）。
func (a *wa) constStringShort(r int, s string) {
	a.patch(1, dex.RefSpec{Kind: dex.RefString, Word: 1, String: s}, 0x1a|uint16(r)<<8, 0)
}
func (a *wa) goto10(label string) { a.branch(form10t, label, 0x28) }
func (a *wa) goto16(label string) { a.branch(form20t, label, 0x29) }
func (a *wa) goto32(label string) { a.branch(form30t, label, 0x2a) }
func (a *wa) cmpLong(dst, x, y int) {
	a.emit(0x31|uint16(dst)<<8, uint16(x)|uint16(y)<<8)
}
func (a *wa) ifOp(op byte, x, y int, label string) {
	a.branch(form22t, label, uint16(op)|uint16(x&0xf)<<8|uint16(y&0xf)<<12)
}
func (a *wa) ifEq(x, y int, l string) { a.ifOp(0x32, x, y, l) }
func (a *wa) ifNe(x, y int, l string) { a.ifOp(0x33, x, y, l) }
func (a *wa) ifLt(x, y int, l string) { a.ifOp(0x34, x, y, l) }
func (a *wa) ifGe(x, y int, l string) { a.ifOp(0x35, x, y, l) }
func (a *wa) ifGt(x, y int, l string) { a.ifOp(0x36, x, y, l) }
func (a *wa) ifLe(x, y int, l string) { a.ifOp(0x37, x, y, l) }
func (a *wa) ifzOp(op byte, r int, l string) {
	a.branch(form21t, l, uint16(op)|uint16(r)<<8)
}
func (a *wa) ifEqz(r int, l string) { a.ifzOp(0x38, r, l) }
func (a *wa) ifNez(r int, l string) { a.ifzOp(0x39, r, l) }
func (a *wa) ifLtz(r int, l string) { a.ifzOp(0x3a, r, l) }
func (a *wa) ifGez(r int, l string) { a.ifzOp(0x3b, r, l) }
func (a *wa) ifGtz(r int, l string) { a.ifzOp(0x3c, r, l) }
func (a *wa) ifLez(r int, l string) { a.ifzOp(0x3d, r, l) }

// unary12x 发射一条 12x 一元指令。
func (a *wa) unary12x(op byte, dst, src int) {
	a.emit(uint16(op) | uint16(dst&0xf)<<8 | uint16(src&0xf)<<12)
}

// bin23x 发射一条 23x 二元指令。
func (a *wa) bin23x(op byte, dst, x, y int) {
	a.emit(uint16(op)|uint16(dst)<<8, uint16(x)|uint16(y)<<8)
}

// lit16 发射 22s 立即数指令。
func (a *wa) lit16(op byte, dst, src int, v int16) {
	a.emit(uint16(op)|uint16(dst)<<8, uint16(src)|uint16(v)<<8)
}

// lit8 发射 22b 立即数指令。
func (a *wa) lit8(op byte, dst, src int, v int8) {
	a.emit(uint16(op)|uint16(dst)<<8, uint16(src)|uint16(byte(v))<<8)
}

// ---- 字段/调用发射 ----

func (a *wa) field22c(op byte, dst, obj int, f dex.FieldSpec) {
	a.patch(1, dex.RefSpec{Kind: dex.RefField, Word: 1, Field: f},
		uint16(op)|uint16(dst&0xf)<<8|uint16(obj&0xf)<<12, 0)
}

func (a *wa) field21c(op byte, r int, f dex.FieldSpec) {
	a.patch(1, dex.RefSpec{Kind: dex.RefField, Word: 1, Field: f}, uint16(op)|uint16(r)<<8, 0)
}

// invoke35c 发射 35c 调用；regs 是寄存器字列表（≤5）。
func (a *wa) invoke35c(op byte, regs []int, m dex.MethodSpec) {
	if len(regs) > 5 {
		panic("35c 最多 5 个寄存器字")
	}
	argc := len(regs)
	var w2 uint16
	for i, r := range regs {
		if i < 4 {
			w2 |= uint16(r&0xf) << (4 * uint(i))
		}
	}
	var g uint16
	if argc == 5 {
		g = uint16(regs[4] & 0xf)
	}
	a.patch(1, dex.RefSpec{Kind: dex.RefMethod, Word: 1, Method: m},
		uint16(op)|uint16(argc)<<12|g<<8, 0, w2)
}

// invoke3rc 发射 3rc 调用；regs 必须是连续寄存器区间的起点与个数。
func (a *wa) invoke3rc(op byte, first, count int, m dex.MethodSpec) {
	a.patch(1, dex.RefSpec{Kind: dex.RefMethod, Word: 1, Method: m},
		uint16(op)|uint16(count)<<8, 0, uint16(first))
}

// packedSwitch 发射 packed-switch 指令与 payload（targets 为 case 标签）。
func (a *wa) packedSwitch(reg int, targets []string) {
	sw := a.branch(form31t, "", uint16(0x2b)|uint16(reg)<<8)
	pidx := a.emit(make([]uint16, 4+2*len(targets))...)
	// switch -> payload 的相对偏移（相对 switch 指令）。
	a.brs[len(a.brs)-1].tgt = pidx
	w := a.items[pidx]
	w[0], w[1] = 0x0100, uint16(len(targets))
	for i, lb := range targets {
		a.brs = append(a.brs, waBranch{
			item: pidx, word: 4 + 2*i, form: formPayload, label: lb,
			tgt: -1, base: 0, baseItem: sw,
		})
	}
}

// fillArrayData 发射 fill-array-data 指令与 payload（字节数组）。
func (a *wa) fillArrayData(reg int, data []byte) {
	a.branch(form31t, "__fap", uint16(0x26)|uint16(reg)<<8)
	pidx := len(a.items)
	words := make([]uint16, 4+(len(data)+1)/2)
	words[0] = 0x0300
	words[1] = 1
	words[2] = uint16(len(data))
	words[3] = uint16(len(data) >> 16)
	for i, b := range data {
		if i%2 == 0 {
			words[4+i/2] = uint16(b)
		} else {
			words[4+i/2] |= uint16(b) << 8
		}
	}
	a.emit(words...)
	a.labels["__fap"] = pidx
}

// ---- mock 宿主 ----

type mockStr struct{ text string }

type mockObj struct {
	desc  string
	ints  map[string]int32
	wides map[string]int64
	refs  map[string]any
}

func newMockObj(desc string) *mockObj {
	return &mockObj{desc: desc, ints: map[string]int32{}, wides: map[string]int64{}, refs: map[string]any{}}
}

type mockRuntime struct {
	strings map[string]*mockStr
	statics map[string]*mockObj // 类描述符 -> 静态字段容器
	invokes map[string]func(args []vmp.Value) (vmp.Value, error)
	// calls 记录调用轨迹，供断言调用形态/参数顺序。
	calls []string
	// depth 限制递归，防止 fixture 错误导致栈溢出。
	depth int
}

func newMockRuntime() *mockRuntime {
	return &mockRuntime{
		strings: map[string]*mockStr{},
		statics: map[string]*mockObj{},
		invokes: map[string]func([]vmp.Value) (vmp.Value, error){},
	}
}

func (r *mockRuntime) on(sig string, fn func(args []vmp.Value) (vmp.Value, error)) {
	r.invokes[sig] = fn
}

func (r *mockRuntime) NewString(units []uint16) (any, error) {
	text := unitsToText(units)
	if s, ok := r.strings[text]; ok {
		return s, nil
	}
	s := &mockStr{text: text}
	r.strings[text] = s
	return s, nil
}

func (r *mockRuntime) staticFor(class string) *mockObj {
	o, ok := r.statics[class]
	if !ok {
		o = newMockObj(class)
		r.statics[class] = o
	}
	return o
}

func (r *mockRuntime) FieldGet(f vmp.FieldRef, obj any) (vmp.Value, error) {
	holder := r.staticFor(f.Class)
	if !f.Static {
		mo, ok := obj.(*mockObj)
		if !ok || mo == nil {
			return vmp.Value{}, fmt.Errorf("iget %s.%s 的接收者为 nil（vm 侧应为 null 检查先行）", f.Class, f.Name)
		}
		holder = mo
	}
	switch f.Type[0] {
	case 'J':
		return vmp.Wide(holder.wides[f.Name]), nil
	case 'L', '[':
		return vmp.Ref(holder.refs[f.Name]), nil
	default:
		return vmp.Int(holder.ints[f.Name]), nil
	}
}

func (r *mockRuntime) FieldPut(f vmp.FieldRef, obj any, v vmp.Value) error {
	holder := r.staticFor(f.Class)
	if !f.Static {
		mo, ok := obj.(*mockObj)
		if !ok || mo == nil {
			return fmt.Errorf("iput %s.%s 的接收者为 nil", f.Class, f.Name)
		}
		holder = mo
	}
	switch f.Type[0] {
	case 'J':
		holder.wides[f.Name] = int64(v.I)
	case 'L', '[':
		holder.refs[f.Name] = v.Ref
	default:
		holder.ints[f.Name] = int32(v.I)
	}
	return nil
}

func (r *mockRuntime) Invoke(m vmp.MethodRef, args []vmp.Value) (vmp.Value, error) {
	r.calls = append(r.calls, m.Sig())
	if r.depth > 64 {
		return vmp.Value{}, fmt.Errorf("mock 调用深度超限（疑似 fixture 递归）")
	}
	fn, ok := r.invokes[m.Sig()]
	if !ok {
		return vmp.Value{}, fmt.Errorf("mock 未实现调用 %s", m.Sig())
	}
	r.depth++
	v, err := fn(args)
	r.depth--
	return v, err
}

// unitsToText 把 UTF-16 码元还原为可用于比较的文本。
func unitsToText(u []uint16) string {
	var sb strings.Builder
	for _, c := range u {
		sb.WriteRune(rune(c))
	}
	return sb.String()
}

// ---- 原始 DEX 参考解释器 ----

type dexRunner struct {
	f      *dex.File
	rt     *mockRuntime
	prog   map[string]*dex.CodeItemFull
	sig    map[string]string // sig -> method desc
	static map[string]bool
}

// newDexRunner 为 fixture DEX 建立签名索引。
func newDexRunner(t *testing.T, f *dex.File, classDesc string, methods []fixMethod) *dexRunner {
	t.Helper()
	r := &dexRunner{
		f: f, rt: newMockRuntime(),
		prog: map[string]*dex.CodeItemFull{}, sig: map[string]string{}, static: map[string]bool{},
	}
	for _, m := range methods {
		off, proto := findMethod(t, f, classDesc, m.Name)
		ci, err := f.ParseCodeItem(off)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", m.Name, err)
		}
		sig := classDesc + "->" + m.Name + proto
		r.prog[sig] = ci
		r.sig[sig] = proto
		r.static[sig] = m.Access&0x8 != 0
	}
	return r
}

func findMethod(t *testing.T, f *dex.File, classDesc, name string) (uint32, string) {
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
				proto, err := f.ProtoDesc(uint32(ref.ProtoIdx))
				if err != nil {
					t.Fatal(err)
				}
				return m.CodeOff, proto
			}
		}
	}
	t.Fatalf("fixture 中找不到方法 %s", name)
	return 0, ""
}

// run 以 args 执行原始方法体。
func (r *dexRunner) run(t *testing.T, sig string, args []vmp.Value) (vmp.Value, error) {
	t.Helper()
	ci, ok := r.prog[sig]
	if !ok {
		return vmp.Value{}, fmt.Errorf("未知方法 %s", sig)
	}
	exec := &dexExec{f: r.f, ci: ci, rt: r.rt, proto: r.sig[sig], static: r.static[sig]}
	return exec.run(args)
}

type dexExec struct {
	f      *dex.File
	ci     *dex.CodeItemFull
	rt     *mockRuntime
	proto  string
	static bool
	vals   []uint64
	refs   []any
	last   vmp.Value
	steps  int
}

// run 按 Dalvik 语义解释原始指令流。
func (e *dexExec) run(args []vmp.Value) (vmp.Value, error) {
	n := int(e.ci.Registers)
	e.vals = make([]uint64, n)
	e.refs = make([]any, n)
	ret, params, err := vmp.ParseProtoDesc(e.proto)
	if err != nil {
		return vmp.Value{}, err
	}
	// 参数从最高编号寄存器开始，long 占两格；实例方法 this 在前。
	reg := n - int(e.ci.Ins)
	i := 0
	if !e.static {
		if i >= len(args) || args[i].Kind != vmp.KindRef {
			return vmp.Value{}, fmt.Errorf("DEX 参考解释器：实例方法的 this 必须是引用")
		}
		e.refs[reg] = args[i].Ref
		reg++
		i++
	}
	for _, p := range params {
		if i >= len(args) {
			return vmp.Value{}, fmt.Errorf("DEX 参考解释器：实参不足")
		}
		a := args[i]
		i++
		switch {
		case p[0] == 'J':
			e.wideSet(reg, int64(a.I))
			reg += 2
		case p[0] == 'L' || p[0] == '[':
			e.refs[reg] = a.Ref
			reg++
		default:
			e.setInt(reg, int32(a.I))
			reg++
		}
	}
	if i != len(args) || reg != n {
		return vmp.Value{}, fmt.Errorf("DEX 参考解释器：实参布局不符（用了 %d/%d 个寄存器，参数 %d/%d）", reg, n, i, len(args))
	}
	_ = ret
	pc := 0
	for {
		e.steps++
		if e.steps > 2_000_000 {
			return vmp.Value{}, fmt.Errorf("DEX 参考解释器步数超限")
		}
		if pc < 0 || pc >= len(e.ci.Insns) {
			return vmp.Value{}, fmt.Errorf("DEX 参考解释器 pc 越界 %d/%d", pc, len(e.ci.Insns))
		}
		w0 := e.ci.Insns[pc]
		op := byte(w0 & 0xff)
		switch op {
		case 0x00:
			pc++
		case 0x01:
			a, b := int(w0>>8&0xf), int(w0>>12&0xf)
			e.vals[a], e.refs[a] = e.vals[b], e.refs[b]
			pc++
		case 0x02:
			a, b := int(w0>>8), int(e.ci.Insns[pc+1])
			e.vals[a], e.refs[a] = e.vals[b], e.refs[b]
			pc += 2
		case 0x03:
			a, b := int(e.ci.Insns[pc+1]), int(e.ci.Insns[pc+2])
			e.vals[a], e.refs[a] = e.vals[b], e.refs[b]
			pc += 3
		case 0x04:
			a, b := int(w0>>8&0xf), int(w0>>12&0xf)
			e.wideSet(a, e.wideGet(b))
			pc++
		case 0x05:
			a, b := int(w0>>8), int(e.ci.Insns[pc+1])
			e.wideSet(a, e.wideGet(b))
			pc += 2
		case 0x06:
			a, b := int(e.ci.Insns[pc+1]), int(e.ci.Insns[pc+2])
			e.wideSet(a, e.wideGet(b))
			pc += 3
		case 0x07:
			a, b := int(w0>>8&0xf), int(w0>>12&0xf)
			e.refs[a] = e.refs[b]
			pc++
		case 0x08:
			a, b := int(w0>>8), int(e.ci.Insns[pc+1])
			e.refs[a] = e.refs[b]
			pc += 2
		case 0x09:
			a, b := int(e.ci.Insns[pc+1]), int(e.ci.Insns[pc+2])
			e.refs[a] = e.refs[b]
			pc += 3
		case 0x0a:
			e.vals[w0>>8] = e.last.I
			e.last = vmp.Value{}
			pc++
		case 0x0b:
			e.vals[w0>>8] = e.last.I
			e.last = vmp.Value{}
			pc++
		case 0x0c:
			e.refs[w0>>8] = e.last.Ref
			e.last = vmp.Value{}
			pc++
		case 0x0e:
			return vmp.Value{Kind: vmp.KindVoid}, nil
		case 0x0f:
			return vmp.Int(e.i32(int(w0 >> 8))), nil
		case 0x10:
			return vmp.Value{Kind: vmp.KindWide, I: uint64(e.wideGet(int(w0 >> 8)))}, nil
		case 0x11:
			return vmp.Ref(e.refs[w0>>8]), nil
		case 0x12:
			e.setInt(int(w0>>8&0xf), int32(int8(w0>>12)))
			pc++
		case 0x13:
			e.setInt(int(w0>>8), int32(int16(e.ci.Insns[pc+1])))
			pc += 2
		case 0x14:
			u := uint32(e.ci.Insns[pc+1]) | uint32(e.ci.Insns[pc+2])<<16
			e.setInt(int(w0>>8), int32(u))
			pc += 3
		case 0x16:
			e.wideSet(int(w0>>8), int64(int16(e.ci.Insns[pc+1])))
			pc += 2
		case 0x17:
			u := uint32(e.ci.Insns[pc+1]) | uint32(e.ci.Insns[pc+2])<<16
			e.wideSet(int(w0>>8), int64(int32(u)))
			pc += 3
		case 0x18:
			u := uint64(e.ci.Insns[pc+1]) | uint64(e.ci.Insns[pc+2])<<16 |
				uint64(e.ci.Insns[pc+3])<<32 | uint64(e.ci.Insns[pc+4])<<48
			e.wideSet(int(w0>>8), int64(u))
			pc += 5
		case 0x19:
			e.wideSet(int(w0>>8), int64(int16(e.ci.Insns[pc+1]))<<48)
			pc += 2
		case 0x1a:
			s, err := e.f.String(uint32(e.ci.Insns[pc+1]))
			if err != nil {
				return vmp.Value{}, err
			}
			obj, err := e.rt.NewString(utf16Of(s))
			if err != nil {
				return vmp.Value{}, err
			}
			e.refs[w0>>8] = obj
			pc += 2
		case 0x1b:
			idx := uint32(e.ci.Insns[pc+1]) | uint32(e.ci.Insns[pc+2])<<16
			s, err := e.f.String(idx)
			if err != nil {
				return vmp.Value{}, err
			}
			obj, err := e.rt.NewString(utf16Of(s))
			if err != nil {
				return vmp.Value{}, err
			}
			e.refs[w0>>8] = obj
			pc += 3
		case 0x28:
			pc += int(int8(w0 >> 8))
		case 0x29:
			pc += int(int16(e.ci.Insns[pc+1]))
		case 0x2a:
			rel := int32(uint32(e.ci.Insns[pc+1]) | uint32(e.ci.Insns[pc+2])<<16)
			pc += int(rel)
		case 0x31:
			x, y := e.i64(int(e.ci.Insns[pc+1]&0xff)), e.i64(int(e.ci.Insns[pc+1]>>8))
			switch {
			case x < y:
				e.setInt(int(w0>>8), -1)
			case x > y:
				e.setInt(int(w0>>8), 1)
			default:
				e.setInt(int(w0>>8), 0)
			}
			pc += 2
		case 0x32, 0x33, 0x34, 0x35, 0x36, 0x37:
			x, y := int(w0>>8&0xf), int(w0>>12&0xf)
			taken := false
			switch op {
			case 0x32:
				taken = e.i32(x) == e.i32(y)
			case 0x33:
				taken = e.i32(x) != e.i32(y)
			case 0x34:
				taken = e.i32(x) < e.i32(y)
			case 0x35:
				taken = e.i32(x) >= e.i32(y)
			case 0x36:
				taken = e.i32(x) > e.i32(y)
			case 0x37:
				taken = e.i32(x) <= e.i32(y)
			}
			if taken {
				pc += int(int16(e.ci.Insns[pc+1]))
			} else {
				pc += 2
			}
		case 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d:
			x := int(w0 >> 8)
			taken := false
			switch op {
			case 0x38:
				taken = e.i32(x) == 0
			case 0x39:
				taken = e.i32(x) != 0
			case 0x3a:
				taken = e.i32(x) < 0
			case 0x3b:
				taken = e.i32(x) >= 0
			case 0x3c:
				taken = e.i32(x) > 0
			case 0x3d:
				taken = e.i32(x) <= 0
			}
			if taken {
				pc += int(int16(e.ci.Insns[pc+1]))
			} else {
				pc += 2
			}
		case 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58:
			f, err := e.field(uint32(e.ci.Insns[pc+1]))
			if err != nil {
				return vmp.Value{}, err
			}
			v, err := e.rt.FieldGet(f, e.refs[w0>>12&0xf])
			if err != nil {
				return vmp.Value{}, err
			}
			e.store(int(w0>>8&0xf), f.Type, v)
			pc += 2
		case 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f:
			f, err := e.field(uint32(e.ci.Insns[pc+1]))
			if err != nil {
				return vmp.Value{}, err
			}
			v := e.load(int(w0>>8&0xf), f.Type)
			if err := e.rt.FieldPut(f, e.refs[w0>>12&0xf], v); err != nil {
				return vmp.Value{}, err
			}
			pc += 2
		case 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66:
			f, err := e.field(uint32(e.ci.Insns[pc+1]))
			if err != nil {
				return vmp.Value{}, err
			}
			f.Static = true // 0x60-0x66 是 sget* 家族：静态字段，接收者为类而非对象
			v, err := e.rt.FieldGet(f, nil)
			if err != nil {
				return vmp.Value{}, err
			}
			e.store(int(w0>>8), f.Type, v)
			pc += 2
		case 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d:
			f, err := e.field(uint32(e.ci.Insns[pc+1]))
			if err != nil {
				return vmp.Value{}, err
			}
			f.Static = true // 0x67-0x6d 是 sput* 家族
			v := e.load(int(w0>>8), f.Type)
			if err := e.rt.FieldPut(f, nil, v); err != nil {
				return vmp.Value{}, err
			}
			pc += 2
		case 0x6e, 0x6f, 0x70, 0x71, 0x72:
			argc := int(w0 >> 12)
			g := int(w0 >> 8 & 0xf)
			w2 := e.ci.Insns[pc+2]
			regs := []int{int(w2 & 0xf), int(w2 >> 4 & 0xf), int(w2 >> 8 & 0xf), int(w2 >> 12 & 0xf)}
			regs = regs[:min(argc, 4)]
			if argc == 5 {
				regs = append(regs, g)
			}
			nxt, err := e.doInvoke(pc, kindOfDexOp(op), regs)
			if err != nil {
				return vmp.Value{}, err
			}
			pc = nxt
		case 0x74, 0x75, 0x76, 0x77, 0x78:
			argc := int(w0 >> 8)
			first := int(e.ci.Insns[pc+2])
			regs := make([]int, argc)
			for i := range regs {
				regs[i] = first + i
			}
			nxt, err := e.doInvoke(pc, kindOfDexOp(op-6), regs)
			if err != nil {
				return vmp.Value{}, err
			}
			pc = nxt
		case 0x7b:
			a, b := int(w0>>8&0xf), int(w0>>12&0xf)
			e.setInt(a, -e.i32(b))
			pc++
		case 0x7c:
			a, b := int(w0>>8&0xf), int(w0>>12&0xf)
			e.setInt(a, ^e.i32(b))
			pc++
		case 0x7d:
			a, b := int(w0>>8&0xf), int(w0>>12&0xf)
			e.wideSet(a, -e.wideGet(b))
			pc++
		case 0x7e:
			a, b := int(w0>>8&0xf), int(w0>>12&0xf)
			e.wideSet(a, ^e.wideGet(b))
			pc++
		case 0x81:
			a, b := int(w0>>8&0xf), int(w0>>12&0xf)
			e.wideSet(a, int64(e.i32(b)))
			pc++
		case 0x83:
			a, b := int(w0>>8&0xf), int(w0>>12&0xf)
			e.setInt(a, int32(e.wideGet(b)))
			pc++
		case 0x8d, 0x8e, 0x8f:
			a, b := int(w0>>8&0xf), int(w0>>12&0xf)
			x := e.i32(b)
			switch op {
			case 0x8d:
				e.setInt(a, int32(int8(x)))
			case 0x8e:
				e.setInt(a, int32(uint16(x)))
			case 0x8f:
				e.setInt(a, int32(int16(x)))
			}
			pc++
		case 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a:
			dst := int(w0 >> 8)
			x, y := int(e.ci.Insns[pc+1]&0xff), int(e.ci.Insns[pc+1]>>8)
			v, err := intBinOp(op, e.i32(x), e.i32(y))
			if err != nil {
				return vmp.Value{}, err
			}
			e.setInt(dst, v)
			pc += 2
		case 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5:
			dst := int(w0 >> 8)
			x, y := int(e.ci.Insns[pc+1]&0xff), int(e.ci.Insns[pc+1]>>8)
			v, err := longBinOp(op, e.wideGet(x), e.wideGet(y))
			if err != nil {
				return vmp.Value{}, err
			}
			e.wideSet(dst, v)
			pc += 2
		case 0xd0:
			dst := int(w0 >> 8)
			src := int(e.ci.Insns[pc+1] & 0xff)
			e.setInt(dst, e.i32(src)+int32(int16(e.ci.Insns[pc+1]>>8)))
			pc += 2
		case 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2:
			dst := int(w0 >> 8)
			src := int(e.ci.Insns[pc+1] & 0xff)
			lit := int8(e.ci.Insns[pc+1] >> 8)
			v, err := litOp(op, e.i32(src), lit)
			if err != nil {
				return vmp.Value{}, err
			}
			e.setInt(dst, v)
			pc += 2
		default:
			return vmp.Value{}, fmt.Errorf("DEX 参考解释器不支持 0x%02x", op)
		}
	}
}

// doInvoke 处理调用并按邻接规则消费 move-result。
func (e *dexExec) doInvoke(pc int, kind vmp.InvokeKind, regs []int) (int, error) {
	m, params, ret, err := e.method(uint32(e.ci.Insns[pc+1]))
	if err != nil {
		return 0, err
	}
	m.Kind = kind
	var args []vmp.Value
	ri := 0
	if m.Kind != vmp.InvokeStatic {
		args = append(args, vmp.Ref(e.refs[regs[ri]]))
		ri++
	}
	for _, p := range params {
		if p[0] == 'J' {
			lo := uint64(uint32(e.i32(regs[ri])))
			hi := uint64(uint32(e.i32(regs[ri+1])))
			args = append(args, vmp.Value{Kind: vmp.KindWide, I: hi<<32 | lo})
			ri += 2
		} else if p[0] == 'L' || p[0] == '[' {
			args = append(args, vmp.Ref(e.refs[regs[ri]]))
			ri++
		} else {
			args = append(args, vmp.Int(e.i32(regs[ri])))
			ri++
		}
	}
	v, err := e.rt.Invoke(m, args)
	if err != nil {
		return 0, err
	}
	e.last = v
	next := pc + 3
	if next < len(e.ci.Insns) {
		switch byte(e.ci.Insns[next] & 0xff) {
		case 0x0a, 0x0b:
			e.vals[e.ci.Insns[next]>>8] = v.I
			e.last = vmp.Value{}
			next++
		case 0x0c:
			e.refs[e.ci.Insns[next]>>8] = v.Ref
			e.last = vmp.Value{}
			next++
		}
	}
	_ = ret
	return next, nil
}

func (e *dexExec) method(idx uint32) (vmp.MethodRef, []string, string, error) {
	cls, name, ret, params, err := e.f.MethodFull(idx)
	if err != nil {
		return vmp.MethodRef{}, nil, "", err
	}
	proto := dex.BuildProtoDesc(ret, params)
	return vmp.MethodRef{Class: cls, Name: name, Proto: proto}, params, ret, nil
}

// kindOfDexOp 把 35c/3rc 调用操作码映射为调用形态。
func kindOfDexOp(op byte) vmp.InvokeKind {
	switch op {
	case 0x6e:
		return vmp.InvokeVirtual
	case 0x6f:
		return vmp.InvokeSuper
	case 0x70:
		return vmp.InvokeDirect
	case 0x72:
		return vmp.InvokeInterface
	}
	return vmp.InvokeStatic
}

func (e *dexExec) field(idx uint32) (vmp.FieldRef, error) {
	clsIdx, typeIdx, nameIdx, err := e.f.FieldRefAt(idx)
	if err != nil {
		return vmp.FieldRef{}, err
	}
	cls, err := e.f.Type(uint32(clsIdx))
	if err != nil {
		return vmp.FieldRef{}, err
	}
	name, err := e.f.String(nameIdx)
	if err != nil {
		return vmp.FieldRef{}, err
	}
	typ, err := e.f.Type(uint32(typeIdx))
	if err != nil {
		return vmp.FieldRef{}, err
	}
	return vmp.FieldRef{Class: cls, Name: name, Type: typ}, nil
}

func (e *dexExec) i32(r int) int32 { return int32(e.vals[r]) }
func (e *dexExec) i64(r int) int64 { return e.wideGet(r) }

func (e *dexExec) wideGet(r int) int64 {
	return int64(uint64(e.vals[r]) | uint64(e.vals[r+1])<<32)
}

func (e *dexExec) wideSet(r int, v int64) {
	e.vals[r] = uint64(v)
	e.vals[r+1] = uint64(v) >> 32
	e.refs[r], e.refs[r+1] = nil, nil
}

func (e *dexExec) setInt(r int, v int32) {
	e.vals[r] = uint64(int64(v))
	e.refs[r] = nil
}

// load 读取寄存器并按字段类型规格化为字段值。
func (e *dexExec) load(r int, typ string) vmp.Value {
	switch typ[0] {
	case 'J':
		return vmp.Wide(e.wideGet(r))
	case 'L', '[':
		return vmp.Ref(e.refs[r])
	case 'Z':
		return vmp.Int(e.i32(r) & 1)
	case 'B':
		return vmp.Int(int32(int8(e.i32(r))))
	case 'C':
		return vmp.Int(int32(uint16(e.i32(r))))
	case 'S':
		return vmp.Int(int32(int16(e.i32(r))))
	default:
		return vmp.Int(e.i32(r))
	}
}

// store 把字段值写入寄存器并按类型规格化。
func (e *dexExec) store(r int, typ string, v vmp.Value) {
	switch typ[0] {
	case 'J':
		e.wideSet(r, int64(v.I))
	case 'L', '[':
		e.refs[r] = v.Ref
	default:
		x := int32(v.I)
		switch typ[0] {
		case 'Z':
			x &= 1
		case 'B':
			x = int32(int8(x))
		case 'C':
			x = int32(uint16(x))
		case 'S':
			x = int32(int16(x))
		}
		e.setInt(r, x)
	}
}

func intBinOp(op byte, x, y int32) (int32, error) {
	switch op {
	case 0x90:
		return x + y, nil
	case 0x91:
		return x - y, nil
	case 0x92:
		return x * y, nil
	case 0x93:
		if y == 0 {
			return 0, vmp.ErrDivZero
		}
		return x / y, nil
	case 0x94:
		if y == 0 {
			return 0, vmp.ErrDivZero
		}
		return x % y, nil
	case 0x95:
		return x & y, nil
	case 0x96:
		return x | y, nil
	case 0x97:
		return x ^ y, nil
	case 0x98:
		return x << (uint32(y) & 31), nil
	case 0x99:
		return x >> (uint32(y) & 31), nil
	case 0x9a:
		return int32(uint32(x) >> (uint32(y) & 31)), nil
	}
	return 0, fmt.Errorf("未知 int 二元 op 0x%02x", op)
}

func longBinOp(op byte, x, y int64) (int64, error) {
	switch op {
	case 0x9b:
		return x + y, nil
	case 0x9c:
		return x - y, nil
	case 0x9d:
		return x * y, nil
	case 0x9e:
		if y == 0 {
			return 0, vmp.ErrDivZero
		}
		return x / y, nil
	case 0x9f:
		if y == 0 {
			return 0, vmp.ErrDivZero
		}
		return x % y, nil
	case 0xa0:
		return x & y, nil
	case 0xa1:
		return x | y, nil
	case 0xa2:
		return x ^ y, nil
	case 0xa3:
		return x << (uint32(y) & 63), nil
	case 0xa4:
		return x >> (uint32(y) & 63), nil
	case 0xa5:
		return int64(uint64(x) >> (uint32(y) & 63)), nil
	}
	return 0, fmt.Errorf("未知 long 二元 op 0x%02x", op)
}

func litOp(op byte, x int32, lit int8) (int32, error) {
	switch op {
	case 0xd8:
		return x + int32(lit), nil
	case 0xd9:
		return int32(lit) - x, nil
	case 0xda:
		return x * int32(lit), nil
	case 0xdb:
		if lit == 0 {
			return 0, vmp.ErrDivZero
		}
		return x / int32(lit), nil
	case 0xdc:
		if lit == 0 {
			return 0, vmp.ErrDivZero
		}
		return x % int32(lit), nil
	case 0xdd:
		return x & int32(lit), nil
	case 0xde:
		return x | int32(lit), nil
	case 0xdf:
		return x ^ int32(lit), nil
	case 0xe0:
		return x << (uint32(lit) & 31), nil
	case 0xe1:
		return x >> (uint32(lit) & 31), nil
	case 0xe2:
		return int32(uint32(x) >> (uint32(lit) & 31)), nil
	}
	return 0, fmt.Errorf("未知 lit8 op 0x%02x", op)
}

// utf16Of 把字符串编码为 UTF-16 码元（与实现侧相同的常规路径）。
func utf16Of(s string) []uint16 {
	out := make([]uint16, 0, len(s))
	for _, r := range s {
		if r > 0xffff {
			r -= 0x10000
			out = append(out, uint16(0xd800+(r>>10)), uint16(0xdc00+(r&0x3ff)))
			continue
		}
		out = append(out, uint16(r))
	}
	return out
}

// ---- 值比较 ----

func repr(v vmp.Value) string {
	switch v.Kind {
	case vmp.KindVoid:
		return "void"
	case vmp.KindInt:
		return fmt.Sprintf("i:%d", int32(v.I))
	case vmp.KindWide:
		return fmt.Sprintf("j:%d", int64(v.I))
	case vmp.KindRef:
		return reprRef(v.Ref)
	}
	return "?"
}

func reprRef(r any) string {
	switch o := r.(type) {
	case nil:
		return "null"
	case *mockStr:
		return "s:" + o.text
	case *mockObj:
		var ks []string
		for k, v := range o.ints {
			ks = append(ks, fmt.Sprintf("%s=%d", k, v))
		}
		for k, v := range o.wides {
			ks = append(ks, fmt.Sprintf("%s=%d", k, v))
		}
		for k, v := range o.refs {
			ks = append(ks, fmt.Sprintf("%s=%s", k, reprRef(v)))
		}
		sort.Strings(ks)
		return fmt.Sprintf("o:%s{%s}", o.desc, strings.Join(ks, ","))
	}
	return fmt.Sprintf("%T", r)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
