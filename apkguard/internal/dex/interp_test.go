package dex

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"
)

// 本文件实现一个**仅供测试使用**的极简 Dalvik 解释器。
//
// 存在的理由：A2 的正确性不能只靠「DEX 结构自洽」来保证——
// 结构完全合法但寄存器分配错误（例如把入参寄存器当成局部变量）的解密方法，
// 同样能通过 dex.Verify 与 ParseInsns，却会在真机上崩溃。
// 只有真正把注入的字节码跑一遍、比对解密结果，才能证明语义正确。
//
// 支持的指令范围严格覆盖注入代码用到的子集，遇到其他操作码直接报错，
// 以免「静默跳过」掩盖问题。

// debugCalls 在非 nil 时记录解释器分派到的每一次方法调用描述符。
//
// 仅用于测试诊断：壳 Application 的反射委托链路较长，出错时需要看到
// 实际调用轨迹才能定位是哪一步偏离预期。为 nil 时不产生任何记录。
var debugCalls []string

// fakeCalls 是测试可注册的额外方法处理器，键为方法描述符。
//
// 解释器内建的处理器只覆盖壳代码自身用到的那一小撮 JDK/框架 API；
// 更「外围」的模拟（assets、文件系统、密码学、ClassLoader 接管链路）
// 由各自的使用方按需注册，避免本文件无限膨胀。
var fakeCalls = map[string]func(in *interp, regs []int) (int32, any, error){}

// interpError 表示解释器遇到不支持或非法的指令。
type interpError struct{ msg string }

func (e *interpError) Error() string { return e.msg }

func errf(format string, args ...any) error {
	return &interpError{msg: fmt.Sprintf(format, args...)}
}

// ---- 测试用的对象模型 ----

// fakeStr 模拟 java.lang.String。
type fakeStr struct{ s string }

// fakeBytes 模拟 byte[]。
type fakeBytes struct{ b []byte }

// fakeMD 模拟 java.security.MessageDigest。
//
// 这个 mock 存在的理由：A2 的密钥流已从「单字节仿射流」改为
// SHA-256(secret‖0x01‖nonce‖LE32(i))，注入的解密器必须真的调用
// java.security.MessageDigest 才能还原明文。若解释器不实现它，
// runDecryptor 无法执行解密器，最强的「Go 加密 ↔ 字节码解密」往返测试
// 就成了空话。这里用 crypto/sha256 提供与真机一致的摘要结果。
type fakeMD struct{}

// fakeArr 模拟对象数组（如 Object[]、Method[]、Class[]）。
//
// 壳 Application 的反射委托逻辑要遍历 Method[]，因此需要真实的对象数组。
type fakeArr struct {
	desc  string
	items []any
}

// fakeCls 模拟 java.lang.Class。
//
// supers 用于验证壳代码会沿父类链逐级查找（原 Application 未覆写
// attachBaseContext 时，必须能在父类上找到）。
type fakeCls struct {
	name   string
	supers []*fakeCls
	mths   []*fakeMth
}

// getSuperclass 返回父类；无父类时返回 nil。
func (c *fakeCls) getSuperclass() *fakeCls {
	if len(c.supers) == 0 {
		return nil
	}
	return c.supers[0]
}

// fakeMth 模拟 java.lang.reflect.Method。
type fakeMth struct {
	name     string
	params   []*fakeCls
	accessed bool
	// invoked 记录它被调用时收到的实参，供测试断言。
	invoked []any
	// ret / retSet 让调用方指定 invoke 的返回值。
	//
	// 壳的 ClassLoader 接管链路要靠反射拿到 ActivityThread 实例；
	// 若 invoke 一律返回 nil，那条链路就无法被测到。
	ret    any
	retSet bool
}

// fakeObj 模拟一个普通对象实例，记录其类型描述符与 int 实例字段。
//
// A13 注入的类会读写实例字段，因此需要真实的字段存储来验证语义。
type fakeObj struct {
	desc   string
	fields map[string]int32
	// objFields 保存对象类型的实例字段。
	//
	// 签名校验要读 PackageInfo.signatures（Signature[]），这是对象字段，
	// 无法塞进 fields 的 int32 槽位，因此单独用一张表承载。
	objFields map[string]any
	// aux 供测试把任意负载挂到模拟对象上。
	//
	// 例如 SecretKeySpec 需要保存密钥字节、File 需要保存路径，
	// 这些都不是 int 字段，用 aux 承载比另建全局表更直观。
	aux any
}

// setObjField 写入一个对象类型字段。
func (o *fakeObj) setObjField(name string, v any) {
	if o.objFields == nil {
		o.objFields = map[string]any{}
	}
	o.objFields[name] = v
}

// getObjField 读取一个对象类型字段，不存在时返回 nil。
func (o *fakeObj) getObjField(name string) any {
	if o.objFields == nil {
		return nil
	}
	return o.objFields[name]
}

// getField 读取实例字段；不存在时返回 0（与 Java 的字段默认值一致）。
func (o *fakeObj) getField(name string) int32 {
	if o.fields == nil {
		return 0
	}
	return o.fields[name]
}

// setField 写入实例字段。
func (o *fakeObj) setField(name string, v int32) {
	if o.fields == nil {
		o.fields = map[string]int32{}
	}
	o.fields[name] = v
}

// padStatics 保存各静态字段的当前值，键为 "类描述符->字段名"。
//
// 解释器只在测试内运行，用包级变量模拟静态区即可。
var padStatics = map[string]int32{}

// objStatics 保存对象类型的静态字段，键同 padStatics。
//
// 壳 Application 用静态字段缓存原 Application 实例，需要真实存储。
var objStatics = map[string]any{}

// fakeClasses 是解释器可见的「已加载类」表，键为 Java 点分名。
//
// 壳代码调用 Class.forName 时从这里取；测试据此注入一个模拟的原 Application 类。
var fakeClasses = map[string]*fakeCls{}

// fakeCode 把方法描述符映射到它在被测 DEX 中的 code_item 偏移。
//
// 壳 Application 的 attachBaseContext 会调用同一个类里的静态辅助方法 a()，
// 解释器必须能进入该方法体，因此需要这份索引。
var fakeCode = map[string]uint32{}

// regKind 标记寄存器槽位的值类型。
//
// 宽值（long/double）在 DEX 里占**两个**相邻寄存器（低半 r、高半 r+1）。
// 只存 int32 无法表达「相邻格属于同一个值」，也就无法验证 A6 的宽值保护：
// 把宽值高半当空闲寄存器写坏会 VerifyError，而解释器此前根本跑不了宽值指令，
// 构造不出这种冲突。因此显式记录每个槽位的类型。
type regKind uint8

const (
	regUnknown  regKind = iota // 未定义（校验器可匹配任意类型）
	regInt                     // int/float 等单槽值
	regObj                     // 对象引用
	regWideLow                 // long/double 低半
	regWideHigh                // long/double 高半
)

func (k regKind) String() string {
	switch k {
	case regInt:
		return "int"
	case regObj:
		return "object"
	case regWideLow:
		return "wide-low"
	case regWideHigh:
		return "wide-high"
	}
	return "unknown"
}

// interp 是一个极简解释器实例。
type interp struct {
	f     *File
	regs  []int32
	objs  []any
	kinds []regKind
	insns []uint16
	// calls 记录发生过的调用，形如 "Ljava/lang/String;->length()I"。
	calls []string
}

// newInterp 为一个方法体创建解释器。
func newInterp(f *File, ci *CodeItemFull) *interp {
	return &interp{
		f:     f,
		regs:  make([]int32, ci.Registers),
		objs:  make([]any, ci.Registers),
		kinds: make([]regKind, ci.Registers),
		insns: ci.Insns,
	}
}

// setArg 把入参写入寄存器（Dalvik 的入参位于最高编号的寄存器）。
//
// 对象类入参写入 objs，int 类入参写入 regs——A13 注入的方法既有
// 对象入参（this）也有 int 入参，两者必须分别落到对应的寄存器堆。
func (in *interp) setArg(idx, totalIns int, v any) error {
	reg := len(in.regs) - totalIns + idx
	if reg < 0 || reg >= len(in.regs) {
		return errf("入参寄存器越界: regs=%d ins=%d idx=%d", len(in.regs), totalIns, idx)
	}
	if n, ok := v.(int32); ok {
		in.setIntAt(reg, n)
		return nil
	}
	in.setObjAt(reg, v)
	return nil
}

// setInt / setObj 是解释器**唯一**的寄存器写入入口。
//
// 必须有统一的写入函数，而不是各处直接写 regs/objs 数组：寄存器在 Dalvik 里
// 只有一份值，写入原始类型后它就不再持有引用。若只写 regs 而不清 objs，
// 该槽位会残留上一个对象的引用，于是 if-eq/if-nez 这类「按引用判断」的指令
// 会把刚写入的整数误当成对象——D5 设备绑定就是这样被误判为「不匹配」的。
func (in *interp) setInt(reg uint16, v int32) { in.setIntAt(int(reg), v) }
func (in *interp) setObj(reg uint16, o any)   { in.setObjAt(int(reg), o) }

// setIntAt / setObjAt 接受已经算好的 int 下标：指令里的寄存器号宽度不一，
// 用 uint16 入口 + int 入口覆盖两种来源。
//
// 两者都维护 kinds：写入会覆盖槽位类型；若覆盖的是某个宽值的低半或高半，
// 该宽值的另一半随之失效（校验器视角是类型冲突，动态执行时在后续读取暴露）。
func (in *interp) setIntAt(reg int, v int32) {
	if in.kinds[reg] == regWideLow && reg+1 < len(in.kinds) {
		in.kinds[reg+1] = regUnknown
	}
	in.regs[reg] = v
	in.objs[reg] = nil
	in.kinds[reg] = regInt
}
func (in *interp) setObjAt(reg int, o any) {
	if in.kinds[reg] == regWideLow && reg+1 < len(in.kinds) {
		in.kinds[reg+1] = regUnknown
	}
	in.objs[reg] = o
	in.regs[reg] = 0
	in.kinds[reg] = regObj
}

// setWideAt 写入一个 64 位宽值：低半在 r、高半在 r+1，两格都打上类型标记。
func (in *interp) setWideAt(reg int, v int64) error {
	if reg < 0 || reg+1 >= len(in.regs) {
		return errf("宽值寄存器越界 v%d（registers=%d）", reg, len(in.regs))
	}
	lo := int32(uint32(v))
	hi := int32(uint32(v >> 32))
	in.regs[reg] = lo
	in.objs[reg] = nil
	in.kinds[reg] = regWideLow
	in.regs[reg+1] = hi
	in.objs[reg+1] = nil
	in.kinds[reg+1] = regWideHigh
	return nil
}

// wideValue 读取一个 64 位宽值，并校验低/高半的类型标记。
//
// 这是 A6 宽值保护的观察点：谓词寄存器若选错、写坏了某个宽值的高半，
// 这里会以「宽值类型冲突」失败，而不是把两个半字拼出一个看似合理的值。
func (in *interp) wideValue(reg int) (int64, error) {
	if reg < 0 || reg+1 >= len(in.regs) {
		return 0, errf("宽值寄存器越界 v%d（registers=%d）", reg, len(in.regs))
	}
	if in.kinds[reg] != regWideLow || in.kinds[reg+1] != regWideHigh {
		return 0, errf("宽值类型冲突：读取 v%d（long 低半）时 v%d=%s、v%d=%s；"+
			"高半被当作普通寄存器写坏（A6 谓词选到了宽值的相邻格）",
			reg, reg, in.kinds[reg], reg+1, in.kinds[reg+1])
	}
	lo := int64(uint32(in.regs[reg]))
	hi := int64(uint32(in.regs[reg+1]))
	return hi<<32 | lo, nil
}

// isNull 判断寄存器是否为 null 引用。
//
// Dalvik 的 if-eqz/if-nez 对对象引用做的是空判断，而本解释器把对象放在
// objs、int 放在 regs 两个寄存器堆里：对象寄存器的 regs 槽位恒为 0，
// 只看 regs 会把任何非空对象误判成 null。因此必须同时看两个堆。
func (in *interp) isNull(reg int) bool {
	return in.regs[reg] == 0 && in.objs[reg] == nil
}

// sameValue 判断两个寄存器是否「值相等」，供 if-eq/if-ne 使用。
//
// 与 isNull 同理：只要任一槽位持有对象引用，比较的就必须是引用本身，
// 而不是 regs 里那个恒为 0 的占位整数——否则任意两个不同对象都会被判为
// 相等，分支恒定走「相等」一侧，测试就会对着错误的分支欢呼。
// Dalvik 的真实语义是：引用比较同一性，且 null 与任何非 null 不等。
func (in *interp) sameValue(x, y int) bool {
	if in.objs[x] != nil || in.objs[y] != nil {
		return !in.isNull(x) && !in.isNull(y) && in.objs[x] == in.objs[y]
	}
	return in.regs[x] == in.regs[y]
}

// Run 执行方法体，返回 return-object 的值。
func (in *interp) Run() (any, error) {
	pc := 0
	for steps := 0; steps < 500000; steps++ {
		if pc < 0 || pc >= len(in.insns) {
			return nil, errf("pc 越界 %d/%d", pc, len(in.insns))
		}
		w0 := in.insns[pc]
		op := byte(w0 & 0xff)
		switch op {
		case 0x00: // nop
			pc++
		case 0x01: // move vA, vB
			dst, src := int(w0>>8&0xf), int(w0>>12&0xf)
			if in.objs[src] != nil {
				in.setObjAt(dst, in.objs[src])
			} else {
				in.setIntAt(dst, in.regs[src])
			}
			pc++
		case 0x04: // move-wide vA, vB（12x）
			dst, src := int(w0>>8&0xf), int(w0>>12&0xf)
			v, err := in.wideValue(src)
			if err != nil {
				return nil, err
			}
			if err := in.setWideAt(dst, v); err != nil {
				return nil, err
			}
			pc++
		case 0x05: // move-wide/from16 vAA, vBBBB（22x）
			dst, src := int(w0>>8), int(in.insns[pc+1])
			v, err := in.wideValue(src)
			if err != nil {
				return nil, err
			}
			if err := in.setWideAt(dst, v); err != nil {
				return nil, err
			}
			pc += 2
		case 0x06: // move-wide/16 vAAAA, vBBBB（32x）
			dst, src := int(in.insns[pc+1]), int(in.insns[pc+2])
			v, err := in.wideValue(src)
			if err != nil {
				return nil, err
			}
			if err := in.setWideAt(dst, v); err != nil {
				return nil, err
			}
			pc += 3
		case 0x07: // move-object vA, vB
			dst, src := int(w0>>8&0xf), int(w0>>12&0xf)
			in.setObjAt(dst, in.objs[src])
			pc++
		case 0x0e: // return-void
			return nil, nil
		case 0x0f: // return vAA（返回 int）
			return in.regs[w0>>8], nil
		case 0x10: // return-wide vAA（返回 long/double）
			v, err := in.wideValue(int(w0 >> 8))
			if err != nil {
				return nil, err
			}
			return v, nil
		case 0x11: // return-object vAA
			return in.objs[w0>>8], nil
		case 0x12: // const/4 vA, #+B
			reg := int(w0 >> 8 & 0xf)
			in.setIntAt(reg, int32(int8(w0>>12)))
			pc++
		case 0x13: // const/16 vAA, #+BBBB
			in.setIntAt(int(w0>>8), int32(int16(in.insns[pc+1])))
			pc += 2
		case 0x14: // const vAA, #+BBBBBBBB（31i）
			v := uint32(in.insns[pc+1]) | uint32(in.insns[pc+2])<<16
			// setInt 已经清掉对象堆，不能再写一次 objs——那会把刚写入的
			// 常量清零（const 与 const/4、const/16 必须同样处理）。
			in.setInt(w0>>8, int32(v))
			pc += 3
		case 0x16: // const-wide/16 vAA, #+BBBB
			if err := in.setWideAt(int(w0>>8), int64(int16(in.insns[pc+1]))); err != nil {
				return nil, err
			}
			pc += 2
		case 0x17: // const-wide/32 vAA, #+BBBBBBBB
			v := int64(int32(uint32(in.insns[pc+1]) | uint32(in.insns[pc+2])<<16))
			if err := in.setWideAt(int(w0>>8), v); err != nil {
				return nil, err
			}
			pc += 3
		case 0x18: // const-wide vAA, #+BBBBBBBBBBBBBBBB（51l）
			u := uint64(in.insns[pc+1]) | uint64(in.insns[pc+2])<<16 |
				uint64(in.insns[pc+3])<<32 | uint64(in.insns[pc+4])<<48
			if err := in.setWideAt(int(w0>>8), int64(u)); err != nil {
				return nil, err
			}
			pc += 5
		case 0x19: // const-wide/high16 vAA, #+BBBB000000000000
			if err := in.setWideAt(int(w0>>8), int64(int16(in.insns[pc+1]))<<48); err != nil {
				return nil, err
			}
			pc += 2
		case 0x1a: // const-string vAA, string@BBBB
			s, err := in.f.String(uint32(in.insns[pc+1]))
			if err != nil {
				return nil, err
			}
			in.setObj(w0>>8, &fakeStr{s: s})
			pc += 2
		case 0x1b: // const-string/jumbo vAA, string@BBBBBBBB
			idx := uint32(in.insns[pc+1]) | uint32(in.insns[pc+2])<<16
			s, err := in.f.String(idx)
			if err != nil {
				return nil, err
			}
			in.setObj(w0>>8, &fakeStr{s: s})
			pc += 3
		case 0x1c: // const-class vAA, type@BBBB
			d, err := in.f.Type(uint32(in.insns[pc+1]))
			if err != nil {
				return nil, err
			}
			c := fakeClasses[ShellJavaName(d)]
			if c == nil {
				c = &fakeCls{name: ShellJavaName(d)}
			}
			in.setObj(w0>>8, c)
			pc += 2
		case 0x1f: // check-cast vAA, type@BBBB
			// 模拟实现不做真实类型检查：只确认被转换的引用非 nil 即可，
			// 壳代码用到的向下转型（Object -> Application）恒成立。
			pc += 2
		case 0x21: // array-length vA, vB
			dst, src := int(w0>>8&0xf), int(w0>>12&0xf)
			switch arr := in.objs[src].(type) {
			case *fakeBytes:
				in.setIntAt(dst, int32(len(arr.b)))
			case *fakeArr:
				in.setIntAt(dst, int32(len(arr.items)))
			default:
				return nil, errf("array-length 的操作数不是数组")
			}
			pc++
		case 0x32: // if-eq vA, vB, +CCCC
			x, y := int(w0>>8&0xf), int(w0>>12&0xf)
			if in.sameValue(x, y) {
				pc += int(int16(in.insns[pc+1]))
			} else {
				pc += 2
			}
		case 0x33: // if-ne vA, vB, +CCCC
			x, y := int(w0>>8&0xf), int(w0>>12&0xf)
			if !in.sameValue(x, y) {
				pc += int(int16(in.insns[pc+1]))
			} else {
				pc += 2
			}
		case 0x38: // if-eqz vAA, +BBBB
			if in.isNull(int(w0 >> 8)) {
				pc += int(int16(in.insns[pc+1]))
			} else {
				pc += 2
			}
		case 0x39: // if-nez vAA, +BBBB
			if !in.isNull(int(w0 >> 8)) {
				pc += int(int16(in.insns[pc+1]))
			} else {
				pc += 2
			}
		case 0x22: // new-instance vAA, type@BBBB
			d, err := in.f.Type(uint32(in.insns[pc+1]))
			if err != nil {
				return nil, err
			}
			// java.lang.String 直接用可变对象建模：<init> 会就地填充内容，
			// 寄存器中的引用自始至终不变（这与 Dalvik 的真实语义一致）。
			if d == "Ljava/lang/String;" {
				in.setObj(w0>>8, &fakeStr{})
			} else {
				in.setObj(w0>>8, &fakeObj{desc: d})
			}
			pc += 2
		case 0x23: // new-array vA, vB, type@CCCC
			dst, sizeReg := int(w0>>8&0xf), int(w0>>12&0xf)
			n := in.regs[sizeReg]
			if n < 0 {
				return nil, errf("new-array 的长度为负 %d", n)
			}
			// 数组种类由 type@CCCC 决定：只有 [B 用字节数组建模，
			// 其余（如 Object[]、Method[]）都必须建成对象数组，
			// 否则后续的 aput-object/aget-object 会拿到错误的容器类型。
			ad, err := in.f.Type(uint32(in.insns[pc+1]))
			if err != nil {
				return nil, err
			}
			if ad == "[B" {
				in.setObjAt(dst, &fakeBytes{b: make([]byte, n)})
			} else {
				in.setObjAt(dst, &fakeArr{desc: ad, items: make([]any, n)})
			}
			pc += 2
		case 0x28: // goto +AA
			pc += int(int8(w0 >> 8))
		case 0x29: // goto/16 +AAAA
			pc += int(int16(in.insns[pc+1]))
		case 0x2a: // goto/32 +AAAAAAAA
			rel := int32(uint32(in.insns[pc+1]) | uint32(in.insns[pc+2])<<16)
			pc += int(rel)
		case 0x34: // if-lt vA, vB, +CCCC
			x, y := int(w0>>8&0xf), int(w0>>12&0xf)
			if in.regs[x] < in.regs[y] {
				pc += int(int16(in.insns[pc+1]))
			} else {
				pc += 2
			}
		case 0x35: // if-ge vA, vB, +CCCC
			x, y := int(w0>>8&0xf), int(w0>>12&0xf)
			if in.regs[x] >= in.regs[y] {
				pc += int(int16(in.insns[pc+1]))
			} else {
				pc += 2
			}
		case 0x36: // if-gt vA, vB, +CCCC
			x, y := int(w0>>8&0xf), int(w0>>12&0xf)
			if in.regs[x] > in.regs[y] {
				pc += int(int16(in.insns[pc+1]))
			} else {
				pc += 2
			}
		case 0x37: // if-le vA, vB, +CCCC
			x, y := int(w0>>8&0xf), int(w0>>12&0xf)
			if in.regs[x] <= in.regs[y] {
				pc += int(int16(in.insns[pc+1]))
			} else {
				pc += 2
			}
		case 0x4f: // aput-byte vAA, vBB, vCC（23x，2 字）
			v := in.regs[w0>>8]
			arrReg := int(in.insns[pc+1] & 0xff)
			idxReg := int(in.insns[pc+1] >> 8)
			arr, ok := in.objs[arrReg].(*fakeBytes)
			if !ok {
				return nil, errf("aput-byte 的操作数不是数组")
			}
			idx := in.regs[idxReg]
			if idx < 0 || int(idx) >= len(arr.b) {
				return nil, errf("aput-byte 下标越界 %d/%d", idx, len(arr.b))
			}
			arr.b[idx] = byte(v)
			pc += 2
		case 0x46: // aget-object vAA, vBB, vCC（23x，2 字）
			dst := int(w0 >> 8)
			arrReg := int(in.insns[pc+1] & 0xff)
			idxReg := int(in.insns[pc+1] >> 8)
			arr, ok := in.objs[arrReg].(*fakeArr)
			if !ok {
				return nil, errf("aget-object 的操作数不是对象数组")
			}
			idx := in.regs[idxReg]
			if idx < 0 || int(idx) >= len(arr.items) {
				return nil, errf("aget-object 下标越界 %d/%d", idx, len(arr.items))
			}
			in.setObjAt(dst, arr.items[idx])
			pc += 2
		case 0x48: // aget-byte vAA, vBB, vCC（23x，2 字）
			dst := int(w0 >> 8)
			arrReg := int(in.insns[pc+1] & 0xff)
			idxReg := int(in.insns[pc+1] >> 8)
			arr, ok := in.objs[arrReg].(*fakeBytes)
			if !ok {
				return nil, errf("aget-byte 的操作数不是 byte[]")
			}
			idx := in.regs[idxReg]
			if idx < 0 || int(idx) >= len(arr.b) {
				return nil, errf("aget-byte 下标越界 %d/%d", idx, len(arr.b))
			}
			in.setIntAt(dst, int32(int8(arr.b[idx])))
			pc += 2
		case 0x4d: // aput-object vAA, vBB, vCC（23x，2 字）
			v := in.objs[w0>>8]
			arrReg := int(in.insns[pc+1] & 0xff)
			idxReg := int(in.insns[pc+1] >> 8)
			arr, ok := in.objs[arrReg].(*fakeArr)
			if !ok {
				return nil, errf("aput-object 的操作数不是对象数组")
			}
			idx := in.regs[idxReg]
			if idx < 0 || int(idx) >= len(arr.items) {
				return nil, errf("aput-object 下标越界 %d/%d", idx, len(arr.items))
			}
			arr.items[idx] = v
			pc += 2
		case 0x52: // iget vA, vB, field@CCCC（读取 int 实例字段）
			dst, objReg := int(w0>>8&0xf), int(w0>>12&0xf)
			name, err := in.fieldName(uint32(in.insns[pc+1]))
			if err != nil {
				return nil, err
			}
			obj, ok := in.objs[objReg].(*fakeObj)
			if !ok {
				return nil, errf("iget 的接收者不是对象实例")
			}
			in.setIntAt(dst, obj.getField(name))
			pc += 2
		case 0x54: // iget-object vA, vB, field@CCCC（读取对象实例字段）
			dst, objReg := int(w0>>8&0xf), int(w0>>12&0xf)
			name, err := in.fieldName(uint32(in.insns[pc+1]))
			if err != nil {
				return nil, err
			}
			obj, ok := in.objs[objReg].(*fakeObj)
			if !ok {
				return nil, errf("iget-object 的接收者不是对象实例")
			}
			in.setObjAt(dst, obj.getObjField(name))
			pc += 2
		case 0x59: // iput vA, vB, field@CCCC（写入 int 实例字段）
			valReg, objReg := int(w0>>8&0xf), int(w0>>12&0xf)
			name, err := in.fieldName(uint32(in.insns[pc+1]))
			if err != nil {
				return nil, err
			}
			obj, ok := in.objs[objReg].(*fakeObj)
			if !ok {
				return nil, errf("iput 的接收者不是对象实例")
			}
			obj.setField(name, in.regs[valReg])
			pc += 2
		case 0x60: // sget vAA, field@BBBB（读取 int 静态字段）
			name, err := in.fieldName(uint32(in.insns[pc+1]))
			if err != nil {
				return nil, err
			}
			in.setInt(w0>>8, padStatics[name])
			pc += 2
		case 0x67: // sput vAA, field@BBBB（写入 int 静态字段）
			name, err := in.fieldName(uint32(in.insns[pc+1]))
			if err != nil {
				return nil, err
			}
			padStatics[name] = in.regs[w0>>8]
			pc += 2
		case 0x62: // sget-object vAA, field@BBBB（读取对象静态字段）
			name, err := in.fieldName(uint32(in.insns[pc+1]))
			if err != nil {
				return nil, err
			}
			in.setObj(w0>>8, objStatics[name])
			pc += 2
		case 0x69: // sput-object vAA, field@BBBB（写入对象静态字段）
			name, err := in.fieldName(uint32(in.insns[pc+1]))
			if err != nil {
				return nil, err
			}
			objStatics[name] = in.objs[w0>>8]
			pc += 2
		case 0x6e, 0x6f, 0x70, 0x71, 0x72: // invoke-virtual/super/direct/static/interface
			next, err := in.doInvoke(pc)
			if err != nil {
				return nil, err
			}
			pc = next
		case 0x77: // invoke-static/range {vCCCC..vNNNN}
			next, err := in.doInvokeRange(pc)
			if err != nil {
				return nil, err
			}
			pc = next
		case 0x8d: // int-to-byte vA, vB
			dst, src := int(w0>>8&0xf), int(w0>>12&0xf)
			in.setIntAt(dst, int32(int8(byte(in.regs[src]))))
			pc++
		case 0x90: // add-int vAA, vBB, vCC
			dst := int(w0 >> 8)
			x, y := int(in.insns[pc+1]&0xff), int(in.insns[pc+1]>>8)
			in.setIntAt(dst, in.regs[x]+in.regs[y])
			pc += 2
		case 0x91: // sub-int vAA, vBB, vCC
			dst := int(w0 >> 8)
			x, y := int(in.insns[pc+1]&0xff), int(in.insns[pc+1]>>8)
			in.setIntAt(dst, in.regs[x]-in.regs[y])
			pc += 2
		case 0x92: // mul-int
			dst := int(w0 >> 8)
			x, y := int(in.insns[pc+1]&0xff), int(in.insns[pc+1]>>8)
			in.setIntAt(dst, in.regs[x]*in.regs[y])
			pc += 2
		case 0x93: // div-int
			dst := int(w0 >> 8)
			x, y := int(in.insns[pc+1]&0xff), int(in.insns[pc+1]>>8)
			if in.regs[y] == 0 {
				return nil, errf("div-int 除数为零")
			}
			in.setIntAt(dst, in.regs[x]/in.regs[y])
			pc += 2
		case 0x94: // rem-int
			dst := int(w0 >> 8)
			x, y := int(in.insns[pc+1]&0xff), int(in.insns[pc+1]>>8)
			if in.regs[y] == 0 {
				return nil, errf("rem-int 除数为零")
			}
			in.setIntAt(dst, in.regs[x]%in.regs[y])
			pc += 2
		case 0x95: // and-int
			dst := int(w0 >> 8)
			x, y := int(in.insns[pc+1]&0xff), int(in.insns[pc+1]>>8)
			in.setIntAt(dst, in.regs[x]&in.regs[y])
			pc += 2
		case 0x98: // shl-int
			dst := int(w0 >> 8)
			x, y := int(in.insns[pc+1]&0xff), int(in.insns[pc+1]>>8)
			in.setIntAt(dst, in.regs[x]<<uint(in.regs[y]))
			pc += 2
		case 0x99: // shr-int
			dst := int(w0 >> 8)
			x, y := int(in.insns[pc+1]&0xff), int(in.insns[pc+1]>>8)
			in.setIntAt(dst, in.regs[x]>>uint(in.regs[y]))
			pc += 2
		case 0x9a: // ushr-int
			dst := int(w0 >> 8)
			x, y := int(in.insns[pc+1]&0xff), int(in.insns[pc+1]>>8)
			in.setIntAt(dst, int32(uint32(in.regs[x])>>uint(in.regs[y])))
			pc += 2
		case 0x7b: // neg-int vA, vB
			dst, src := int(w0>>8&0xf), int(w0>>12&0xf)
			in.setIntAt(dst, -in.regs[src])
			pc++
		case 0x7c: // not-int vA, vB
			dst, src := int(w0>>8&0xf), int(w0>>12&0xf)
			in.setIntAt(dst, ^in.regs[src])
			pc++
		case 0x20: // instance-of vA, vB, type@CCCC
			dst, src := int(w0>>8&0xf), int(w0>>12&0xf)
			d, err := in.f.Type(uint32(in.insns[pc+1]))
			if err != nil {
				return nil, err
			}
			// 只做「描述符是否匹配」的模拟：被检查对象若是本解释器建模的
			// fakeObj/fakeArr，就比较其 desc；其余一律为 false。
			ok := false
			switch o := in.objs[src].(type) {
			case *fakeObj:
				ok = o.desc == d
			case *fakeArr:
				ok = o.desc == d
			}
			if ok {
				in.setIntAt(dst, 1)
			} else {
				in.setIntAt(dst, 0)
			}
			pc += 2
		case 0x96: // or-int vAA, vBB, vCC
			dst := int(w0 >> 8)
			x, y := int(in.insns[pc+1]&0xff), int(in.insns[pc+1]>>8)
			in.setIntAt(dst, in.regs[x]|in.regs[y])
			pc += 2
		case 0x97: // xor-int vAA, vBB, vCC
			dst := int(w0 >> 8)
			x, y := int(in.insns[pc+1]&0xff), int(in.insns[pc+1]>>8)
			in.setIntAt(dst, in.regs[x]^in.regs[y])
			pc += 2
		case 0xd8: // add-int/lit8 vAA, vBB, #+CC
			dst, src := int(w0>>8), int(in.insns[pc+1]&0xff)
			in.setIntAt(dst, in.regs[src]+int32(int8(in.insns[pc+1]>>8)))
			pc += 2
		case 0xda: // mul-int/lit8
			dst, src := int(w0>>8), int(in.insns[pc+1]&0xff)
			in.setIntAt(dst, in.regs[src]*int32(int8(in.insns[pc+1]>>8)))
			pc += 2
		case 0xe0: // shl-int/lit8
			dst, src := int(w0>>8), int(in.insns[pc+1]&0xff)
			in.setIntAt(dst, in.regs[src]<<uint(int8(in.insns[pc+1]>>8)))
			pc += 2
		case 0xe1: // shr-int/lit8
			dst, src := int(w0>>8), int(in.insns[pc+1]&0xff)
			in.setIntAt(dst, in.regs[src]>>uint(int8(in.insns[pc+1]>>8)))
			pc += 2
		default:
			return nil, errf("解释器不支持的操作码 0x%02x @word %d", op, pc)
		}
	}
	return nil, errf("执行步数超出上限，可能存在死循环")
}

// doInvoke 处理 35c 形式的调用；返回值写入紧随其后的 move-result。
func (in *interp) doInvoke(pc int) (int, error) {
	w0 := in.insns[pc]
	nArgs := int(w0 >> 12)
	g := int(w0 >> 8 & 0xf)
	methodIdx := uint32(in.insns[pc+1])
	w2 := in.insns[pc+2]
	// 35c 的实参顺序是 C、D、E、F，第 5 个实参在 word0 的 G 字段里，
	// 因此 G 必须**排在最后**而不是最前——顺序错了会把第 5 个实参
	// 当成接收者，调用语义完全走样。
	slots := []int{int(w2 & 0xf), int(w2 >> 4 & 0xf), int(w2 >> 8 & 0xf), int(w2 >> 12 & 0xf)}
	n := nArgs
	if n > len(slots) {
		n = len(slots)
	}
	regs := append([]int(nil), slots[:n]...)
	if nArgs == 5 {
		regs = append(regs, g)
	}

	val, obj, err := in.call(methodIdx, regs)
	if err != nil {
		return 0, err
	}
	next := pc + 3
	// 紧随其后的 move-result / move-result-object 负责落值。
	if next < len(in.insns) {
		nop := byte(in.insns[next] & 0xff)
		if nop == 0x0a || nop == 0x0b || nop == 0x0c {
			dst := int(in.insns[next] >> 8)
			// 调用返回值可能是对象也可能是整数：只有拿到对象时才写对象堆，
			// 否则会把刚写入的整数值清掉。
			if obj != nil {
				in.setObjAt(dst, obj)
			} else {
				in.setIntAt(dst, val)
			}
			next++
		}
	}
	return next, nil
}

// doInvokeRange 处理 3rc 形式的调用。
func (in *interp) doInvokeRange(pc int) (int, error) {
	w0 := in.insns[pc]
	nArgs := int(w0 >> 8)
	first := int(in.insns[pc+2])
	methodIdx := uint32(in.insns[pc+1])
	regs := make([]int, nArgs)
	for i := range regs {
		regs[i] = first + i
	}
	val, obj, err := in.call(methodIdx, regs)
	if err != nil {
		return 0, err
	}
	next := pc + 3
	if next < len(in.insns) {
		nop := byte(in.insns[next] & 0xff)
		if nop == 0x0a || nop == 0x0b || nop == 0x0c {
			dst := int(in.insns[next] >> 8)
			// 调用返回值可能是对象也可能是整数：只有拿到对象时才写对象堆，
			// 否则会把刚写入的整数值清掉。
			if obj != nil {
				in.setObjAt(dst, obj)
			} else {
				in.setIntAt(dst, val)
			}
			next++
		}
	}
	return next, nil
}

// fieldName 返回字段的「类描述符->字段名」键，用于模拟字段存储。
func (in *interp) fieldName(idx uint32) (string, error) {
	cls, _, nameIdx, err := in.f.FieldRefAt(idx)
	if err != nil {
		return "", err
	}
	desc, err := in.f.Type(uint32(cls))
	if err != nil {
		return "", err
	}
	name, err := in.f.String(nameIdx)
	if err != nil {
		return "", err
	}
	return desc + "->" + name, nil
}

// call 按方法描述符分派到具体的模拟实现。
func (in *interp) call(methodIdx uint32, regs []int) (int32, any, error) {
	desc, err := in.f.MethodDesc(methodIdx)
	if err != nil {
		return 0, nil, err
	}
	in.calls = append(in.calls, desc)
	if debugCalls != nil {
		debugCalls = append(debugCalls, desc)
	}
	if h, ok := fakeCalls[desc]; ok {
		return h(in, regs)
	}

	switch desc {
	case "Ljava/lang/String;->length()I":
		s, ok := in.objs[regs[0]].(*fakeStr)
		if !ok {
			return 0, nil, errf("length 的接收者不是字符串")
		}
		// Java 的 String.length() 返回 UTF-16 码元数。
		// 解密方法的入参是纯 ASCII 十六进制串，因此它等于字节数的两倍。
		return int32(len(utf16Units(s.s))), nil, nil
	case "Ljava/lang/String;->charAt(I)C":
		s, ok := in.objs[regs[0]].(*fakeStr)
		if !ok {
			return 0, nil, errf("charAt 的接收者不是字符串")
		}
		units := utf16Units(s.s)
		i := in.regs[regs[1]]
		if i < 0 || int(i) >= len(units) {
			return 0, nil, errf("charAt 下标越界 %d/%d", i, len(units))
		}
		return int32(units[i]), nil, nil
	case "Ljava/lang/Character;->digit(CI)I":
		return int32(digitOf(rune(in.regs[regs[0]]), int(in.regs[regs[1]]))), nil, nil
	// A2 的解密器用 android.util.Base64.decode(s, flags) 解码密文
	case "Landroid/util/Base64;->decode(Ljava/lang/String;I)[B":
		sv, ok := in.objs[regs[0]].(*fakeStr)
		if !ok {
			return 0, nil, errf("Base64.decode 的第一个参数不是 String")
		}
		raw, err := base64.StdEncoding.DecodeString(sv.s)
		if err != nil {
			return 0, nil, errf("Base64.decode 失败: %v", err)
		}
		return 0, &fakeBytes{b: raw}, nil
	// A2 的解密器用 MessageDigest/SHA-256 派生密钥流（见 fakeMD 的说明）。
	case "Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;":
		alg, ok := in.objs[regs[0]].(*fakeStr)
		if !ok {
			return 0, nil, errf("MessageDigest.getInstance 的实参不是字符串")
		}
		if alg.s != "SHA-256" {
			return 0, nil, errf("MessageDigest.getInstance 只模拟 SHA-256，收到 %q", alg.s)
		}
		return 0, &fakeMD{}, nil
	case "Ljava/security/MessageDigest;->digest([B)[B":
		if _, ok := in.objs[regs[0]].(*fakeMD); !ok {
			return 0, nil, errf("MessageDigest.digest 的接收者不是 MessageDigest")
		}
		arr, ok := in.objs[regs[1]].(*fakeBytes)
		if !ok {
			return 0, nil, errf("MessageDigest.digest 的实参不是 byte[]")
		}
		sum := sha256.Sum256(arr.b)
		return 0, &fakeBytes{b: sum[:]}, nil
	case "Ljava/lang/String;-><init>([BLjava/lang/String;)V":
		arr, ok := in.objs[regs[1]].(*fakeBytes)
		if !ok {
			return 0, nil, errf("String.<init> 的第一个参数不是 byte[]")
		}
		enc, ok := in.objs[regs[2]].(*fakeStr)
		if !ok || enc.s != "UTF-8" {
			return 0, nil, errf("String.<init> 的字符集必须是 UTF-8")
		}
		if !utf8.Valid(arr.b) {
			return 0, nil, errf("String.<init> 收到非法 UTF-8 字节序列: % x", arr.b)
		}
		obj, ok := in.objs[regs[0]].(*fakeStr)
		if !ok {
			return 0, nil, errf("String.<init> 的接收者不是 new-instance 创建的字符串")
		}
		obj.s = string(arr.b) // 就地初始化，寄存器中的引用不变
		return 0, nil, nil
	case "Ljava/lang/Object;-><init>()V":
		// A13 注入类的构造器会调用它；此处无需任何状态变更。
		return 0, nil, nil

	case "Ljava/lang/String;->equals(Ljava/lang/Object;)Z":
		a, ok := in.objs[regs[0]].(*fakeStr)
		if !ok {
			return 0, nil, errf("String.equals 的接收者不是字符串")
		}
		b, ok := in.objs[regs[1]].(*fakeStr)
		if !ok {
			return 0, nil, errf("String.equals 的实参不是字符串")
		}
		if a.s == b.s {
			return 1, nil, nil
		}
		return 0, nil, nil

	// ---- 壳 Application 的反射委托逻辑所需的模拟实现 ----

	case "Landroid/app/Application;-><init>()V", "Landroid/app/Application;->attachBaseContext(Landroid/content/Context;)V":
		// 模拟父类实现：无需状态变更。
		return 0, nil, nil
	case "Landroid/app/Application;->onCreate()V":
		// 记录父类 onCreate 被调用，供测试断言「先 super 后委托」。
		obj, _ := in.objs[regs[0]].(*fakeObj)
		if obj != nil {
			obj.setField("$onCreate", obj.getField("$onCreate")+1)
		}
		return 0, nil, nil

	case "Ljava/lang/Class;->getName()Ljava/lang/String;":
		// 崩溃处理器靠它把异常类型名显示出来（Class.getName 在模拟类里
		// 就是注册时的点分名）。
		c, ok := in.objs[regs[0]].(*fakeCls)
		if !ok {
			return 0, nil, errf("Class.getName 的接收者不是 Class")
		}
		return 0, &fakeStr{s: c.name}, nil

	case "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;":
		s, ok := in.objs[regs[0]].(*fakeStr)
		if !ok {
			return 0, nil, errf("Class.forName 的实参不是字符串")
		}
		c, ok := fakeClasses[s.s]
		if !ok {
			return 0, nil, errf("Class.forName(%q)：模拟环境未注册该类", s.s)
		}
		return 0, c, nil
	case "Ljava/lang/Class;->forName(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;":
		// 壳委托原 Application 时用的是带显式 ClassLoader 的重载：
		// 原类位于解密后的 DEX 里，只有接管后的加载器才看得见它。
		s, ok := in.objs[regs[0]].(*fakeStr)
		if !ok {
			return 0, nil, errf("Class.forName 的实参不是字符串")
		}
		if in.objs[regs[2]] == nil {
			return 0, nil, errf("Class.forName(%q) 的 ClassLoader 为 null", s.s)
		}
		c, ok := fakeClasses[s.s]
		if !ok {
			return 0, nil, errf("Class.forName(%q)：模拟环境未注册该类", s.s)
		}
		return 0, c, nil
	case "Ljava/lang/Class;->newInstance()Ljava/lang/Object;":
		c, ok := in.objs[regs[0]].(*fakeCls)
		if !ok {
			return 0, nil, errf("Class.newInstance 的接收者不是 Class")
		}
		return 0, &fakeObj{desc: "L" + strings.ReplaceAll(c.name, ".", "/") + ";"}, nil
	case "Ljava/lang/Class;->getDeclaredMethods()[Ljava/lang/reflect/Method;":
		c, ok := in.objs[regs[0]].(*fakeCls)
		if !ok {
			return 0, nil, errf("Class.getDeclaredMethods 的接收者不是 Class")
		}
		items := make([]any, len(c.mths))
		for i, m := range c.mths {
			items[i] = m
		}
		return 0, &fakeArr{desc: descMethodArr, items: items}, nil
	case "Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;":
		c, ok := in.objs[regs[0]].(*fakeCls)
		if !ok {
			return 0, nil, errf("Class.getSuperclass 的接收者不是 Class")
		}
		sup := c.getSuperclass()
		if sup == nil {
			return 0, nil, nil
		}
		return 0, sup, nil
	case "Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;":
		// 未启用 B3 时壳退化为使用自身加载器；此处只需返回一个非空对象。
		return 0, &fakeObj{desc: "Ljava/lang/ClassLoader;"}, nil

	case "Ljava/lang/reflect/Method;->getName()Ljava/lang/String;":
		m, ok := in.objs[regs[0]].(*fakeMth)
		if !ok {
			return 0, nil, errf("Method.getName 的接收者不是 Method")
		}
		return 0, &fakeStr{s: m.name}, nil
	case "Ljava/lang/reflect/Method;->getParameterTypes()[Ljava/lang/Class;":
		m, ok := in.objs[regs[0]].(*fakeMth)
		if !ok {
			return 0, nil, errf("Method.getParameterTypes 的接收者不是 Method")
		}
		items := make([]any, len(m.params))
		for i, p := range m.params {
			items[i] = p
		}
		return 0, &fakeArr{desc: descClassArr, items: items}, nil
	case "Ljava/lang/reflect/Method;->setAccessible(Z)V":
		m, ok := in.objs[regs[0]].(*fakeMth)
		if !ok {
			return 0, nil, errf("Method.setAccessible 的接收者不是 Method")
		}
		m.accessed = in.regs[regs[1]] != 0
		return 0, nil, nil
	case "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;":
		m, ok := in.objs[regs[0]].(*fakeMth)
		if !ok {
			return 0, nil, errf("Method.invoke 的接收者不是 Method")
		}
		if !m.accessed {
			return 0, nil, errf("Method.invoke 前未调用 setAccessible(true)")
		}
		args, ok := in.objs[regs[2]].(*fakeArr)
		if !ok {
			return 0, nil, errf("Method.invoke 的实参数组类型不对")
		}
		m.invoked = append(m.invoked, args.items...)
		if m.retSet {
			return 0, m.ret, nil
		}
		target, _ := in.objs[regs[1]].(*fakeObj)
		if target != nil {
			target.setField("$attach", target.getField("$attach")+1)
		}
		return 0, nil, nil
	}
	// 被测 DEX 自身的注入方法：进入其方法体执行。
	if off, ok := fakeCode[desc]; ok {
		return in.execNested(desc, off, regs)
	}
	return 0, nil, errf("解释器未实现的方法调用 %s", desc)
}

// execNested 进入被测 DEX 中某个方法的方法体执行（用于壳类内部的方法调用）。
func (in *interp) execNested(desc string, codeOff uint32, regs []int) (int32, any, error) {
	ci, err := in.f.ParseCodeItem(codeOff)
	if err != nil {
		// 带上方法描述符与 code_off：偏移为 0 基本说明调到了没有方法体的
		// native/abstract 方法，或 fakeCode 登记了错的偏移。
		return 0, nil, errf("%s (code_off=%d): %v", desc, codeOff, err)
	}
	if len(regs) != int(ci.Ins) {
		return 0, nil, errf("%s 的实参个数应为 %d，实际 %d", desc, ci.Ins, len(regs))
	}
	sub := newInterp(in.f, ci)
	for i, r := range regs {
		// 寄存器要么持有对象（objs），要么持有 int（regs），必须按实际持有者取值：
		// 只看 objs 会把所有 int 实参当成 null 传入，形参恒为 0。
		var v any
		if in.objs[r] != nil {
			v = in.objs[r]
		} else {
			v = in.regs[r]
		}
		if err := sub.setArg(i, int(ci.Ins), v); err != nil {
			return 0, nil, err
		}
	}
	v, err := sub.Run()
	if err != nil {
		return 0, nil, err
	}
	switch x := v.(type) {
	case int32:
		return x, nil, nil
	case *fakeObj:
		return 0, x, nil
	case *fakeStr:
		return 0, x, nil
	case *fakeBytes:
		return 0, x, nil
	case *fakeArr:
		return 0, x, nil
	case nil:
		return 0, nil, nil
	}
	return 0, nil, errf("%s 返回了不支持的类型 %T", desc, v)
}

// ---- 便捷入口 ----

// runDecryptor 执行指定偏移处的解密方法，返回其字符串结果。
//
// 会先校验方法签名确实为 (Ljava/lang/String;)Ljava/lang/String;，
// 避免误把其它方法当解密器执行。
func runDecryptor(f *File, methodIdx uint32, codeOff uint32, input string) (string, error) {
	desc, err := f.MethodDesc(methodIdx)
	if err != nil {
		return "", err
	}
	const want = "(Ljava/lang/String;)Ljava/lang/String;"
	if len(desc) < len(want) || desc[len(desc)-len(want):] != want {
		return "", errf("解密方法签名不符: %s", desc)
	}
	ci, err := f.ParseCodeItem(codeOff)
	if err != nil {
		return "", err
	}
	if ci.Ins != 1 {
		return "", errf("解密方法的入参个数应为 1，实际 %d", ci.Ins)
	}
	in := newInterp(f, ci)
	if err := in.setArg(0, int(ci.Ins), &fakeStr{s: input}); err != nil {
		return "", err
	}
	v, err := in.Run()
	if err != nil {
		return "", err
	}
	s, ok := v.(*fakeStr)
	if !ok {
		return "", errf("解密方法未返回字符串，实际 %T", v)
	}
	return s.s, nil
}

// runArrayHelper 执行指定偏移处的常量还原方法，返回其字符串结果。
//
// 校验方法签名确实为 ([B)Ljava/lang/String;，避免误执行其它方法。
func runArrayHelper(f *File, methodIdx uint32, codeOff uint32, input []byte) (string, error) {
	desc, err := f.MethodDesc(methodIdx)
	if err != nil {
		return "", err
	}
	const want = "([B)Ljava/lang/String;"
	if len(desc) < len(want) || desc[len(desc)-len(want):] != want {
		return "", errf("还原方法签名不符: %s", desc)
	}
	ci, err := f.ParseCodeItem(codeOff)
	if err != nil {
		return "", err
	}
	if ci.Ins != 1 {
		return "", errf("还原方法的入参个数应为 1，实际 %d", ci.Ins)
	}
	in := newInterp(f, ci)
	if err := in.setArg(0, int(ci.Ins), &fakeBytes{b: append([]byte(nil), input...)}); err != nil {
		return "", err
	}
	v, err := in.Run()
	if err != nil {
		return "", err
	}
	s, ok := v.(*fakeStr)
	if !ok {
		return "", errf("还原方法未返回字符串，实际 %T", v)
	}
	return s.s, nil
}

// runPadMethod 执行 A13 注入类的一个方法，返回其执行结果。
//
// 入参按顺序填入寄存器：实例方法需把 this 放在最前（args[0] 传对象），
// 静态方法直接传实参。返回值为 return/return-object 的结果。
func runPadMethod(f *File, methodIdx uint32, codeOff uint32, args ...any) (any, error) {
	ci, err := f.ParseCodeItem(codeOff)
	if err != nil {
		return nil, err
	}
	if int(ci.Ins) != len(args) {
		return nil, errf("方法入参个数不符：声明 %d，调用 %d", ci.Ins, len(args))
	}
	in := newInterp(f, ci)
	for i, a := range args {
		if err := in.setArg(i, int(ci.Ins), a); err != nil {
			return nil, err
		}
	}
	return in.Run()
}

// digitOf 模拟 Character.digit(char, radix)。
func digitOf(c rune, radix int) int {
	if radix < 2 || radix > 36 {
		return -1
	}
	var v int
	switch {
	case c >= '0' && c <= '9':
		v = int(c - '0')
	case c >= 'a' && c <= 'z':
		v = int(c-'a') + 10
	case c >= 'A' && c <= 'Z':
		v = int(c-'A') + 10
	default:
		return -1
	}
	if v >= radix {
		return -1
	}
	return v
}
