package dex

import "sort"

// 本文件实现 A7「反射成员名强制加密」的**只读扫描端**：找出「被直接作为反射
// 成员名参数传给 Class.getMethod/getDeclaredMethod/getField/getDeclaredField」
// 的字符串常量。A7 本身不改写任何 DEX，扫描结果由 Pass 层登记进
// Artifact.Shared，再由 A2（字符串加密）无条件加密（不受 ObfStringMin 限制）。
//
// 为什么需要它：反射成员名往往很短（"get"、"put"、"a"、"isTagEnabled"），
// A2 的最短长度门槛会把它们留在明文——静态分析者只要 grep 这些名字就能
// 还原被反射调用的目标。参考样本正是对这批名字做了字符串加密。
//
// 判据刻意保守（宁少勿错）：
//   - 只认 4 个「第一个参数就是成员名」的方法引用（方法引用判定走 method_ids，
//     见 MethodRefAt/MethodFull）；
//   - 类名入口（Class.forName / ClassLoader.loadClass）一律不算：参考样本里
//     类名本身是明文，只有成员名被加密；
//   - 字符串还必须符合成员名的常见形态（1..64 字节可打印 ASCII、不含 / 与空白）。
//
// 寄存器追踪只做**局部线性**近似：const-string 写入寄存器后，move* 会传播，
// 其余已知会写寄存器的指令会清除记录。漏报的代价只是少加密一个串（还有 A2
// 的最短长度兜底），误报才会白增体积，因此实现取「宁可漏、不可错」。

// ReflectionNames 扫描 DEX 中「被用作反射成员名参数」的字符串集合。
//
// 返回的 map 以明文字符串为键；同一字符串在多个 DEX/多个调用点出现只记一次。
// 解析失败的方法体（畸形 code_item）会被跳过而不是让整次扫描失败——扫描是
// 加固流程中的「加分项」，不应把原本可加固的 APK 挡在门外。
func ReflectionNames(f *File) (map[string]bool, error) {
	out := map[string]bool{}
	cache := map[uint32]string{}
	err := f.walkAllCode(func(codeOff uint32) error {
		ci, err := f.ParseCodeItem(codeOff)
		if err != nil {
			return nil // 畸形方法体：跳过，不影响其余方法
		}
		l, err := ParseInsns(ci.Insns)
		if err != nil {
			return nil
		}
		// cur 记录「寄存器 -> 当前可能持有的字符串索引集合」。
		cur := map[int]map[uint32]bool{}
		for i := 0; i < l.ItemCount(); i++ {
			if !l.ItemIsInsn(i) {
				continue
			}
			w := l.ItemWords(i)
			if len(w) == 0 {
				continue
			}
			op := byte(w[0] & 0xff)
			switch {
			case op == 0x1a: // const-string vAA, string@BBBB
				cur[int(w[0]>>8)] = stringSet(uint32(w[1]))
			case op == 0x1b: // const-string/jumbo vAA, string@BBBBBBBB
				cur[int(w[0]>>8)] = stringSet(uint32(w[1]) | uint32(w[2])<<16)
			case op >= 0x01 && op <= 0x09: // move / move-wide / move-object
				dst, src, ok := moveRegs(op, w)
				if !ok {
					continue
				}
				if v, ok := cur[src]; ok {
					cur[dst] = v
				} else {
					delete(cur, dst)
				}
			case (op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78):
				if !reflectionMemberAPI(f, cache, uint32(w[1])) {
					continue
				}
				regs, ok := invokeRegs(op, w)
				if !ok {
					continue
				}
				// 成员名是第一个**形参**：实例方法（非 invoke-static）的
				// 实参列表第一个是接收者，名字在 regs[1]；invoke-static 没有
				// 接收者，名字在 regs[0]。
				pos := 1
				if op == 0x71 {
					pos = 0
				}
				if pos >= len(regs) {
					continue
				}
				for idx := range cur[regs[pos]] {
					s, err := f.String(idx)
					if err != nil || !reflectionNameShape(s) {
						continue
					}
					out[s] = true
				}
			default:
				for _, r := range reflectWrittenRegs(op, w) {
					delete(cur, r)
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ReflectionNamesOf 是 ReflectionNames 的字节入口：解析失败时返回错误。
//
// 供不持有 *File 的调用方（如测试或未来的 Pass 变体）使用；主流程走
// ReflectionNames，避免重复解析。
func ReflectionNamesOf(data []byte) (map[string]bool, error) {
	f, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return ReflectionNames(f)
}

// reflectionNameAPIs 是「第一个形参是成员名」的反射入口方法集合。
//
// 刻意不包含：
//   - Ljava/lang/Class;->forName / Ljava/lang/ClassLoader;->loadClass（类名，样本明文）；
//   - Ljava/lang/Class;->getDeclaredConstructor（无名字参数）；
//   - Ljava/lang/Class;->getDeclaredClasses / getFields / getMethods（无参数）；
//   - Ljava/lang/reflect/Method;->invoke（参数不是名字）。
var reflectionNameAPIs = map[string]bool{
	"Ljava/lang/Class;->getMethod":         true,
	"Ljava/lang/Class;->getDeclaredMethod": true,
	"Ljava/lang/Class;->getField":          true,
	"Ljava/lang/Class;->getDeclaredField":  true,
}

// reflectionMemberAPI 判断 method_ids 第 idx 项是否为上述入口之一。
//
// 键形如 "Ljava/lang/Class;->getMethod"，与 ClassInfos/MethodFull 的表示一致；
// 结果按 method 索引缓存，避免同一方法被反复查表。
func reflectionMemberAPI(f *File, cache map[uint32]string, idx uint32) bool {
	key, ok := cache[idx]
	if !ok {
		k, err := f.MethodDesc(idx)
		if err != nil {
			// 查不到的方法引用不可能匹配；缓存空串避免反复报错。
			cache[idx] = ""
			return false
		}
		key = classAndName(k)
		cache[idx] = key
	}
	return reflectionNameAPIs[key]
}

// classAndName 从完整方法描述 "Lcls;->name(proto)ret" 中截出 "Lcls;->name"。
func classAndName(desc string) string {
	arrow := -1
	for i := 0; i+1 < len(desc); i++ {
		if desc[i] == '-' && desc[i+1] == '>' {
			arrow = i
			break
		}
	}
	if arrow < 0 {
		return desc
	}
	paren := len(desc)
	for i := arrow + 2; i < len(desc); i++ {
		if desc[i] == '(' {
			paren = i
			break
		}
	}
	return desc[:paren]
}

// reflectionNameShape 判断字符串是否符合成员名的常见形态。
//
// 这不是严格语法校验，只用来压掉明显的误伤：成员名不含路径分隔符与空白，
// 长度不超过 64。参考样本里的成员名（addFontFromAssetManager、isTagEnabled、
// a、get）全部通过；样本里另一类"Found content provider "带空格，本就不该
// 被当成成员名加密。
func reflectionNameShape(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			return false
		}
		if c == '/' || c == ' ' || c == '\\' {
			return false
		}
	}
	return true
}

// stringSet 构造只有一个元素的集合。
func stringSet(idx uint32) map[uint32]bool { return map[uint32]bool{idx: true} }

// moveRegs 解析 move / move-wide / move-object 的源与目标寄存器。
func moveRegs(op byte, w []uint16) (dst, src int, ok bool) {
	switch op {
	case 0x01, 0x04, 0x07: // 12x
		return int(w[0] >> 8 & 0xf), int(w[0] >> 12 & 0xf), true
	case 0x02, 0x05, 0x08: // 22x
		return int(w[0] >> 8), int(w[1]), true
	case 0x03, 0x06, 0x09: // 32x：word1=目标 AAAA，word2=源 BBBB
		return int(w[1]), int(w[2]), true
	}
	return 0, 0, false
}

// invokeRegs 解析 invoke 指令的实参寄存器列表（35c 与 3rc 两种格式）。
func invokeRegs(op byte, w []uint16) ([]int, bool) {
	switch {
	case op >= 0x6e && op <= 0x72: // 35c：布局 A|G|op，A 是实参个数（1..5），C..G 是寄存器
		n := int(w[0] >> 12 & 0xf)
		if n < 1 || n > 5 {
			return nil, false
		}
		all := []int{
			int(w[2] & 0xf),
			int(w[2] >> 4 & 0xf),
			int(w[2] >> 8 & 0xf),
			int(w[2] >> 12 & 0xf),
			int(w[0] >> 8 & 0xf),
		}
		return all[:n], true
	case op >= 0x74 && op <= 0x78: // 3rc：A 是寄存器个数，C 是首个寄存器
		n := int(w[0] >> 8)
		if n < 1 {
			return nil, false
		}
		out := make([]int, n)
		first := int(w[2])
		for i := range out {
			out[i] = first + i
		}
		return out, true
	}
	return nil, false
}

// reflectWrittenRegs 返回一条指令写入的目标寄存器（仅用于清除字符串追踪）。
//
// 只覆盖「可能写对象引用」的常见操作码；未列出的操作码视为不写寄存器——
// 对合法字节码这是成立的（非法组合不可能通过校验），且漏清除只会让追踪
// 更久，从而**偏向多报**。为控制误报，凡本表列出的写操作都清除对应寄存器。
func reflectWrittenRegs(op byte, w []uint16) []int {
	if len(w) == 0 {
		return nil
	}
	a4 := int(w[0] >> 8 & 0xf)
	aa := int(w[0] >> 8)
	switch {
	case op >= 0x0a && op <= 0x0d: // move-result* / move-exception
		return []int{aa}
	case op == 0x12: // const/4
		return []int{a4}
	case op >= 0x13 && op <= 0x19: // const/16, const, const/high16, const-wide*
		return []int{aa}
	case op == 0x1c, op == 0x22: // const-class / new-instance
		return []int{aa}
	case op == 0x20, op == 0x23, op == 0x21: // instance-of / new-array / array-length
		return []int{a4}
	case op >= 0x44 && op <= 0x4a: // aget*
		return []int{aa}
	case op >= 0x52 && op <= 0x58: // iget*
		return []int{a4}
	case op >= 0x60 && op <= 0x66: // sget*
		return []int{aa}
	case op >= 0x2d && op <= 0x31: // cmp*
		return []int{aa}
	case op >= 0x7b && op <= 0x8f: // 一元运算（12x）
		return []int{a4}
	case op >= 0x90 && op <= 0xaf: // 二元运算（23x）
		return []int{aa}
	case op >= 0xb0 && op <= 0xcf: // 二元运算 /2addr（12x）
		return []int{a4}
	case op >= 0xd0 && op <= 0xd7: // lit16（22s）
		return []int{aa}
	case op >= 0xd8 && op <= 0xe2: // lit8（22b）
		return []int{aa}
	case op == 0xfe || op == 0xff: // const-method-handle / const-method-type
		return []int{aa}
	}
	return nil
}

// SortedReflectionNames 返回扫描结果的有序切片（便于确定性日志与测试）。
func SortedReflectionNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
