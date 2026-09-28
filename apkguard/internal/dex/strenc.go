package dex

import (
	"fmt"
	"sort"
)

// StringEncrypt 描述 A2 字符串加密的参数。
//
// 加密方案：把字符串的 UTF-8 字节与「密钥 + 下标派生」的密钥流逐字节异或，
// 再编码为十六进制字符串存入字符串池。运行时由注入的解密方法还原。
//
// 之所以用十六进制而不是直接存密文：DEX 的字符串池是 MUTF-8 编码的
// UTF-16 序列，任意异或结果可能产生孤立代理码元，而 Go 的 string
// 无法表示孤立代理；十六进制只用到 0-9a-f，天然安全。
type StringEncrypt struct {
	// Class 是解密器类描述符，形如 "Lapkguard/Dec;"。
	Class string
	// MethodName 是解密方法名，签名固定为 (Ljava/lang/String;)Ljava/lang/String;。
	MethodName string
	// Key 是主密钥字节。
	Key byte
	// MinLen 是参与加密的最短字符串长度（按 UTF-8 字节计）。
	MinLen int
	// InjectClass 为 true 时把解密器类本体写入本 DEX。
	//
	// 多 DEX 场景下只能有一个 DEX 落地该类（否则运行时类重复定义），
	// 其余 DEX 置 false：只登记类型/方法引用，不生成 class_def。
	InjectClass bool
	// Skip 返回 true 表示该字符串不参与加密；可为 nil。
	Skip func(s string) bool
}

// stringEncryptPlan 是加密方案的最终形态（池索引已解析）。
type stringEncryptPlan struct {
	spec StringEncrypt
	// cipher 记录「明文 -> 密文」，用于改写 const-string 指令。
	cipher map[string]string
	// replace 记录「明文 -> 密文」中需要把池内条目整体替换的那些：
	// 仅被 const-string 引用的字符串可以整体替换，从而把明文彻底移出池。
	replace map[string]string
	// decrypt 是解密方法的引用。
	decrypt MethodSpec
	// methodIdx 是解密方法在 method_ids 中的最终索引。
	methodIdx uint32
}

// keyStream 返回第 i 个字节的密钥流字节。
func keyStream(key byte, i int) byte { return key + byte(i*17) }

// encryptString 把明文字符串加密为十六进制密文。
func encryptString(s string, key byte) string {
	b := []byte(s)
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		v := c ^ keyStream(key, i)
		out[2*i] = digits[v>>4]
		out[2*i+1] = digits[v&0xf]
	}
	return string(out)
}

// collectConstStrings 返回全部被 const-string 指令引用的旧字符串索引（升序去重），
// 以及「存在无法改写引用」的字符串集合。
//
// 所谓「无法改写」：某条 const-string 恰好位于 try 区间端点所在字的内部。
// 这类字符串的明文必须留在池中，否则无法改写的那些指令会读到密文。
func collectConstStrings(f *File) (idxs []uint32, blocked map[uint32]bool, err error) {
	seen := map[uint32]bool{}
	blocked = map[uint32]bool{}
	err = f.walkAllCode(func(codeOff uint32) error {
		ci, err := f.ParseCodeItem(codeOff)
		if err != nil {
			return err
		}
		boundary := map[int]bool{}
		for _, t := range ci.Tries {
			s := int(t.StartAddr)
			boundary[s] = true
			boundary[s+int(t.InsnCount)] = true
		}
		return walkInsns(ci.Insns, func(op byte, pos int, w []uint16) error {
			if op != 0x1a && op != 0x1b {
				return nil
			}
			var idx uint32
			if op == 0x1a {
				idx = uint32(w[pos+1])
			} else {
				idx = uint32(w[pos+1]) | uint32(w[pos+2])<<16
			}
			seen[idx] = true
			if boundary[pos+1] || (op == 0x1b && boundary[pos+2]) {
				blocked[idx] = true
			}
			return nil
		})
	})
	if err != nil {
		return nil, nil, err
	}
	for i := range seen {
		idxs = append(idxs, i)
	}
	sort.Slice(idxs, func(a, b int) bool { return idxs[a] < idxs[b] })
	return idxs, blocked, nil
}

// planStringEncrypt 在池构建前确定加密集合。
//
// 返回的 replace 用于「把池内明文整体替换为密文」，cipher 用于改写指令。
func planStringEncrypt(f *File, se *StringEncrypt, values []string) (cipher, replace map[string]string, err error) {
	cipher = map[string]string{}
	replace = map[string]string{}

	usage, err := f.StringUsage()
	if err != nil {
		return nil, nil, err
	}
	idxs, blocked, err := collectConstStrings(f)
	if err != nil {
		return nil, nil, err
	}
	// 仅被 const-string 使用的字符串：可以从池中彻底移除明文。
	// 其余（类型名、方法名、字段名、注解、源文件名、调试信息、原型 shorty）
	// 必须保留明文，否则 type_ids / proto_ids / debug_info 等会指向密文而损坏。
	//
	// shorty 尤其危险：它不被任何指令引用，只看「是否被 const-string 使用」
	// 会误判为可整体替换；而 ART 要求它只含 VZBSCIJFD/L，加密后直接拒收整个 DEX。
	constOnly := func(idx uint32) bool {
		return !usage.Type[idx] && !usage.MethodName[idx] && !usage.FieldName[idx] &&
			!usage.Anno[idx] && !usage.SourceFile[idx] && !usage.Debug[idx] &&
			!usage.Shorty[idx]
	}
	for _, i := range idxs {
		s := values[i]
		if len(s) < se.MinLen {
			continue
		}
		if se.Skip != nil && se.Skip(s) {
			continue
		}
		if _, ok := cipher[s]; ok {
			continue
		}
		ct := encryptString(s, se.Key)
		cipher[s] = ct
		if constOnly(i) && !blocked[i] {
			replace[s] = ct
		}
	}
	return cipher, replace, nil
}

// stringDecryptorAddition 构造注入解密器所需的全部索引表条目与类定义。
//
// 当 se.InjectClass 为 false 时只登记类型/原型/方法引用（供 invoke 指令使用），
// 不生成 class_def —— 用于多 DEX 场景下「非主 DEX 引用主 DEX 的解密器」。
func stringDecryptorAddition(se *StringEncrypt) (Addition, error) {
	protoStr := ProtoSpec{Ret: "Ljava/lang/String;", Params: []string{"Ljava/lang/String;"}}
	protoCharI := ProtoSpec{Ret: "C", Params: []string{"I"}}
	protoInt := ProtoSpec{Ret: "I"}
	protoDigit := ProtoSpec{Ret: "I", Params: []string{"C", "I"}}
	protoInit := ProtoSpec{Ret: "V", Params: []string{"[B", "Ljava/lang/String;"}}

	charAt := MethodSpec{Class: "Ljava/lang/String;", Name: "charAt", Proto: protoCharI}
	length := MethodSpec{Class: "Ljava/lang/String;", Name: "length", Proto: protoInt}
	digit := MethodSpec{Class: "Ljava/lang/Character;", Name: "digit", Proto: protoDigit}
	strInit := MethodSpec{Class: "Ljava/lang/String;", Name: "<init>", Proto: protoInit}
	decrypt := MethodSpec{Class: se.Class, Name: se.MethodName, Proto: protoStr}

	add := Addition{
		Types: []string{
			se.Class, "[B", "C", "I", "V",
			"Ljava/lang/String;", "Ljava/lang/Character;",
		},
		Protos:  []ProtoSpec{protoStr, protoCharI, protoInt, protoDigit, protoInit},
		Methods: []MethodSpec{decrypt, charAt, length, digit, strInit},
	}
	if !se.InjectClass {
		return add, nil
	}

	code, err := stringDecryptorCode(se.Key, charAt, length, digit, strInit)
	if err != nil {
		return Addition{}, err
	}
	add.Classes = []ClassSpec{{
		Name:  se.Class,
		Super: "Ljava/lang/Object;",
		// 类级标志只能是「类能用的那些位」：STATIC 是**成员**标志，
		// 写在 class_def 上属于非法组合（真实工具链产出的 DEX 里
		// 五万多个类没有一个这么写）。纯静态工具类用 PUBLIC | FINAL。
		Access: accPublic | accFinal, // 纯静态工具类
		Methods: []ClassMethod{{
			Name:   se.MethodName,
			Proto:  protoStr,
			Access: accPublic | accStatic,
			Code:   code,
		}},
	}}
	return add, nil
}

// stringDecryptorCode 生成解密方法的字节码。
//
// 等价 Java 源码：
//
//	static String a(String s) {
//	    int n = s.length() >> 1;
//	    byte[] b = new byte[n];
//	    for (int i = 0; i < n; i++) {
//	        int hi = Character.digit(s.charAt(i << 1), 16);
//	        int lo = Character.digit(s.charAt(i << 1 | 1), 16);
//	        b[i] = (byte) (((hi << 4) | lo) ^ (KEY + i * 17));
//	    }
//	    return new String(b, "UTF-8");
//	}
//
// 寄存器分配（共 8 个）。注意 Dalvik 的入参寄存器固定在**最高**编号处：
// registers=8、ins=1 时，唯一入参 s 落在 v7，局部变量只能用 v0~v6。
//
//	v0 = n    v1 = b    v2 = i    v3 = hi    v4 = lo    v5 = 临时    v6 = 常量 16
//	v7 = s（入参）
func stringDecryptorCode(key byte, charAt, length, digit, strInit MethodSpec) (*CodeBlob, error) {
	const (
		rN   = 0
		rB   = 1
		rI   = 2
		rHi  = 3
		rLo  = 4
		rTmp = 5
		rC16 = 6
		rS   = 7
	)
	a := NewAsm()

	if err := a.InvokeVirtual([]int{rS}, length); err != nil {
		return nil, err
	}
	a.MoveResult(rN)
	a.ShrIntLit8(rN, 1) // n = s.length() >> 1
	if err := a.NewArray(rB, rN, "[B"); err != nil {
		return nil, err
	}
	a.Const4(rI, 0)
	a.Const16(rC16, 16)

	a.Label("loop")
	if err := a.IfGe(rI, rN, "end"); err != nil {
		return nil, err
	}
	// hi = Character.digit(s.charAt(i << 1), 16)
	a.Move(rTmp, rI)
	a.ShlIntLit8(rTmp, 1)
	if err := a.InvokeVirtual([]int{rS, rTmp}, charAt); err != nil {
		return nil, err
	}
	a.MoveResult(rHi)
	if err := a.InvokeStatic([]int{rHi, rC16}, digit); err != nil {
		return nil, err
	}
	a.MoveResult(rHi)
	// lo = Character.digit(s.charAt((i << 1) + 1), 16)
	a.AddIntLit8(rTmp, 1)
	if err := a.InvokeVirtual([]int{rS, rTmp}, charAt); err != nil {
		return nil, err
	}
	a.MoveResult(rLo)
	if err := a.InvokeStatic([]int{rLo, rC16}, digit); err != nil {
		return nil, err
	}
	a.MoveResult(rLo)
	// b[i] = (byte) (((hi << 4) | lo) ^ (KEY + i * 17))
	a.ShlIntLit8(rHi, 4)
	a.OrInt(rHi, rHi, rLo)
	a.Move(rTmp, rI)
	a.MulIntLit8(rTmp, 17)
	a.AddIntLit8(rTmp, int8(key))
	a.XorInt(rHi, rHi, rTmp)
	a.IntToByte(rHi, rHi)
	a.APutByte(rHi, rB, rI)
	a.AddIntLit8(rI, 1)
	a.Goto16("loop")

	a.Label("end")
	a.NewInstance(rI, "Ljava/lang/String;")
	a.ConstString(rHi, "UTF-8")
	if err := a.InvokeDirect([]int{rI, rB, rHi}, strInit); err != nil {
		return nil, err
	}
	a.ReturnObject(rI)

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{
		Registers: 8,
		Ins:       1,
		Outs:      3,
		Insns:     insns,
		Patches:   patches,
	}, nil
}

// mergeAddition 把 src 合并进 dst（dst 可为 nil）。
func mergeAddition(dst *Addition, src Addition) *Addition {
	if dst == nil {
		dst = &Addition{}
	}
	dst.Types = append(dst.Types, src.Types...)
	dst.Protos = append(dst.Protos, src.Protos...)
	dst.Methods = append(dst.Methods, src.Methods...)
	dst.Fields = append(dst.Fields, src.Fields...)
	dst.Classes = append(dst.Classes, src.Classes...)
	return dst
}

// encryptCodeItem 改写一个 code_item 中的 const-string 指令。
//
// 输入 src 是「当前形态」的 code_item 字节流（可能是原始字节，
// 也可能是 A2/A3 前序步骤的产物）。返回的 blob 是替换后的字节流，
// skip 给出其中「已是新索引、不可再映射」的字位置，交给 remapCode 跳过。
// changed 为 false 时调用者应沿用原字节。
func (b *builder) encryptCodeItem(pl *plan, src []byte) (blob []byte, skip map[int]bool, changed bool, err error) {
	se := pl.strEnc
	if se == nil {
		return nil, nil, false, nil
	}
	ci, err := ParseCodeItemBytes(src)
	if err != nil {
		return nil, nil, false, err
	}

	// try 区间的端点必须是合法指令边界。若端点落在待替换指令的内部字上，
	// 替换会破坏端点定位，因此这类位置一律跳过（保守但不影响正确性）。
	boundary := map[int]bool{}
	for _, t := range ci.Tries {
		s := int(t.StartAddr)
		e := s + int(t.InsnCount)
		boundary[s] = true
		boundary[e] = true
	}

	l, err := ParseInsns(ci.Insns)
	if err != nil {
		return nil, nil, false, err
	}

	decIdx, ok := pl.methodIdx[se.decrypt.Key()]
	if !ok {
		return nil, nil, false, fmt.Errorf("dex: 字符串解密方法 %s 未登记", se.decrypt.Desc())
	}
	if decIdx > 0xffff {
		return nil, nil, false, fmt.Errorf("dex: 字符串解密方法索引 %d 超出 16 位", decIdx)
	}

	// 记录被替换的项，稍后据此推导 skip 位置。
	replaced := map[int]bool{}
	for i := 0; i < l.ItemCount(); i++ {
		if !l.ItemIsInsn(i) {
			continue
		}
		w := l.ItemWords(i)
		op := byte(w[0] & 0xff)
		if op != 0x1a && op != 0x1b {
			continue
		}
		old := l.ItemOldOffset(i)
		interior := []int{old + 1}
		if op == 0x1b {
			interior = append(interior, old+2)
		}
		blocked := false
		for _, p := range interior {
			if boundary[p] {
				blocked = true
				break
			}
		}
		if blocked {
			continue
		}

		var idx uint32
		if op == 0x1a {
			idx = uint32(w[1])
		} else {
			idx = uint32(w[1]) | uint32(w[2])<<16
		}
		s, err := b.f.String(idx)
		if err != nil {
			continue
		}
		if b.opts.Rename != nil {
			if nv, ok := b.opts.Rename[s]; ok {
				s = nv
			}
		}
		ct, ok := se.cipher[s]
		if !ok {
			continue
		}
		ctIdx, ok := pl.stringIdx[ct]
		if !ok {
			return nil, nil, false, fmt.Errorf("dex: 字符串密文未进入字符串池")
		}
		reg := int(w[0] >> 8)

		// ① const-string/jumbo vReg, cipher@ctIdx（3 字）
		// ② invoke-static/range {vReg}, decrypt（3 字）
		// ③ move-result-object vReg（1 字）
		//
		// 其中密文索引（项内偏移 1、2）与解密方法索引（项内偏移 4）
		// 直接写成最终值，由 Replace 的 fresh 参数登记，供 remapCode 跳过。
		l.Replace(i, []uint16{
			0x1b | uint16(reg)<<8, uint16(ctIdx & 0xffff), uint16(ctIdx >> 16),
			0x77 | uint16(1)<<8, uint16(decIdx), uint16(reg),
			0x0c | uint16(reg)<<8,
		}, 1, 2, 4)
		replaced[i] = true
	}
	if len(replaced) == 0 {
		return nil, nil, false, nil
	}

	insns, m, fresh := l.Encode()
	skip = fresh

	ci.Insns = insns
	// invoke-static/range 至少需要 1 个出参字
	if ci.Outs < 1 {
		ci.Outs = 1
	}
	// 把地址修正交给 Encode 统一处理：它除了改 try 区间与处理器目标地址，
	// 还会重算 handler_off（异常处理器列表内的字节偏移）——后者必须重算，
	// 否则地址编码长度变化会让偏移失效，ART 判 "Bogus handler offset" 并
	// 丢弃整个 DEX。
	return ci.Encode(func(old uint32) uint32 { return FixAddr(m, old) }), skip, true, nil
}

// sameWords 判断两个字序列是否完全相同。
func sameWords(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
