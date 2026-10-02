package dex

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"sort"
)

// 密钥流的构造（谁改这里都必须同时改 stringDecryptorCode，二者逐字节对应）。
//
// 旧实现（已废弃，务必不要改回去）：
//
//	func keyStream(key byte, i int) byte { return key + byte(i*17) }
//
// 它的密钥只有 1 字节，且密钥流是下标的**仿射函数**。后果：攻击者只要拿到
// 任意一个字符串的 (明文, 密文) 对（"UTF-8"、"Android"、类名、"http://..."
// 这类常量必然存在），就能令 pt[i]^ct[i] == key + i*17，直接解出唯一的 key，
// 再一次性解出全 DEX 的所有字符串——A2 因此几乎等于没加密。
//
// 新实现：密钥提升为 32 字节的伪随机秘密，密钥流改用 SHA-256 派生：
//
//	nonce    = SHA-256(secret ‖ 0x00 ‖ 明文)[0:8]
//	keystream(i) = SHA-256(secret ‖ 0x01 ‖ nonce ‖ LE32(i))[0]
//	ciphertext   = nonce ‖ (明文[i] XOR keystream(i))
//
// 为什么单点已知明文攻不下它：
//   - keystream(i) 是 SHA-256 的输出，已知某个 i 的流字节能反推 secret 或
//     其它 i 的流字节是不可能的（需要求 SHA-256 的原像/内部状态）；
//   - 每个字符串带独立 nonce（由明文确定性派生，见 stringNonce），因此
//     不同字符串在相同下标处的密钥流相互独立，不存在常数差或任何线性关系，
//     不能用两个字符串的异或消元（two-time pad）互相解密；
//   - 下标以 32 位小端进入哈希输入，位置信息不丢失，同一字符串内不同位置也
//     是完全独立的哈希输出。
//
// 为什么用 java.security.MessageDigest/SHA-256 而不是 AES-CTR：
//   - 不需要 Cipher/SecretKeySpec/IvParameterSpec 一整套样板，注入字节码更短、
//     更不容易写错寄存器与宽值；
//   - SHA-256 在 Android 全版本可用，且"摘要"语义比"加密"更不显眼。
//
// 确定性：secret 由 Pass 层从 seed/dex_key 派生，nonce 是明文的确定性函数，
// 所以同一 seed/密钥必然得到同一密文，产物可复现。

// StringEncrypt 描述 A2 字符串加密的参数。
//
// 加密方案：先给明文前置 8 字节 nonce，再与 SHA-256 派生的密钥流逐字节异或，
// 最后以 **Base64** 编码成 ASCII 字符串存入字符串池，运行时由注入的解密方法还原。
//
// 为什么用 Base64 而不是十六进制：
//   - 体积：十六进制把密文撑大一倍，Base64 只多 1/3；
//   - 特征：十六进制密文是「长串 0-9a-f」，扫描器一行正则就能把它挑出来；
//     Base64 混入大小写字母，同样的正则命中率大幅下降；
//   - 为什么不能直接存原始密文字节：DEX 的字符串池是 MUTF-8 编码的 UTF-16
//     序列，任意异或结果可能产生孤立代理码元，而 Go 的 string 无法表示孤立代理。
//
// 安全前提（见 planStringEncrypt）：密文必须与池内既有字符串**不重复**，
// 否则池会去重成同一项，导致别的引用解密出错误的明文。
type StringEncrypt struct {
	// Class 是解密器类描述符，形如 "Lapkguard/Dec;"。
	Class string
	// MethodName 是解密方法名，签名固定为 (Ljava/lang/String;)Ljava/lang/String;。
	MethodName string
	// Key 是主密钥，32 字节。
	//
	// 旧实现是单字节且密钥流可被单点已知明文攻破；改用 32 字节并交给
	// SHA-256 派生密钥流后，已知任意多组 (明文, 密文) 也无法反推密钥。
	Key [32]byte
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

// stringNonceSize 是每个字符串前置的 nonce 字节数。
//
// 必须足够长以压住「不同明文撞同一 nonce」的概率：4 字节在数万字符串规模下
// 生日碰撞已不可忽略（两个撞上 nonce 的字符串共用密钥流，退化成 two-time pad）；
// 8 字节把碰撞概率压到 2^-64 量级，而只多 8 字节（约 11 个 Base64 字符）开销。
const stringNonceSize = 8

// stringKSInputSize 是解密器为 SHA-256 构造的输入数组长度：
// secret(32) ‖ 域分隔(1) ‖ nonce(8) ‖ 小端下标(4)。
const stringKSInputSize = 32 + 1 + stringNonceSize + 4

// stringNonce 由密钥与明文确定性地派生 nonce。
//
// 为什么 nonce 由明文派生而不是随机：
//   - 加固必须可复现（同一 seed/密钥 → 同一密文），随机数会破坏这一点；
//   - nonce 是公开的（就放在密文最前面），它的作用不是保密，而是让**不同字符串
//     的密钥流彼此独立**。明文不同则 nonce 不同，两个字符串就无法互相消元。
//
// 域分隔字节 0x00 与密钥流的 0x01 区分开，避免两处 SHA-256 输入空间重叠。
func stringNonce(key [32]byte, plain []byte) [stringNonceSize]byte {
	h := sha256.New()
	h.Write(key[:])
	h.Write([]byte{0x00})
	h.Write(plain)
	sum := h.Sum(nil)
	var n [stringNonceSize]byte
	copy(n[:], sum)
	return n
}

// keyStreamByte 返回第 i 个字节的密钥流字节。
//
// keystream = SHA-256(secret ‖ 0x01 ‖ nonce ‖ LE32(i))，取摘要首字节。
// 每个位置一个独立哈希，已知任一位置的流字节都无法推出其它位置或密钥。
func keyStreamByte(key [32]byte, nonce [stringNonceSize]byte, i int) byte {
	var idx [4]byte
	binary.LittleEndian.PutUint32(idx[:], uint32(i))
	h := sha256.New()
	h.Write(key[:])
	h.Write([]byte{0x01})
	h.Write(nonce[:])
	h.Write(idx[:])
	sum := h.Sum(nil)
	return sum[0]
}

// encryptString 把明文字符串加密为 Base64 密文。
//
// 输出布局：Base64( nonce(8) ‖ 逐字节异或结果 )。
// 解密方法先 Base64 解码，取出前 8 字节 nonce，再算出同一密钥流还原明文。
func encryptString(s string, key [32]byte) string {
	p := []byte(s)
	nonce := stringNonce(key, p)
	buf := make([]byte, stringNonceSize+len(p))
	copy(buf, nonce[:])
	for i, c := range p {
		buf[stringNonceSize+i] = c ^ keyStreamByte(key, nonce, i)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// DecryptorStrings 返回 A2 注入的解密器类体里用到的字符串常量。
//
// 为什么需要它：A2 与 A3 是两次**独立**的 Rebuild，A2 写回的 DEX 里解密器
// 已经是既有类，于是 A3 会把解密器自己的常量也当成「应用常量」数组化，
// 让解密器反过来依赖还原器——既白增体积，又破坏了「A2 已覆盖全部常量时
// A3 不应当再改写」这条不变量（后者由 TestEncryptThenArrayE2E 钉住）。
//
// 这里不硬编码常量表，而是真的构造一次解密器、把它的字符串引用收集出来，
// 避免实现改动后这份清单悄悄过期。
func DecryptorStrings() []string {
	add, err := stringDecryptorAddition(&StringEncrypt{
		Class: "Lx/Dec;", MethodName: "a", InjectClass: true,
	})
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, c := range add.Classes {
		for _, m := range c.Methods {
			if m.Code == nil {
				continue
			}
			for _, p := range m.Code.Patches {
				if p.Ref.Kind != RefString || seen[p.Ref.String] {
					continue
				}
				seen[p.Ref.String] = true
				out = append(out, p.Ref.String)
			}
		}
	}
	return out
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
	// 池内既有字符串集合：用于「密文撞车」检查（见下）。
	existing := make(map[string]bool, len(values))
	for _, v := range values {
		existing[v] = true
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
		// 密文不得与池内**任一**既有字符串相同。
		//
		// 字符串池是按内容去重的：若密文恰好等于另一个条目的内容，两者会合并成
		// 同一项，于是那个条目的指令解出来的会是本条目的明文——静默的数据损坏。
		// 十六进制时代这种碰撞几乎不可能，换 Base64 后密文含有可读字母，概率
		// 上升到必须显式挡住（宁可少加密一个字符串，也不能改错语义）。
		if existing[ct] {
			continue
		}
		existing[ct] = true
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
	protoInit := ProtoSpec{Ret: "V", Params: []string{"[B", "Ljava/lang/String;"}}
	// android.util.Base64.decode(String, int) -> byte[]
	protoDecode := ProtoSpec{Ret: "[B", Params: []string{"Ljava/lang/String;", "I"}}
	// java.security.MessageDigest.getInstance(String) -> MessageDigest
	protoGetDigest := ProtoSpec{Ret: "Ljava/security/MessageDigest;", Params: []string{"Ljava/lang/String;"}}
	// java.security.MessageDigest.digest(byte[]) -> byte[]（内部会先 update 再 reset）
	protoDigest := ProtoSpec{Ret: "[B", Params: []string{"[B"}}

	strInit := MethodSpec{Class: "Ljava/lang/String;", Name: "<init>", Proto: protoInit}
	decB64 := MethodSpec{Class: "Landroid/util/Base64;", Name: "decode", Proto: protoDecode}
	mdGet := MethodSpec{Class: "Ljava/security/MessageDigest;", Name: "getInstance", Proto: protoGetDigest}
	mdDigest := MethodSpec{Class: "Ljava/security/MessageDigest;", Name: "digest", Proto: protoDigest}
	decrypt := MethodSpec{Class: se.Class, Name: se.MethodName, Proto: protoStr}

	add := Addition{
		Types: []string{
			se.Class, "[B", "I", "V",
			"Ljava/lang/String;", "Landroid/util/Base64;",
			"Ljava/security/MessageDigest;",
		},
		Protos:  []ProtoSpec{protoStr, protoInit, protoDecode, protoGetDigest, protoDigest},
		Methods: []MethodSpec{decrypt, strInit, decB64, mdGet, mdDigest},
	}
	if !se.InjectClass {
		return add, nil
	}

	code, err := stringDecryptorCode(se.Key, decB64, strInit, mdGet, mdDigest)
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
// 等价 Java 源码（与 Go 侧 encryptString/keyStreamByte 必须逐字节一致）：
//
//	static String a(String s) {
//	    byte[] b = android.util.Base64.decode(s, 0);      // b = nonce ‖ cipher
//	    byte[] in = new byte[45];                          // secret‖0x01‖nonce‖LE32(i)
//	    for (int k = 0; k < 32; k++) in[k] = SECRET[k];
//	    in[32] = 1;
//	    for (int k = 0; k < 8; k++) in[33 + k] = b[k];
//	    MessageDigest md = MessageDigest.getInstance("SHA-256");
//	    byte[] out = new byte[b.length - 8];
//	    for (int i = 0; i < out.length; i++) {
//	        in[41] = (byte) i;          // 小端
//	        in[42] = (byte) (i >>> 8);
//	        in[43] = (byte) (i >>> 16);
//	        in[44] = (byte) (i >>> 24);
//	        byte[] ks = md.digest(in);  // digest(input) 会重置摘要状态
//	        out[i] = (byte) (b[8 + i] ^ ks[0]);
//	    }
//	    return new String(out, "UTF-8");
//	}
//
// 寄存器分配（registers=12、ins=1 → 入参 s 落在 v11）：
//
//	v0 = b   v1 = i   v2 = n(明文长度)   v3 = in(45 字节输入)
//	v4 = md  v5 = ks  v6/v7 = 临时       v8 = out
//	v9 = 255(掩码)  v10 = 数组下标临时   v11 = s（入参）
//
// outs=3：方法内最大的一次 invoke 是 String.<init>(byte[], String) 的 3 个参数。
func stringDecryptorCode(key [32]byte, decB64, strInit, mdGet, mdDigest MethodSpec) (*CodeBlob, error) {
	const (
		rB    = 0
		rI    = 1
		rLen  = 2
		rIn   = 3
		rMD   = 4
		rKS   = 5
		rT    = 6
		rT2   = 7
		rOut  = 8
		rMask = 9
		rZ    = 10
		rS    = 11
	)
	// 密钥流输入数组内的字段偏移，与 Go 侧 keyStreamByte 的写入顺序一致。
	const (
		offDomain  = 32
		offNonce   = offDomain + 1
		offCounter = offNonce + stringNonceSize
	)
	a := NewAsm()

	// b = Base64.decode(s, 0)
	a.Const4(rT2, 0)
	if err := a.InvokeStatic([]int{rS, rT2}, decB64); err != nil {
		return nil, err
	}
	a.MoveResultObject(rB)

	// n = b.length - nonceSize
	a.ArrayLength(rLen, rB)
	a.Const16(rT, stringNonceSize)
	a.SubInt(rLen, rLen, rT)

	// out = new byte[n]
	if err := a.NewArray(rOut, rLen, "[B"); err != nil {
		return nil, err
	}

	// in = new byte[45]
	a.Const16(rT, stringKSInputSize)
	if err := a.NewArray(rIn, rT, "[B"); err != nil {
		return nil, err
	}
	a.Const16(rMask, 255)

	// in[0..31] = secret，in[32] = 域分隔 1
	a.Const4(rZ, 0)
	for _, c := range key {
		a.Const16(rT, int16(c))
		a.APutByte(rT, rIn, rZ)
		a.AddIntLit8(rZ, 1)
	}
	a.Const16(rT, 1)
	a.APutByte(rT, rIn, rZ)
	a.AddIntLit8(rZ, 1)

	// in[33..40] = nonce = b[0..7]
	a.Const4(rT2, 0)
	for j := 0; j < stringNonceSize; j++ {
		a.AGetByte(rT, rB, rT2)
		a.APutByte(rT, rIn, rZ)
		a.AddIntLit8(rZ, 1)
		a.AddIntLit8(rT2, 1)
	}

	// md = MessageDigest.getInstance("SHA-256")
	a.ConstString(rT2, "SHA-256")
	if err := a.InvokeStatic([]int{rT2}, mdGet); err != nil {
		return nil, err
	}
	a.MoveResultObject(rMD)

	a.Const4(rI, 0)

	a.Label("loop")
	if err := a.IfGe(rI, rLen, "end"); err != nil {
		return nil, err
	}

	// in[41..44] = 小端 i
	//
	// 必须用 Const16：offCounter=41 超出 const/4 的 4 位有符号立即数范围，
	// 用 Const4 会被截成 41&0xf=9，把计数器写到 in[9..12] 上（踩掉密钥字节）。
	a.Const16(rZ, offCounter)
	for shift := 0; shift < 32; shift += 8 {
		a.Move(rT, rI)
		if shift > 0 {
			a.ShrIntLit8(rT, int8(shift))
		}
		a.AndInt(rT, rT, rMask)
		a.APutByte(rT, rIn, rZ)
		a.AddIntLit8(rZ, 1)
	}

	// ks = md.digest(in)
	if err := a.InvokeVirtual([]int{rMD, rIn}, mdDigest); err != nil {
		return nil, err
	}
	a.MoveResultObject(rKS)

	// out[i] = (byte)(b[8+i] ^ ks[0])
	a.Move(rT2, rI)
	a.AddIntLit8(rT2, stringNonceSize)
	a.AGetByte(rT, rB, rT2)
	a.Const4(rZ, 0)
	a.AGetByte(rT2, rKS, rZ)
	a.XorInt(rT, rT, rT2)
	a.IntToByte(rT, rT)
	a.APutByte(rT, rOut, rI)

	a.AddIntLit8(rI, 1)
	a.Goto16("loop")

	a.Label("end")
	a.NewInstance(rT, "Ljava/lang/String;")
	a.ConstString(rT2, "UTF-8")
	if err := a.InvokeDirect([]int{rT, rOut, rT2}, strInit); err != nil {
		return nil, err
	}
	a.ReturnObject(rT)

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{
		Registers: 12,
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
