package dex

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"sort"

	"apkguard/internal/pack"
)

// A2 的加解密方案（谁改这里都必须同时改 stringDecryptor*，二者逐字节对应）。
//
// 现行方案（默认）：**AES-256-SIV（RFC 5297）**，与载荷/容器那条线统一。
//
//	blob = pack.EncryptNamed(明文, key, "") = [SIV 标签 16B][AES-256-CTR 密文]
//	池中密文 = Base64(blob)
//
// 运行时由守卫库的 JNI 入口 Native.sivDecrypt(key32, ad, blob) 解密：
// SIV 标签既是 CTR 的计数器初值、又是 S2V 的 MAC，解密时重算 S2V 常量时间
// 比对，篡改密钥/密文/AD 一律返回 null（注入的解密器收到 null 会抛异常，
// 绝不静默返回原文）。AD 组件为空字符串——同一明文在同密钥下得到**相同**
// 密文（确定性，产物可复现；这与旧实现一致，因为旧 nonce 也是明文的函数）。
//
// 为什么换成 SIV：审计与用户要求「全面弃用自造/CBC 类密码学，走标准 AEAD」。
// 旧实现的 SHA-256 keystream 虽是自造构造，但它不是 AEAD（无完整性保护：
// 密文被篡改后仍会解出一段字节，只是内容错乱），且需要把整套 MessageDigest
// 循环注入字节码。SIV 是标准 AEAD、解密必校验、且运行时只需一次 JNI 调用，
// 注入的解密器因此更短、更不易写错寄存器。
//
// 逃生开关（StrencLegacyKeystream / StringEncrypt.LegacyKeystream）为 true 时
// 回到旧的 SHA-256 keystream 实现（不依赖原生库、无需嵌入守卫库）：
//
//	nonce = SHA-256(secret ‖ 0x00 ‖ 明文)[0:8]
//	ks(i) = SHA-256(secret ‖ 0x01 ‖ nonce ‖ LE32(i))[0]
//	ciphertext = Base64(nonce ‖ (明文[i] XOR ks(i)))
//
// 该路径仅用于「不方便带 .so 的兼容性场景」，安全强度弱于 SIV（无完整性），
// 默认关闭。旧实现更早的形态是单字节密钥 + 仿射流 key+i*17，已被彻底删除。

// StringEncrypt 描述 A2 字符串加密的参数。
//
// 加密方案（默认）：用 AES-256-SIV 加密明文得到 [SIV 标签 16B][CTR 密文]，
// 再以 **Base64** 编码成 ASCII 字符串存入字符串池，运行时由注入的解密方法
// 经 Native.sivDecrypt 还原。LegacyKeystream 为 true 时改用旧的
// SHA-256 keystream（见文件头说明）。
//
// 为什么用 Base64 而不是十六进制：
//   - 体积：十六进制把密文撑大一倍，Base64 只多 1/3；
//   - 特征：十六进制密文是「长串 0-9a-f」，扫描器一行正则就能把它挑出来；
//     Base64 混入大小写字母，同样的正则命中率大幅下降；
//   - 为什么不能直接存原始密文字节：DEX 的字符串池是 MUTF-8 编码的 UTF-16
//     序列，任意字节序列可能产生孤立代理码元，而 Go 的 string 无法表示孤立代理。
//
// 安全前提（见 planStringEncrypt）：密文必须与池内既有字符串**不重复**，
// 否则池会去重成同一项，导致别的引用解密出错误的明文。
type StringEncrypt struct {
	// Class 是解密器类描述符，形如 "Lapkguard/Dec;"。
	Class string
	// MethodName 是解密方法名，签名固定为 (Ljava/lang/String;)Ljava/lang/String;。
	MethodName string
	// LegacyKeystream 为 true 时使用旧的 SHA-256 keystream 实现（自造构造，
	// 无完整性保护，但不需要原生库）。默认 false，走 AES-256-SIV。
	//
	// 该开关只影响 Go 侧加密与注入的解密器形态，二者必须一致：传 true 时
	// stringDecryptorAddition 生成旧的 MessageDigest 解密器，否则生成
	// 「Base64 → Native.sivDecrypt → new String」的新解密器。
	LegacyKeystream bool
	// LibName 是注入解密器 <clinit> 里 System.loadLibrary 的库名（不含 lib
	// 前缀与 .so 后缀）。留空时用 NativeLibName（"apkguard"）。
	//
	// 必须与产物里实际加载的守卫库名一致。C7（原生库伪装）会改库名并改写
	// 壳侧 loadLibrary 实参，但它只改写壳 DEX——因此 Pass 层在 C7 启用时必须
	// 把 C7 派生出的假名传进来（见 passes/guardLibNameOf），否则 A2 注入的
	// loadLibrary 会与实际文件名不符而 UnsatisfiedLinkError。
	//
	// 仅当 Bridge 为空（解密器直接调用 Native.sivDecrypt）时才使用。
	LibName string
	// Bridge 非空时，解密器改为调用该「纯 Java 包装类」的静态方法完成原生
	// 解密（签名 (byte[],byte[],byte[]) -> byte[]），**不再**注入 <clinit>、
	// 也不引用 loadLibrary 或 Native 桥接类。值形如 "Lcom/apkguard/shell/Siv;"，
	// 见 SivWrapperAddition。
	//
	// 用于业务 DEX 由我们自己的 DexClassLoader 加载的场景（B1/B2/B3 加壳后）：
	// 现代 APK 的 extractNativeLibs=false 让安装后的 lib/<abi>/ 是空目录，
	// 业务 DEX 里的 System.loadLibrary 必然 UnsatisfiedLinkError。把调用转发到
	// 壳侧（系统类加载器命名空间）的包装类即可，原生绑定发生在能解析 APK 内
	// lib/<abi>/*.so 的那一侧。
	//
	// 留空时保持旧行为（解密器直接 Native.sivDecrypt + <clinit> loadLibrary）。
	Bridge string
	// Key 是主密钥，32 字节。
	//
	// 旧实现是单字节且密钥流可被单点已知明文攻破；现在是 32 字节主密钥，
	// 交给 AES-256-SIV 使用（旧路径再 SHA-256 派生密钥流）。32 字节宽度
	// 对两种路径都足够，已知任意多组 (明文, 密文) 都无法反推密钥。
	Key [32]byte
	// MinLen 是参与加密的最短字符串长度（按 UTF-8 字节计）。
	MinLen int
	// SingleRefOnly 为 true 时只加密「恰好被 1 条 const-string 指令引用」的
	// 字符串（对齐参考样本的选择性加密分布：样本 463 个候选中只加密 206 个，
	// 多引用串一律留明文）。
	//
	// 这是**降低保护强度**的形态选项：多引用串继续以明文留在字符串池，
	// 静态扫描器可直接提取。默认 false：长度达到 MinLen 的串一律加密，
	// 与既有行为一致。
	SingleRefOnly bool
	// InjectClass 为 true 时把解密器类本体写入本 DEX。
	//
	// 多 DEX 场景下每个含密文的 DEX 都应各自注入一份**类名互不相同**的
	// 解密器（参考样本的强指纹：每个 DEX 自带解密器、两两零交叉引用），
	// 因此该字段通常为 true；false 只用于「只登记类型/方法引用、不生成
	// class_def」的窄场景。
	InjectClass bool
	// Skip 返回 true 表示该字符串不参与加密；可为 nil。
	Skip func(s string) bool
	// ForceEncrypt 中的字符串**无条件加密**：跳过 MinLen 与 SingleRefOnly。
	// A7 用它强制加密反射成员名——这类名字往往很短（"get"/"a"/"isTagEnabled"），
	// 低于 MinLen 时会被留在明文，正是 A7 要补的洞。
	//
	// 与 Skip 的关系：Skip 表示「该串必须留在池里」（解密器自身的方法名、
	// 类型名、"SHA-256" 等）。强制集合里的串即使命中 Skip 也仍会改写
	// const-string 引用（cipher），但不会把池内条目整体替换掉（replace）——
	// 既保证反射调用点不再明文，也不破坏解密器对池项的引用。
	ForceEncrypt map[string]bool
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

// ---- 旧路径（LegacyKeystream）专用的 nonce / 密钥流 ----
//
// 仅在 StringEncrypt.LegacyKeystream 为 true 时使用；默认的 AES-SIV 路径
// 完全不需要它们。保留是为了「逃生开关」能回到旧实现。

// stringNonceSize 是旧路径中每个字符串前置的 nonce 字节数。
//
// 必须足够长以压住「不同明文撞同一 nonce」的概率：4 字节在数万字符串规模下
// 生日碰撞已不可忽略（两个撞上 nonce 的字符串共用密钥流，退化成 two-time pad）；
// 8 字节把碰撞概率压到 2^-64 量级，而只多 8 字节（约 11 个 Base64 字符）开销。
const stringNonceSize = 8

// stringKSInputSize 是旧解密器为 SHA-256 构造的输入数组长度：
// secret(32) ‖ 域分隔(1) ‖ nonce(8) ‖ 小端下标(4)。
const stringKSInputSize = 32 + 1 + stringNonceSize + 4

// stringNonce 由密钥与明文确定性地派生 nonce（旧路径）。
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

// keyStreamByte 返回第 i 个字节的密钥流字节（旧路径）。
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

// legacyEncryptString 是旧路径的加密：Base64( nonce(8) ‖ 逐字节异或结果 )。
//
// 与 injectDecryptorLegacy 生成的方法逐字节对应。
func legacyEncryptString(s string, key [32]byte) string {
	p := []byte(s)
	nonce := stringNonce(key, p)
	buf := make([]byte, stringNonceSize+len(p))
	copy(buf, nonce[:])
	for i, c := range p {
		buf[stringNonceSize+i] = c ^ keyStreamByte(key, nonce, i)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// encryptString 把明文字符串加密为 Base64 密文。
//
// legacy=false（默认）：AES-256-SIV，输出 Base64( [SIV 16B] ‖ CTR 密文 )；
// legacy=true：旧 SHA-256 keystream，输出 Base64( nonce(8) ‖ 异或结果 )。
//
// 两种形态都保证输出是纯 ASCII（可安全放进 DEX 字符串池）。SIV 的唯一
// 失败点是 AES 密钥长度——本函数固定 32 字节，因此实践中不会失败，但仍
// 显式返回错误而不是静默产出退化结果。
func encryptString(s string, key [32]byte, legacy bool) (string, error) {
	if legacy {
		return legacyEncryptString(s, key), nil
	}
	blob, err := pack.EncryptNamed([]byte(s), key, "")
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(blob), nil
}

// addStringsFromClasses 把注入类的全部方法体里引用的字符串常量收集进 out。
func addStringsFromClasses(out map[string]bool, classes []ClassSpec) {
	for _, c := range classes {
		for _, m := range c.Methods {
			if m.Code == nil {
				continue
			}
			for _, p := range m.Code.Patches {
				if p.Ref.Kind == RefString {
					out[p.Ref.String] = true
				}
			}
		}
	}
}

// DecryptorStrings 返回 A2 注入到 DEX 里的「工具自身」字符串常量。
//
// 为什么需要它：A2 与 A3 是两次**独立**的 Rebuild，A2 写回的 DEX 里解密器与
// native 桥接类已经是既有类，于是 A3 会把它们的常量也当成「应用常量」数组化，
// 让解密器/桥接类反过来依赖还原器——既白增体积，又破坏了「A2 已覆盖全部
// 常量时 A3 不应当再改写」这条不变量（后者由 TestEncryptThenArrayE2E 钉住）。
//
// 这里不硬编码常量表，而是真的构造一次解密器与桥接类、把它们的字符串引用
// 收集出来，避免实现改动后这份清单悄悄过期。返回顺序不稳定，调用方按集合用。
func DecryptorStrings() []string {
	seen := map[string]bool{}
	// 解密器（默认 SIV 形态）。
	if add, err := stringDecryptorAddition(&StringEncrypt{
		Class: "Lx/Dec;", MethodName: "a", InjectClass: true,
	}); err == nil {
		addStringsFromClasses(seen, add.Classes)
	}
	// 桥接类由 A2 在同一次重建里一并注入（消费方见 passes/strenc.go），
	// 它的常量（"SHA-256"、库名）同样必须排除，否则 A3 会把它们数组化。
	if add, err := NativeBridgeAddition(&NativeBridgeSpec{
		Class: NativeBridgeClass, LibName: NativeLibName, NeedDecrypt: true,
	}); err == nil {
		addStringsFromClasses(seen, add.Classes)
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	return out
}

// collectConstStrings 返回全部被 const-string 指令引用的旧字符串索引（升序去重）、
// 「每个索引被多少条 const-string 指令引用」的计数，以及「存在无法改写引用」的
// 字符串集合。
//
// 所谓「无法改写」：某条 const-string 恰好位于 try 区间端点所在字的内部。
// 这类字符串的明文必须留在池中，否则无法改写的那些指令会读到密文。
//
// 引用计数用于 SingleRefOnly 选择性加密；计数的是**指令条数**而不是去重后的
// 使用点数，与参考样本「按 const-string 引用点判定」的口径一致。
func collectConstStrings(f *File) (idxs []uint32, refs map[uint32]int, blocked map[uint32]bool, err error) {
	seen := map[uint32]int{}
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
			seen[idx]++
			if boundary[pos+1] || (op == 0x1b && boundary[pos+2]) {
				blocked[idx] = true
			}
			return nil
		})
	})
	if err != nil {
		return nil, nil, nil, err
	}
	refs = make(map[uint32]int, len(seen))
	for i, n := range seen {
		idxs = append(idxs, i)
		refs[i] = n
	}
	sort.Slice(idxs, func(a, b int) bool { return idxs[a] < idxs[b] })
	return idxs, refs, blocked, nil
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
	idxs, refs, blocked, err := collectConstStrings(f)
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
		forced := se.ForceEncrypt[s]
		if len(s) < se.MinLen && !forced {
			continue
		}
		// SingleRefOnly：只处理恰好被 1 条 const-string 引用的串。
		// 多引用串保持明文与原始指令不变（对齐参考样本的选择性加密形态）。
		// 强制集合（A7 反射成员名）不受该形态选项影响。
		if se.SingleRefOnly && refs[i] != 1 && !forced {
			continue
		}
		// Skip 的语义是「这条字符串必须留在池里」——典型是解密器自身引用的
		// 常量：方法名 "a"、类型名、"SHA-256"/"UTF-8"。强制集合里的串仍然要
		// 改写 const-string 引用（否则反射成员名会以明文常量暴露），只是不能
		// 把池内条目整体替换成密文（否则解密器方法名等会找不到池项）。
		// 因此 kept 时跳过 replace，但仍写入 cipher。
		kept := se.Skip != nil && se.Skip(s)
		if kept && !forced {
			continue
		}
		if _, ok := cipher[s]; ok {
			continue
		}
		ct, err := encryptString(s, se.Key, se.LegacyKeystream)
		if err != nil {
			return nil, nil, fmt.Errorf("dex: 加密字符串失败: %w", err)
		}
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
		if !kept && constOnly(i) && !blocked[i] {
			replace[s] = ct
		}
	}
	return cipher, replace, nil
}

// StringEncryptTargets 返回按 se 参数会被加密的字符串条数（纯分析，不改写 DEX）。
//
// Pass 层用它判断某个 DEX 是否含密文：返回 0 时该 DEX 不应注入解密器类，
// 也不值得触发一次重建。计数口径与构建期的 planStringEncrypt 完全一致
// （直接复用同一函数与同一套自身串排除逻辑），因此不会与实际重建结果偏差。
func StringEncryptTargets(f *File, se *StringEncrypt) (int, error) {
	values, err := f.AllStrings()
	if err != nil {
		return 0, err
	}
	// 与 buildPlan 的 StringEncrypt 分支一致：解密器自身的字符串常量
	// 不参与加密，否则会形成「解密前先解密」的死循环。
	decAdd, err := stringDecryptorAddition(se)
	if err != nil {
		return 0, err
	}
	s := *se
	inner := s.Skip
	self := map[string]bool{}
	collectAdditionStrings(&decAdd, self)
	s.Skip = func(str string) bool {
		if self[str] {
			return true
		}
		return inner != nil && inner(str)
	}
	cipher, _, err := planStringEncrypt(f, &s, values)
	if err != nil {
		return 0, err
	}
	return len(cipher), nil
}

// stringDecryptorAddition 构造注入解密器所需的全部索引表条目与类定义。
//
// 默认生成 AES-256-SIV 解密器（Base64 解码 → Native.sivDecrypt → new String，
// 校验失败抛异常），并给类加一个 <clinit> 加载守卫库；se.LegacyKeystream 为
// true 时生成旧的 MessageDigest 解密器（见 stringDecryptorAdditionLegacy）。
//
// 当 se.InjectClass 为 false 时只登记类型/原型/方法引用（供 invoke 指令使用），
// 不生成 class_def —— 供「只引用、不落地类体」的窄场景使用（A2 Pass 现为每个
// 含密文 DEX 各注入一份类名不同的类体，因此传 true）。
func stringDecryptorAddition(se *StringEncrypt) (Addition, error) {
	if se.LegacyKeystream {
		return stringDecryptorAdditionLegacy(se)
	}

	protoStr := ProtoSpec{Ret: "Ljava/lang/String;", Params: []string{"Ljava/lang/String;"}}
	protoInit := ProtoSpec{Ret: "V", Params: []string{"[B", "Ljava/lang/String;"}}
	// android.util.Base64.decode(String, int) -> byte[]
	protoDecode := ProtoSpec{Ret: "[B", Params: []string{"Ljava/lang/String;", "I"}}
	// Native.sivDecrypt(byte[], byte[], byte[]) -> byte[]（守卫库 JNI 入口）
	protoSiv := ProtoSpec{Ret: "[B", Params: []string{"[B", "[B", "[B"}}
	// RuntimeException.<init>()V（解密失败时抛出）
	protoV := ProtoSpec{Ret: "V"}
	// System.loadLibrary(String)V
	protoLoad := ProtoSpec{Ret: "V", Params: []string{"Ljava/lang/String;"}}

	strInit := MethodSpec{Class: "Ljava/lang/String;", Name: "<init>", Proto: protoInit}
	decB64 := MethodSpec{Class: "Landroid/util/Base64;", Name: "decode", Proto: protoDecode}
	// 原生解密的调用目标：默认是桥接类自身的 sivDecrypt（旧行为）；se.Bridge
	// 非空时改指壳侧包装类的转发方法——此时解密器不注入 <clinit>、不引用
	// loadLibrary/System，业务 DEX 里不再出现任何库名。
	sivClass, sivName := NativeBridgeClass, NativeDecrypt
	if se.Bridge != "" {
		sivClass, sivName = se.Bridge, SivWrapperMethod
	}
	sivDec := MethodSpec{Class: sivClass, Name: sivName, Proto: protoSiv}
	rtInit := MethodSpec{Class: "Ljava/lang/RuntimeException;", Name: "<init>", Proto: protoV}
	loadLib := MethodSpec{Class: descSystem, Name: "loadLibrary", Proto: protoLoad}
	decrypt := MethodSpec{Class: se.Class, Name: se.MethodName, Proto: protoStr}
	clinit := MethodSpec{Class: se.Class, Name: "<clinit>", Proto: protoV}

	libName := se.LibName
	if libName == "" {
		libName = NativeLibName
	}

	add := Addition{
		Types: []string{
			se.Class, "[B", "I", "V",
			"Ljava/lang/String;", "Landroid/util/Base64;",
			sivClass, "Ljava/lang/RuntimeException;",
		},
		Protos:  []ProtoSpec{protoStr, protoInit, protoDecode, protoSiv, protoV},
		Methods: []MethodSpec{decrypt, strInit, decB64, sivDec, rtInit},
	}
	// 只有在「解密器自己加载库」的分支才登记 System/loadLibrary：Bridge 路径
	// 下多登记一个 loadLibrary 方法引用会把 "loadLibrary" 重新写进业务 DEX 的
	// 字符串池，破坏「业务 DEX 不再出现库加载」这一形态断言。
	if se.Bridge == "" {
		add.Types = append(add.Types, descSystem)
		add.Protos = append(add.Protos, protoLoad)
		add.Methods = append(add.Methods, loadLib)
	}
	if !se.InjectClass {
		return add, nil
	}

	code, err := stringDecryptorCodeSIV(se.Key, decB64, strInit, sivDec, rtInit)
	if err != nil {
		return Addition{}, err
	}
	if se.Bridge == "" {
		// 旧行为：解密器自带 <clinit> 加载守卫库（适用于业务 DEX 由系统类
		// 加载器加载的场景，例如未加壳的纯混淆产物）。
		clinitCode, err := stringDecryptorClinit(libName, loadLib)
		if err != nil {
			return Addition{}, err
		}
		add.Methods = append(add.Methods, clinit)
		add.Classes = []ClassSpec{{
			Name:  se.Class,
			Super: descObject,
			// 类级标志只能是「类能用的那些位」：STATIC 是**成员**标志，
			// 写在 class_def 上属于非法组合（真实工具链产出的 DEX 里
			// 五万多个类没有一个这么写）。纯静态工具类用 PUBLIC | FINAL。
			Access: accPublic | accFinal, // 纯静态工具类
			Methods: []ClassMethod{
				// <clinit> 先加载守卫库：sivDecrypt 是 native 方法，库没加载
				// 会以 UnsatisfiedLinkError 崩溃，且崩溃点离原因很远。
				{Name: "<clinit>", Proto: protoV, Access: accStatic, Code: clinitCode},
				{Name: se.MethodName, Proto: protoStr, Access: accPublic | accStatic, Code: code},
			},
		}}
		return add, nil
	}
	// Bridge 路径：无 <clinit>，原生加载由壳侧包装类所在命名空间完成。
	add.Classes = []ClassSpec{{
		Name:   se.Class,
		Super:  descObject,
		Access: accPublic | accFinal, // 纯静态工具类
		Methods: []ClassMethod{
			{Name: se.MethodName, Proto: protoStr, Access: accPublic | accStatic, Code: code},
		},
	}}
	return add, nil
}

// stringDecryptorAdditionLegacy 是旧的 SHA-256 keystream 解密器（逃生开关）。
//
// 与 stringDecryptorCodeLegacy 逐字节对应；不依赖原生库，因此该路径下
// A2 不需要嵌入守卫库、也不注入 native 桥接类。
func stringDecryptorAdditionLegacy(se *StringEncrypt) (Addition, error) {
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

	code, err := stringDecryptorCodeLegacy(se.Key, decB64, strInit, mdGet, mdDigest)
	if err != nil {
		return Addition{}, err
	}
	add.Classes = []ClassSpec{{
		Name:  se.Class,
		Super: descObject,
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

// stringDecryptorCodeSIV 生成新版解密方法的字节码。
//
// 等价 Java 源码（AD 为空数组，与 Go 侧 pack.EncryptNamed(plain, key, "") 对应）：
//
//	static String a(String s) {
//	    byte[] blob  = android.util.Base64.decode(s, 0);
//	    byte[] key   = { SECRET[0], …, SECRET[31] };   // 32 字节常量内联
//	    byte[] ad    = new byte[0];
//	    byte[] plain = Native.sivDecrypt(key, ad, blob);
//	    if (plain == null) throw new RuntimeException();  // 校验失败必须可见
//	    return new String(plain, "UTF-8");
//	}
//
// 寄存器分配（registers=7、ins=1 → 入参 s 落在 v6）：
//
//	v0 = blob   v1 = key   v2 = ad   v3 = plain
//	v4 = 临时/对象（异常、String 实例、数组长度）  v5 = 临时（下标、"UTF-8"）  v6 = s
//
// outs=3：方法内最大的一次 invoke 是 String.<init>(byte[], String) 的 3 个参数。
func stringDecryptorCodeSIV(key [32]byte, decB64, strInit, sivDec, rtInit MethodSpec) (*CodeBlob, error) {
	const (
		rBlob  = 0
		rKey   = 1
		rAd    = 2
		rPlain = 3
		rObj   = 4
		rTmp   = 5
		rS     = 6
	)
	a := NewAsm()

	// blob = Base64.decode(s, 0)
	a.Const4(rTmp, 0)
	if err := a.InvokeStatic([]int{rS, rTmp}, decB64); err != nil {
		return nil, err
	}
	a.MoveResultObject(rBlob)

	// key = new byte[32]，逐字节填入常量密钥
	a.Const16(rTmp, 32)
	if err := a.NewArray(rKey, rTmp, "[B"); err != nil {
		return nil, err
	}
	a.Const4(rTmp, 0)
	for _, c := range key {
		a.Const16(rObj, int16(c))
		a.APutByte(rObj, rKey, rTmp)
		a.AddIntLit8(rTmp, 1)
	}

	// ad = new byte[0]（零长度 AD 组件，等价于 EncryptNamed(name="")）
	a.Const4(rObj, 0)
	if err := a.NewArray(rAd, rObj, "[B"); err != nil {
		return nil, err
	}

	// plain = Native.sivDecrypt(key, ad, blob)
	if err := a.InvokeStatic([]int{rKey, rAd, rBlob}, sivDec); err != nil {
		return nil, err
	}
	a.MoveResultObject(rPlain)

	// if (plain == null) throw new RuntimeException();
	// 解密失败必须可见：绝不静默返回原文，也不返回 null 让调用方继续。
	a.IfNez(rPlain, "ok") // 非空则跳过抛异常分支
	a.NewInstance(rObj, "Ljava/lang/RuntimeException;")
	if err := a.InvokeDirect([]int{rObj}, rtInit); err != nil {
		return nil, err
	}
	a.Throw(rObj)

	// return new String(plain, "UTF-8");
	a.Label("ok")
	a.NewInstance(rObj, "Ljava/lang/String;")
	a.ConstString(rTmp, utf8Charset)
	if err := a.InvokeDirect([]int{rObj, rPlain, rTmp}, strInit); err != nil {
		return nil, err
	}
	a.ReturnObject(rObj)

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{
		Registers: 7,
		Ins:       1,
		Outs:      3,
		Insns:     insns,
		Patches:   patches,
	}, nil
}

// stringDecryptorClinit 生成解密器类的静态初始化块：加载守卫库。
//
// 等价 Java：
//
//	static { System.loadLibrary("<守卫库名>"); }
//
// 库名由 StringEncrypt.LibName 传入（留空回退 NativeLibName）；C7 启用时
// 由 Pass 层传入改名后的假名，保证与实际文件名一致。
func stringDecryptorClinit(libName string, loadLib MethodSpec) (*CodeBlob, error) {
	a := NewAsm()
	a.ConstString(0, libName)
	if err := a.InvokeStatic([]int{0}, loadLib); err != nil {
		return nil, err
	}
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 1, Ins: 0, Outs: 1, Insns: insns, Patches: patches}, nil
}

// stringDecryptorCodeLegacy 生成旧版（SHA-256 keystream）解密方法的字节码。
//
// 等价 Java 源码（与 Go 侧 legacyEncryptString/keyStreamByte 必须逐字节一致）：
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
func stringDecryptorCodeLegacy(key [32]byte, decB64, strInit, mdGet, mdDigest MethodSpec) (*CodeBlob, error) {
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

	insns, m, fresh, err := l.EncodeChecked()
	if err != nil {
		return nil, nil, false, err
	}
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
	code, err := ci.EncodeChecked(func(old uint32) uint32 { return FixAddr(m, old) })
	if err != nil {
		return nil, nil, false, err
	}
	return code, skip, true, nil
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

// Throw 生成 throw vReg（格式 11x，操作码 0x27）。
//
// 定义在 strenc.go 而不是 asm.go：它是 A2 的 SIV 解密器在「解密失败」分支
// 专用的指令，asm.go 的通用指令集刻意不含异常语义。注册在这里可避免改动
// 共享的汇编器文件。
func (a *Asm) Throw(reg int) {
	a.emit(0x27 | uint16(reg&0xff)<<8)
}
