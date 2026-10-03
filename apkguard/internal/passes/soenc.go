package passes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"apkguard/internal/config"
	"apkguard/internal/native"
	"apkguard/internal/pack"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// ---- C2 SO 加壳（整文件加密） ----
//
// 做法：把 lib/<abi>/*.so 从 APK 移除，逐个用 pack.Encrypt（AES-256-CBC，
// 「IV ‖ 密文」）加密后存进 assets/；壳（B3 的 Loader）在 attachBaseContext
// 里把它们解密落地到应用私有目录，并把该目录并入库搜索路径。
//
// 完整性：启用 -payload-mac 时，库载荷追加与 B1 **同规格**的
// encrypt-then-MAC（复用 pack.MAC/MacKey/域分离常量，绑定原始库名），
// 壳侧在解密前先校验（loader.go 的库循环复用同一个 v()）。
//
// 之所以选「整文件加密」而不是「段加密」：整文件不改动 ELF 一个字节，
// 16KB 页对齐、DT_NEEDED、.init_array、重定位表全部原样保留，不存在
// 「重新链接」风险；而 .text 段加密与 JNI_OnLoad 的执行时序矛盾，必须
// 自建 ELF 加载器，投入产出比极差（见 docs/方案-C2-SO加壳.md §2.1）。
//
// 兼容性上限（必须如实报告，不能靠推测）：
//   - native 层裸名 dlopen("libfoo.so")：链接器命名空间只含 APK 的 lib 目录
//     与系统目录，不读 Java 的 librarySearchPath，**无法接管**；
//   - android_dlopen_ext 从 APK 按偏移加载（Flutter / React Native / Unity /
//     TFLite 常见）：库直接从 APK 的 lib/ 里按 zip 偏移 mmap，我们把 .so
//     移走后偏移与文件都不存在，**无法接管**。
//
// 因此本 Pass 在加密前做一次**框架特征静态审计**：一旦命中上述框架特征，
// 默认判定「native 自加载、不可整文件加密」，**整个 APK 跳过 C2**（不做
// 部分加密——同 ABI 混放会让 DT_NEEDED 依赖链一半在私有目录、一半在 lib/，
// 解析行为不可控）。跳过会写入 Note/Stat，绝不静默通过。
const sharedKeySOLibs = "C2.libs"

// soItem 是一份加密后的原生库载荷。
type soItem struct {
	// Abi 是原始 ABI 目录名（如 "x86_64"）。
	Abi string
	// Name 是原始文件名（如 "libfoo.so"），运行时必须按原名落地。
	Name string
	// Entry 是原 APK 条目名（如 "lib/x86_64/libfoo.so"）。
	Entry string
	// Asset 是加密载荷在 APK 中的条目名。
	Asset string
	// Size 是载荷字节数（含前置 IV；启用 -payload-mac 时还含尾部 32 字节 tag）。
	Size int
	// Plain 是原始 .so 字节数，用于报告。
	Plain int
}

// shellSOLibs 是 C2 交给 B3（Loader）与 C1（ABI 选择）的清单。
type shellSOLibs struct {
	// Key 是加密所用密钥；B3 会断言它与 B1 的密钥一致。
	Key [pack.KeySize]byte
	// Items 是全部原生库载荷。
	Items []soItem
	// Abis 是 C2 移除 lib/ 之前 APK 覆盖的 ABI 集合（有序）。
	//
	// 这是 C1 的 ABI 选择必须优先使用的集合：C2 之后 abisOf() 会返回空，
	// 若 C1 据此判定「APK 没有原生库」就会给全部 ABI 注入 libapkguard.so，
	// 让只支持 arm64 的应用被装到 32 位设备上。
	Abis []string
	// MAC 表示本批库载荷尾部带 HMAC-SHA256 标签（对应 -payload-mac），
	// 壳在解密前必须先校验。
	//
	// 与 B1 的 shellPayloads.MAC 同源：两者都取自 opts.PayloadMAC，
	// 且 C2 依赖 B1/B2/B3（config.Validate 强制）。壳侧实际读取的是 B3
	// 传给 dex.LoaderSpec 的那一个开关（同为 opts.PayloadMAC），因此
	// 不存在「打包侧带了 tag、壳侧却不校验」的错配窗口。这里记录一份
	// 仅供报告与测试断言，不新增第二个开关。
	MAC bool
}

// soLibsOf 读取 C2 写入的原生库清单；未启用 C2 时返回 nil。
func soLibsOf(art *pipeline.Artifact) *shellSOLibs {
	v := art.Get(sharedKeySOLibs)
	if v == nil {
		return nil
	}
	sl, _ := v.(*shellSOLibs)
	return sl
}

// soAbisOf 返回 C2 记录的原 ABI 集合（供 C1 使用）；无记录时返回 nil。
func soAbisOf(art *pipeline.Artifact) map[string]bool {
	sl := soLibsOf(art)
	if sl == nil || len(sl.Abis) == 0 {
		return nil
	}
	out := make(map[string]bool, len(sl.Abis))
	for _, a := range sl.Abis {
		out[a] = true
	}
	return out
}

// encryptNativeLibs 实现 C2：原生库整体加密。
type encryptNativeLibs struct{}

func (encryptNativeLibs) ID() config.FeatureID { return "C2" }
func (encryptNativeLibs) In() pipeline.Level   { return pipeline.LevelZip }
func (encryptNativeLibs) Out() pipeline.Level  { return pipeline.LevelZip }

// soAssetWords / soAssetExts 是 SO 载荷的伪装名片段（不暴露 "lib"/"so" 字样）。
var (
	soAssetWords = []string{"config", "data", "index", "cache", "meta", "base", "res", "assets"}
	soAssetExts  = []string{".bin", ".dat", ".res", ".pack"}
)

// soAssetName 由种子、ABI 与库名派生一个稳定且不重复的载荷条目名。
//
// 与 B1 的 AssetName 使用不同的命名空间前缀，避免两批载荷撞名。
func soAssetName(seed, abi, name string) string {
	sum := sha256.Sum256([]byte("apkguard/soasset/" + seed + "/" + abi + "/" + name))
	word := soAssetWords[int(sum[0])%len(soAssetWords)]
	ext := soAssetExts[int(sum[1])%len(soAssetExts)]
	return "assets/" + word + "_" + hex.EncodeToString(sum[2:6]) + ext
}

// highRiskFrameworks 是「native 自加载」的框架特征库名。
//
// 命中即判定该 APK 不可整文件加密：这些框架通常用 android_dlopen_ext
// 从 APK 按 zip 偏移直接 mmap 自己的库（尤其是 libapp.so / libflutter.so），
// 移走 lib/ 下的文件会让它们找不到库而启动即崩，且无法用 Java 层的
// librarySearchPath 挽救。
var highRiskFrameworks = []string{
	"libflutter.so", "libapp.so", // Flutter（Dart AOT）
	"libhermes.so", "libreactnativejni.so", // React Native
	"libunity.so",                                  // Unity
	"libmonochrome.so", "libtensorflowlite_jni.so", // 其它按偏移加载的框架
}

// detectHighRisk 扫描 APK 的 lib/ 条目，返回命中的高危框架库名（有序去重）。
//
// 这是**启发式**审计，不是 DEX 调用点扫描：它只能识别已知的框架特征。
// 完整审计（遍历 DEX 指令流找 System.loadLibrary / System.load / Runtime.load
// 的调用点与字面名）尚未实现，这一点必须在报告里如实说明。
func detectHighRisk(art *pipeline.Artifact) []string {
	found := map[string]bool{}
	for _, e := range art.Entries() {
		n := e.NameString()
		if !strings.HasPrefix(n, "lib/") || !strings.HasSuffix(n, ".so") {
			continue
		}
		base := n
		if i := strings.LastIndex(n, "/"); i >= 0 {
			base = n[i+1:]
		}
		for _, h := range highRiskFrameworks {
			if base == h {
				found[base] = true
			}
		}
	}
	if len(found) == 0 {
		return nil
	}
	out := make([]string, 0, len(found))
	for k := range found {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (e *encryptNativeLibs) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	// 两个开关等价：-so-encrypt（Options.SOEncrypt）与 -enable C2。
	// 任一置位即生效；都未置位时说明该 Pass 被误调用（正常流水线不会调用
	// 未启用的 Pass），返回 nil 并留痕，避免静默。
	if !opts.SOEncrypt && !opts.IsEnabled("C2") {
		art.Note("C2 SO 加壳：未启用（-so-encrypt 与 -enable C2 均未置位），未做任何改动")
		return nil
	}

	// 收集待加密的业务 .so。必须排除工具自己注入的 libapkguard.so：
	// 加密它会让 C1/C4/C5/C6/D4 的 native 桥接全崩。
	type target struct {
		entry *zipx.Entry
		abi   string
		name  string
	}
	var targets []target
	abiSet := map[string]bool{}
	for _, en := range art.Entries() {
		n := en.NameString()
		if !strings.HasPrefix(n, "lib/") || !strings.HasSuffix(n, ".so") {
			continue
		}
		parts := strings.Split(n, "/")
		if len(parts) < 3 {
			continue
		}
		base := parts[len(parts)-1]
		if base == native.LibFileName {
			continue // 桥接库始终留在 lib/，壳自身要用
		}
		abiSet[parts[1]] = true
		targets = append(targets, target{entry: en, abi: parts[1], name: base})
	}

	abis := make([]string, 0, len(abiSet))
	for a := range abiSet {
		abis = append(abis, a)
	}
	sort.Strings(abis)

	if len(targets) == 0 {
		// 纯 Java 应用（如 Dhizuku）走这里：合法空操作，不是缺陷。
		art.Note("C2 SO 加壳：APK 不含业务原生库（lib/ 下无 .so），空操作")
		art.Stat("C2.libs", "0")
		return nil
	}

	// 框架特征审计：命中即整体跳过，避免破坏 Flutter/RN/Unity 类应用。
	if risky := detectHighRisk(art); len(risky) > 0 {
		art.Note("C2 SO 加壳：检测到 native 自加载框架特征（%s），判定为不可整文件加密，"+
			"已跳过全部 %d 个 .so（这些框架常用 android_dlopen_ext 从 APK 按偏移加载，移走 lib/ 会让应用启动即崩，且无法用 librarySearchPath 挽救）",
			strings.Join(risky, "、"), len(targets))
		art.Stat("C2.skipped_frameworks", strings.Join(risky, ","))
		art.Stat("C2.libs", "0")
		return nil
	}

	key, err := payloadKey(art, opts)
	if err != nil {
		return err
	}

	used := map[string]bool{}
	for _, en := range art.Entries() {
		used[en.NameString()] = true
	}

	// 按 ABI、文件名排序，保证产物可复现。
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].abi != targets[j].abi {
			return targets[i].abi < targets[j].abi
		}
		return targets[i].name < targets[j].name
	})

	items := make([]soItem, 0, len(targets))
	plainTotal, blobTotal := 0, 0
	for _, t := range targets {
		data, err := t.entry.Data()
		if err != nil {
			return fmt.Errorf("读取 %s 失败: %w", t.entry.NameString(), err)
		}
		asset := soAssetName(opts.Seed, t.abi, t.name)
		for i := 1; used[asset]; i++ {
			asset = soAssetName(opts.Seed+fmt.Sprint(i), t.abi, t.name)
		}
		used[asset] = true

		blob, err := pack.Encrypt(data, key, pack.IVFromSeed(opts.Seed+"/so/"+t.abi+"/"+t.name))
		if err != nil {
			return fmt.Errorf("加密 %s 失败: %w", t.entry.NameString(), err)
		}
		if opts.PayloadMAC {
			// 与 B1 完全同规格的 encrypt-then-MAC：tag = HMAC-SHA256(macKey,
			// 原始库名 ‖ IV‖密文)，追加在密文尾部。
			//
			// 绑定**原始库名**（t.name，如 "libfoo.so"）而不是 assets 条目名：
			// 与 B1 绑定原始 DEX 名同理，改名后的合法产物在校验侧仍能对上，
			// 且不同库的载荷无法互换。
			blob = append(blob, pack.MAC(blob, key, t.name)...)
		}
		// 与 B1 一致：密文熵值接近 8，必须 Stored（Deflate 无收益且徒增运行时开销）。
		pipeline.Add(art, zipx.NewStored(asset, blob))
		items = append(items, soItem{
			Abi: t.abi, Name: t.name, Entry: t.entry.NameString(),
			Asset: asset, Size: len(blob), Plain: len(data),
		})
		plainTotal += len(data)
		blobTotal += len(blob)
	}

	// 移除明文 .so。逐个按条目名精确移除，避免误伤 libapkguard.so。
	remove := map[string]bool{}
	for _, it := range items {
		remove[it.Entry] = true
	}
	n := pipeline.Remove(art, func(en *zipx.Entry) bool { return remove[en.NameString()] })
	if n != len(items) {
		return fmt.Errorf("应移除 %d 个明文 .so，实际移除 %d 个", len(items), n)
	}

	art.Put(sharedKeySOLibs, &shellSOLibs{Key: key, Items: items, Abis: abis, MAC: opts.PayloadMAC})

	if opts.PayloadMAC {
		art.Note("C2 SO 加壳：%d 个原生库（ABI：%s）已从 lib/ 移除并加密存入 assets（%d → %d 字节）；"+
			"每个载荷尾部附 32 字节 HMAC-SHA256（encrypt-then-MAC，绑定原始库名），壳解密前先校验；"+
			"壳将在启动时解密到私有目录，并把该目录并入库搜索路径；原始 ABI 集合已记录供 C1 使用",
			len(items), strings.Join(abis, "、"), plainTotal, blobTotal)
		art.Stat("C2.mac", "1")
		art.Stat("C2.mac_bytes", fmt.Sprint(pack.TagSize*len(items)))
	} else {
		art.Note("C2 SO 加壳：%d 个原生库（ABI：%s）已从 lib/ 移除并加密存入 assets（%d → %d 字节）；"+
			"壳将在启动时解密到私有目录，并把该目录并入库搜索路径；原始 ABI 集合已记录供 C1 使用",
			len(items), strings.Join(abis, "、"), plainTotal, blobTotal)
		art.Stat("C2.mac", "0")
	}
	art.Stat("C2.libs", fmt.Sprint(len(items)))
	art.Stat("C2.abis", strings.Join(abis, ","))
	art.Stat("C2.plain", fmt.Sprint(plainTotal))
	art.Stat("C2.blob", fmt.Sprint(blobTotal))
	return nil
}
