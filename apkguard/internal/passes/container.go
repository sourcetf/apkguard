package passes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"apkguard/internal/config"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// ---- B8 载荷容器化 + 诱饵配置 ----
//
// 手法来自参考样本（`sample.apk`）：真实载荷藏在容器里，容器内是密文与一份
// 写着假包名的配置 JSON。效果是：按 assets 顶层逐个解密的分析脚本会先撞上
// 假线索。
//
// 我们的实现分两件事，都不需要改加载器：
//
//  1. **载荷重定位**：把真实载荷移进 `assets/<词>/<hex8>/<hex12>.<ext>` 的
//     目录树里。B3 生成 Loader 时读的是载荷清单里的 Asset 字段，路径本就参数化，
//     因此壳侧零改动。
//  2. **诱饵容器**：在**同一个目录树**里另植入诱饵文件，内容是高熵随机字节，
//     外加一份写着假包名的配置 JSON。关键要求是**与真实载荷同构**——同样的
//     路径形态、同样的扩展名集合、同样的字节观感。
//
// 为什么必须同构：早期实现把诱饵放成顶层 `assets/<词>_<hex>.zip`（带 PK 头），
// 脱壳脚本只要「找 PK 头」就能直接锁定诱饵、跳过真载荷，等于用排除法替攻击者
// 定位了真目标。现在从路径到字节都无法区分，排除法失效。
type payloadContainer struct{}

func (payloadContainer) ID() config.FeatureID { return "B8" }
func (payloadContainer) In() pipeline.Level   { return pipeline.LevelZip }
func (payloadContainer) Out() pipeline.Level  { return pipeline.LevelZip }

// defaultDecoyPkg 是诱饵配置里写的「包名」。
//
// 刻意用一个与业务无关、又像是系统/安装器组件的名字：
// 分析者按包名检索时会先去找它，而它在这个 APK 里根本不存在。
const defaultDecoyPkg = "dummy.installed.check"

func (c *payloadContainer) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	sp := payloadsOf(art)
	if sp == nil || len(sp.Items) == 0 {
		return fmt.Errorf("B8 需要先启用 B1（DEX 整体加密）产生载荷")
	}

	// 容器目录：由种子与包名派生，看起来像「某个组件的缓存目录」。
	sum := sha256.Sum256([]byte("apkguard/container/" + opts.Seed))
	seg1 := containerWords[int(sum[0])%len(containerWords)]
	seg2 := hex.EncodeToString(sum[1:5])
	tree := "assets/" + seg1 + "/" + seg2

	renamed := 0
	for i := range sp.Items {
		e := pipeline.Find(art, sp.Items[i].Asset)
		if e == nil {
			continue
		}
		d := sha256.Sum256([]byte("apkguard/container/item/" + opts.Seed + "/" + sp.Items[i].Name))
		name := fmt.Sprintf("%s/%s.%s", tree, hex.EncodeToString(d[:6]), containerExts[int(d[6])%len(containerExts)])
		// 与诱饵同名时错开，避免重名条目（apksigner 会以 Duplicate entry 拒绝整个归档）。
		for pipeline.Find(art, name) != nil {
			d = sha256.Sum256(d[:])
			name = fmt.Sprintf("%s/%s.%s", tree, hex.EncodeToString(d[:6]), containerExts[int(d[6])%len(containerExts)])
		}
		e.Name = []byte(name)
		sp.Items[i].Asset = name
		renamed++
	}

	// C2 的原生库载荷也必须一起搬走。
	//
	// 只搬 B1 的 DEX 载荷是不够的：C2 的库载荷当时仍以顶层
	// `assets/<词>_<hex>.<ext>` 存在，而它往往是**整个 APK 里最大的 assets
	// 条目**（termux 的 libtermux.so 加密后 28 MB，比任何单个 DEX 载荷都大）。
	// 「按体积抓最大的 assets 条目」的脱壳脚本一抓就中，B8 想要的「顶层不再
	// 直接暴露载荷」直接落空——留着一份真载荷在顶层，等于给攻击者排除了大量
	// 噪声。B3 在本 Pass 之后才生成壳，读的是 soItem.Asset，所以这里改路径
	// 不需要动壳。
	if sl := soLibsOf(art); sl != nil {
		for i := range sl.Items {
			e := pipeline.Find(art, sl.Items[i].Asset)
			if e == nil {
				continue
			}
			d := sha256.Sum256([]byte("apkguard/container/lib/" + opts.Seed + "/" + sl.Items[i].Abi + "/" + sl.Items[i].Name))
			name := fmt.Sprintf("%s/%s.%s", tree, hex.EncodeToString(d[:6]), containerExts[int(d[6])%len(containerExts)])
			for pipeline.Find(art, name) != nil {
				d = sha256.Sum256(d[:])
				name = fmt.Sprintf("%s/%s.%s", tree, hex.EncodeToString(d[:6]), containerExts[int(d[6])%len(containerExts)])
			}
			e.Name = []byte(name)
			sl.Items[i].Asset = name
			renamed++
		}
		art.Put(sharedKeySOLibs, sl)
	}

	// 诱饵：与真实载荷同构地落进同一个目录树。
	//
	// 体积取真实载荷总量的 2%（至少 256 KB）：太小会被一眼看作占位文件。
	decoySize := packTotal(sp) / 50
	if decoySize < 256<<10 {
		decoySize = 256 << 10
	}
	if decoySize > 4<<20 {
		decoySize = 4 << 20
	}
	decoyPkg := strings.TrimSpace(opts.DecoyPkg)
	if decoyPkg == "" {
		decoyPkg = defaultDecoyPkg
	}
	decoyName := decoyFileName(art, tree, "apkguard/container/decoy/"+opts.Seed)
	blob := decoyBytes(opts.Seed, decoySize)
	pipeline.Add(art, zipx.NewStored(decoyName, blob))

	// 配置 JSON 与样本容器内的 json 同构（假包名），同样落进该目录树。
	// 它是给分析者的假线索，不参与任何加载路径。
	cfgName := decoyJSONName(art, tree, "apkguard/container/decoycfg/"+opts.Seed)
	cfg, err := json.MarshalIndent(decoyConfig{
		PackageName: decoyPkg,
		AppName:     seg1,
		APKFileName: pathBaseName(decoyName),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("B8：生成诱饵配置失败: %w", err)
	}
	pipeline.Add(art, zipx.NewStored(cfgName, cfg))

	art.Put(sharedKeyPayloads, sp)

	art.Note("B8 载荷容器化：%d 份载荷（含 C2 的原生库载荷）移入 %s/（顶层 assets 不再直接暴露载荷）；"+
		"另在同目录树植入同构诱饵 %s（高熵随机字节，无 PK 头）与假包名 %q 的配置，排除法无法区分真假",
		renamed, tree, decoyName, decoyPkg)
	art.Stat("B8.moved", fmt.Sprint(renamed))
	art.Stat("B8.tree", tree)
	art.Stat("B8.decoy", decoyName)
	art.Stat("B8.decoy_cfg", cfgName)
	art.Stat("B8.decoy_pkg", decoyPkg)
	art.Stat("B8.decoy_bytes", fmt.Sprint(len(blob)))
	return nil
}

// containerWords 是容器目录名候选（资源/缓存类词，不暴露用途）。
var containerWords = []string{"core", "cache", "runtime", "support", "vendor", "media", "locale", "feature"}

// containerExts 是容器内载荷的伪装扩展名。
var containerExts = []string{"dat", "bin", "res", "pack"}

// packTotal 返回载荷密文总长。
func packTotal(sp *shellPayloads) int {
	n := 0
	for _, it := range sp.Items {
		n += len(it.Blob)
	}
	return n
}

// decoyConfig 是诱饵容器里的配置 JSON（字段与样本一致）。
type decoyConfig struct {
	PackageName string `json:"packageName"`
	AppName     string `json:"appName"`
	APKFileName string `json:"apkFileName"`
}

// decoyFileName 生成与真实载荷同构的诱饵条目名：同目录、同 <hex12>.<ext> 形态。
//
// deriveKey 种子不同即名字不同；与既有条目（真载荷、配置）冲突时重哈希避让。
func decoyFileName(art *pipeline.Artifact, tree, seed string) string {
	d := sha256.Sum256([]byte(seed))
	for {
		name := fmt.Sprintf("%s/%s.%s", tree, hex.EncodeToString(d[:6]),
			containerExts[int(d[6])%len(containerExts)])
		if pipeline.Find(art, name) == nil {
			return name
		}
		d = sha256.Sum256(d[:])
	}
}

// decoyJSONName 生成诱饵配置 JSON 的同构条目名（同目录树下的 <hex12>.json）。
func decoyJSONName(art *pipeline.Artifact, tree, seed string) string {
	d := sha256.Sum256([]byte(seed))
	for {
		name := fmt.Sprintf("%s/%s.json", tree, hex.EncodeToString(d[:6]))
		if pipeline.Find(art, name) == nil {
			return name
		}
		d = sha256.Sum256(d[:])
	}
}

// decoyBytes 生成高熵随机字节，且刻意不含 PK 头。
//
// 与真实载荷一样是纯随机（前置 16 字节 IV 没有可辨识 magic），
// 因此「找 PK 头 / 找 zip」这类启发式无法把诱饵与真载荷区分开。
// 随机首字节恰好凑成 "PK" 的概率极低，但仍然显式排掉，杜绝偶发魔数。
func decoyBytes(seed string, size int) []byte {
	rnd := newRand(seed + "/decoydata")
	b := make([]byte, size)
	rnd.Read(b)
	if len(b) >= 2 && b[0] == 'P' && b[1] == 'K' {
		b[0] ^= 0xff
	}
	return b
}

// pathBaseName 返回路径的最后一段。
func pathBaseName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}
