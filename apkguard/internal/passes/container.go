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
// 手法来自参考样本（`sample.apk`）：它的真实载荷藏在
// `assets/<随机名>.zip` 里，zip 内是 `*.dat`（14.4 MB 密文）与 `*.json`，
// 而 json 里写的包名是 `dummy.installed.check`——与真实包名无关。
// 效果是：按 assets 顶层逐个解密的分析脚本会先撞上容器与假包名。
//
// 我们的实现分两件事，都不需要改加载器：
//
//  1. **载荷重定位**：把真实载荷从 `assets/<word>_<hex>.<ext>` 移到
//     `assets/<容器路径>/...` 的目录树里。B3 生成 Loader 时读的是载荷清单里的
//     Asset 字段，路径本就参数化，因此壳侧零改动。
//  2. **诱饵容器**：另植入一个 `assets/<名字>.zip`，内含高熵的 `.dat`
//     （随机字节，看起来就是加密载荷）与一份配置 JSON（假包名 + 假文件名），
//     与样本的容器同构。分析者会优先怀疑它。
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
		e.Name = []byte(name)
		sp.Items[i].Asset = name
		renamed++
	}

	// 诱饵容器：内容与样本同构（一个高熵 .dat + 一份配置 JSON）。
	decoyPkg := strings.TrimSpace(opts.DecoyPkg)
	if decoyPkg == "" {
		decoyPkg = defaultDecoyPkg
	}
	decoyName := "assets/" + seg1 + "_" + seg2 + ".zip"
	// 体积取真实载荷总量的 2%（至少 256 KB）：太小会被一眼看作占位文件。
	decoySize := packTotal(sp) / 50
	if decoySize < 256<<10 {
		decoySize = 256 << 10
	}
	if decoySize > 4<<20 {
		decoySize = 4 << 20
	}
	blob, err := decoyContainer(opts.Seed, decoyName, decoyPkg, decoySize)
	if err != nil {
		return err
	}
	pipeline.Add(art, zipx.NewStored(decoyName, blob))

	art.Put(sharedKeyPayloads, sp)

	art.Note("B8 载荷容器化：%d 份载荷移入 %s/（顶层 assets 不再直接暴露载荷）；"+
		"另植入诱饵容器 %s（内含高熵 .dat 与假包名 %q 的配置）",
		renamed, tree, decoyName, decoyPkg)
	art.Stat("B8.moved", fmt.Sprint(renamed))
	art.Stat("B8.tree", tree)
	art.Stat("B8.decoy", decoyName)
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

// decoyContainer 生成一个内含「高熵 .dat + 配置 JSON」的 zip。
//
// 用 zipx 自己的写入器构造：产物与真实 APK 的打包路径一致，
// 不会因为用了不同的压缩实现而露出「这个 zip 不是同一个工具产的」这一类痕迹。
func decoyContainer(seed, containerName, decoyPkg string, size int) ([]byte, error) {
	base := strings.TrimSuffix(pathBase(containerName), ".zip")
	rnd := newRand(seed + "/decoy")
	dat := make([]byte, size)
	for i := range dat {
		dat[i] = byte(rnd.Intn(256))
	}
	// 让 .dat 开头也像加密载荷（前置 16 字节 IV 的可辨识特征不存在，
	// 因此纯随机即可；这里刻意不要放任何 magic）。
	cfg, err := json.MarshalIndent(decoyConfig{
		PackageName: decoyPkg,
		AppName:     base,
		APKFileName: base + ".dat",
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("B8：生成诱饵配置失败: %w", err)
	}

	archive := &zipx.Archive{}
	archive.Entries = append(archive.Entries, zipx.NewStored(base+".dat", dat))
	archive.Entries = append(archive.Entries, zipx.NewStored(base+".json", cfg))
	return zipx.Write(archive, zipx.AlignOptions{Align: 1, SoAlign: 1}), nil
}

// pathBase 返回路径的最后一段。
func pathBase(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}
