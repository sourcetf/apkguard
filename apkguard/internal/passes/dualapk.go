package passes

import (
	"context"
	"fmt"

	"apkguard/internal/config"
	"apkguard/internal/pipeline"
)

// ---- B9 双 APK 投放器 ----
//
// 产物形态的改写发生在**签名之后**（由 pipeline.DefaultSink 在拿到已签名的
// 插件 APK 后调用 pipeline 内部的宿主构建器），因为插件必须是完整、已签名、
// 可被系统安装器接受的 APK；普通 Pass 都跑在签名之前，看不到签名结果。
//
// 因此本 Pass 只承担「启用与前置校验」：
//   - `-enable B9` 时把 opts.DualAPK 置真（与 `-dual-apk` 等价，
//     避免出现「启用了 B9 却什么都没发生」的静默空操作）；
//   - 在插件不可能被安装的组合下 fail-fast（未启用 E1、三种签名方案全禁）。
//
// 一个完整的 host/plugin 拆包流程需要两层 APK 的生命周期管理（双图标、
// 双份卸载、Android 10+ 后台安装限制、Android 14 targetSdk 限制），
// 与「加固自有应用」的定位是冲突的：本功能默认关闭，启用即接受这些代价。
type dualAPK struct{}

func (dualAPK) ID() config.FeatureID { return "B9" }
func (dualAPK) In() pipeline.Level   { return pipeline.LevelZip }
func (dualAPK) Out() pipeline.Level  { return pipeline.LevelZip }

func (d *dualAPK) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	if !opts.IsEnabled("E1") {
		return fmt.Errorf("B9（双 APK 投放器）需要启用 E1（APK 签名）：未签名的插件 APK 无法通过系统安装器安装")
	}
	if opts.NoV1 && opts.NoV2 && opts.NoV3 {
		return fmt.Errorf("B9（双 APK 投放器）要求插件 APK 至少保留 v1/v2/v3 之一，当前三种方案全被禁用，安装器会拒绝插件")
	}
	if pipeline.Find(art, "AndroidManifest.xml") == nil {
		return fmt.Errorf("B9（双 APK 投放器）：产物缺少 AndroidManifest.xml，无法作为插件 APK")
	}
	// 与 -dual-apk 等价：真正的封装在 sink 收尾阶段执行（见 pipeline/dualapk.go）。
	opts.DualAPK = true
	art.Note("B9 双 APK 投放器：已启用——插件将在签名后整体加密进宿主 assets，宿主落地到 getExternalFilesDir()/plugins/ 后用 PackageInstaller 调起系统安装器（需要 REQUEST_INSTALL_PACKAGES，首次需用户确认）")
	art.Stat("B9.mode", "host+plugin")
	return nil
}
