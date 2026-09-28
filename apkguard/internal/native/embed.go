package native

import (
	"embed"
	"fmt"
	"strings"
)

// prebuilt 是交叉编译好的原生库，按 ABI 存放。
//
// 之所以**预编译并内嵌**而不是在加固时调用 NDK：本工具的定位是单文件、
// 无外部依赖（见 main.go 的包注释）。把 .so 编译挪到加固阶段会让每个
// 使用方都必须装一套 NDK，这与定位冲突。代价是 ABI 集合在构建时确定
// （arm64-v8a / armeabi-v7a / x86_64），覆盖当前全部在售 Android 设备。
//
//go:embed prebuilt/*/libapkguard.so
var prebuilt embed.FS

// abis 是支持的 ABI，顺序即写入 APK 的顺序（仅影响报告的可读性）。
var abis = []string{"arm64-v8a", "armeabi-v7a", "x86_64"}

// LibName 是原生库名（对应 libapkguard.so）。
const LibName = "apkguard"

// LibFileName 是原生库在 APK 内的文件名。
const LibFileName = "lib" + LibName + ".so"

// BridgeClass / BridgeClassDesc 是 native 桥接类的 Java 名与 DEX 描述符。
//
// 必须与 apkguard.c 里 JNI 符号名中的包路径一致：
// Java_com_apkguard_nativebridge_Native_derive 里就写死了
// com.apkguard.nativebridge.Native。两者一旦不一致，System.loadLibrary
// 之后调用 native 方法会抛 UnsatisfiedLinkError。
const (
	BridgeClass     = "com.apkguard.nativebridge.Native"
	BridgeClassDesc = "Lcom/apkguard/nativebridge/Native;"
)

// AbiLib 描述一个 ABI 对应的原生库。
type AbiLib struct {
	// Abi 是 ABI 目录名，如 "arm64-v8a"。
	Abi string
	// Entry 是它在 APK 中的条目名，如 "lib/arm64-v8a/libapkguard.so"。
	Entry string
	// Data 是库文件内容。
	Data []byte
}

// Prebuilt 返回全部可用的原生库。
//
// 任何一个 ABI 缺失都视为错误而不是静默跳过：少一个 ABI 就意味着对应
// 架构的设备装不上（Android 在安装时按 ABI 校验原生库），这种问题
// 一旦漏到线上很难定位。
func Prebuilt() ([]AbiLib, error) {
	out := make([]AbiLib, 0, len(abis))
	for _, abi := range abis {
		p := "prebuilt/" + abi + "/" + LibFileName
		data, err := prebuilt.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("native: 缺少 %s 的预编译库 %s: %w", abi, p, err)
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("native: %s 的预编译库为空", abi)
		}
		out = append(out, AbiLib{
			Abi:   abi,
			Entry: "lib/" + abi + "/" + LibFileName,
			Data:  data,
		})
	}
	return out, nil
}

// AbiNames 返回支持的 ABI 列表（有序），用于错误提示。
func AbiNames() string {
	out := make([]string, len(abis))
	copy(out, abis)
	return strings.Join(out, "、")
}

// TotalSize 返回全部原生库的总字节数，用于报告体积增量。
func TotalSize(libs []AbiLib) int {
	n := 0
	for _, l := range libs {
		n += len(l.Data)
	}
	return n
}
