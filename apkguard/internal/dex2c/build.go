package dex2c

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// BuildOptions 控制一次 B7 编译。
type BuildOptions struct {
	// Limit 是翻译方法数上限（>0 才会执行；调用方负责 0=关闭）。
	Limit int
	// Seed 决定方法选取、库名与函数名的确定性扰动。
	Seed string
	// Reflected 是 A7 登记的「按名反射调用」的成员名（可为 nil）。
	Reflected map[string]bool
	// NDK 是已定位的 NDK；Limit>0 且选中方法>0 时必须非 nil。
	NDK *NDK
	// ABIs 是要编译的 ABI 集合；空表示全部 3 个。
	ABIs []string
	// KeepTemp 保留临时构建目录（测试/取证用）。
	KeepTemp bool
}

// Plan 是一次 B7 构建的结果。
type Plan struct {
	// Methods 是最终翻译的方法（顺序即 C 中的定义顺序）。
	Methods []*Method
	// Selection 是选择统计（含全部跳过原因）。
	Selection *Selection
	// CName / LibName 是生成的文件名（不含目录）。
	CName, LibName string
	// CSource 是生成的 C 源（逐字节确定性）。
	CSource []byte
	// SOs 是 ABI -> ELF 字节。
	SOs map[string][]byte
	// ABIs 是实际编译的 ABI（固定顺序）。
	ABIs []string
	// CompileLog 是每个 ABI 的编译命令输出（取证用）。
	CompileLog []string
	// TempDir 在 KeepTemp 时保留，否则为空。
	TempDir string
}

// Build 执行「选择 -> 生成 C -> NDK 交叉编译 -> ELF 校验」。
//
// 一个方法都没选中时不报错：返回带统计的空 Plan，由调用方给出明确提示
// （「没有任何方法满足可翻译子集」与「工具坏了」是两回事）。
func Build(inputs []DexInput, opts BuildOptions) (*Plan, error) {
	sel := Select(inputs, opts.Limit, opts.Seed, opts.Reflected)
	plan := &Plan{Selection: sel, Methods: sel.Methods, SOs: map[string][]byte{}}
	if len(plan.Methods) == 0 {
		return plan, nil
	}
	if opts.NDK == nil {
		return nil, fmt.Errorf("B7: Dex2C 需要 Android NDK 交叉编译（未提供 NDK）")
	}
	abis := opts.ABIs
	if len(abis) == 0 {
		abis = AbiNames()
	}
	for _, a := range abis {
		if _, ok := abiTriple[a]; !ok {
			return nil, fmt.Errorf("B7: 不支持的 ABI %q", a)
		}
	}
	plan.ABIs = abis

	plan.LibName = libNameOf(opts.Seed, plan.Methods)
	plan.CName = fmt.Sprintf("b7_%s.c", plan.LibName[3:len(plan.LibName)-3])
	for i, m := range sel.Methods {
		m.FnName = funcNameOf(opts.Seed+fmt.Sprintf("#%d", i), m)
	}
	csrc, err := generateC(sel.Methods, opts.Seed)
	if err != nil {
		return nil, fmt.Errorf("B7: 生成 C 代码失败: %w", err)
	}
	plan.CSource = csrc

	dir, err := os.MkdirTemp("", "apkguard-b7-")
	if err != nil {
		return nil, fmt.Errorf("B7: 创建临时构建目录失败: %w", err)
	}
	cleanup := !opts.KeepTemp
	if opts.KeepTemp {
		plan.TempDir = dir
	}
	defer func() {
		if cleanup {
			if err := os.RemoveAll(dir); err != nil {
				// Windows 上 WSL/clang 刚退出时偶发文件句柄未释放，稍后重试一次。
				time.Sleep(200 * time.Millisecond)
				_ = os.RemoveAll(dir)
			}
		}
	}()
	srcPath := filepath.Join(dir, plan.CName)
	if err := os.WriteFile(srcPath, csrc, 0o644); err != nil {
		return nil, fmt.Errorf("B7: 写入 C 源失败: %w", err)
	}

	for _, abi := range abis {
		// 每个 ABI 用独立输出名，避免相互覆盖（最终注入 APK 时统一用 LibName）。
		outName := strings.TrimSuffix(plan.LibName, ".so") + "." + abi + ".so"
		logLine, err := opts.NDK.Compile(dir, abi, plan.CName, outName)
		plan.CompileLog = append(plan.CompileLog, "["+abi+"]\n"+logLine)
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(filepath.Join(dir, outName))
		if err != nil {
			return nil, fmt.Errorf("B7: 读取 %s 编译产物失败: %w", abi, err)
		}
		if err := VerifyELF(data, abi); err != nil {
			return nil, err
		}
		plan.SOs[abi] = data
	}
	return plan, nil
}
