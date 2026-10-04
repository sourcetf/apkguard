package dex2c

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// AbiNames 返回受支持 ABI 的固定顺序（与 internal/native 的预编译库一致）。
func AbiNames() []string { return []string{"arm64-v8a", "armeabi-v7a", "x86_64"} }

// abiTriple 是 ABI -> NDK clang 目标三元组（API 24，与签名默认 minSdk 一致）。
var abiTriple = map[string]string{
	"arm64-v8a":   "aarch64-linux-android24",
	"armeabi-v7a": "armv7a-linux-androideabi24",
	"x86_64":      "x86_64-linux-android24",
}

// abiELFMachine 是各 ABI 对应的 ELF e_machine 期望值。
var abiELFMachine = map[string]elf.Machine{
	"arm64-v8a":   elf.EM_AARCH64,
	"armeabi-v7a": elf.EM_ARM,
	"x86_64":      elf.EM_X86_64,
}

// WSLDistroEnv 是指定 WSL 发行版的环境变量名。
//
// 当 -ndk-path 是 Linux 路径（形如 /home/...）而工具运行在 Windows 上时，
// B7 会通过 WSL 调用该路径下的 clang；默认发行版可能是 docker-desktop
// 之类的非开发发行版，因此允许用该环境变量显式指定，如
//
//	APKGUARD_WSL_DISTRO=Ubuntu-26.04
const WSLDistroEnv = "APKGUARD_WSL_DISTRO"

// NDK 是一个已定位的 Android NDK。
type NDK struct {
	// Root 是 NDK 根目录（调用方传入或探测到的原样路径）。
	Root string
	// BinDir 是 toolchains/llvm/prebuilt/<host>/bin。
	BinDir string
	// Clang 是 clang 可执行文件路径。
	Clang string
	// ViaWSL 为真表示路径是 Linux 路径，需要经 wsl 调用。
	ViaWSL bool
	// Distro 是 WSL 发行版（空表示用默认发行版）。
	Distro string
}

// FindNDK 定位 NDK：显式路径优先，其次环境变量与常见安装位置。
//
// 失败时返回的错误一定包含「NDK」，便于 CLI/GUI 给出明确提示。B7 的哲学是
// 「宁可失败，绝不静默地产出一个没有 Dex2C 的 Dex2C 产物」。
func FindNDK(path string) (*NDK, error) {
	distro := os.Getenv(WSLDistroEnv)
	if path != "" {
		if n := probeNDK(path, distro); n != nil {
			return n, nil
		}
		return nil, fmt.Errorf("B7: -ndk-path %q 不是可用的 Android NDK："+
			"需要包含 toolchains/llvm/prebuilt/<host>/bin/clang（NDK r26+）；"+
			"Windows 上也可以指定 WSL 里的 Linux 路径（配合 %s 指定发行版）", path, WSLDistroEnv)
	}
	for _, c := range ndkCandidates() {
		if n := probeNDK(c, distro); n != nil {
			return n, nil
		}
	}
	return nil, fmt.Errorf("B7: 未找到 Android NDK（Dex2C 需要 NDK 交叉编译生成的 C 代码）：" +
		"请安装 NDK r26+ 并用 -ndk-path 指定根目录，或设置 ANDROID_NDK_HOME；" +
		"Windows 上指定 WSL 中的 Linux 路径时可用 " + WSLDistroEnv + " 指定发行版")
}

// ndkCandidates 返回按优先级排列的候选 NDK 根目录（不重复）。
func ndkCandidates() []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, env := range []string{"ANDROID_NDK_HOME", "ANDROID_NDK_ROOT"} {
		add(os.Getenv(env))
	}
	for _, sdkEnv := range []string{"ANDROID_HOME", "ANDROID_SDK_ROOT"} {
		addLatestNDK(filepath.Join(os.Getenv(sdkEnv), "ndk"), add)
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		addLatestNDK(filepath.Join(home, "android-sdk", "ndk"), add)
		addLatestNDK(filepath.Join(home, "AppData", "Local", "Android", "Sdk", "ndk"), add)
	}
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		addLatestNDK(filepath.Join(local, "Android", "Sdk", "ndk"), add)
	}
	return out
}

// addLatestNDK 把目录下版本号最大的若干 NDK 加入候选（与 build_native.py 一致）。
func addLatestNDK(dir string, add func(string)) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	for _, n := range names {
		add(filepath.Join(dir, n))
	}
}

// probeNDK 检查一个候选路径是否是可用 NDK；不可用返回 nil。
func probeNDK(root, distro string) *NDK {
	prebuilt := filepath.Join(root, "toolchains", "llvm", "prebuilt")
	if hosts, err := os.ReadDir(prebuilt); err == nil {
		order := hostOrder()
		for _, want := range order {
			for _, h := range hosts {
				if !h.IsDir() || h.Name() != want {
					continue
				}
				bin := filepath.Join(prebuilt, h.Name(), "bin")
				clang := findClang(bin)
				if clang != "" {
					return &NDK{Root: root, BinDir: bin, Clang: clang}
				}
			}
		}
		// 目录名千差万别时退一步：任意 host 目录中找 clang。
		for _, h := range hosts {
			if !h.IsDir() {
				continue
			}
			bin := filepath.Join(prebuilt, h.Name(), "bin")
			if clang := findClang(bin); clang != "" {
				return &NDK{Root: root, BinDir: bin, Clang: clang}
			}
		}
	}
	// Windows 上允许指定 WSL 内的 Linux 路径。
	if runtime.GOOS == "windows" && strings.HasPrefix(filepath.ToSlash(root), "/") {
		bin := strings.TrimSuffix(filepath.ToSlash(root), "/") + "/toolchains/llvm/prebuilt/linux-x86_64/bin"
		clang := bin + "/clang"
		if wslFileExecutable(distro, clang) {
			return &NDK{Root: root, BinDir: bin, Clang: clang, ViaWSL: true, Distro: distro}
		}
	}
	return nil
}

// hostOrder 返回本机优先的 prebuilt host 目录名。
func hostOrder() []string {
	switch runtime.GOOS {
	case "windows":
		return []string{"windows-x86_64", "linux-x86_64", "darwin-x86_64"}
	case "darwin":
		return []string{"darwin-x86_64", "darwin-arm64", "linux-x86_64"}
	default:
		return []string{"linux-x86_64"}
	}
}

// findClang 在 bin 目录里找可用的 clang。
func findClang(bin string) string {
	for _, name := range []string{"clang", "clang.exe"} {
		p := filepath.Join(bin, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	// 回退到三元组包装脚本（.cmd 需要经 cmd.exe 调用）。
	for _, abi := range AbiNames() {
		t := abiTriple[abi]
		for _, name := range []string{t + "-clang.cmd", t + "-clang"} {
			p := filepath.Join(bin, name)
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p
			}
		}
	}
	return ""
}

// wslFileExecutable 检查 WSL 内某个文件是否存在且可执行。
//
// 刻意经 `sh -c` 调用：直接 `wsl -e test -x <path>` 时 wsl.exe 会把 `-x`
// 当成自己的参数（实测返回 E_UNEXPECTED/127），必须在 shell 里执行。
func wslFileExecutable(distro, path string) bool {
	script := "test -x '" + strings.ReplaceAll(path, "'", `'\''`) + "'"
	args := wslPrefix(distro)
	args = append(args, "-e", "sh", "-c", script)
	return exec.Command("wsl", args...).Run() == nil
}

// wslPrefix 返回 wsl 命令的前缀参数。
func wslPrefix(distro string) []string {
	if distro != "" {
		return []string{"-d", distro}
	}
	return nil
}

// CompileFlags 返回交叉编译一个 ABI 的完整参数（不含 clang 自身与文件名）。
//
// 关键项：
//   - -Wl,-z,max-page-size=16384：Android 15+ 的 16 KB 页要求（与守卫库一致）；
//   - -fvisibility=hidden：不导出内部符号，只保留 JNIEXPORT 的注册入口；
//   - --build-id=none / 无 -g：保证同输入逐字节可复现。
func CompileFlags(triple, out, src string) []string {
	return []string{
		"--target=" + triple,
		"-shared", "-O2", "-fPIC", "-std=gnu11",
		"-fvisibility=hidden",
		"-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
		"-Wl,-z,max-page-size=16384",
		"-Wl,-z,relro", "-Wl,-z,now",
		"-Wl,--gc-sections", "-Wl,-s", "-Wl,--build-id=none",
		"-o", out, src,
	}
}

// Compile 在 dir 目录下把 src 编译成 out（相对文件名），返回命令输出。
func (n *NDK) Compile(dir, abi, src, out string) (string, error) {
	triple, ok := abiTriple[abi]
	if !ok {
		return "", fmt.Errorf("B7: 不支持的 ABI %q", abi)
	}
	args := CompileFlags(triple, out, src)
	var cmd *exec.Cmd
	if n.ViaWSL {
		a := wslPrefix(n.Distro)
		a = append(a, "-e", n.Clang)
		a = append(a, args...)
		cmd = exec.Command("wsl", a...)
	} else if strings.HasSuffix(strings.ToLower(n.Clang), ".cmd") || strings.HasSuffix(strings.ToLower(n.Clang), ".bat") {
		a := append([]string{"/c", n.Clang}, args...)
		cmd = exec.Command("cmd.exe", a...)
	} else {
		cmd = exec.Command(n.Clang, args...)
	}
	cmd.Dir = dir
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	logLine := "cmd: " + strings.Join(cmd.Args, " ") + "\n"
	if err := cmd.Run(); err != nil {
		return logLine + buf.String(), fmt.Errorf("B7: NDK clang 编译 %s 失败: %v\n命令: %s\n输出:\n%s",
			abi, err, strings.Join(cmd.Args, " "), buf.String())
	}
	return logLine + buf.String(), nil
}

// VerifyELF 校验编译产物是目标 ABI 的合法 ELF，且全部 PT_LOAD 满足 16 KB 页对齐。
func VerifyELF(data []byte, abi string) error {
	if len(data) == 0 {
		return fmt.Errorf("B7: %s 的编译产物为空", abi)
	}
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("B7: %s 的编译产物不是合法 ELF: %w", abi, err)
	}
	defer f.Close()
	want, ok := abiELFMachine[abi]
	if !ok {
		return fmt.Errorf("B7: 不支持的 ABI %q", abi)
	}
	if f.Machine != want {
		return fmt.Errorf("B7: %s 的 ELF Machine=%s，期望 %s", abi, f.Machine, want)
	}
	if f.Type != elf.ET_DYN {
		return fmt.Errorf("B7: %s 的 ELF 类型为 %s，期望共享库 ET_DYN", abi, f.Type)
	}
	loads := 0
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		loads++
		if p.Align < 0x4000 {
			return fmt.Errorf("B7: %s 的 PT_LOAD p_align=0x%x < 0x4000（Android 15+ 16KB 页要求）",
				abi, p.Align)
		}
	}
	if loads == 0 {
		return fmt.Errorf("B7: %s 的 ELF 没有 PT_LOAD 段", abi)
	}
	return nil
}

// ReadLoadAlignments 返回 ELF 全部 PT_LOAD 的 p_align（供测试/报告使用）。
func ReadLoadAlignments(data []byte) ([]uint64, error) {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []uint64
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			out = append(out, p.Align)
		}
	}
	return out, nil
}
