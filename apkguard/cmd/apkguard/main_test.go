package main

import (
	"flag"
	"testing"
)

// TestReturnNopsFlagDefault 钉住 A20 第二形态的默认值：
// 未显式传 -return-nops 时 ReturnNops=true；只有显式 -return-nops=false 才关闭。
//
// A20 本身是非默认功能；这条测试保证「一旦启用 A20，就默认带参考样本的
// return 前单发 nop 形态」，同时保留显式关闭的能力。
func TestReturnNopsFlagDefault(t *testing.T) {
	parse := func(args ...string) cliConfig {
		t.Helper()
		var c cliConfig
		fs := flag.NewFlagSet("apkguard-test", flag.ContinueOnError)
		registerFlags(fs, &c)
		if err := fs.Parse(args); err != nil {
			t.Fatalf("解析 %v 失败: %v", args, err)
		}
		return c
	}

	if c := parse(); !c.returnNops {
		t.Fatal("未显式传 -return-nops 时默认应为 true（A20 一旦启用即带 return 前 nop 形态）")
	}
	if c := parse("-return-nops=false"); c.returnNops {
		t.Fatal("显式 -return-nops=false 应关闭该形态")
	}
	if c := parse("-return-nops=true"); !c.returnNops {
		t.Fatal("显式 -return-nops=true 应开启")
	}

	// 配置透传：默认开与显式关都必须原样进入 buildOptions。
	opts, err := buildOptions(parse())
	if err != nil {
		t.Fatalf("buildOptions 失败: %v", err)
	}
	if !opts.ReturnNops {
		t.Fatal("buildOptions 未把默认开启的 ReturnNops 透传下去")
	}
	opts, err = buildOptions(parse("-return-nops=false"))
	if err != nil {
		t.Fatalf("buildOptions 失败: %v", err)
	}
	if opts.ReturnNops {
		t.Fatal("buildOptions 未透传显式关闭的 ReturnNops")
	}
}

// TestRenameResourceIDsFlagDefault 钉住 A1 R 类改名的默认值：
// 未显式传 -rename-resource-ids 时 RenameResourceIDs=true；只有显式
// -rename-resource-ids=false 才关闭。
//
// 与 ReturnNops 同一模式：默认值由 CLI flag 提供，config.Options 的 JSON 零值
// 仍是 false（API 调用方不传该字段即视为关闭）。
func TestRenameResourceIDsFlagDefault(t *testing.T) {
	parse := func(args ...string) cliConfig {
		t.Helper()
		var c cliConfig
		fs := flag.NewFlagSet("apkguard-test", flag.ContinueOnError)
		registerFlags(fs, &c)
		if err := fs.Parse(args); err != nil {
			t.Fatalf("解析 %v 失败: %v", args, err)
		}
		return c
	}

	if c := parse(); !c.renameResourceIDs {
		t.Fatal("未显式传 -rename-resource-ids 时默认应为 true（对齐参考样本的 R 类改名）")
	}
	if c := parse("-rename-resource-ids=false"); c.renameResourceIDs {
		t.Fatal("显式 -rename-resource-ids=false 应关闭 R 类改名")
	}
	if c := parse("-rename-resource-ids=true"); !c.renameResourceIDs {
		t.Fatal("显式 -rename-resource-ids=true 应开启")
	}

	// 配置透传：默认开与显式关都必须原样进入 buildOptions。
	opts, err := buildOptions(parse())
	if err != nil {
		t.Fatalf("buildOptions 失败: %v", err)
	}
	if !opts.RenameResourceIDs {
		t.Fatal("buildOptions 未把默认开启的 RenameResourceIDs 透传下去")
	}
	opts, err = buildOptions(parse("-rename-resource-ids=false"))
	if err != nil {
		t.Fatalf("buildOptions 失败: %v", err)
	}
	if opts.RenameResourceIDs {
		t.Fatal("buildOptions 未透传显式关闭的 RenameResourceIDs")
	}
}

// TestNewCapabilityFlags 钉住本轮新增 6 个 flag 的默认值与透传：
// -rename-libraries / -dual-apk 默认 false，-extract-methods / -vmp-methods /
// -dex2c-methods 默认 0（0=关闭），-ndk-path 默认空（自动探测）。
//
// 与 ReturnNops/RenameResourceIDs 同一模式：默认值由 CLI flag 提供，
// config.Options 的 JSON 零值仍是 false/0/""（API 调用方不传即关闭）。
func TestNewCapabilityFlags(t *testing.T) {
	parse := func(args ...string) cliConfig {
		t.Helper()
		var c cliConfig
		fs := flag.NewFlagSet("apkguard-test", flag.ContinueOnError)
		registerFlags(fs, &c)
		if err := fs.Parse(args); err != nil {
			t.Fatalf("解析 %v 失败: %v", args, err)
		}
		return c
	}

	// 默认值
	c := parse()
	if c.renameLibraries || c.dualAPK {
		t.Fatal("-rename-libraries / -dual-apk 默认应为 false")
	}
	if c.extractMethods != 0 || c.vmpMethods != 0 || c.dex2cMethods != 0 {
		t.Fatal("-extract-methods / -vmp-methods / -dex2c-methods 默认应为 0（关闭）")
	}
	if c.ndkPath != "" {
		t.Fatal("-ndk-path 默认应为空（自动探测）")
	}
	opts, err := buildOptions(parse())
	if err != nil {
		t.Fatalf("buildOptions 失败: %v", err)
	}
	if opts.RenameLibraries || opts.DualAPK || opts.ExtractMethods != 0 ||
		opts.VMPMethods != 0 || opts.Dex2CMethods != 0 || opts.NDKPath != "" {
		t.Fatalf("默认值未原样透传: %+v", opts)
	}

	// 显式设置后必须原样进入 buildOptions。
	opts, err = buildOptions(parse(
		"-rename-libraries", "-dual-apk",
		"-extract-methods=25", "-vmp-methods=5", "-dex2c-methods=7",
		"-ndk-path=/opt/android-ndk"))
	if err != nil {
		t.Fatalf("buildOptions 失败: %v", err)
	}
	if !opts.RenameLibraries || !opts.DualAPK {
		t.Fatal("buildOptions 未透传 -rename-libraries / -dual-apk")
	}
	if opts.ExtractMethods != 25 || opts.VMPMethods != 5 || opts.Dex2CMethods != 7 {
		t.Fatalf("方法数上限透传错误: extract=%d vmp=%d dex2c=%d",
			opts.ExtractMethods, opts.VMPMethods, opts.Dex2CMethods)
	}
	if opts.NDKPath != "/opt/android-ndk" {
		t.Fatalf("NDKPath 透传错误: %q", opts.NDKPath)
	}
}
