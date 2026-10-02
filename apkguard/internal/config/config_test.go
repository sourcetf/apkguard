package config

import (
	"sort"
	"strings"
	"testing"
)

// TestAllFeaturesUnique 验证功能项 ID 唯一且数量符合设计文档。
//
// 设计文档列了 38 项，另有 2 项按参考样本的手法补充实现（A15 巨型 Manifest
// 填充、B8 载荷容器化、A16~A20 欺骗类、C2 SO 加壳、C7 原生库伪装），因此总数为 46。
func TestAllFeaturesUnique(t *testing.T) {
	fs := All()
	if len(fs) != 46 {
		t.Errorf("功能项数量应为 46，实际 %d", len(fs))
	}
	seen := map[FeatureID]bool{}
	for _, f := range fs {
		if seen[f.ID] {
			t.Errorf("功能项 ID 重复: %s", f.ID)
		}
		seen[f.ID] = true
		if f.Name == "" || f.Desc == "" || f.Group == "" {
			t.Errorf("%s 缺少必填字段", f.ID)
		}
		if f.StageCN == "" || f.RiskCN == "" {
			t.Errorf("%s 未填充中文标注", f.ID)
		}
	}
	// 各前缀数量
	counts := map[byte]int{}
	for _, f := range fs {
		counts[f.ID[0]]++
	}
	want := map[byte]int{'A': 20, 'B': 8, 'C': 7, 'D': 5, 'E': 6}
	for k, v := range want {
		if counts[k] != v {
			t.Errorf("%c 类功能项应为 %d 个，实际 %d", k, v, counts[k])
		}
	}
}

// TestDefaults 验证默认启用项符合设计（仅常规项默认开）。
func TestDefaults(t *testing.T) {
	for _, f := range All() {
		if f.Risk == RiskDangerous && f.Default {
			t.Errorf("危险区功能项 %s 不应默认启用", f.ID)
		}
	}
	// 默认启用的应当是 A1/A2/A3/A4/A14/E1/E2/E3/E6。
	//
	// E6 是产物的静态兼容性自检（DEX 版本、ABI 覆盖、关键条目），
	// 属于「不通过就别发布」的必检项，因此默认开启。
	var on []string
	o := &Options{}
	for _, f := range All() {
		if o.IsEnabled(f.ID) {
			on = append(on, string(f.ID))
		}
	}
	sort.Strings(on)
	want := []string{"A1", "A14", "A2", "A3", "A4", "E1", "E2", "E3", "E6"}
	sort.Strings(want)
	if strings.Join(on, ",") != strings.Join(want, ",") {
		t.Errorf("默认启用项不匹配:\n got=%v\nwant=%v", on, want)
	}
}

// TestGroups 验证分组覆盖全部功能项。
func TestGroups(t *testing.T) {
	total := 0
	for _, g := range Groups() {
		if len(g.Features) == 0 {
			t.Errorf("分组 %s 为空", g.Name)
		}
		total += len(g.Features)
	}
	if total != len(All()) {
		t.Errorf("分组条目总数 %d != 功能项总数 %d", total, len(All()))
	}
}

// TestValidateDependencies 验证依赖校验能拦截非法组合。
func TestValidateDependencies(t *testing.T) {
	// B1 开启但缺少 B2/B3
	o := &Options{In: "a.apk", KS: "k.jks"}
	o.SetEnabled("B1", true)
	err := o.Validate()
	if err == nil {
		t.Fatal("应检出 B1 缺少 B2/B3 依赖")
	}
	if !strings.Contains(err.Error(), "B2") || !strings.Contains(err.Error(), "B3") {
		t.Errorf("错误信息未指出缺失的依赖: %v", err)
	}

	// 补齐依赖后应通过
	o.SetEnabled("B2", true)
	o.SetEnabled("B3", true)
	if err := o.Validate(); err != nil {
		t.Errorf("补齐依赖后仍报错: %v", err)
	}
}

// TestValidateRequired 验证必要参数校验。
func TestValidateRequired(t *testing.T) {
	o := &Options{}
	err := o.Validate()
	if err == nil {
		t.Fatal("缺少输入与密钥库时应报错")
	}
	if !strings.Contains(err.Error(), "输入 APK") || !strings.Contains(err.Error(), "密钥库") {
		t.Errorf("错误信息不完整: %v", err)
	}
}

// TestValidateRanges 验证数值范围校验。
func TestValidateRanges(t *testing.T) {
	o := &Options{In: "a.apk", KS: "k.jks"}
	o.ExtractRatio = 200
	if err := o.Validate(); err == nil || !strings.Contains(err.Error(), "抽取比例") {
		t.Errorf("应检出抽取比例越界: %v", err)
	}
	o.ExtractRatio = 0
	o.ObfStringMin = -1
	if err := o.Validate(); err == nil || !strings.Contains(err.Error(), "最小加密长度") {
		t.Errorf("应检出负值: %v", err)
	}
}

// TestEnabledIDs 验证启用项列表有序。
func TestEnabledIDs(t *testing.T) {
	o := &Options{}
	o.SetEnabled("C4", true)
	o.SetEnabled("A1", false)
	ids := o.EnabledIDs()
	if len(ids) == 0 {
		t.Fatal("启用列表为空")
	}
	for i := 1; i < len(ids); i++ {
		if ids[i-1] >= ids[i] {
			t.Errorf("启用列表未按字典序: %v", ids)
			break
		}
	}
	for _, id := range ids {
		if id == "A1" {
			t.Error("A1 已显式关闭，不应出现在启用列表")
		}
	}
}

// TestValidateKeystoreOnlyWhenSigning 验证密钥库只在启用签名时才必需。
//
// 未启用 E1 时产物本就是未签名 APK，「必须指定密钥库」会把
// 「只做加固、自己签名」这一正当用法挡在门外。
func TestValidateKeystoreOnlyWhenSigning(t *testing.T) {
	o := &Options{
		Enabled: map[FeatureID]bool{"E1": false},
		In:      "a.apk",
	}
	if err := o.Validate(); err != nil {
		t.Fatalf("禁用签名时不应要求密钥库: %v", err)
	}
	// 启用签名（或使用默认值，E1 默认为开）时必须要求密钥库。
	o2 := &Options{Enabled: map[FeatureID]bool{"E1": true}, In: "a.apk"}
	err := o2.Validate()
	if err == nil || !strings.Contains(err.Error(), "密钥库") {
		t.Fatalf("启用签名时应要求密钥库，实际: %v", err)
	}
	if err := (&Options{In: "a.apk"}).Validate(); err == nil {
		t.Fatal("默认配置启用了签名，缺少密钥库时应报错")
	}
}
