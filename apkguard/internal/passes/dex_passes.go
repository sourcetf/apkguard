package passes

import (
	"context"
	"fmt"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// ---- A4 调试信息清除 ----

// dropDebugInfo 清除 DEX 中的调试信息（SourceFile / LineNumberTable / 局部变量等）。
//
// 实现要点：不直接删字节，而是走 DEX 重建流程——重建时跳过 debug_info_item 的
// 输出并把 code_item 的 debug_info_off 置零，同时清空 class_def 的 source_file_idx。
// 这样能保证索引表与偏移全部自洽。
type dropDebugInfo struct{}

func (dropDebugInfo) ID() config.FeatureID { return "A4" }
func (dropDebugInfo) In() pipeline.Level   { return pipeline.LevelZip }
func (dropDebugInfo) Out() pipeline.Level  { return pipeline.LevelZip }

func (d *dropDebugInfo) Run(_ context.Context, art *pipeline.Artifact, _ *config.Options) error {
	entries := pipeline.FindAll(art, func(e *zipx.Entry) bool {
		return isDexEntry(e)
	})
	if len(entries) == 0 {
		return fmt.Errorf("未找到任何 DEX 条目")
	}

	before := 0
	after := 0
	ok := 0
	for _, e := range entries {
		data, err := e.Data()
		if err != nil {
			// 非标准 DEX（如样本的伪装文件）跳过，不视为失败
			continue
		}
		f, err := dex.Parse(data)
		if err != nil {
			// 解析失败说明不是真正的 DEX，保持原样
			continue
		}
		out, err := dex.Rebuild(f, dex.RebuildOptions{DropDebugInfo: true})
		if err != nil {
			return fmt.Errorf("重建 %s 失败: %w", e.NameString(), err)
		}
		if err := dex.Verify(out); err != nil {
			return fmt.Errorf("%s 重建后校验失败: %w", e.NameString(), err)
		}
		if err := e.SetData(out, true); err != nil {
			return fmt.Errorf("写回 %s 失败: %w", e.NameString(), err)
		}
		before += len(data)
		after += len(out)
		ok++
	}

	if ok == 0 {
		return fmt.Errorf("没有任何 DEX 条目可被解析（可能全部为伪装文件）")
	}
	saved := before - after
	art.Note("A4 调试信息清除：处理 %d 个 DEX，%d → %d 字节（减少 %d，%.1f%%）",
		ok, before, after, saved, pct(saved, before))
	art.Stat("A4.dex", fmt.Sprint(ok))
	art.Stat("A4.before", fmt.Sprint(before))
	art.Stat("A4.after", fmt.Sprint(after))
	art.Stat("A4.saved", fmt.Sprint(saved))
	return nil
}

// isDexEntry 判断条目是否为 DEX 文件（按名字与内容双条件）。
func isDexEntry(e *zipx.Entry) bool {
	name := e.NameString()
	if len(name) < 4 || name[len(name)-4:] != ".dex" {
		return false
	}
	// 内容层面确认 magic（压缩条目先解压）
	data, err := e.Data()
	if err != nil || len(data) < 8 {
		return false
	}
	return string(data[:4]) == "dex\n"
}

// pct 计算 a/b 的百分比。
func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) * 100 / float64(b)
}
