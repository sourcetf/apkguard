// 本文件实现 A5/A11 的子行为：资源值字符串的「零宽字符多份化」。
//
// 背景（来自样本 resources.arsc 的逆向结论）：同一个逻辑值在全局字符串池里
// 出现 2~4 份，差异只在 U+200E / U+200F（LRM / RLM）的前后缀数量。作用是
// 打散「按字符串内容做签名/去重/白名单」的规则——同一个值在池里没有唯一
// 字节形态。
//
// 与样本的差异：样本里部分带标记的副本仍被 entry 引用；这里生成的副本
// **一律不被引用**（纯池内垃圾），因此对运行时资源解析零影响：
//   - 只往全局字符串池**末尾追加**，已有条目的下标一律不动，entry 里的
//     字符串索引因此逐条保持有效（中间插入会让其后所有索引平移）；
//   - 追加副本的字节 = 原值 + 零宽标记，不改变任何被引用的值。
//
// 只改全局池意味着表结构里唯一需要回填的是池块自身与表头的长度字段：
// 包块在池之后，其内部偏移（含 268/276 的 typeStrings/keyStrings）全部
// 相对包块自身，不随池增长变化，因此不需要任何重定位。
package arsc

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"

	"apkguard/internal/axml"
)

const (
	// valueTypeString 是 Res_value.dataType == TYPE_STRING：data 是全局
	// 字符串池下标（resource 的字符串值都这么引用）。
	valueTypeString = 0x03

	// 零宽标记字符，与样本一致：LRM 从左到右标记 / RLM 从右到左标记。
	padLRM = '\u200e'
	padRLM = '\u200f'

	// 默认选 20~40 个逻辑值，每个追加 1~3 条副本。
	padMinValues = 20
	padMaxValues = 40
	padMinCopies = 1
	padMaxCopies = 3

	// 重形态：N 个前缀（N 取 90~100）+ 6 个后缀，与样本的
	// 「90~97 前缀 + 6 后缀」一致（这里把 N 上限放宽到 100）。
	padHeavyPrefixMin = 90
	padHeavyPrefixMax = 100
	padHeavySuffix    = 6

	// 超长值不复制：避免大文本被整段复制多份导致体积膨胀。
	// 1024 字节足以覆盖 UI 文案，长文本不是「按内容去重」的主战场。
	padMaxValueLen = 1024

	// 组合编号（padComboXxx）。
	padComboPrefix = 0 // 1 个前缀标记
	padComboSuffix = 1 // 1 个后缀标记
	padComboHeavy  = 2 // N 个前缀 + 6 个后缀
)

// ValuePadOptions 控制资源值零宽副本的生成。
type ValuePadOptions struct {
	// Seed 是确定性随机种子：相同 seed + 相同输入 → 相同产物。
	// 留空时用当前时间（不可复现）。
	Seed string
	// MinValues / MaxValues 限定选中的逻辑值条数（0 表示默认 20 / 40）。
	// 实际条数还会按池大小自适应下调（见 PadValues），因此小表不会被
	// 追加条目撑大占比。
	MinValues, MaxValues int
}

// ValuePadStats 是资源值零宽副本的统计。
type ValuePadStats struct {
	// PoolBefore / PoolAfter 是全局字符串池的条目数。
	PoolBefore, PoolAfter int
	// Referenced 是被 entry 引用的入池字符串值条数（含被排除的形态）。
	Referenced int
	// ExcludedPaths 是因 res/ 前缀被排除的条数（避免与资源路径改名/扫描
	// 互相干扰，见 padableValue）。
	ExcludedShape int
	// Candidates 是按内容去重后的可用逻辑值条数。
	Candidates int
	// Originals 是实际被追加了至少一条副本的逻辑值数。
	Originals int
	// Appended 是追加的副本条数。
	Appended int
	// Single / Heavy 是单标记（1 前缀或 1 后缀）与重前缀形态的条数。
	Single, Heavy int
	// Skipped 是「选定但一条副本都没生成」的逻辑值数（一般只在池里
	// 恰好已存在同字节形态时发生）。
	Skipped int
}

// PadValues 为被 entry 引用的字符串值追加若干带零宽标记的副本到全局池末尾。
//
// 输入必须是完整 RES_TABLE 字节流；返回改写后的字节流（无可追加时返回副本）。
// 结构自洽性：追加后 stringCount、偏移表、stringsStart、池块 size 与表头
// size 全部由同一个字符串池编码器重建（与 keys.go 共用），包块及之后的内容
// 原样搬运——包内偏移相对包块自身，且包块在池之后，整体平移不影响其取值。
func PadValues(data []byte, opts ValuePadOptions) ([]byte, ValuePadStats, error) {
	var st ValuePadStats
	hdr, total, err := tableSpan(data)
	if err != nil {
		return nil, st, err
	}
	pool, err := parseStringPool(data, hdr)
	if err != nil {
		return nil, st, fmt.Errorf("arsc: 解析全局字符串池失败: %w", err)
	}
	st.PoolBefore = len(pool.strings)

	// 1) 收集「被 entry 引用」的全局池下标。遍历失败（块结构异常）时
	//    直接放弃本次追加：少追加只是少一层反去重，不会破坏表。
	refs := map[int]bool{}
	err = forEachTopChunk(data, hdr, total, func(t uint16, p, sz int) bool {
		if t != typePackage {
			return true
		}
		forEachPackageChunk(data, p, sz, func(ct uint16, q, csz int) {
			if ct == typeType {
				collectTypeStringRefs(data, q, csz, refs)
			}
		})
		return true
	})
	if err != nil {
		return nil, st, err
	}

	// 2) 按内容去重、过滤不适合复制的值。升序遍历保证确定性。
	seen := map[string]bool{}
	var cands []padCandidate
	for i, s := range pool.strings {
		if !refs[i] {
			continue
		}
		st.Referenced++
		if strings.HasPrefix(s, "res/") {
			// res/ 路径由 A5/A11 的路径改名单独负责；给路径追加带标记的
			// 副本会让后续 ResPaths 扫描把它们当成新路径（凭空多出映射），
			// 干扰「路径 → ZIP 条目」的一致性，因此排除。
			st.ExcludedShape++
			continue
		}
		if !padableValue(s) {
			st.ExcludedShape++
			continue
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		cands = append(cands, padCandidate{idx: i, val: s})
	}
	st.Candidates = len(cands)
	if len(cands) == 0 {
		st.PoolAfter = st.PoolBefore
		return append([]byte(nil), data...), st, nil
	}

	// 3) 选值：默认 20~40 条，按池大小自适应下调（池的 1/4 为上限），
	//    再受候选数限制。确定性随机源与 keys.go 同一套种子派生。
	rnd := keyRand(opts.Seed)
	lo, hi := opts.MinValues, opts.MaxValues
	if lo <= 0 {
		lo = padMinValues
	}
	if hi < lo {
		hi = lo
	}
	count := lo + rnd.Intn(hi-lo+1)
	if n := len(pool.strings) / 4; n < count {
		count = n
	}
	if count < 1 {
		count = 1
	}
	if count > len(cands) {
		count = len(cands)
	}

	// 4) 逐值生成 1~3 条副本，组合互不相同：单前缀 / 单后缀 / N 前缀+6 后缀。
	//    全部原值先入 seen，副本之间、副本与原值之间都不允许同字节。
	for _, s := range pool.strings {
		seen[s] = true
	}
	var appended []string
	for _, pi := range rnd.Perm(len(cands))[:count] {
		c := cands[pi]
		k := padMinCopies + rnd.Intn(padMaxCopies-padMinCopies+1)
		made := 0
		for _, combo := range rnd.Perm(3) {
			if made >= k {
				break
			}
			for _, s := range padCopyCandidates(c.val, combo, rnd) {
				if seen[s] {
					continue
				}
				seen[s] = true
				appended = append(appended, s)
				made++
				if combo == padComboHeavy {
					st.Heavy++
				} else {
					st.Single++
				}
				break
			}
		}
		if made > 0 {
			st.Originals++
		} else {
			st.Skipped++
		}
	}
	st.Appended = len(appended)
	if len(appended) == 0 {
		st.PoolAfter = st.PoolBefore
		return append([]byte(nil), data...), st, nil
	}

	// 5) 重建全局池并拼回：池块替换 + 表头 size 回填，其余原样搬运。
	vals := make([]string, 0, len(pool.strings)+len(appended))
	vals = append(vals, pool.strings...)
	vals = append(vals, appended...)
	newPool, err := axml.EncodeStringPoolWithStyles(vals, pool.utf8, pool.styles)
	if err != nil {
		return nil, st, fmt.Errorf("arsc: 重编码全局字符串池失败: %w", err)
	}
	out := make([]byte, 0, len(data)-pool.size+len(newPool))
	out = append(out, data[:hdr]...)           // 表头（长度字段稍后回填）
	out = append(out, newPool...)              // 全局池（紧随表头）
	out = append(out, data[hdr+pool.size:]...) // 包块等原样搬运
	// 表头 size 描述整张表总长；包块内部相对偏移不变，无需重定位。
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	st.PoolAfter = len(vals)
	return out, st, nil
}

// padCandidate 是一个「被引用且适合复制」的逻辑值。
type padCandidate struct {
	idx int // 池中首个出现该内容的槽位（仅用于确定性排序/调试）
	val string
}

// padableValue 判断一个被引用的值是否适合生成零宽副本。
//
// 排除：
//   - 空串：副本只有标记，没有去重价值；
//   - 超过 padMaxValueLen 的长文本：避免体积成倍膨胀；
//   - 已含 U+200E/U+200F 的值：不再叠加，避免与既有形态碰撞或深度嵌套。
func padableValue(s string) bool {
	if s == "" || len(s) > padMaxValueLen {
		return false
	}
	return !strings.ContainsAny(s, "\u200e\u200f")
}

// padCopyCandidates 生成同一组合下、字节互不相同的候选副本（最多 2 个）。
//
// 样本里同一个逻辑值的池内形态共有四种：原值（0 前缀 0 后缀，本来就在池里）、
// 1 前缀、1 后缀、N 前缀 + 6 后缀。这里只生成后三种——追加一份与原值逐字节
// 相同的「0 前缀」副本既不会增加不同字节形态的数量，也纯属浪费体积。
//
// 调用方按顺序取第一个不在池里的；两个都撞（池里恰好已有同形态）时
// 放弃该组合，因此理论上某个值可能一条副本都追加不上（统计里的 Skipped）。
func padCopyCandidates(val string, combo int, r *rand.Rand) []string {
	switch combo {
	case padComboPrefix:
		a, b := padLRM, padRLM
		if r.Intn(2) == 1 {
			a, b = b, a
		}
		return []string{string(a) + val, string(b) + val}
	case padComboSuffix:
		a, b := padLRM, padRLM
		if r.Intn(2) == 1 {
			a, b = b, a
		}
		return []string{val + string(a), val + string(b)}
	case padComboHeavy:
		// N 个前缀 + 6 个后缀；每个标记独立随机，与样本的
		// 「大量 LRM/RLM 混合」形态一致。
		n := padHeavyPrefixMin + r.Intn(padHeavyPrefixMax-padHeavyPrefixMin+1)
		var sb strings.Builder
		sb.Grow((n+padHeavySuffix)*3 + len(val))
		for i := 0; i < n; i++ {
			sb.WriteRune(padMarker(r))
		}
		sb.WriteString(val)
		for i := 0; i < padHeavySuffix; i++ {
			sb.WriteRune(padMarker(r))
		}
		return []string{sb.String()}
	}
	return nil
}

// padMarker 随机返回 LRM 或 RLM。
func padMarker(r *rand.Rand) rune {
	if r.Intn(2) == 0 {
		return padLRM
	}
	return padRLM
}

// forEachPackageChunk 遍历一个包块内的子块；结构异常时停止（不报错）。
//
// 只做尺寸校验，不解读内容：调用方按块类型自行处理。
func forEachPackageChunk(data []byte, off, size int, fn func(typ uint16, off, size int)) {
	end := off + size
	hdr := int(binary.LittleEndian.Uint16(data[off+2:]))
	if hdr < 8 || hdr > size {
		return
	}
	for q := off + hdr; q+8 <= end; {
		t := binary.LittleEndian.Uint16(data[q:])
		sz := int(binary.LittleEndian.Uint32(data[q+4:]))
		if sz < 8 || q+sz > end {
			return
		}
		fn(t, q, sz)
		q += sz
	}
}

// collectTypeStringRefs 收集一个 ResTable_type 块里所有 Res_value 对全局
// 字符串池的索引（dataType == TYPE_STRING）。
func collectTypeStringRefs(data []byte, off, size int, out map[int]bool) {
	forEachEntry(data, off, size, func(eo, end int) bool {
		addEntryStringRefs(data, eo, end, out)
		return true
	})
}

// addEntryStringRefs 读取单个 entry 的字符串值引用（简单值或复合 map 的
// 每个 value），写入 out。
//
// 三种形态（与 keys.go 的 addEntryKey 保持同一套偏移认知）：
//   - compact：key 索引占 size 字段，flags 高字节是 dataType，data 紧随其后；
//   - 复合（FLAG_COMPLEX）：entry 后是 ResTable_map_entry（parent u32 + count
//     u32），每个 ResTable_map 12 字节：name u32 + Res_value（dataType 在
//     map+7，data 在 map+8）；
//   - 普通：entry（8 字节）后跟 Res_value（dataType 在 entry+11，data 在 +12）。
func addEntryStringRefs(data []byte, eo, end int, out map[int]bool) {
	if eo < 0 || eo+8 > end {
		return
	}
	flags := binary.LittleEndian.Uint16(data[eo+2:])
	switch {
	case flags&entryFlagCompact != 0:
		if data[eo+3] == valueTypeString {
			if idx := int(binary.LittleEndian.Uint32(data[eo+4:])); idx >= 0 {
				out[idx] = true
			}
		}
	case flags&entryFlagComplex != 0:
		if eo+16 > end {
			return
		}
		n := int(binary.LittleEndian.Uint32(data[eo+12:]))
		for i := 0; i < n; i++ {
			mv := eo + 16 + 12*i
			if mv+12 > end {
				return // 截断的 map 数组：已收集的保留，其余放弃
			}
			if data[mv+7] == valueTypeString {
				if idx := int(binary.LittleEndian.Uint32(data[mv+8:])); idx >= 0 {
					out[idx] = true
				}
			}
		}
	default:
		if eo+16 > end {
			return
		}
		if data[eo+11] == valueTypeString {
			if idx := int(binary.LittleEndian.Uint32(data[eo+12:])); idx >= 0 {
				out[idx] = true
			}
		}
	}
}
