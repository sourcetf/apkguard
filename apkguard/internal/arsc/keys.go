// 本文件实现 A5/A11 的子行为：资源条目名（keyStrings 池）随机化。
//
// 为什么只换字符串内容就够：ResTable_entry 通过 **key 索引**引用 keyStrings 池，
// 索引语义与槽位内容无关。逐槽位换名后：
//   - 资源 ID → 类型 → 条目的映射完全不变（应用里 R.* 引用的是整数 ID）；
//   - aapt2 dump / getResourceEntryName 读到的条目名变成随机 token，
//     app_name / ic_launcher 这类语义不再泄露；
//   - 与既有「全局字符串池里的 res/ 路径改名」互不干扰，可叠加。
//
// 与路径改写同理：ARSC 内所有偏移都是相对的（keyStrings 相对包块，
// Type.entriesStart 相对 Type 块），因此替换池之后只需回填
// 池块 size、所属包块 size 与表头 size 三处长度字段，其余字节原样搬运，
// 不需要任何重定位。
package arsc

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"apkguard/internal/axml"
)

const (
	typePackage = 0x0200 // RES_TABLE_PACKAGE_TYPE
	typeType    = 0x0201 // RES_TABLE_TYPE_TYPE

	// ResTable_entry.flags（compact 形态复用同一字段）。
	entryFlagCompact = 0x0008
	// ResTable_type.flags。
	typeFlagSparse   = 0x01 // 稀疏条目数组：(u16 idx, u16 offset/4) 对
	typeFlagOffset16 = 0x02 // 条目偏移是 u16，单位为 4 字节

	// ResTable_package 头部各字段相对包块起始的偏移。
	// typeStrings(268) / keyStrings(276) 是 aapt2 长期稳定的布局；
	// typeIdOffset(284) 只在 headerSize ≥ 288 的新版头里存在。
	pkgTypeStringsOff  = 268
	pkgKeyStringsOff   = 276
	pkgTypeIdOffsetOff = 284
	pkgHeaderMin       = 280 // 至少要能读到 keyStrings 字段

	// keyPrefixPercent 是「被改名 key 带类型前缀」的目标比例（约 13%）。
	keyPrefixPercent = 13

	// keyNameAlphabet 是新名的字符集。
	keyNameAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
)

// KeyRenameOptions 控制 keyStrings 随机化。
type KeyRenameOptions struct {
	// Seed 是确定性随机种子：相同 seed + 相同输入 → 相同产物。
	// 留空时用当前时间（不可复现）。
	Seed string
	// Keep 是必须保留原名的条目名集合，由调用方收集后传入。
	// A5/A11 传入的是产物中**全部可解析 DEX 的字符串池**：
	// 名字出现在 DEX 里，说明可能有 Resources.getIdentifier 之类的按名查表。
	Keep map[string]bool
}

// KeyRenameStats 是 keyStrings 随机化的统计。
type KeyRenameStats struct {
	// Total 是全部包 keyStrings 池的条目总数。
	Total int
	// Renamed / Kept 是改写与保留的条数（Kept == Total - Renamed）。
	Renamed int
	Kept    int
	// KeptDex 是命中 Keep 集合（DEX 引用）而保留的条数。
	KeptDex int
	// KeptShape 是因形状规则（点分/斜杠库名、非 ASCII、短名、空串）保留的条数。
	KeptShape int
	// Prefixed 是新名中带 vx_*_ 类型前缀的条数。
	Prefixed int
	// Packages 是处理到的、含 keyStrings 的包数。
	Packages int
}

// RandomizeKeys 把 resources.arsc 中全部包 keyStrings 池里的资源条目名随机化。
//
// 输入必须是完整的 RES_TABLE 字节流；返回改写后的字节流（无改动时返回副本）。
// 只改「池槽位里的字符串内容」，entry 的 key 索引不变，因此
// 「资源 ID → 类型 → 条目」的映射逐条保持。UTF-8 与 UTF-16 池都支持。
//
// 保留规则（安全第一，宁少勿多），满足任一条件保留原名：
//  1. 名字在 opts.Keep 中（通常是 DEX 字符串池引用，见 KeyRenameOptions.Keep）；
//  2. 名字含非 ASCII、长度 < 3、或含 '.' / '/'（点分库名如
//     Widget.AppCompat.Toolbar，样本也保留）。
//
// 新名为 [a-z0-9]{6,14}，由 Seed 确定性派生、与文件路径无关、全表唯一；
// 约 13% 的被改名 key 带类型前缀（按所属 entry 的 typeId 查 typeStrings：
// string/color/dimen/integer/bool → vx_s_/vx_c_/vx_d_/vx_i_/vx_b_，其余 vx_x_）。
func RandomizeKeys(data []byte, opts KeyRenameOptions) ([]byte, KeyRenameStats, error) {
	var st KeyRenameStats
	if len(data) < tableHeaderLen {
		return nil, st, fmt.Errorf("arsc: 数据过短")
	}
	if binary.LittleEndian.Uint16(data[0:]) != typeTable {
		return nil, st, fmt.Errorf("arsc: 不是 RES_TABLE_TYPE（0x%04x）", binary.LittleEndian.Uint16(data[0:]))
	}
	hdr := int(binary.LittleEndian.Uint16(data[2:]))
	if hdr < tableHeaderLen || hdr > len(data) {
		return nil, st, fmt.Errorf("arsc: 表头长度非法 %d", hdr)
	}
	total := int(binary.LittleEndian.Uint32(data[4:]))
	if total < hdr || total > len(data) {
		return nil, st, fmt.Errorf("arsc: 表长度非法 %d", total)
	}

	pkgs, err := scanPackages(data, hdr, total)
	if err != nil {
		return nil, st, err
	}
	if len(pkgs) == 0 {
		// 没有包（或没有 keyStrings）：没有可改的东西，原样返回副本。
		return append([]byte(nil), data...), st, nil
	}
	st.Packages = len(pkgs)

	rnd := keyRand(opts.Seed)
	// used 预置全部池中现有字符串：新名既不能与保留的原名冲突，也不能与
	// 其它槽位的原名相同。所有生成都在同一张表上查重，保证「全表唯一」。
	used := map[string]bool{}
	for _, pk := range pkgs {
		st.Total += len(pk.pool.strings)
		for _, s := range pk.pool.strings {
			used[s] = true
		}
	}

	// 生成阶段：按包顺序、槽位顺序处理，保证同 seed 完全可复现。
	edits := make([]keyEdit, 0, len(pkgs))
	for _, pk := range pkgs {
		vals := make([]string, len(pk.pool.strings))
		copy(vals, pk.pool.strings)
		changed := false
		for i := range vals {
			s := vals[i]
			switch {
			case opts.Keep[s]:
				// 先判 DEX：同时满足形状规则时按 DEX 归类，统计口径互斥。
				st.KeptDex++
			case keepKeyShape(s):
				st.KeptShape++
			default:
				wantPrefix := rnd.Intn(100) < keyPrefixPercent
				var nw string
				if wantPrefix {
					pre := keyPrefixFor(pk.typeID(i), pk.typeNames, pk.typeIdOffset)
					nw = pre + randomKeyToken(rnd, 6, 10)
					for used[nw] {
						nw = pre + randomKeyToken(rnd, 6, 10)
					}
					st.Prefixed++
				} else {
					nw = randomKeyToken(rnd, 6, 14)
					for used[nw] {
						nw = randomKeyToken(rnd, 6, 14)
					}
				}
				used[nw] = true
				vals[i] = nw
				changed = true
				st.Renamed++
			}
		}
		if changed {
			edits = append(edits, keyEdit{pk: pk, vals: vals})
		}
	}
	st.Kept = st.Total - st.Renamed

	if len(edits) == 0 {
		return append([]byte(nil), data...), st, nil
	}

	// 重建：按池块分段拼接。长度变化只影响池块及其后的字节，而所有需要
	// 回填的 size 字段（表头、各包块头）都在各自池块之前，用「原始偏移 +
	// 已插入净增量」换算即可，不做整体重定位。
	out := make([]byte, 0, len(data)+64)
	prev := 0
	cumBefore := 0 // 本包块之前（更早的包）已插入的净增量
	for _, e := range edits {
		pool, err := axml.EncodeStringPoolWithStyles(e.vals, e.pk.pool.utf8, e.pk.pool.styles)
		if err != nil {
			return nil, st, fmt.Errorf("arsc: 重编码 keyStrings 失败: %w", err)
		}
		if e.pk.poolOff < prev {
			return nil, st, fmt.Errorf("arsc: keyStrings 池位置乱序（%d < %d）", e.pk.poolOff, prev)
		}
		out = append(out, data[prev:e.pk.poolOff]...)
		out = append(out, pool...)
		prev = e.pk.poolOff + e.pk.pool.size

		ownDelta := len(pool) - e.pk.pool.size
		newPkgOff := e.pk.off + cumBefore
		// 包块 size 字段在池块之前，此处 out 已覆盖该位置。
		binary.LittleEndian.PutUint32(out[newPkgOff+4:], uint32(e.pk.size+ownDelta))
		cumBefore += ownDelta
	}
	out = append(out, data[prev:]...)
	// 表头 size 描述整张表总长。
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	return out, st, nil
}

// keyEdit 是单个包 keyStrings 池的改写结果。
type keyEdit struct {
	pk   *pkgKeys
	vals []string
}

// pkgKeys 是单个包中与 keyStrings 改写相关的信息。
type pkgKeys struct {
	off     int // 包块起始（用于回填包块 size）
	size    int // 包块总长
	poolOff int // keyStrings 池块起始（绝对）
	pool    *stringPool

	// keyType：key 索引 → typeId（同一 key 被多类型引用时取文件顺序首个）。
	keyType map[int]int
	// typeNames 是包内 typeStrings 池的内容（下标对应 typeId-1-typeIdOffset）。
	typeNames []string
	// typeIdOffset 是包头的 typeIdOffset（旧头无此字段时为 0）。
	typeIdOffset int
}

// typeID 返回 key 索引 i 所属的 typeId；未知返回 0。
func (pk *pkgKeys) typeID(i int) int { return pk.keyType[i] }

// scanPackages 遍历表头之后的顶层块，收集全部含 keyStrings 的包。
//
// 顶层块形如：全局字符串池 → 包 1 → 包 2 → …（表头没有任何绝对偏移）。
func scanPackages(data []byte, start, end int) ([]*pkgKeys, error) {
	var out []*pkgKeys
	for p := start; p+8 <= end; {
		t := binary.LittleEndian.Uint16(data[p:])
		sz := int(binary.LittleEndian.Uint32(data[p+4:]))
		if t == 0 && sz == 0 {
			// 尾部对齐填充：要求全零，避免把未知数据当填充静默跳过。
			for _, b := range data[p:end] {
				if b != 0 {
					return nil, fmt.Errorf("arsc: 表尾出现非零的未知块（偏移 %d）", p)
				}
			}
			break
		}
		if sz < 8 || p+sz > end {
			return nil, fmt.Errorf("arsc: 块（type=0x%04x，偏移 %d）长度非法 %d", t, p, sz)
		}
		if t == typePackage {
			pk, err := parsePackageKeys(data, p, sz)
			if err != nil {
				return nil, err
			}
			if pk != nil {
				out = append(out, pk)
			}
		}
		p += sz
	}
	return out, nil
}

// parsePackageKeys 解析单个包块；包内没有可改写的 keyStrings 时返回 (nil, nil)。
func parsePackageKeys(data []byte, off, size int) (*pkgKeys, error) {
	end := off + size
	hdr := int(binary.LittleEndian.Uint16(data[off+2:]))
	if hdr < pkgHeaderMin || hdr > size {
		// 旧版包头没有 keyStrings 字段（或头部异常）：无从改写，原样保留。
		return nil, nil
	}
	keyOff := int(binary.LittleEndian.Uint32(data[off+pkgKeyStringsOff:]))
	if keyOff == 0 {
		return nil, nil
	}
	if keyOff < hdr || off+keyOff+poolHeaderLen > end {
		return nil, fmt.Errorf("arsc: 包（偏移 %d）的 keyStrings 偏移非法 %d", off, keyOff)
	}
	pool, err := parseStringPool(data, off+keyOff)
	if err != nil {
		return nil, fmt.Errorf("arsc: 解析包（偏移 %d）的 keyStrings 失败: %w", off, err)
	}
	if off+keyOff+pool.size > end {
		return nil, fmt.Errorf("arsc: 包（偏移 %d）的 keyStrings 越出包块", off)
	}

	pk := &pkgKeys{
		off:     off,
		size:    size,
		poolOff: off + keyOff,
		pool:    pool,
		keyType: map[int]int{},
	}
	// typeStrings：把 typeId 映射为 string/color/dimen/... 前缀用。
	// 解析失败只是拿不到前缀（退化为 vx_x_），不影响改名本身，因此不报错。
	if hdr >= pkgTypeStringsOff+4 {
		if tsOff := int(binary.LittleEndian.Uint32(data[off+pkgTypeStringsOff:])); tsOff != 0 &&
			tsOff >= hdr && off+tsOff+poolHeaderLen <= end {
			if tp, err := parseStringPool(data, off+tsOff); err == nil {
				pk.typeNames = tp.strings
			}
		}
	}
	if hdr >= pkgTypeIdOffsetOff+4 {
		pk.typeIdOffset = int(binary.LittleEndian.Uint32(data[off+pkgTypeIdOffsetOff:]))
	}
	collectKeyTypes(data, off+hdr, end, pk.keyType)
	return pk, nil
}

// collectKeyTypes 遍历包内子块，从每个 Type 的 entry 数组建立
// 「key 索引 → typeId」映射（仅用于决定约 13% 新名的类型前缀）。
//
// Type 块解析失败只影响前缀（跳过该块），绝不影响改名本身：
// 名字怎么改都不改变 entry 的 key 索引语义。
func collectKeyTypes(data []byte, start, end int, out map[int]int) {
	for q := start; q+8 <= end; {
		t := binary.LittleEndian.Uint16(data[q:])
		sz := int(binary.LittleEndian.Uint32(data[q+4:]))
		if sz < 8 || q+sz > end {
			return // 包内子块结构异常：放弃前缀映射
		}
		if t == typeType {
			collectTypeChunkKeys(data, q, sz, out)
		}
		q += sz
	}
}

// collectTypeChunkKeys 解析一个 ResTable_type 块的所有 entry，记录 key→typeId。
func collectTypeChunkKeys(data []byte, off, size int, out map[int]int) {
	hdr := int(binary.LittleEndian.Uint16(data[off+2:]))
	if hdr < 20 || hdr > size {
		return
	}
	typeID := int(data[off+8])
	if typeID <= 0 || typeID > 255 {
		return
	}
	flags := data[off+9]
	entryCount := int(binary.LittleEndian.Uint32(data[off+12:]))
	entriesStart := int(binary.LittleEndian.Uint32(data[off+16:]))
	if entryCount < 0 || entryCount > 1<<22 || entriesStart < hdr {
		return
	}
	entBase := off + entriesStart
	if entBase > off+size {
		return
	}
	end := off + size

	// entriesStart 之后是偏移数组（48 位下标/32 位偏移/16 位偏移三种编码），
	// 再往后才是 entry 数据区。偏移数组长度按编码类型校验。
	switch {
	case flags&typeFlagSparse != 0:
		if off+hdr+entryCount*4 > end {
			return
		}
		for i := 0; i < entryCount; i++ {
			off4 := int(binary.LittleEndian.Uint16(data[off+hdr+4*i+2:]))
			if off4 == 0xffff {
				continue
			}
			addEntryKey(data, entBase+off4*4, end, typeID, out)
		}
	case flags&typeFlagOffset16 != 0:
		if off+hdr+entryCount*2 > end {
			return
		}
		for i := 0; i < entryCount; i++ {
			o16 := int(binary.LittleEndian.Uint16(data[off+hdr+2*i:]))
			if o16 == 0xffff {
				continue
			}
			addEntryKey(data, entBase+o16*4, end, typeID, out)
		}
	default:
		if off+hdr+entryCount*4 > end {
			return
		}
		for i := 0; i < entryCount; i++ {
			o32 := int(binary.LittleEndian.Uint32(data[off+hdr+4*i:]))
			if o32 == 0xffffffff {
				continue
			}
			addEntryKey(data, entBase+o32, end, typeID, out)
		}
	}
}

// addEntryKey 读取一个 ResTable_entry 的 key 索引并登记其 typeId。
//
// compact（FLAG_COMPACT）形态下 key 索引占原来的 size 字段（偏移 0），
// 普通形态下 key 是偏移 4 处的 u32。
func addEntryKey(data []byte, eo, end, typeID int, out map[int]int) {
	if eo < 0 || eo+8 > end {
		return
	}
	flags := binary.LittleEndian.Uint16(data[eo+2:])
	var key int
	if flags&entryFlagCompact != 0 {
		key = int(binary.LittleEndian.Uint16(data[eo:]))
	} else {
		key = int(binary.LittleEndian.Uint32(data[eo+4:]))
	}
	if key < 0 {
		return
	}
	if _, seen := out[key]; !seen {
		out[key] = typeID
	}
}

// keepKeyShape 判断名字是否必须按「形状规则」保留原名。
//
// 规则（与设计一致，宁少勿多）：
//   - 长度 < 3 或空串；
//   - 含 '.' 或 '/'（Widget.AppCompat.Toolbar 这类点分库名，样本也保留）；
//   - 含非 ASCII（中文/emoji 之类，改名收益低且更容易伤人肉排查）。
//
// 注意：长度用字节数判断，非 ASCII 串即使字节数 ≥ 3 也会被第三条挡下。
func keepKeyShape(s string) bool {
	if len(s) < 3 || strings.ContainsAny(s, "./") {
		return true
	}
	for _, r := range s {
		if r > 0x7f {
			return true
		}
	}
	return false
}

// keyPrefixFor 由 typeId 查 typeStrings 得到 vx_*_ 前缀。
//
// 类型名未知（缺 typeStrings、typeIdOffset 越界、索引超出）时用 vx_x_：
// 前缀只是「故意泄露类型」的伪装风格，宁可用兜底值也不能猜错类型。
func keyPrefixFor(typeID int, typeNames []string, typeIdOffset int) string {
	if typeID > 0 && len(typeNames) > 0 {
		idx := typeID - 1 - typeIdOffset
		if idx >= 0 && idx < len(typeNames) {
			switch typeNames[idx] {
			case "string":
				return "vx_s_"
			case "color":
				return "vx_c_"
			case "dimen":
				return "vx_d_"
			case "integer":
				return "vx_i_"
			case "bool":
				return "vx_b_"
			}
		}
	}
	return "vx_x_"
}

// randomKeyToken 生成 [a-z0-9] 的随机 token，长度在 [minLen, maxLen] 内。
func randomKeyToken(r *rand.Rand, minLen, maxLen int) string {
	n := minLen + r.Intn(maxLen-minLen+1)
	b := make([]byte, n)
	for i := range b {
		b[i] = keyNameAlphabet[r.Intn(len(keyNameAlphabet))]
	}
	return string(b)
}

// keyRand 构造确定性随机源。
//
// 与 passes.newRand 相同的种子哈希（h = h*131 + c），因此传同一个 seed 时
// 行为可复现；留空时用当前时间（只影响不可复现的随机化场景，不用于安全用途）。
// math/rand 的 NewSource(seed) 序列在 Go 1 兼容性承诺内稳定，跨版本可复现。
func keyRand(seed string) *rand.Rand {
	if seed != "" {
		var h int64
		for _, c := range seed {
			h = h*131 + int64(c)
		}
		return rand.New(rand.NewSource(h))
	}
	return rand.New(rand.NewSource(time.Now().UnixNano()))
}
