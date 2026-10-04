// 本文件实现 A5/A11 的子行为：未使用 typeId 的 typeStrings 占位名 ?<id>。
//
// 背景（来自样本 resources.arsc 的逆向结论）：typeStrings 池里存在 `?15`
// 这类占位名，且该 id 恰好没有被任何 Type/TypeSpec 使用（内层 APK 的
// ?12/?16 同理）。推断表被自定义工具重建过——aapt2 不写这种名字。
//
// 本实现把「包内未被任何 Type/TypeSpec 引用的 typeId」对应的 typeStrings
// 槽位统一改名为 ?<id>：
//   - 已使用的 id 名字保持原样（anim/string/layout 这类类型名改了会破坏
//     getIdentifier 与 aapt2 的类型名解析）；
//   - 只改内容、不增删槽位，池的 stringCount 不变；
//   - 需要回填的只有 typeStrings 池块 size、它之后的 keyStrings 相对偏移
//     （typeStrings/keyStrings 都在包头内，相对包块定位）、包块 size 与
//     表头 size。包块内其余块按顺序扫描，没有绝对偏移。
package arsc

import (
	"encoding/binary"
	"fmt"
	"strconv"

	"apkguard/internal/axml"
)

// typeTypeSpec 是 RES_TABLE_TYPE_SPEC_TYPE：与 Type 块一样归属一个 typeId。
const typeTypeSpec = 0x0202

// TypeNameStats 是 typeStrings 占位名改写的统计。
type TypeNameStats struct {
	// Packages 是扫描到的包数。
	Packages int
	// Slots 是全部包的 typeStrings 槽位总数。
	Slots int
	// Unused 是未被任何 Type/TypeSpec 使用的槽位数。
	Unused int
	// Placeholders 是实际写入 ?<id> 的槽位数（已经是 ?<id> 的不计）。
	Placeholders int
	// IDs 是被判定为未使用、应使用占位名的 typeId 列表（去重、升序）。
	IDs []int
}

// PlaceholderTypeNames 把各包 typeStrings 池里未使用 id 的槽位改名为 ?<id>。
//
// 输入必须是完整 RES_TABLE 字节流；返回改写后的字节流（无改动时返回副本）。
// 已使用的类型名一律保持原样。包内子块结构异常时跳过该包（宁少勿多），
// 只有顶层结构与池本身非法才报错。
func PlaceholderTypeNames(data []byte) ([]byte, TypeNameStats, error) {
	var st TypeNameStats
	hdr, total, err := tableSpan(data)
	if err != nil {
		return nil, st, err
	}

	var edits []*typeNameEdit
	var perr error
	err = forEachTopChunk(data, hdr, total, func(t uint16, p, sz int) bool {
		if t != typePackage {
			return true
		}
		st.Packages++
		e, err := planTypeNames(data, p, sz)
		if err != nil {
			perr = err
			return false
		}
		if e == nil {
			return true
		}
		st.Slots += len(e.pool.strings)
		st.Unused += len(e.ids)
		st.Placeholders += e.written
		st.IDs = append(st.IDs, e.ids...)
		if e.written > 0 {
			edits = append(edits, e)
		}
		return true
	})
	if err != nil {
		return nil, st, err
	}
	if perr != nil {
		return nil, st, perr
	}
	if len(edits) == 0 {
		return append([]byte(nil), data...), st, nil
	}

	// 按池块分段拼接：与 keys.go 的 RandomizeKeys 同一套思路——长度变化
	// 只影响池块及其后的字节，需要回填的字段都在池块之前，用「原始偏移 +
	// 已插入净增量」换算，不做整体重定位。
	out := make([]byte, 0, len(data)+64)
	prev := 0
	cum := 0 // 本包块之前已插入的净增量
	for _, e := range edits {
		start := e.off + e.tsRel
		out = append(out, data[prev:start]...)
		out = append(out, e.newPool...)
		prev = start + e.pool.size

		newPkg := e.off + cum
		// 包块 size 描述包内全部字节。
		binary.LittleEndian.PutUint32(out[newPkg+4:], uint32(e.size+e.delta))
		// keyStrings 在 typeStrings 之后时，其相对偏移随池增长平移；
		// 在 typeStrings 之前（非 aapt2 产物）则不受影响。
		if e.keyRel > e.tsRel {
			binary.LittleEndian.PutUint32(out[newPkg+pkgKeyStringsOff:], uint32(e.keyRel+e.delta))
		}
		cum += e.delta
	}
	out = append(out, data[prev:]...)
	// 表头 size 描述整张表总长。
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	return out, st, nil
}

// typeNameEdit 是单个包 typeStrings 池的改写计划。
type typeNameEdit struct {
	off     int // 包块起始（原始坐标）
	size    int // 包块原始总长
	tsRel   int // typeStrings 相对包块的偏移
	keyRel  int // keyStrings 相对包块的偏移（0 表示没有）
	delta   int // 池块净增长
	written int // 实际改写的槽位数
	ids     []int
	pool    *stringPool
	newPool []byte
}

// planTypeNames 解析单个包并生成 typeStrings 改写计划；
// 无需改写或包内没有 typeStrings 时返回 (nil, nil)。
func planTypeNames(data []byte, off, size int) (*typeNameEdit, error) {
	end := off + size
	hdr := int(binary.LittleEndian.Uint16(data[off+2:]))
	if hdr < pkgTypeStringsOff+4 || hdr > size {
		// 旧版包头没有 typeStrings 字段：无从改写，原样保留。
		return nil, nil
	}
	tsRel := int(binary.LittleEndian.Uint32(data[off+pkgTypeStringsOff:]))
	if tsRel == 0 {
		return nil, nil
	}
	if tsRel < hdr || off+tsRel+poolHeaderLen > end {
		return nil, fmt.Errorf("arsc: 包（偏移 %d）的 typeStrings 偏移非法 %d", off, tsRel)
	}
	pool, err := parseStringPool(data, off+tsRel)
	if err != nil {
		return nil, fmt.Errorf("arsc: 解析包（偏移 %d）的 typeStrings 失败: %w", off, err)
	}
	if off+tsRel+pool.size > end {
		return nil, fmt.Errorf("arsc: 包（偏移 %d）的 typeStrings 越出包块", off)
	}

	// typeIdOffset：槽位 i（0 基）对应 typeId = i + 1 + typeIdOffset。
	typeIDOffset := 0
	if hdr >= pkgTypeIdOffsetOff+4 {
		typeIDOffset = int(binary.LittleEndian.Uint32(data[off+pkgTypeIdOffsetOff:]))
	}
	used, ok := usedTypeIDs(data, off+hdr, end)
	if !ok {
		// 包内子块结构异常：无法确信「哪些 id 真的没被使用」，
		// 放弃整个包，避免把在用类型名误改成占位名。
		return nil, nil
	}

	vals := make([]string, len(pool.strings))
	copy(vals, pool.strings)
	var ids []int
	written := 0
	for i := range vals {
		id := i + 1 + typeIDOffset
		if used[id] {
			continue
		}
		ids = append(ids, id)
		want := "?" + strconv.Itoa(id)
		if vals[i] != want {
			vals[i] = want
			written++
		}
	}
	keyRel := 0
	if hdr >= pkgKeyStringsOff+4 {
		keyRel = int(binary.LittleEndian.Uint32(data[off+pkgKeyStringsOff:]))
	}
	if written == 0 {
		// 没有未使用 id，或未使用槽位已经是 ?<id>：不做字节改动，
		// 但仍返回统计信息（例如样本的 ?15 就属于这种）。
		return &typeNameEdit{off: off, size: size, tsRel: tsRel, keyRel: keyRel,
			pool: pool, ids: ids}, nil
	}
	np, err := axml.EncodeStringPoolWithStyles(vals, pool.utf8, pool.styles)
	if err != nil {
		return nil, fmt.Errorf("arsc: 重编码包（偏移 %d）的 typeStrings 失败: %w", off, err)
	}
	return &typeNameEdit{
		off: off, size: size, tsRel: tsRel, keyRel: keyRel,
		delta: len(np) - pool.size, written: written, ids: ids,
		pool: pool, newPool: np,
	}, nil
}

// usedTypeIDs 收集包内所有 Type（0x0201）与 TypeSpec（0x0202）使用的 typeId。
//
// 第二个返回值 false 表示包内子块结构异常，调用方必须放弃该包：
// 少收集一个 id 就可能把在用的类型名改成占位名，破坏 getIdentifier。
func usedTypeIDs(data []byte, start, end int) (map[int]bool, bool) {
	used := map[int]bool{}
	for q := start; q+8 <= end; {
		t := binary.LittleEndian.Uint16(data[q:])
		sz := int(binary.LittleEndian.Uint32(data[q+4:]))
		if sz < 8 || q+sz > end {
			return nil, false
		}
		if t == typeType || t == typeTypeSpec {
			if sz < 12 {
				return nil, false
			}
			if id := int(data[q+8]); id > 0 && id <= 255 {
				used[id] = true
			}
		}
		q += sz
	}
	return used, true
}
