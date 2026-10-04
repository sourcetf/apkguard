package dex

import (
	"encoding/binary"
	"fmt"
	"sort"
)

// ---- B5 函数抽取：抽取（stub 化）与回填的纯函数 ----
//
// 与设计文档（docs/方案-B5-函数抽取.md）的差异：本项目不 patch ART 内存映射，
// 而是把抽取计划**附着在 DEX 字节流尾部**（trailer），由壳 Loader 在
// 「AES 解密之后、落盘与 DexClassLoader 之前」直接在内存中的 byte[] 上回填。
// 这样做的三个理由：
//
//  1. 回填只碰我们自己手里的 byte[]，完全不接触 ART 内部结构（无 mprotect、
//     无版本相关风险）；
//  2. 计划随 B1 载荷一起加密（同一密钥、同一容器），不需要 B3/shell.go 之外的
//     额外载荷条目与共享状态，B8 容器化也无需搬迁它；
//  3. 回填后 DEX 与抽取前**逐字节一致**（含头部 checksum/SHA-1），ART 看到的
//     就是原始文件，校验/执行路径与未启用 B5 完全相同。
//
// 静态层面（产物 APK 内的加密载荷）被抽取方法只剩等长 stub；明文方法体只存在
// 于「解密后的内存」与「回填后的私有目录文件」中——磁盘空体率不再是 100%，
// 这是本项目为降低实现风险做出的明确取舍（见交付报告「残余风险」）。

// ExtractPlanMagic 是计划 trailer 的魔数："AGX1"（'A' 'G' 'X' '1' 的小端 u32）。
//
// 壳 Loader 与 Go 侧 ApplyExtractPlan 必须用同一个值判断 trailer 是否存在；
// 未启用 B5 的普通载荷不含该魔数，回填步骤直接跳过（行为与旧版一致）。
const ExtractPlanMagic uint32 = 0x31584741

// 计划 trailer 的内部布局（全部小端）：
//
//	magic   u32
//	count   u32
//	checksum u32      ┐ 原 DEX 头部 24 字节（checksum+signature），
//	signature [20]byte┘ 回填后写回 DEX 偏移 8..32，使文件与抽取前逐字节一致
//	entries count × (code_off u32, byte_len u32)
//	bodies  各条目的原 code_item 原始字节，按 entries 顺序拼接
//
// 字段顺序是壳侧字节码的硬约定（entry 表在 trailer+32，bodies 紧随其后）；
// 改动必须同步 loader.go 的 p() 与 ApplyExtractPlan。
const (
	extractPlanHeaderSize = 8  // magic + count
	extractPlanFixSize    = 24 // 原 checksum + 原 SHA-1 签名
	extractPlanEntrySize  = 8  // code_off + byte_len
	// extractPlanBodiesOff 是 bodies 相对 trailer 起点的固定偏移（不含条目表）。
	extractPlanEntriesOff = extractPlanHeaderSize + extractPlanFixSize // 32
)

// ExtractInfo 描述一个带方法体的方法（候选或已抽取）。
type ExtractInfo struct {
	// Class 是类类型描述符（形如 "Lcom/x/A;"）。
	Class string
	// Name 是方法名。
	Name string
	// Proto 是原型描述（形如 "(I)V"）。
	Proto string
	// Ret 是返回类型描述符（"V"/"I"/"J"/"L...;" 等）。
	Ret string
	// Access 是 class_data 中的方法访问标志。
	Access uint32
	// CodeOff 是 code_item 的文件偏移。
	CodeOff uint32
	// Registers 是 registers_size。
	Registers int
	// InsnsWords 是 insns_size（16 位字个数）。
	InsnsWords int
	// TriesSize 是 tries_size（异常表条数）。
	TriesSize int
	// Shared 表示同一 code_off 被多个方法共用（抽取会影响全部共用者）。
	Shared bool
}

// ExtractEntry 是一个被抽取的方法体。
type ExtractEntry struct {
	// CodeOff 是原 DEX 中 code_item 的偏移。
	CodeOff uint32
	// ByteLen 是 code_item 的完整字节长度。
	ByteLen int
	// Data 是原 code_item 的原始字节（含头部、指令、异常表）。
	Data []byte
	// Info 是方法元数据（诊断/报告用，不进入 trailer）。
	Info ExtractInfo
}

// ExtractPlan 是一次抽取的全部结果。
type ExtractPlan struct {
	// Entries 按 code_off 升序。
	Entries []ExtractEntry
	// Checksum / Signature 是抽取前 DEX 头部的 Adler-32 与 SHA-1，
	// 回填时写回，使结果与抽取前逐字节一致。
	Checksum  uint32
	Signature [20]byte
}

// extractAcc 是本文件用到的 DEX 方法访问标志位。
const (
	extractAccSynchronized = 0x00020
	extractAccNative       = 0x00100
	extractAccAbstract     = 0x00400
	extractAccConstructor  = 0x10000
	extractAccDeclSync     = 0x20000
)

// ScanExtractCandidates 扫描 DEX 中全部带方法体的方法，返回候选清单。
//
// 顺序稳定（class_defs 顺序 × class_data 顺序），同一输入的可复现性依赖它。
func ScanExtractCandidates(data []byte) ([]ExtractInfo, error) {
	f, err := Parse(data)
	if err != nil {
		return nil, err
	}
	var out []ExtractInfo
	err = f.Classes(func(_ uint32, cd ClassDef, className string) error {
		if cd.ClassDataOff == 0 {
			return nil
		}
		pcd, err := f.ParseClassData(cd.ClassDataOff)
		if err != nil {
			return err
		}
		for _, lst := range [][]EncodedMethod{pcd.DirectMethods, pcd.VirtualMethods} {
			for _, m := range lst {
				if m.CodeOff == 0 {
					continue
				}
				info, err := extractInfoAt(f, className, m)
				if err != nil {
					return err
				}
				out = append(out, info)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// 标记共享 code_off：多个方法共用同一方法体时，抽取/回填都按整组处理，
	// 选择阶段必须把它们视为一个整体（ExtractCode 内部即如此）。
	seen := map[uint32]int{}
	for _, info := range out {
		seen[info.CodeOff]++
	}
	for i := range out {
		out[i].Shared = seen[out[i].CodeOff] > 1
	}
	return out, nil
}

// extractInfoAt 读取单个方法的元数据。
func extractInfoAt(f *File, className string, m EncodedMethod) (ExtractInfo, error) {
	d := f.data
	base := int(m.CodeOff)
	if base < 0 || base+16 > len(d) {
		return ExtractInfo{}, fmt.Errorf("%w: code_item 越界 @%d", ErrTruncated, m.CodeOff)
	}
	info := ExtractInfo{
		Class:      className,
		Access:     m.Acc,
		CodeOff:    m.CodeOff,
		Registers:  int(binary.LittleEndian.Uint16(d[base:])),
		TriesSize:  int(binary.LittleEndian.Uint16(d[base+6:])),
		InsnsWords: int(binary.LittleEndian.Uint32(d[base+12:])),
	}
	ref, err := f.MethodRefAt(m.Idx)
	if err != nil {
		return ExtractInfo{}, err
	}
	if info.Name, err = f.String(ref.NameIdx); err != nil {
		return ExtractInfo{}, err
	}
	ret, params, err := f.ProtoParts(uint32(ref.ProtoIdx))
	if err != nil {
		return ExtractInfo{}, err
	}
	info.Ret = ret
	info.Proto = BuildProtoDesc(ret, params)
	// 指令区必须落在文件内（畸形输入不允许进入抽取）。
	if base+16+2*info.InsnsWords > len(d) {
		return ExtractInfo{}, fmt.Errorf("%w: %s->%s%s 的指令区越界", ErrTruncated, className, info.Name, info.Proto)
	}
	return info, nil
}

// ExtractStubWords 返回按返回类型生成的最小合法 stub 指令序列。
//
// const/4 写 0 得到 verifier 的 zero 类型，对 32 位基本类型（含 float）与引用
// 类型都可赋值；64 位用 const-wide/16 v0,#0。v0 在非 void 方法里必然存在
// （否则返回值无处安放），调用方仍需自行确认 registers_size。
func ExtractStubWords(ret string) ([]uint16, error) {
	switch ret {
	case "V":
		return []uint16{0x000e}, nil // return-void
	case "Z", "B", "C", "S", "I", "F":
		return []uint16{0x0012, 0x000f}, nil // const/4 v0,#0 ; return v0
	case "J", "D":
		return []uint16{0x0014, 0x0010}, nil // const-wide/16 v0,#0 ; return-wide v0
	}
	if len(ret) > 0 && (ret[0] == 'L' || ret[0] == '[') {
		return []uint16{0x0012, 0x0011}, nil // const/4 v0,#0 ; return-object v0
	}
	return nil, fmt.Errorf("dex: 无法为返回类型 %q 生成 stub", ret)
}

// ExtractCode 对 DEX 做抽取：selectFn 命中的方法体被替换为等长 stub，原始
// code_item 收进计划并作为 trailer 追加在 DEX 之后。
//
// 返回 (原样数据, nil, nil) 表示没有任何方法被选中（调用方不应写回）。
// 选择以 code_off 为单位：同一 code_off 的全部方法都必须通过 selectFn，
// 否则整组跳过（避免误伤共用方法体的另一方法）。
//
// 注意：trailer 追加在 file_size 之外，因此 DEX 本体（前 file_size 字节）
// 仍然是自洽的（头部 checksum/SHA-1 在本函数内已重算）。
func ExtractCode(data []byte, selectFn func(ExtractInfo) bool) ([]byte, *ExtractPlan, error) {
	f, err := Parse(data)
	if err != nil {
		return nil, nil, err
	}
	if len(data) < 32 {
		return nil, nil, ErrNotDex
	}
	var infos []ExtractInfo
	err = f.Classes(func(_ uint32, cd ClassDef, className string) error {
		if cd.ClassDataOff == 0 {
			return nil
		}
		pcd, err := f.ParseClassData(cd.ClassDataOff)
		if err != nil {
			return err
		}
		for _, lst := range [][]EncodedMethod{pcd.DirectMethods, pcd.VirtualMethods} {
			for _, m := range lst {
				if m.CodeOff == 0 {
					continue
				}
				info, err := extractInfoAt(f, className, m)
				if err != nil {
					return err
				}
				infos = append(infos, info)
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	groups := map[uint32][]ExtractInfo{}
	var order []uint32
	for _, info := range infos {
		if _, ok := groups[info.CodeOff]; !ok {
			order = append(order, info.CodeOff)
		}
		groups[info.CodeOff] = append(groups[info.CodeOff], info)
	}
	var chosen []uint32
	for _, co := range order {
		all := true
		for _, info := range groups[co] {
			if !selectFn(info) {
				all = false
				break
			}
		}
		if all {
			chosen = append(chosen, co)
		}
	}
	if len(chosen) == 0 {
		return data, nil, nil
	}
	sort.Slice(chosen, func(i, j int) bool { return chosen[i] < chosen[j] })

	out := append([]byte(nil), data...)
	plan := &ExtractPlan{
		Checksum: binary.LittleEndian.Uint32(data[8:]),
	}
	copy(plan.Signature[:], data[12:32])

	for _, co := range chosen {
		info := groups[co][0]
		stub, err := ExtractStubWords(info.Ret)
		if err != nil {
			return nil, nil, err
		}
		if len(stub) > info.InsnsWords {
			return nil, nil, fmt.Errorf("dex: %s->%s%s 的 stub 需要 %d 字，方法体只有 %d 字",
				info.Class, info.Name, info.Proto, len(stub), info.InsnsWords)
		}
		// 只改指令区：头部（registers/ins/outs/tries/debug_info）与异常表原样保留，
		// 因此回填只需写回 code_item 原始字节即可逐字节还原。
		base := int(co) + 16
		for i := 0; i < info.InsnsWords; i++ {
			var w uint16
			if i < len(stub) {
				w = stub[i]
			}
			binary.LittleEndian.PutUint16(out[base+2*i:], w)
		}
		byteLen, err := codeItemByteLen(f, co)
		if err != nil {
			return nil, nil, err
		}
		raw := make([]byte, byteLen)
		copy(raw, data[co:co+uint32(byteLen)])
		plan.Entries = append(plan.Entries, ExtractEntry{
			CodeOff: co,
			ByteLen: byteLen,
			Data:    raw,
			Info:    info,
		})
	}

	// stub 之后 DEX 仍必须是自洽的：重算 checksum/SHA-1 只覆盖 DEX 本体
	// （trailer 尚未追加），这样「前 file_size 字节」是一份校验自洽的 DEX。
	fixed := Finalize(out)
	copy(out, fixed)
	return append(out, encodeExtractPlan(plan)...), plan, nil
}

// encodeExtractPlan 把计划编码为 trailer 字节。
func encodeExtractPlan(plan *ExtractPlan) []byte {
	n := extractPlanEntriesOff + extractPlanEntrySize*len(plan.Entries)
	total := n
	for _, e := range plan.Entries {
		total += len(e.Data)
	}
	buf := make([]byte, n, total)
	binary.LittleEndian.PutUint32(buf[0:], ExtractPlanMagic)
	binary.LittleEndian.PutUint32(buf[4:], uint32(len(plan.Entries)))
	binary.LittleEndian.PutUint32(buf[8:], plan.Checksum)
	copy(buf[12:32], plan.Signature[:])
	p := extractPlanEntriesOff
	for _, e := range plan.Entries {
		binary.LittleEndian.PutUint32(buf[p:], e.CodeOff)
		binary.LittleEndian.PutUint32(buf[p+4:], uint32(e.ByteLen))
		p += extractPlanEntrySize
	}
	for _, e := range plan.Entries {
		buf = append(buf, e.Data...)
	}
	return buf
}

// ApplyExtractPlan 解析 DEX 尾部的抽取计划并原地回填，返回截去 trailer 的 DEX
// 与回填条数。
//
// 这是壳 Loader 的 Go 侧对拍实现（loader.go 生成的 p() 与它同一格式、同一
// 边界规则）。没有 trailer（未启用 B5）时返回输入副本与 0，不改变任何字节。
func ApplyExtractPlan(data []byte) ([]byte, int, error) {
	if len(data) < 40 {
		return append([]byte(nil), data...), 0, nil
	}
	fs := binary.LittleEndian.Uint32(data[32:])
	if fs < 32 || uint64(fs)+extractPlanHeaderSize > uint64(len(data)) ||
		binary.LittleEndian.Uint32(data[fs:]) != ExtractPlanMagic {
		return append([]byte(nil), data...), 0, nil
	}
	count := binary.LittleEndian.Uint32(data[fs+4:])
	if count == 0 ||
		uint64(fs)+extractPlanEntriesOff+extractPlanEntrySize*uint64(count) > uint64(len(data)) {
		return nil, 0, fmt.Errorf("dex: B5 计划 trailer 头非法（fs=%d count=%d len=%d）", fs, count, len(data))
	}
	out := append([]byte(nil), data...)
	// 恢复原头部 checksum/SHA-1：回填全部完成后，本 DEX 与抽取前逐字节一致。
	copy(out[8:32], out[fs+8:fs+32])
	bp := int(fs) + extractPlanEntriesOff + extractPlanEntrySize*int(count)
	for i := 0; i < int(count); i++ {
		ep := int(fs) + extractPlanEntriesOff + extractPlanEntrySize*i
		off := binary.LittleEndian.Uint32(out[ep:])
		length := binary.LittleEndian.Uint32(out[ep+4:])
		if uint64(off)+uint64(length) > uint64(fs) || bp+int(length) > len(out) {
			return nil, 0, fmt.Errorf("dex: B5 计划第 %d 条越界（off=%d len=%d fs=%d）", i, off, length, fs)
		}
		copy(out[off:off+length], out[bp:bp+int(length)])
		bp += int(length)
	}
	return out[:fs], int(count), nil
}

// codeItemByteLen 计算 code_item 的完整字节长度（含异常表与 handler 数据）。
//
// 与 assemble.go 的 builder.codeItemLength 同一算法，但面向任意 DEX 字节流
// （抽取发生在重建之后，没有 builder 可用）。
func codeItemByteLen(f *File, off uint32) (int, error) {
	d := f.data
	base := int(off)
	if base < 0 || base+16 > len(d) {
		return 0, fmt.Errorf("%w: code_item 越界 @%d", ErrTruncated, off)
	}
	insnsSize := binary.LittleEndian.Uint32(d[base+12:])
	triesSize := binary.LittleEndian.Uint16(d[base+6:])
	p := base + 16 + int(insnsSize)*2
	if p > len(d) {
		return 0, fmt.Errorf("%w: code_item @%d 指令区越界", ErrTruncated, off)
	}
	if triesSize > 0 {
		if (insnsSize & 1) != 0 {
			p += 2
		}
		p += int(triesSize) * 8
		if p > len(d) {
			return 0, fmt.Errorf("%w: code_item @%d 异常表越界", ErrTruncated, off)
		}
		handlersSize, np, err := ULEB128(d, p)
		if err != nil {
			return 0, err
		}
		p = np
		for i := uint32(0); i < handlersSize; i++ {
			var size int32
			size, p, err = SLEB128(d, p)
			if err != nil {
				return 0, err
			}
			cnt := size
			if cnt < 0 {
				cnt = -cnt
			}
			for k := int32(0); k < cnt; k++ {
				if _, p, err = ULEB128(d, p); err != nil {
					return 0, err
				}
				if _, p, err = ULEB128(d, p); err != nil {
					return 0, err
				}
			}
			if size <= 0 {
				if _, p, err = ULEB128(d, p); err != nil {
					return 0, err
				}
			}
		}
	}
	return p - base, nil
}
