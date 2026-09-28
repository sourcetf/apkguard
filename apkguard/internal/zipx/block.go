package zipx

import "encoding/binary"

// sigBlockMagic 是 APK 签名块尾部的固定魔术串。
var sigBlockMagic = []byte("APK Sig Block 42")

// Sections 是 APK 的物理分段视图。
//
// 一个已签名的 APK（v2/v3）物理布局为：
//
//	[本地文件头与条目数据][APK 签名块][中央目录][EOCD]
//
// 注意：EOCD 中的「中央目录偏移」字段指向的是真实中央目录位置（即签名块之后），
// 因此不能靠该字段判断签名块是否存在，而应检查中央目录前 16 字节是否为签名块魔术串。
type Sections struct {
	BeforeBlock  []byte // 签名块之前：本地文件头 + 条目数据
	SigningBlock []byte // 现有 APK 签名块，未签名时为 nil
	CentralDir   []byte // 中央目录
	EOCD         []byte // 从 EOCD 签名到文件末尾（含注释）
}

// Split 将归档数据切分为四段。
func Split(data []byte) (*Sections, error) {
	eocd := findEOCD(data)
	if eocd < 0 {
		return nil, ErrNotZip
	}
	cdSize := int(binary.LittleEndian.Uint32(data[eocd+12:]))
	cdStart := eocd - cdSize
	if cdStart < 0 || cdStart > eocd {
		return nil, ErrCorrupt
	}

	s := &Sections{
		CentralDir: data[cdStart:eocd],
		EOCD:       data[eocd:],
	}

	sbStart, ok := findSigningBlock(data, cdStart)
	if !ok {
		s.BeforeBlock = data[:cdStart]
		return s, nil
	}
	s.BeforeBlock = data[:sbStart]
	s.SigningBlock = data[sbStart:cdStart]
	return s, nil
}

// findSigningBlock 依据中央目录前的魔术串定位签名块，返回其起始偏移。
func findSigningBlock(data []byte, cdStart int) (int, bool) {
	if cdStart < 32 || cdStart > len(data) {
		return 0, false
	}
	magicOff := cdStart - len(sigBlockMagic)
	if string(data[magicOff:cdStart]) != string(sigBlockMagic) {
		return 0, false
	}
	// 尾部长度字段位于魔术串之前 8 字节，其值等于「块总长 - 8」。
	blockLen := int(binary.LittleEndian.Uint64(data[cdStart-24 : cdStart-16]))
	sbStart := cdStart - 8 - blockLen
	if sbStart < 0 || sbStart+8 > cdStart {
		return 0, false
	}
	// 头部长度字段应与尾部一致。
	if int(binary.LittleEndian.Uint64(data[sbStart:sbStart+8])) != blockLen {
		return 0, false
	}
	return sbStart, true
}

// HasSigningBlock 报告归档中是否已存在 APK 签名块。
func (s *Sections) HasSigningBlock() bool { return len(s.SigningBlock) > 0 }

// StripSigningBlock 返回移除签名块后的归档数据。
//
// 移除后必须重新签名，否则 v2/v3 校验会因内容变化而失败。
func StripSigningBlock(data []byte) ([]byte, error) {
	s, err := Split(data)
	if err != nil {
		return nil, err
	}
	if !s.HasSigningBlock() {
		return data, nil
	}
	out := make([]byte, 0, len(s.BeforeBlock)+len(s.CentralDir)+len(s.EOCD))
	out = append(out, s.BeforeBlock...)
	out = append(out, s.CentralDir...)
	out = append(out, s.EOCD...)

	// 中央目录偏移需回退到签名块之前的位置。
	eocdStart := len(s.BeforeBlock) + len(s.CentralDir)
	binary.LittleEndian.PutUint32(out[eocdStart+16:], uint32(len(s.BeforeBlock)))
	return out, nil
}
