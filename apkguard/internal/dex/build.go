package dex

import (
	"encoding/binary"
	"fmt"
)

// Empty 返回一个「不含任何条目」的合法 DEX 字节流。
//
// 用途：加壳（B1~B4）需要在原 APK 之外**新建**一个只含壳类的 DEX，
// 而引擎此前只能重建「已存在的 DEX」。有了这个空壳，新建 DEX 就可以
// 复用完全相同的重建流程：Empty() 造骨架，再把壳类作为 Addition 追加进去，
// 从而无需为「从零生成」单独写一套索引表/数据区的排布逻辑。
//
// 返回的字节流已通过 Finalize 计算好签名与校验和，可直接被 Parse 接受。
func Empty() []byte { return EmptyWithVersion(DexVersionDefault) }

// DEX 版本号（魔数里的那三位数字）。
//
// 这一位不能随便取：安卓对 DEX 版本有**最低要求**。035 是远古版本
// （安卓 2.2~7.x 时代的产物），现代系统会直接拒绝加载，表现为
// 「装得上、一打开就崩」——而本地任何结构校验都看不出问题。
//
// 实测（安卓 16）：被测 APK 自带的原始 DEX 是 037，可以正常运行；
// 我们新建的壳 DEX 曾是 035，启动即崩。037 对应安卓 7.0+，与 minSdk 24
// 相符，因此作为新建 DEX 的默认版本。
//
// 更稳妥的做法是「跟随输入」：重建已有 DEX 时沿用它的版本
// （重建流程整体拷贝魔数，见 assemble.go），只有从零新建才用默认值。
const (
	// dexVersion035 仅用于测试与识别，不应再作为产物版本。
	dexVersion035 = 0x30<<16 | 0x33<<8 | 0x35
	// DexVersionDefault 是新建 DEX 的默认版本：037。
	DexVersionDefault = 0x30<<16 | 0x33<<8 | 0x37
)

// EmptyWithVersion 与 Empty 相同，但可指定版本号（低 24 位是 "037" 的 ASCII）。
func EmptyWithVersion(version uint32) []byte {
	out := make([]byte, headerSize)
	copy(out[0:8], "dex\n000\x00")
	out[4] = byte(version >> 16)
	out[5] = byte(version >> 8)
	out[6] = byte(version)
	binary.LittleEndian.PutUint32(out[offFileSize:], headerSize)
	binary.LittleEndian.PutUint32(out[offHeaderSize:], headerSize)
	binary.LittleEndian.PutUint32(out[offEndianTag:], endianTag)
	// 其余各段数量与偏移均为 0，表示「无条目」。
	return Finalize(out)
}

// Build 生成一个只包含给定类的新 DEX。
//
// 这是加壳流程的基础设施：壳类（Application 代理、ClassLoader 接管逻辑、
// 环境检测等）全部通过它落到一个独立的 DEX 中。
func Build(add Addition) ([]byte, error) {
	f, err := Parse(Empty())
	if err != nil {
		return nil, fmt.Errorf("dex: 构造空 DEX 失败: %w", err)
	}
	out, err := Rebuild(f, RebuildOptions{Addition: &add})
	if err != nil {
		return nil, err
	}
	if err := Verify(out); err != nil {
		return nil, err
	}
	return out, nil
}
