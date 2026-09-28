package dex

import (
	"encoding/binary"
	"testing"
)

// walkInsnsDiag 以 payload 感知方式遍历指令流，返回最终位置与错误。
//
// 该函数与 remapCode 的遍历逻辑保持一致，仅用于诊断。
func walkInsnsDiag(words []uint16, report func(pos int, op byte, w int)) (int, error) {
	payloadAt := map[int]bool{}
	pos := 0
	for pos < len(words) {
		if payloadAt[pos] {
			w, ok, err := payloadWidth(words, pos)
			if err != nil {
				return pos, err
			}
			if !ok {
				return pos, errNotPayload
			}
			if report != nil {
				report(pos, 0xff, w)
			}
			pos += w
			continue
		}
		op := byte(words[pos] & 0xff)
		w := int(insnWidths[op])
		if w <= 0 || pos+w > len(words) {
			return pos, errBadWidth
		}
		if report != nil {
			report(pos, op, w)
		}
		if offWord, ok := branchInsns[op]; ok {
			rel := int32(uint32(words[pos+offWord]) | uint32(words[pos+offWord+1])<<16)
			if t := pos + int(rel); t >= 0 && t < len(words) {
				payloadAt[t] = true
			}
		}
		pos += w
	}
	return pos, nil
}

// TestDumpInsnStream 遍历全部方法，找出指令流无法精确走完的那些。
func TestDumpInsnStream(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	bad, total := 0, 0
	f.Classes(func(_ uint32, cd ClassDef, name string) error {
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
				ci, err := f.CodeInsns(m.CodeOff)
				if err != nil {
					continue
				}
				total++
				words := make([]uint16, ci.InsnsSize)
				for i := uint32(0); i < ci.InsnsSize; i++ {
					words[i] = uint16(f.data[ci.InsnsOff+2*int(i)]) |
						uint16(f.data[ci.InsnsOff+2*int(i)+1])<<8
				}
				pos, werr := walkInsnsDiag(words, nil)
				if werr != nil || pos != len(words) {
					bad++
					if bad <= 3 {
						desc, _ := f.MethodDesc(m.Idx)
						t.Logf("异常: code=@%d 方法=%s size=%d 走到=%d err=%v",
							m.CodeOff, desc, len(words), pos, werr)
						// 完整打印指令流，便于定位错位点
						for p := 0; p < len(words); {
							o := byte(words[p] & 0xff)
							ww := int(insnWidths[o])
							t.Logf("    word %3d: raw=0x%04x op=0x%02x width=%d", p, words[p], o, ww)
							if ww <= 0 {
								break
							}
							p += ww
						}
					}
				}
			}
		}
		return nil
	})
	t.Logf("共检查 %d 个方法，异常 %d 个", total, bad)
	if bad > 0 {
		t.Fatalf("存在 %d 个指令流异常的方法", bad)
	}
}

var (
	errNotPayload = errDiag("标记为 payload 但标识不匹配")
	errBadWidth   = errDiag("指令宽度越界")
)

type errDiag string

func (e errDiag) Error() string { return string(e) }

var _ = binary.LittleEndian
