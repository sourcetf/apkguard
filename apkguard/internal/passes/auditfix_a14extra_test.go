package passes

import (
	"context"
	"encoding/binary"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// A14 必须清掉携带时间的扩展字段（0x5455 / 0x000a），否则统一的 DOS 时间被覆盖。
func TestA14StripsTimeExtras(t *testing.T) {
	withTime := []byte{0x55, 0x54, 0x05, 0x00, 1, 2, 3, 4, 5}
	ntfs := []byte{0x0a, 0x00, 0x04, 0x00, 9, 9, 9, 9}
	keep := []byte{0x35, 0xd9, 0x02, 0x00, 0, 0}
	e := zipx.NewStored("a.txt", []byte("x"))
	e.LocalExtra = append(append(append([]byte{}, withTime...), ntfs...), keep...)
	e.CentralExtra = append([]byte{}, withTime...)
	art := newArtifact(e)
	if err := (&metaUnify{}).Run(context.Background(), art, &config.Options{}); err != nil {
		t.Fatal(err)
	}
	got := art.Entries()[0]
	if string(got.LocalExtra) != string(keep) {
		t.Fatalf("LocalExtra = %x，期望只保留对齐记录 %x", got.LocalExtra, keep)
	}
	if len(got.CentralExtra) != 0 {
		t.Fatalf("CentralExtra = %x，期望清空", got.CentralExtra)
	}
	_ = binary.LittleEndian
	_ = pipeline.LevelZip
}
