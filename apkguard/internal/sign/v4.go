package sign

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"apkguard/internal/keystore"
)

// v4 常量（依据 Android APK Signature Scheme v4 规范）。
const (
	v4Version       = 2
	v4HashAlgorithm = 1  // 仅支持 SHA-256
	v4Log2BlockSize = 12 // 仅支持 4096 字节块
	// fs-verity 中每个哈希块可承载 4096/32 = 128 个哈希。
	v4HashesPerBlock = (1 << v4Log2BlockSize) / sha256.Size
)

// buildIDSig 生成 v4 签名文件（.idsig）内容。
//
// apkDigest 必须与 v2/v3 签名块中记录的内容摘要完全一致，
// 平台会交叉比对两者，不一致将判定签名无效。
//
// 文件结构（全部小端）：
//
//	int32 version
//	sized_bytes hashing_info
//	sized_bytes signing_info
//	sized_bytes merkle_tree
func buildIDSig(apk []byte, mat *keystore.Material, apkDigest []byte) ([]byte, error) {
	algo, err := pickAlgo(mat.PrivateKey)
	if err != nil {
		return nil, err
	}
	leaf := mat.Leaf()
	if leaf == nil {
		return nil, ErrNoCert
	}

	tree, rawRootHash := fsverityTree(apk, nil)

	// hashing_info = hash_algorithm(4) | log2_blocksize(1) | salt | raw_root_hash
	var tmp [4]byte
	hashingInfo := make([]byte, 0, 64)
	binary.LittleEndian.PutUint32(tmp[:], v4HashAlgorithm)
	hashingInfo = append(hashingInfo, tmp[:]...)
	hashingInfo = append(hashingInfo, byte(v4Log2BlockSize))
	hashingInfo = append(hashingInfo, lp(nil)...) // salt 为空
	hashingInfo = append(hashingInfo, lp(rawRootHash)...)

	// 待签名数据块
	signedBlob := buildV4DataForSigning(int64(len(apk)), hashingInfo, apkDigest, leaf.Raw)
	digestOfBlob, err := hashBytes(algo.Hash, signedBlob)
	if err != nil {
		return nil, err
	}
	sig, err := algo.sign(mat.PrivateKey, digestOfBlob)
	if err != nil {
		return nil, fmt.Errorf("sign: v4 签名失败: %w", err)
	}
	spki, err := marshalSPKI(mat.PrivateKey)
	if err != nil {
		return nil, err
	}

	// signing_info = apk_digest | x509_certificate | additional_data | public_key
	//                | signature_algorithm_id | signature
	signingInfo := make([]byte, 0, 256)
	signingInfo = append(signingInfo, lp(apkDigest)...)
	signingInfo = append(signingInfo, lp(leaf.Raw)...)
	signingInfo = append(signingInfo, lp(nil)...)
	signingInfo = append(signingInfo, lp(spki)...)
	binary.LittleEndian.PutUint32(tmp[:], algo.ID)
	signingInfo = append(signingInfo, tmp[:]...)
	signingInfo = append(signingInfo, lp(sig)...)

	out := make([]byte, 0, 12+len(hashingInfo)+len(signingInfo)+len(tree))
	binary.LittleEndian.PutUint32(tmp[:], v4Version)
	out = append(out, tmp[:]...)
	out = append(out, lp(hashingInfo)...)
	out = append(out, lp(signingInfo)...)
	out = append(out, lp(tree)...)
	return out, nil
}

// buildV4DataForSigning 按规范拼装参与签名的数据块 V4DataForSigning。
//
// 字段顺序：size | file_size | hash_algorithm | log2_blocksize | salt |
// raw_root_hash | apk_digest | x509_certificate | additional_data
func buildV4DataForSigning(fileSize int64, hashingInfo, apkDigest, certDER []byte) []byte {
	body := make([]byte, 0, 96+len(apkDigest)+len(certDER))
	var tmp [8]byte

	binary.LittleEndian.PutUint64(tmp[:], uint64(fileSize))
	body = append(body, tmp[:]...)

	binary.LittleEndian.PutUint32(tmp[:4], v4HashAlgorithm)
	body = append(body, tmp[:4]...)
	body = append(body, byte(v4Log2BlockSize))

	// salt 与 raw_root_hash 直接取自 hashing_info 尾部（跳过 5 字节头部）。
	body = append(body, hashingInfo[5:]...)
	body = append(body, lp(apkDigest)...)
	body = append(body, lp(certDER)...)
	body = append(body, lp(nil)...)

	out := make([]byte, 0, 4+len(body))
	var sz [4]byte
	binary.LittleEndian.PutUint32(sz[:], uint32(4+len(body)))
	out = append(out, sz[:]...)
	out = append(out, body...)
	return out
}

// fsverityTree 计算 fs-verity 结构的 Merkle 树。
//
// 返回 tree（写入 .idsig 的树字节）与 rootHash（根页的摘要）。
//
// 结构要点（与 fs-verity 一致，经 apksigner 产物实测校准）：
//   - 数据按 4096 字节分块，最后一块以零补齐到 4096 再哈希；
//   - 每 128 个哈希打包为一个 4096 字节「页」，不足处以零补齐；
//   - 逐层向上直至只剩一个页（根页）；
//   - 输出顺序为「根页在前、叶子页在后」，每页均为 4096 字节；
//   - rootHash = H(根页整体 4096 字节)。
func fsverityTree(data, salt []byte) (tree, rootHash []byte) {
	const blkSize = 1 << v4Log2BlockSize

	// 叶子层：数据块哈希（末块补零）
	nDataBlocks := (len(data) + blkSize - 1) / blkSize
	if nDataBlocks == 0 {
		nDataBlocks = 1
	}
	level := make([][]byte, 0, nDataBlocks)
	for i := 0; i < nDataBlocks; i++ {
		blk := make([]byte, blkSize)
		if off := i * blkSize; off < len(data) {
			copy(blk, data[off:])
		}
		level = append(level, saltedHash(salt, blk))
	}

	// 逐层向上：每层按 128 个哈希打包成页，直到当前哈希序列能装进单页为止。
	// 该单页即根页，不再对根页继续求哈希（否则会多出一层）。
	levels := make([][]byte, 0, 4)
	for {
		levels = append(levels, packLevel(level))
		if len(level) <= v4HashesPerBlock {
			break
		}
		next := make([][]byte, 0, (len(level)+v4HashesPerBlock-1)/v4HashesPerBlock)
		for i := 0; i < len(level); i += v4HashesPerBlock {
			end := i + v4HashesPerBlock
			if end > len(level) {
				end = len(level)
			}
			blk := make([]byte, blkSize)
			off := 0
			for _, h := range level[i:end] {
				copy(blk[off:], h)
				off += sha256.Size
			}
			next = append(next, saltedHash(salt, blk))
		}
		level = next
	}

	rootPage := levels[len(levels)-1]
	rootHash = saltedHash(salt, rootPage)

	// 根页在前，逐层向下
	for i := len(levels) - 1; i >= 0; i-- {
		tree = append(tree, levels[i]...)
	}
	return tree, rootHash
}

// packLevel 把一层哈希按 4096 字节块对齐后拼接。
func packLevel(hashes [][]byte) []byte {
	const blkSize = 1 << v4Log2BlockSize
	out := make([]byte, 0, ((len(hashes)+v4HashesPerBlock-1)/v4HashesPerBlock)*blkSize)
	for i := 0; i < len(hashes); i += v4HashesPerBlock {
		end := i + v4HashesPerBlock
		if end > len(hashes) {
			end = len(hashes)
		}
		blk := make([]byte, blkSize)
		off := 0
		for _, h := range hashes[i:end] {
			copy(blk[off:], h)
			off += sha256.Size
		}
		out = append(out, blk...)
	}
	return out
}

func saltedHash(salt, data []byte) []byte {
	h := sha256.New()
	h.Write(salt)
	h.Write(data)
	return h.Sum(nil)
}
