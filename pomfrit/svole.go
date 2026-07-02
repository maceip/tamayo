package pomfrit

import (
	"math/bits"

	"github.com/maceip/tamayo/faest"
)

// Small-VOLE (sender side) for the optimized_bs MAYO path. Transpiled from
// pq_blind_signatures vole/optimized_bs/small_vole.inc (xor_reduce,
// process_prg_output, vole<receiver=false>) and vole_commit.inc (vole_commit).
// VOLE_BLOCK = 1 (vole_block = 16 bytes), and for aes_ctr VOLE_WIDTH_SHIFT = 3
// (AES_PREFERRED_WIDTH_SHIFT 3, PRG_VOLE_BLOCKS_SHIFT 0), so VOLE_WIDTH = 8.

const (
	voleWidthShift = 3
	voleWidth      = 1 << voleWidthShift // 8
	voleBlockBytes = 16
)

// volePermuteKeyIndex is vole_permute_key_index: Gray-code the high bits (above
// VOLE_WIDTH) while keeping the low VOLE_WIDTH_SHIFT bits unchanged.
func volePermuteKeyIndex(i int) int {
	return i ^ ((i >> 1) &^ (voleWidth - 1))
}

func xorInto16(dst, src []byte) {
	for i := 0; i < voleBlockBytes; i++ {
		dst[i] ^= src[i]
	}
}

// xorReduce is xor_reduce over VOLE_WIDTH (8) blocks: computes the Hamming-code
// syndrome in place. After it runs, io[0] is the XOR of all 8 inputs and
// io[1..VOLE_WIDTH_SHIFT] hold the low syndrome bits. Each io[x] is a distinct
// 16-byte block.
func xorReduce(io [][]byte) {
	for i := 0; i < voleWidthShift; i++ {
		stride := 1 << i
		for j := 0; j < voleWidth; j += 2 * stride {
			for d := 0; d <= i; d++ {
				xorInto16(io[j+d], io[j+d+stride])
			}
			copy(io[j+i+1], io[j+stride])
		}
	}
}

// colLenBytes is one VOLE column (COL_LEN blocks) in bytes.
func (m MayoForest) colLenBytes() int { return m.colLen() * voleBlockBytes }

// voleSender is vole<P, receiver=false>: expands 2^k permuted leaf keys with
// AES-CTR (tweak) into the k VOLE columns vq (k*COL_LEN blocks) and the accum
// column. If uIn is nil it returns accum (this instance's u); otherwise it
// returns the correction uIn XOR accum. keys must already be in
// vole_permute_key_index order.
func (m MayoForest) voleSender(k int, keys [][]byte, iv []byte, tweak uint32, uIn []byte) (vq, cOut []byte) {
	colLen := m.colLen()
	colBytes := m.colLenBytes()
	n := 1 << k

	// Expand each leaf key to a full COL_LEN-block column via AES-CTR.
	exp := make([][]byte, n)
	for i := 0; i < n; i++ {
		exp[i] = make([]byte, colBytes)
		faest.NewPRG(keys[i], iv, tweak).Read(exp[i])
	}

	accum := make([]byte, colBytes)
	vq = make([]byte, k*colBytes)

	for i := 0; i < n; i += voleWidth {
		// Gray's-code column: the bit that flips on incrementing. The OR with
		// 1<<(k-1) makes output_col == k-1 when i+VOLE_WIDTH == 2^k.
		outputCol := bits.TrailingZeros(uint((i + voleWidth) | (1 << (k - 1))))
		for j := 0; j < colLen; j++ {
			prg := make([][]byte, voleWidth)
			for d := 0; d < voleWidth; d++ {
				prg[d] = append([]byte(nil), exp[i+d][j*voleBlockBytes:(j+1)*voleBlockBytes]...)
			}
			xorReduce(prg)

			aj := accum[j*voleBlockBytes : (j+1)*voleBlockBytes]
			xorInto16(aj, prg[0])
			for col := 0; col < voleWidthShift; col++ {
				off := (col*colLen + j) * voleBlockBytes
				xorInto16(vq[off:off+voleBlockBytes], prg[col+1])
			}
			off := (outputCol*colLen + j) * voleBlockBytes
			xorInto16(vq[off:off+voleBlockBytes], aj)
		}
	}

	cOut = make([]byte, colBytes)
	if uIn != nil {
		for x := 0; x < colBytes; x++ {
			cOut[x] = uIn[x] ^ accum[x]
		}
	} else {
		copy(cOut, accum)
	}
	return vq, cOut
}

// voleReceiver is vole<P, receiver=true>: expands 2^k permuted leaf keys (keys[0]
// is the hidden-leaf dummy) into the k VOLE columns q, pre-loaded with the
// correction masked by the per-column Delta bytes. deltaCols[col] is 0x00/0xff.
// correction may be nil (tree 0). Transpiled from small_vole.inc vole<true> +
// vole_reconstruct's correction pre-load.
func (m MayoForest) voleReceiver(k int, keys [][]byte, iv []byte, tweak uint32, correction, deltaCols []byte) []byte {
	colLen := m.colLen()
	colBytes := m.colLenBytes()
	n := 1 << k

	exp := make([][]byte, n)
	for i := 1; i < n; i++ {
		exp[i] = make([]byte, colBytes)
		faest.NewPRG(keys[i], iv, tweak).Read(exp[i])
	}

	q := make([]byte, k*colBytes)
	if correction != nil {
		for col := 0; col < k; col++ {
			var mask byte
			if deltaCols[col] != 0 {
				mask = 0xff
			}
			base := col * colBytes
			for x := 0; x < colBytes; x++ {
				q[base+x] = correction[x] & mask
			}
		}
	}

	accum := make([]byte, colBytes)
	zero := make([]byte, voleBlockBytes)
	for i := 0; i < n; i += voleWidth {
		ignore0 := i == 0
		outputCol := 0
		if !ignore0 {
			outputCol = bits.TrailingZeros(uint((i + voleWidth) | (1 << (k - 1))))
		}
		for j := 0; j < colLen; j++ {
			prg := make([][]byte, voleWidth)
			for d := 0; d < voleWidth; d++ {
				if ignore0 && d == 0 {
					prg[0] = append([]byte(nil), zero...)
					continue
				}
				prg[d] = append([]byte(nil), exp[i+d][j*voleBlockBytes:(j+1)*voleBlockBytes]...)
			}
			xorReduce(prg)

			aj := accum[j*voleBlockBytes : (j+1)*voleBlockBytes]
			if !ignore0 {
				xorInto16(aj, prg[0])
			}
			for col := 0; col < voleWidthShift; col++ {
				off := (col*colLen + j) * voleBlockBytes
				xorInto16(q[off:off+voleBlockBytes], prg[col+1])
			}
			if !ignore0 {
				off := (outputCol*colLen + j) * voleBlockBytes
				xorInto16(q[off:off+voleBlockBytes], aj)
			}
		}
	}
	return q
}

// VoleCommitSender runs vole_commit's sender path: BAVC-commit the seed, then
// small-VOLE each tree, gluing the columns into the full v matrix and emitting
// tree 0's accum as u and the later trees' corrections into commitment.
// Returns u (COL_LEN blocks), v (lambda columns * COL_LEN blocks), the
// corrections commitment (VOLE_ROWS/8 bytes per tree>0) and the BAVC check.
func (m MayoForest) VoleCommitSender(seed, iv []byte) (u, v, commitment, check []byte) {
	c := m.MayoVoleCommit(seed, iv)
	return c.U, c.V, c.Commitment, c.Check
}

// MayoVoleCommitResult bundles the sender vole_commit outputs plus the BAVC
// artifacts (forest, hashed leaves) needed to open at Delta later.
type MayoVoleCommitResult struct {
	U, V, Commitment, Check []byte
	Forest                  [][][][]byte
	HashedLeaves            [][]byte
}

// MayoVoleCommit runs the full sender vole_commit and keeps the BAVC forest and
// leaf hashes for a subsequent Open. Transpiled from vole_commit.inc vole_commit.
func (m MayoForest) MayoVoleCommit(seed, iv []byte) MayoVoleCommitResult {
	voleKeys, hashedLeaves, chk, forest := m.MayoForestCommit(seed, iv)
	colBytes := m.colLenBytes()
	lambda := m.LambdaBytes * 8
	commitRowBytes := m.voleRows() / 8

	var u, commitment []byte
	v := make([]byte, lambda*colBytes)
	colBase := 0
	for i := 0; i < m.Tau; i++ {
		k := m.treeDepth(i)
		n := 1 << k
		keys := make([][]byte, n)
		for p := 0; p < n; p++ {
			keys[p] = voleKeys[i][volePermuteKeyIndex(p)]
		}
		tweak := uint32(0x80000000) + uint32(i)
		var vq, cOut []byte
		if i == 0 {
			vq, cOut = m.voleSender(k, keys, iv, tweak, nil)
			u = cOut
		} else {
			vq, cOut = m.voleSender(k, keys, iv, tweak, u)
			commitment = append(commitment, cOut[:commitRowBytes]...)
		}
		copy(v[colBase*colBytes:], vq)
		colBase += k
	}
	return MayoVoleCommitResult{U: u, V: v, Commitment: commitment, Check: chk, Forest: forest, HashedLeaves: hashedLeaves}
}
