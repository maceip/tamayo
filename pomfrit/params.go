package pomfrit

import "github.com/maceip/tamayo/gf16"

// MayoParams is the whipped MAYO instance proven by One-More-MAYO. Values from
// pq_blind_signatures vole/optimized_bs/parameters.hpp (VOLEMAYO_*): N, M, O,
// V=N-O, K, and the whipping tail polynomial F_TAIL.
type MayoParams struct {
	N, M, O, V, K int
	FTail         [4]byte
}

// The three v1 MAYO instances (L1/L3/L5). F_TAIL from VOLEMAYO_F_TAIL_{78,108,142}.
var (
	VoleMayoL1 = MayoParams{N: 86, M: 78, O: 8, V: 78, K: 10, FTail: [4]byte{8, 1, 1, 0}}
	VoleMayoL3 = MayoParams{N: 118, M: 108, O: 10, V: 108, K: 11, FTail: [4]byte{8, 0, 1, 7}}
	VoleMayoL5 = MayoParams{N: 154, M: 142, O: 12, V: 142, K: 12, FTail: [4]byte{4, 0, 8, 1}}
)

func (p MayoParams) u64sPerVec() int { return (p.M + 15) / 16 }

// mvecScalarMulAdd computes dst ^= scalar * src over a nibble-packed GF(16)
// m-vector (u64sPerVec words each).
func mayoMVecScalarMulAdd(dst []uint64, scalar byte, src []uint64) {
	for i := range dst {
		dst[i] ^= gf16.MulU64(scalar, src[i])
	}
}

// mVecByte reads byte j of the m-vector at u64 offset off.
func mayoMVecByte(data []uint64, off, j int) byte {
	return byte(data[off+j/8] >> ((j % 8) * 8))
}

// putMVecBytes writes m/2 little-endian bytes into an m-vector slot.
func mayoPutMVecBytes(dst []uint64, src []byte) {
	for i, b := range src {
		dst[i/8] |= uint64(b) << ((i % 8) * 8)
	}
}

// applyEP multiplies each nibble-packed m-vector in data by the whipping element
// X in GF(16)[X]/f(X). Transpiled from owf_proof.inc _apply_e_p.
func (p MayoParams) applyEP(data []uint64, numVecs int) {
	m := p.M
	u := p.u64sPerVec()
	elemsInLast := m - (u-1)*16
	lastMask := (uint64(1) << (elemsInLast * 4)) - 1
	if elemsInLast == 16 {
		lastMask = ^uint64(0)
	}

	var tailMul [16]uint32
	for i := 0; i < 16; i++ {
		for j := 0; j < 4; j++ {
			tailMul[i] ^= uint32(gf16.Mul(byte(i), p.FTail[j])) << (j * 4)
		}
	}

	for idx := 0; idx < numVecs; idx++ {
		topNibble := byte((data[(idx+1)*u-1] >> (((m - 1) % 16) * 4)) & 0xf)
		for i := u - 1; i > 0; i-- {
			data[idx*u+i] = (data[idx*u+i] << 4) | (data[idx*u+i-1] >> 60)
		}
		data[idx*u] <<= 4
		data[(idx+1)*u-1] &= lastMask
		data[idx*u] ^= uint64(tailMul[topNibble])
	}
}

// combineP1P2P3 assembles the full n*(n+1)/2 upper-triangular MAYO public map
// from P1 (v*(v+1)/2), P2 (v*o), P3 (o*(o+1)/2). Transpiled from owf_proof.inc
// _combineP1_P2_P3.
func (p MayoParams) combineP1P2P3(in []byte) []uint64 {
	m, n, v, o := p.M, p.N, p.V, p.O
	u := p.u64sPerVec()
	out := make([]uint64, n*(n+1)/2*u)

	p1 := 0
	p2 := p1 + v*(v+1)/2*u*8
	p3 := p2 + v*o*u*8

	outIdx := 0
	for i := 0; i < v; i++ {
		for j := i; j < v; j++ {
			mayoPutMVecBytes(out[outIdx:outIdx+u], in[p1:p1+m/2])
			p1 += u * 8
			outIdx += u
		}
		for j := v; j < n; j++ {
			mayoPutMVecBytes(out[outIdx:outIdx+u], in[p2:p2+m/2])
			p2 += u * 8
			outIdx += u
		}
	}
	mayoPutMVecBytes(out[outIdx:], in[p3:p3+o*(o+1)/2*u*8])
	return out
}
