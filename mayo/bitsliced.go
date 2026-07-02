package mayo

import "github.com/maceip/tamayo/gf16"

// Bitsliced GF(16) vector arithmetic on nibble-packed u64 limbs.
//
// Transpiled from pq-mayo src/bitsliced.rs, scalar paths only: m_vec_add
// (scalar), m_vec_mul_add_scalar, bins_mul_add_x / bins_mul_add_x_inv (scalar),
// and m_vec_multiply_bins_dyn. The SSSE3/AVX2/NEON kernels in the reference are
// omitted deliberately (no cgo / no host-SIMD dependency on tamago); they are a
// pure performance optimization and produce identical results.

const (
	maskLSB uint64 = 0x1111111111111111 // bit 0 of every nibble
	maskMSB uint64 = 0x8888888888888888 // bit 3 of every nibble
)

// mVecAdd computes acc ^= src over mVecLimbs u64 limbs.
func mVecAdd(src, acc []uint64, mVecLimbs int) {
	for i := 0; i < mVecLimbs; i++ {
		acc[i] ^= src[i]
	}
}

// mVecMulAdd computes acc += a * src (a a GF(16) scalar) over mVecLimbs limbs,
// using the packed multiplication table.
func mVecMulAdd(src []uint64, a byte, acc []uint64, mVecLimbs int) {
	tab := gf16.MulTable(a)
	t0 := uint64(tab & 0xff)
	t1 := uint64((tab >> 8) & 0xf)
	t2 := uint64((tab >> 16) & 0xf)
	t3 := uint64((tab >> 24) & 0xf)

	for i := 0; i < mVecLimbs; i++ {
		s := src[i]
		acc[i] ^= (s&maskLSB)*t0 ^
			((s>>1)&maskLSB)*t1 ^
			((s>>2)&maskLSB)*t2 ^
			((s>>3)&maskLSB)*t3
	}
}

// vecMulAddU64 is mVecMulAdd with the length-first argument order used by the
// echelon form code (pq-mayo vec_mul_add_u64).
func vecMulAddU64(legs int, src []uint64, a byte, acc []uint64) {
	mVecMulAdd(src, a, acc, legs)
}

// binsMulAddXInv applies the "multiply by x^-1 and add" step of the bin ladder:
// bins[dst..] ^= ((s ^ t) >> 1) ^ (t*9), with t = s & maskLSB.
func binsMulAddXInv(bins []uint64, src, dst, n int) {
	for i := 0; i < n; i++ {
		t := bins[src+i] & maskLSB
		bins[dst+i] ^= ((bins[src+i] ^ t) >> 1) ^ (t * 9)
	}
}

// binsMulAddX applies the "multiply by x and add" step of the bin ladder:
// bins[dst..] ^= ((s ^ t) << 1) ^ ((t>>3)*3), with t = s & maskMSB.
func binsMulAddX(bins []uint64, src, dst, n int) {
	for i := 0; i < n; i++ {
		t := bins[src+i] & maskMSB
		bins[dst+i] ^= ((bins[src+i] ^ t) << 1) ^ ((t >> 3) * 3)
	}
}

// mVecMultiplyBins collapses 16 accumulator bins into out, computing
// out = sum_{c=1}^{15} c * bins[c] over GF(16). bins holds 16*mVecLimbs limbs
// (bin c at offset c*mVecLimbs) and is used as scratch; out holds mVecLimbs.
func mVecMultiplyBins(bins, out []uint64, mvl int) {
	binsMulAddXInv(bins, 5*mvl, 10*mvl, mvl)
	binsMulAddX(bins, 11*mvl, 12*mvl, mvl)
	binsMulAddXInv(bins, 10*mvl, 7*mvl, mvl)
	binsMulAddX(bins, 12*mvl, 6*mvl, mvl)
	binsMulAddXInv(bins, 7*mvl, 14*mvl, mvl)
	binsMulAddX(bins, 6*mvl, 3*mvl, mvl)
	binsMulAddXInv(bins, 14*mvl, 15*mvl, mvl)
	binsMulAddX(bins, 3*mvl, 8*mvl, mvl)
	binsMulAddXInv(bins, 15*mvl, 13*mvl, mvl)
	binsMulAddX(bins, 8*mvl, 4*mvl, mvl)
	binsMulAddXInv(bins, 13*mvl, 9*mvl, mvl)
	binsMulAddX(bins, 4*mvl, 2*mvl, mvl)
	binsMulAddXInv(bins, 9*mvl, mvl, mvl)
	binsMulAddX(bins, 2*mvl, mvl, mvl)

	copy(out[:mvl], bins[mvl:2*mvl])
}
