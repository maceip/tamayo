package mayo

// Matrix operations on bitsliced m-vectors. Transpiled from pq-mayo
// src/matrix_ops.rs (keygen subset: p1_times_o, mul_add_mat_trans_x_m_mat,
// compute_p3, m_upper). The sign/verify operations (compute_m_and_vpv,
// m_calculate_ps_sps_with_scratch, ...) are ported alongside sign/verify.

// p1TimesO computes acc += P1 * O, where P1 is the upper-triangular v×v matrix
// of m-vectors (stored as v*(v+1)/2 entries) and O is the v×o plain GF(16)
// matrix. Bin-accumulator form.
func p1TimesO(p *Params, p1 []uint64, o []byte, acc []uint64) {
	mvl := p.MVecLimbs
	v := p.V()
	oo := p.O

	bins := make([]uint64, v*oo*16*mvl)
	used := 0
	for r := 0; r < v; r++ {
		for c := r; c < v; c++ {
			src := p1[used*mvl : (used+1)*mvl]
			oCOff := c * oo
			for k := 0; k < oo; k++ {
				bin := (r*oo+k)*16*mvl + int(o[oCOff+k])*mvl
				mVecAdd(src, bins[bin:bin+mvl], mvl)
			}
			used++
		}
	}

	tmp := make([]uint64, mvl)
	for i := 0; i < v*oo; i++ {
		base := i * 16 * mvl
		mVecMultiplyBins(bins[base:], tmp, mvl)
		mVecAdd(tmp, acc[i*mvl:(i+1)*mvl], mvl)
	}
}

// mulAddMatTransXMMat computes acc = matᵀ * bsMat (overwriting acc), where mat
// is matRows×matCols plain GF(16) and bsMat is matRows×bsMatCols m-vectors.
func mulAddMatTransXMMat(p *Params, mat []byte, bsMat []uint64, acc []uint64, matRows, matCols, bsMatCols int) {
	mvl := p.MVecLimbs

	bins := make([]uint64, matCols*bsMatCols*16*mvl)
	for r := 0; r < matCols; r++ {
		binsRow := r * bsMatCols * 16 * mvl
		for c := 0; c < matRows; c++ {
			scalar := mat[c*matCols+r]
			srcRow := c * bsMatCols * mvl
			for k := 0; k < bsMatCols; k++ {
				bin := binsRow + (k*16+int(scalar))*mvl
				src := bsMat[srcRow+k*mvl : srcRow+(k+1)*mvl]
				mVecAdd(src, bins[bin:bin+mvl], mvl)
			}
		}
	}
	for i := 0; i < matCols*bsMatCols; i++ {
		base := i * 16 * mvl
		mVecMultiplyBins(bins[base:], acc[i*mvl:(i+1)*mvl], mvl)
	}
}

// computeP3 computes P3 = Oᵀ * (P1*O + P2). It modifies p2 in place (adds P1*O).
func computeP3(p *Params, p1 []uint64, p2 []uint64, o []byte, p3 []uint64) {
	v := p.V()
	oo := p.O
	p1TimesO(p, p1, o, p2)                       // p2 += P1 * O
	mulAddMatTransXMMat(p, o, p2, p3, v, oo, oo) // p3 = Oᵀ * p2
}

// mUpper folds a size×size matrix of m-vectors into upper-triangular form:
// upper[r,c] = input[r,c] + input[c,r] for r<c, and input[r,r] on the diagonal.
func mUpper(mVecLimbs int, input []uint64, output []uint64, size int) {
	stored := 0
	for r := 0; r < size; r++ {
		for c := r; c < size; c++ {
			dst := output[mVecLimbs*stored : mVecLimbs*(stored+1)]
			srcRC := input[mVecLimbs*(r*size+c) : mVecLimbs*(r*size+c+1)]
			copy(dst[:mVecLimbs], srcRC[:mVecLimbs])
			if r != c {
				srcCR := mVecLimbs * (c*size + r)
				for i := 0; i < mVecLimbs; i++ {
					dst[i] ^= input[srcCR+i]
				}
			}
			stored++
		}
	}
}
