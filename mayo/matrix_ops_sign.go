package mayo

// Bin-accumulator matrix operations used by signing. Transpiled from pq-mayo
// src/matrix_ops.rs (bins_mat_x_m_mat, bins_upper_tri_mat_x_mat_trans,
// p1p1t_times_o, compute_m_and_vpv).

// binsMatXMMat computes acc = mat · bsMat (overwriting acc), where mat is
// matRows×matCols plain GF(16) and bsMat is matCols×bsMatCols m-vectors.
func binsMatXMMat(p *Params, mat []byte, bsMat, acc []uint64, matRows, matCols, bsMatCols int) {
	mvl := p.MVecLimbs
	bins := make([]uint64, matRows*bsMatCols*16*mvl)
	for r := 0; r < matRows; r++ {
		binsRow := r * bsMatCols * 16 * mvl
		matRow := mat[r*matCols : (r+1)*matCols]
		for c := 0; c < matCols; c++ {
			scalar := matRow[c]
			srcRow := c * bsMatCols * mvl
			for k := 0; k < bsMatCols; k++ {
				binIdx := binsRow + (k*16+int(scalar))*mvl
				src := bsMat[srcRow+k*mvl : srcRow+(k+1)*mvl]
				mVecAdd(src, bins[binIdx:binIdx+mvl], mvl)
			}
		}
	}
	for i := 0; i < matRows*bsMatCols; i++ {
		base := i * 16 * mvl
		mVecMultiplyBins(bins[base:], acc[i*mvl:(i+1)*mvl], mvl)
	}
}

// binsUpperTriMatXMatTrans computes acc[r,k] = sum_{c>=r} bsMat[r,c]·mat[k,c],
// with bsMat the rows*(rows+1)/2 upper-triangular m-vectors (row-major).
func binsUpperTriMatXMatTrans(p *Params, bsMat []uint64, mat []byte, acc []uint64, rows, matRows int) {
	mvl := p.MVecLimbs
	cols := rows
	bins := make([]uint64, rows*matRows*16*mvl)
	used := 0
	for r := 0; r < rows; r++ {
		binsRow := r * matRows * 16 * mvl
		for c := r; c < cols; c++ {
			src := bsMat[used*mvl : (used+1)*mvl]
			for k := 0; k < matRows; k++ {
				scalar := mat[k*cols+c]
				binIdx := binsRow + (k*16+int(scalar))*mvl
				mVecAdd(src, bins[binIdx:binIdx+mvl], mvl)
			}
			used++
		}
	}
	for i := 0; i < rows*matRows; i++ {
		base := i * 16 * mvl
		mVecMultiplyBins(bins[base:], acc[i*mvl:(i+1)*mvl], mvl)
	}
}

// p1p1tTimesO computes acc += (P1 + P1ᵀ)·O, skipping the diagonal and adding
// both (r,c) and (c,r) contributions. acc typically already holds P2.
func p1p1tTimesO(p *Params, p1 []uint64, o []byte, acc []uint64) {
	mvl := p.MVecLimbs
	oo := p.O
	v := p.V()

	bins := make([]uint64, v*oo*16*mvl)
	used := 0
	for r := 0; r < v; r++ {
		for c := r; c < v; c++ {
			if c == r {
				used++
				continue
			}
			srcOff := mvl * used
			src := p1[srcOff : srcOff+mvl]
			oCOff := c * oo
			oROff := r * oo
			for k := 0; k < oo; k++ {
				b1 := (r*oo+k)*16*mvl + int(o[oCOff+k])*mvl
				mVecAdd(src, bins[b1:b1+mvl], mvl)
				b2 := (c*oo+k)*16*mvl + int(o[oROff+k])*mvl
				mVecAdd(src, bins[b2:b2+mvl], mvl)
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

// computeMAndVpv computes the M matrices (VL = V·L) and VP1V = V·(P1·Vᵀ).
// pv is caller-provided scratch of length V*K*MVecLimbs.
func computeMAndVpv(p *Params, vdec []byte, l, p1, vl, vp1v, pv []uint64) {
	k := p.K
	v := p.V()
	o := p.O
	binsMatXMMat(p, vdec, l, vl, k, v, o)
	binsUpperTriMatXMatTrans(p, p1, vdec, pv, v, k)
	binsMatXMMat(p, vdec, pv, vp1v, k, v, k)
}
