package mayo

// Public-map evaluation used by verification. Transpiled from pq-mayo
// src/matrix_ops.rs (m_calculate_ps_sps_with_scratch); scratch buffers are
// allocated internally here rather than threaded through a struct.

// mCalculatePsSps computes SPS = S · P · Sᵀ (as bitsliced m-vectors) from the
// public P1/P2/P3 and the decoded signature s (k×n plain GF(16)). sps must hold
// k*k*MVecLimbs limbs.
func mCalculatePsSps(p *Params, p1, p2, p3 []uint64, s []byte, sps []uint64) {
	v := p.V()
	o := p.O
	k := p.K
	n := p.N
	mvl := p.MVecLimbs

	ps := make([]uint64, n*k*mvl)
	accumulator := make([]uint64, 16*mvl*k*n)
	spsAcc := make([]uint64, 16*mvl*k*k)

	// PS accumulation: rows in the vinegar block contribute P1 (upper-tri) and P2.
	p1Used := 0
	for row := 0; row < v; row++ {
		accRowOff := row * k * 16 * mvl
		for j := row; j < v; j++ {
			src := p1[p1Used*mvl : (p1Used+1)*mvl]
			for col := 0; col < k; col++ {
				binIdx := accRowOff + (col*16+int(s[col*n+j]))*mvl
				mVecAdd(src, accumulator[binIdx:binIdx+mvl], mvl)
			}
			p1Used++
		}
		for j := 0; j < o; j++ {
			src := p2[(row*o+j)*mvl : (row*o+j+1)*mvl]
			for col := 0; col < k; col++ {
				binIdx := accRowOff + (col*16+int(s[col*n+j+v]))*mvl
				mVecAdd(src, accumulator[binIdx:binIdx+mvl], mvl)
			}
		}
	}
	// rows in the oil block contribute P3 (upper-tri).
	p3Used := 0
	for row := v; row < n; row++ {
		accRowOff := row * k * 16 * mvl
		for j := row; j < n; j++ {
			src := p3[p3Used*mvl : (p3Used+1)*mvl]
			for col := 0; col < k; col++ {
				binIdx := accRowOff + (col*16+int(s[col*n+j]))*mvl
				mVecAdd(src, accumulator[binIdx:binIdx+mvl], mvl)
			}
			p3Used++
		}
	}
	for idx := 0; idx < n*k; idx++ {
		mVecMultiplyBins(accumulator[idx*16*mvl:], ps[idx*mvl:(idx+1)*mvl], mvl)
	}

	// SPS = S · PS
	for row := 0; row < k; row++ {
		sRow := s[row*n : (row+1)*n]
		spsAccRowOff := row * k * 16 * mvl
		for j := 0; j < n; j++ {
			bin := int(sRow[j])
			psRowOff := j * k * mvl
			for col := 0; col < k; col++ {
				binIdx := spsAccRowOff + (col*16+bin)*mvl
				psIdx := psRowOff + col*mvl
				mVecAdd(ps[psIdx:psIdx+mvl], spsAcc[binIdx:binIdx+mvl], mvl)
			}
		}
	}
	for idx := 0; idx < k*k; idx++ {
		mVecMultiplyBins(spsAcc[idx*16*mvl:], sps[idx*mvl:(idx+1)*mvl], mvl)
	}
}
