package mldsa

import "crypto/sha3"

// shake256 returns outLen bytes of SHAKE256 over the concatenation of the
// inputs (H in FIPS 204).
func shake256(outLen int, in ...[]byte) []byte {
	x := sha3.NewSHAKE256()
	for _, b := range in {
		x.Write(b)
	}
	out := make([]byte, outLen)
	x.Read(out)
	return out
}

// rejNTTPoly is FIPS 204 algorithm 30 (with CoeffFromThreeBytes, algorithm
// 14): sample a uniform NTT-domain polynomial from SHAKE128(rho || s || r).
func rejNTTPoly(rho []byte, s, r byte) poly {
	x := sha3.NewSHAKE128()
	x.Write(rho)
	x.Write([]byte{s, r})
	var a poly
	var buf [3]byte
	for j := 0; j < n; {
		x.Read(buf[:])
		z := int32(buf[0]) | int32(buf[1])<<8 | int32(buf[2]&0x7F)<<16
		if z < q {
			a[j] = z
			j++
		}
	}
	return a
}

// expandA is FIPS 204 algorithm 32: the k x l public matrix in NTT domain.
func (p *Params) expandA(rho []byte) []vec {
	a := make([]vec, p.K)
	for r := 0; r < p.K; r++ {
		a[r] = newVec(p.L)
		for s := 0; s < p.L; s++ {
			a[r][s] = rejNTTPoly(rho, byte(s), byte(r))
		}
	}
	return a
}

// rejBoundedPoly is FIPS 204 algorithm 31 (with CoeffFromHalfByte, algorithm
// 15): sample coefficients in [-eta, eta] from SHAKE256(rhoPrime || nonce).
func rejBoundedPoly(p *Params, rhoPrime []byte, nonce int) poly {
	x := sha3.NewSHAKE256()
	x.Write(rhoPrime)
	x.Write([]byte{byte(nonce), byte(nonce >> 8)})
	var a poly
	var buf [1]byte
	for j := 0; j < n; {
		x.Read(buf[:])
		for _, z := range [2]int32{int32(buf[0] & 0x0F), int32(buf[0] >> 4)} {
			if j == n {
				break
			}
			var c int32
			switch {
			case p.Eta == 2 && z < 15:
				c = 2 - z%5
			case p.Eta == 4 && z < 9:
				c = 4 - z
			default:
				continue
			}
			// store canonical
			c += (c >> 31) & q
			a[j] = c
			j++
		}
	}
	return a
}

// expandS is FIPS 204 algorithm 33: the secret vectors s1 (length l) and s2
// (length k).
func (p *Params) expandS(rhoPrime []byte) (s1, s2 vec) {
	s1 = newVec(p.L)
	s2 = newVec(p.K)
	for r := 0; r < p.L; r++ {
		s1[r] = rejBoundedPoly(p, rhoPrime, r)
	}
	for r := 0; r < p.K; r++ {
		s2[r] = rejBoundedPoly(p, rhoPrime, p.L+r)
	}
	return
}

// expandMask is FIPS 204 algorithm 34: the vector y with coefficients in
// (-gamma1, gamma1].
func (p *Params) expandMask(rhoPP []byte, kappa int) vec {
	y := newVec(p.L)
	c := p.zBits // 1 + bitlen(gamma1-1)
	for r := 0; r < p.L; r++ {
		nonce := kappa + r
		v := shake256(32*c, rhoPP, []byte{byte(nonce), byte(nonce >> 8)})
		y[r] = bitUnpackSigned(v, p.Gamma1-1, p.Gamma1)
	}
	return y
}

// sampleInBall is FIPS 204 algorithm 29: the sparse +-1 challenge polynomial
// with tau nonzero coefficients.
func (p *Params) sampleInBall(cTilde []byte) poly {
	x := sha3.NewSHAKE256()
	x.Write(cTilde)
	var signs [8]byte
	x.Read(signs[:])
	h := uint64(0)
	for i, b := range signs {
		h |= uint64(b) << (8 * i)
	}
	var c poly
	var buf [1]byte
	for i := n - p.Tau; i < n; i++ {
		j := i + 1
		for j > i {
			x.Read(buf[:])
			j = int(buf[0])
		}
		c[i] = c[j]
		s := 1 - 2*int32(h&1) // (-1)^bit
		h >>= 1
		v := s
		v += (v >> 31) & q // canonical
		c[j] = v
	}
	return c
}
