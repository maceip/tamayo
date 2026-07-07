package mldsa

// bitPack packs 256 values of `bits` bits each (values already in
// [0, 2^bits)) little-endian into dst (FIPS 204 SimpleBitPack, algorithm 16).
func bitPack(dst []byte, a *poly, bits int) {
	acc, nAcc, idx := uint64(0), 0, 0
	for i := range a {
		acc |= uint64(uint32(a[i])) << nAcc
		nAcc += bits
		for nAcc >= 8 {
			dst[idx] = byte(acc)
			acc >>= 8
			nAcc -= 8
			idx++
		}
	}
}

// bitUnpack is the inverse of bitPack (FIPS 204 SimpleBitUnpack, algorithm
// 18), returning raw `bits`-bit values.
func bitUnpack(src []byte, bits int) poly {
	var a poly
	acc, nAcc, idx := uint64(0), 0, 0
	mask := uint64(1)<<bits - 1
	for i := range a {
		for nAcc < bits {
			acc |= uint64(src[idx]) << nAcc
			idx++
			nAcc += 8
		}
		a[i] = int32(acc & mask)
		acc >>= bits
		nAcc -= bits
	}
	return a
}

// bitPackSigned packs coefficients z in [-a, b] as b - z in bitlen(a+b) bits
// (FIPS 204 BitPack, algorithm 17). Input canonical in [0, q); the centered
// view is taken here.
func bitPackSigned(dst []byte, w *poly, a, b int32, bits int) {
	var t poly
	for i := range w {
		t[i] = b - centered(w[i])
	}
	bitPack(dst, &t, bits)
}

// bitUnpackSigned is FIPS 204 BitUnpack (algorithm 19): z = b - raw, stored
// canonical mod q. Malformed encodings can produce values outside [-a, b];
// as in the spec, callers reject via norm checks.
func bitUnpackSigned(src []byte, a, b int32) poly {
	bits := bitLen(uint32(a + b))
	w := bitUnpack(src, bits)
	for i := range w {
		c := b - w[i]
		c += (c >> 31) & q
		w[i] = c
	}
	return w
}

func bitLen(v uint32) int {
	l := 0
	for v != 0 {
		v >>= 1
		l++
	}
	return l
}

// hintBitPack is FIPS 204 algorithm 20: omega one-positions plus k running
// counts.
func (p *Params) hintBitPack(dst []byte, h vec) {
	idx := 0
	for i := range h {
		for j := range h[i] {
			if h[i][j] == 1 {
				dst[idx] = byte(j)
				idx++
			}
		}
		dst[p.Omega+i] = byte(idx)
	}
}

// hintBitUnpack is FIPS 204 algorithm 21, with the strict monotonicity and
// zero-padding checks that make the encoding non-malleable. Returns nil on
// any malformed input.
func (p *Params) hintBitUnpack(src []byte) vec {
	h := newVec(p.K)
	idx := 0
	for i := 0; i < p.K; i++ {
		end := int(src[p.Omega+i])
		if end < idx || end > p.Omega {
			return nil
		}
		first := idx
		for idx < end {
			if idx > first && src[idx-1] >= src[idx] {
				return nil
			}
			h[i][src[idx]] = 1
			idx++
		}
	}
	for ; idx < p.Omega; idx++ {
		if src[idx] != 0 {
			return nil
		}
	}
	return h
}

// pkEncode is FIPS 204 algorithm 22.
func (p *Params) pkEncode(rho []byte, t1 vec) []byte {
	pk := make([]byte, p.PublicKeySize)
	copy(pk, rho)
	for i := range t1 {
		bitPack(pk[seedB+i*320:], &t1[i], 10)
	}
	return pk
}

// pkDecode is FIPS 204 algorithm 23.
func (p *Params) pkDecode(pk []byte) (rho []byte, t1 vec) {
	rho = pk[:seedB]
	t1 = newVec(p.K)
	for i := range t1 {
		t1[i] = bitUnpack(pk[seedB+i*320:], 10)
	}
	return
}

// skEncode is FIPS 204 algorithm 24.
func (p *Params) skEncode(rho, key, tr []byte, s1, s2, t0 vec) []byte {
	sk := make([]byte, p.PrivateKeySize)
	off := 0
	off += copy(sk[off:], rho)
	off += copy(sk[off:], key)
	off += copy(sk[off:], tr)
	etaLen := n / 8 * p.etaBits
	for i := range s1 {
		bitPackSigned(sk[off:], &s1[i], p.Eta, p.Eta, p.etaBits)
		off += etaLen
	}
	for i := range s2 {
		bitPackSigned(sk[off:], &s2[i], p.Eta, p.Eta, p.etaBits)
		off += etaLen
	}
	for i := range t0 {
		bitPackSigned(sk[off:], &t0[i], 1<<(d-1)-1, 1<<(d-1), d)
		off += n / 8 * d
	}
	return sk
}

// skDecode is FIPS 204 algorithm 25.
func (p *Params) skDecode(sk []byte) (rho, key, tr []byte, s1, s2, t0 vec) {
	rho, key, tr = sk[:32], sk[32:64], sk[64:128]
	off := 128
	etaLen := n / 8 * p.etaBits
	s1 = newVec(p.L)
	for i := range s1 {
		s1[i] = bitUnpackSigned(sk[off:], p.Eta, p.Eta)
		off += etaLen
	}
	s2 = newVec(p.K)
	for i := range s2 {
		s2[i] = bitUnpackSigned(sk[off:], p.Eta, p.Eta)
		off += etaLen
	}
	t0 = newVec(p.K)
	for i := range t0 {
		t0[i] = bitUnpackSigned(sk[off:], 1<<(d-1)-1, 1<<(d-1))
		off += n / 8 * d
	}
	return
}

// sigEncode is FIPS 204 algorithm 26.
func (p *Params) sigEncode(cTilde []byte, z, h vec) []byte {
	sig := make([]byte, p.SignatureSize)
	off := copy(sig, cTilde)
	zLen := n / 8 * p.zBits
	for i := range z {
		bitPackSigned(sig[off:], &z[i], p.Gamma1-1, p.Gamma1, p.zBits)
		off += zLen
	}
	p.hintBitPack(sig[off:], h)
	return sig
}

// sigDecode is FIPS 204 algorithm 27. h is nil if the hint encoding is
// malformed.
func (p *Params) sigDecode(sig []byte) (cTilde []byte, z, h vec) {
	cTilde = sig[:p.Lambda/4]
	off := p.Lambda / 4
	zLen := n / 8 * p.zBits
	z = newVec(p.L)
	for i := range z {
		z[i] = bitUnpackSigned(sig[off:], p.Gamma1-1, p.Gamma1)
		off += zLen
	}
	h = p.hintBitUnpack(sig[off:])
	return
}

// w1Encode is FIPS 204 algorithm 28.
func (p *Params) w1Encode(w1 vec) []byte {
	out := make([]byte, p.K*n/8*p.w1Bits)
	for i := range w1 {
		bitPack(out[i*n/8*p.w1Bits:], &w1[i], p.w1Bits)
	}
	return out
}
