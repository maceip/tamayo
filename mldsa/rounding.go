package mldsa

// power2Round is FIPS 204 algorithm 35 applied per coefficient: r = r1*2^d +
// r0 with r0 in (-2^(d-1), 2^(d-1)]. Input canonical in [0, q).
func power2Round(r int32) (r1, r0 int32) {
	r0 = r & (1<<d - 1)
	r0 -= (((1 << (d - 1)) - r0) >> 31) & (1 << d) // r0 > 2^(d-1) ? r0 - 2^d : r0
	r1 = (r - r0) >> d
	return
}

// decompose is FIPS 204 algorithm 36 per coefficient: r = r1*(2*gamma2) + r0
// with r0 in (-gamma2, gamma2], and the q-1 wraparound folded into r1 = 0,
// r0 - 1. Input canonical in [0, q); r0 is returned centered. Branch-free in
// the data (the reference implementation's multiply-shift form), since the
// sign path applies it to secret-derived w - c*s2.
func decompose(p *Params, r int32) (r1, r0 int32) {
	r1 = (r + 127) >> 7
	if p.Gamma2 == (q-1)/32 {
		r1 = (r1*1025 + (1 << 21)) >> 22
		r1 &= 15
	} else { // gamma2 == (q-1)/88
		r1 = (r1*11275 + (1 << 23)) >> 24
		r1 ^= ((43 - r1) >> 31) & r1
	}
	r0 = r - r1*2*p.Gamma2
	r0 -= (((q-1)/2 - r0) >> 31) & q
	return
}

// highBits / lowBits are FIPS 204 algorithms 37/38.
func highBits(p *Params, r int32) int32 { r1, _ := decompose(p, r); return r1 }
func lowBits(p *Params, r int32) int32  { _, r0 := decompose(p, r); return r0 }

// makeHint is FIPS 204 algorithm 39: whether adding z to r changes the high
// bits. Inputs canonical in [0, q).
func makeHint(p *Params, z, r int32) int32 {
	if highBits(p, r) != highBits(p, addQ(r, z)) {
		return 1
	}
	return 0
}

// useHint is FIPS 204 algorithm 40: recover the high bits of r using hint h.
func useHint(p *Params, h, r int32) int32 {
	m := (q - 1) / (2 * p.Gamma2)
	r1, r0 := decompose(p, r)
	if h == 0 {
		return r1
	}
	if r0 > 0 {
		return (r1 + 1) % m
	}
	return (r1 - 1 + m) % m
}

// lowBitsVec applies lowBits to a whole vector, returning centered values
// re-encoded canonical for the norm check.
func (p *Params) lowBitsVec(v vec) vec {
	w := newVec(len(v))
	for i := range v {
		for j := range v[i] {
			c := lowBits(p, v[i][j])
			c += (c >> 31) & q
			w[i][j] = c
		}
	}
	return w
}

// highBitsVec applies highBits to a whole vector.
func (p *Params) highBitsVec(v vec) vec {
	w := newVec(len(v))
	for i := range v {
		for j := range v[i] {
			w[i][j] = highBits(p, v[i][j])
		}
	}
	return w
}
