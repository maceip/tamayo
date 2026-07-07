package mldsa

// poly is one ring element of Z_q[X]/(X^256+1). Coefficients are kept
// canonical in [0, q) between operations; centered views are produced only
// where FIPS 204 says mod-plus-minus.
type poly [n]int32

// zetas[k] = zeta^brv8(k) mod q, consumed in the order of FIPS 204
// algorithms 41/42. Computed at init from the spec constants rather than
// transcribed, so the table cannot be mistyped.
var zetas [n]int32

func init() {
	pow := func(e uint32) int32 {
		r := int64(1)
		b := int64(zeta)
		for ; e > 0; e >>= 1 {
			if e&1 == 1 {
				r = r * b % q
			}
			b = b * b % q
		}
		return int32(r)
	}
	for k := 0; k < n; k++ {
		b := uint32(k)
		b = (b&0x0F)<<4 | (b&0xF0)>>4
		b = (b&0x33)<<2 | (b&0xCC)>>2
		b = (b&0x55)<<1 | (b&0xAA)>>1
		zetas[k] = pow(b)
	}
}

func addQ(a, b int32) int32 {
	c := a + b - q
	c += (c >> 31) & q
	return c
}

func subQ(a, b int32) int32 {
	c := a - b
	c += (c >> 31) & q
	return c
}

func mulQ(a, b int32) int32 { return int32(int64(a) * int64(b) % q) }

// centered maps canonical a in [0, q) to a mod-plus-minus q in
// (-(q-1)/2, (q-1)/2], branch-free.
func centered(a int32) int32 {
	// a > (q-1)/2 ? a - q : a
	m := ((q-1)/2 - a) >> 31
	return a - (m & q)
}

func (a *poly) add(b *poly) *poly {
	var c poly
	for i := range c {
		c[i] = addQ(a[i], b[i])
	}
	*a = c
	return a
}

func (a *poly) sub(b *poly) *poly {
	var c poly
	for i := range c {
		c[i] = subQ(a[i], b[i])
	}
	*a = c
	return a
}

// normExceeds reports whether the infinity norm of a (coefficients read
// mod-plus-minus q) is >= bound, branch-free over the coefficients.
func (a *poly) normExceeds(bound int32) bool {
	var acc int32
	for i := range a {
		c := centered(a[i])
		c -= (c >> 31) & (2 * c) // |c|
		// acc accumulates the sign of (bound-1 - |c|): negative iff |c| >= bound.
		acc |= (bound - 1 - c) >> 31
	}
	return acc != 0
}

// ntt is FIPS 204 algorithm 41.
func (a *poly) ntt() *poly {
	k := 0
	for length := n / 2; length >= 1; length >>= 1 {
		for start := 0; start < n; start += 2 * length {
			k++
			z := zetas[k]
			for j := start; j < start+length; j++ {
				t := mulQ(z, a[j+length])
				a[j+length] = subQ(a[j], t)
				a[j] = addQ(a[j], t)
			}
		}
	}
	return a
}

// invNTT is FIPS 204 algorithm 42.
func (a *poly) invNTT() *poly {
	k := n
	for length := 1; length < n; length <<= 1 {
		for start := 0; start < n; start += 2 * length {
			k--
			z := q - zetas[k] // -zeta^brv(k)
			for j := start; j < start+length; j++ {
				t := a[j]
				a[j] = addQ(t, a[j+length])
				a[j+length] = subQ(t, a[j+length])
				a[j+length] = mulQ(z, a[j+length])
			}
		}
	}
	for i := range a {
		a[i] = mulQ(nInv, a[i])
	}
	return a
}

// mulHat is the NTT-domain pointwise product.
func (a *poly) mulHat(b *poly) *poly {
	for i := range a {
		a[i] = mulQ(a[i], b[i])
	}
	return a
}

// vec is a length-k or length-l vector of ring elements.
type vec []poly

func newVec(k int) vec { return make(vec, k) }

func (v vec) ntt() vec {
	for i := range v {
		v[i].ntt()
	}
	return v
}

func (v vec) invNTT() vec {
	for i := range v {
		v[i].invNTT()
	}
	return v
}

func (v vec) add(w vec) vec {
	for i := range v {
		v[i].add(&w[i])
	}
	return v
}

func (v vec) sub(w vec) vec {
	for i := range v {
		v[i].sub(&w[i])
	}
	return v
}

func (v vec) copyOf() vec {
	c := newVec(len(v))
	copy(c, v)
	return c
}

func (v vec) normExceeds(bound int32) bool {
	var bad bool
	for i := range v {
		bad = v[i].normExceeds(bound) || bad
	}
	return bad
}

// mulMatVecHat computes NTT-domain w = A * u for the k x l matrix a.
func mulMatVecHat(a []vec, u vec) vec {
	w := newVec(len(a))
	for r := range a {
		for s := range u {
			t := a[r][s]
			t.mulHat(&u[s])
			w[r].add(&t)
		}
	}
	return w
}

// scaleD2 multiplies every coefficient by 2^d mod q (the t1 * 2^d step of
// verification).
func (v vec) scaleD2() vec {
	for i := range v {
		for j := range v[i] {
			v[i][j] = int32(int64(v[i][j]) << d % q)
		}
	}
	return v
}
