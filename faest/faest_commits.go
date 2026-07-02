package faest

import "github.com/maceip/tamayo/field"

// voleCommits is the verifier-side commitment to an AES state: one field element
// (a VOLE tag, or delta*bit for a public value) per bit, plus the challenge
// delta. The AES arithmetic circuit alternates between a "bit" representation
// (NStBits scalars, one per bit) and a "byte" representation (NStBytes scalars,
// each a byte-combined field element). Transpiled from faest-rs
// src/verifier/{vole_commitments,aes}.rs.
type voleCommits struct {
	f       field.Big
	scalars [][]uint64
	delta   []uint64
}

// vcFromConstant lifts a public byte string into commitments delta*bit_i.
func vcFromConstant(f field.Big, input []byte, delta []uint64) voleCommits {
	n := len(input) * 8
	sc := make([][]uint64, n)
	for i := 0; i < n; i++ {
		if (input[i/8]>>(i%8))&1 != 0 {
			sc[i] = append([]uint64(nil), delta...)
		} else {
			sc[i] = f.Zero()
		}
	}
	return voleCommits{f: f, scalars: sc, delta: delta}
}

func (v voleCommits) sub(start, length int) voleCommits {
	return voleCommits{f: v.f, scalars: v.scalars[start : start+length], delta: v.delta}
}

// getFieldCommit byte-combines the 8 scalars of byte idx into one field element.
func (v voleCommits) getFieldCommit(idx int) []uint64 {
	return v.f.ByteCombine(v.scalars[8*idx : 8*idx+8])
}

func (v voleCommits) getFieldCommitSq(idx int) []uint64 {
	return v.f.ByteCombineSq(v.scalars[8*idx : 8*idx+8])
}

// stateToBytes converts the bit representation to the byte representation.
func (v voleCommits) stateToBytes() [][]uint64 {
	n := len(v.scalars) / 8
	out := make([][]uint64, n)
	for i := 0; i < n; i++ {
		out[i] = v.f.ByteCombine(v.scalars[8*i : 8*i+8])
	}
	return out
}

// addRoundKey adds another commitment vector elementwise.
func (v voleCommits) addRoundKey(o voleCommits) voleCommits {
	sc := make([][]uint64, len(v.scalars))
	for i := range sc {
		sc[i] = v.f.Add(v.scalars[i], o.scalars[i])
	}
	return voleCommits{f: v.f, scalars: sc, delta: v.delta}
}

// addRoundKeyAssign adds another commitment vector in place.
func (v voleCommits) addRoundKeyAssign(o voleCommits) {
	for i := range v.scalars {
		v.scalars[i] = v.f.Add(v.scalars[i], o.scalars[i])
	}
}

// squareEach squares each field element of a byte-representation vector.
func squareEach(f field.Big, a [][]uint64) [][]uint64 {
	o := make([][]uint64, len(a))
	for i := range a {
		o[i] = f.Square(a[i])
	}
	return o
}

// sBoxAffine applies the S-box affine map, taking bit representation to byte
// representation using the SIGMA constants and delta^2.
func (v voleCommits) sBoxAffine(sq bool) voleCommits {
	f := v.f
	sig := f.Sigma(sq)
	t := 0
	if sq {
		t = 1
	}
	deltaSq := f.Square(v.delta)

	nStBytes := len(v.scalars) / 8
	sc := make([][]uint64, nStBytes)
	for i := 0; i < nStBytes; i++ {
		yi := f.Mul(sig[8], deltaSq)
		for si := 0; si < 8; si++ {
			yi = f.Add(yi, f.Mul(v.scalars[i*8+(si+t)%8], sig[si]))
		}
		sc[i] = yi
	}
	return voleCommits{f: f, scalars: sc, delta: v.delta}
}

// shiftRows permutes the byte-representation state in place.
func (v voleCommits) shiftRows() {
	nst := len(v.scalars) / 4
	orig := make([][]uint64, len(v.scalars))
	copy(orig, v.scalars)
	for r := 0; r < 4; r++ {
		off := 0
		if nst == 8 && r > 1 {
			off = 1
		}
		for c := 0; c < nst; c++ {
			v.scalars[4*c+r] = orig[4*((c+r+off)%nst)+r]
		}
	}
}

// inverseShiftRows permutes the bit-representation state.
func (v voleCommits) inverseShiftRows() voleCommits {
	nst := len(v.scalars) / 32
	sc := make([][]uint64, len(v.scalars))
	for r := 0; r < 4; r++ {
		for c := 0; c < nst; c++ {
			var i int
			if nst != 8 || r <= 1 {
				i = 4*((nst+c-r)%nst) + r
			} else {
				i = 4*((nst+c-r-1)%nst) + r
			}
			for k := 0; k < 8; k++ {
				sc[8*(4*c+r)+k] = v.scalars[8*i+k]
			}
		}
	}
	return voleCommits{f: v.f, scalars: sc, delta: v.delta}
}

// bytewiseMixColumns applies MixColumns on the bit representation.
func (v voleCommits) bytewiseMixColumns() voleCommits {
	f := v.f
	nst := len(v.scalars) / 32
	o := make([][]uint64, len(v.scalars))
	for i := range o {
		o[i] = f.Zero()
	}
	for c := 0; c < nst; c++ {
		for r := 0; r < 4; r++ {
			a := v.scalars[32*c+8*r : 32*c+8*r+8]
			b := [][]uint64{
				a[7],
				f.Add(a[0], a[7]),
				a[1],
				f.Add(a[2], a[7]),
				f.Add(a[3], a[7]),
				a[4],
				a[5],
				a[6],
			}
			for j := 0; j < 2; j++ {
				off := 32*c + 8*((4+r-j)%4)
				for k := 0; k < 8; k++ {
					o[off+k] = f.Add(o[off+k], b[k])
				}
			}
			for j := 1; j < 4; j++ {
				off := 32*c + 8*((r+j)%4)
				for k := 0; k < 8; k++ {
					o[off+k] = f.Add(o[off+k], a[k])
				}
			}
		}
	}
	return voleCommits{f: f, scalars: o, delta: v.delta}
}

// inverseAffine applies the inverse S-box affine map on the bit representation.
func (v voleCommits) inverseAffine() {
	f := v.f
	for base := 0; base < len(v.scalars); base += 8 {
		var xi [8][]uint64
		for k := 0; k < 8; k++ {
			xi[k] = v.scalars[base+k]
		}
		for bi := 0; bi < 8; bi++ {
			s := f.Add(f.Add(xi[(bi+7)%8], xi[(bi+5)%8]), xi[(bi+2)%8])
			if bi == 0 || bi == 2 {
				s = f.Add(s, v.delta)
			}
			v.scalars[base+bi] = s
		}
	}
}

// mixColumns applies MixColumns on the byte representation in place.
func (v voleCommits) mixColumns(sq bool) {
	f := v.f
	v2 := f.ByteCombine2(sq)
	v3 := f.ByteCombine3(sq)
	for base := 0; base < len(v.scalars); base += 4 {
		t0, t1, t2, t3 := v.scalars[base], v.scalars[base+1], v.scalars[base+2], v.scalars[base+3]
		v.scalars[base+0] = f.Add(f.Add(f.Add(f.Mul(t0, v2), f.Mul(t1, v3)), t2), t3)
		v.scalars[base+1] = f.Add(f.Add(f.Add(f.Mul(t1, v2), f.Mul(t2, v3)), t0), t3)
		v.scalars[base+2] = f.Add(f.Add(f.Add(f.Mul(t2, v2), f.Mul(t3, v3)), t0), t1)
		v.scalars[base+3] = f.Add(f.Add(f.Add(f.Mul(t0, v3), f.Mul(t3, v2)), t1), t2)
	}
}

// addRoundKeyBytes adds a byte-representation round key in place. In the squared
// domain the key is added directly; otherwise it is scaled by delta.
func (v voleCommits) addRoundKeyBytes(rhs [][]uint64, sq bool) {
	f := v.f
	for i := range v.scalars {
		if sq {
			v.scalars[i] = f.Add(v.scalars[i], rhs[i])
		} else {
			v.scalars[i] = f.Add(v.scalars[i], f.Mul(rhs[i], v.delta))
		}
	}
}
