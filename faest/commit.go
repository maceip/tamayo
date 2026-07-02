package faest

import "github.com/maceip/tamayo/field"

// Commit is a QuickSilver polynomial commitment over field f: a polynomial in
// the (secret) VOLE mask Delta. Key is the X^0 coefficient; Tag holds the
// higher-degree coefficients in descending order, so Tag[0] is the top-degree
// coefficient and Tag[len-1] is the X^1 coefficient. The degree is len(Tag).
//
// The defining property is homomorphic evaluation: for a random Delta,
// eval(A+B) = eval(A)+eval(B) and eval(A*B) = eval(A)*eval(B). Transpiled from
// faest-rs src/prover/field_commitment.rs (FieldCommitment).
type Commit struct {
	f   field.Big
	Key []uint64
	Tag [][]uint64
}

// CommitDeg1 builds a degree-1 commitment (X^0 = key, X^1 = tag).
func CommitDeg1(f field.Big, key, tag []uint64) Commit {
	return Commit{f: f, Key: key, Tag: [][]uint64{tag}}
}

func commitDeg2(f field.Big, key, t0, t1 []uint64) Commit {
	return Commit{f: f, Key: key, Tag: [][]uint64{t0, t1}}
}

func commitDeg3(f field.Big, key, t0, t1, t2 []uint64) Commit {
	return Commit{f: f, Key: key, Tag: [][]uint64{t0, t1, t2}}
}

// Deg returns the polynomial degree.
func (c Commit) Deg() int { return len(c.Tag) }

func (c Commit) cloneTag() [][]uint64 {
	tag := make([][]uint64, len(c.Tag))
	for i := range c.Tag {
		tag[i] = append([]uint64(nil), c.Tag[i]...)
	}
	return tag
}

// Add returns c + o. c must have degree >= o; coefficients are aligned by
// X-power from the constant term up, which covers the same-degree and mixed
// (deg3+deg1, deg3+deg2, deg2+deg1) cases of the reference impl.
func (c Commit) Add(o Commit) Commit {
	d, e := len(c.Tag), len(o.Tag)
	out := Commit{f: c.f, Key: c.f.Add(c.Key, o.Key), Tag: c.cloneTag()}
	for j := 1; j <= e; j++ {
		out.Tag[d-j] = c.f.Add(c.Tag[d-j], o.Tag[e-j])
	}
	return out
}

// AddKey adds s to the X^0 coefficient only (reference AddAssign<F>).
func (c Commit) AddKey(s []uint64) Commit {
	return Commit{f: c.f, Key: c.f.Add(c.Key, s), Tag: c.cloneTag()}
}

// Mul returns c * o with degrees adding. Supports deg1*deg1 -> deg2,
// deg1*deg2 and deg2*deg1 -> deg3.
func (c Commit) Mul(o Commit) Commit {
	f := c.f
	switch {
	case len(c.Tag) == 1 && len(o.Tag) == 1:
		return commitDeg2(f,
			f.Mul(c.Key, o.Key),
			f.Mul(c.Tag[0], o.Tag[0]),
			f.Add(f.Mul(c.Key, o.Tag[0]), f.Mul(c.Tag[0], o.Key)),
		)
	case len(c.Tag) == 1 && len(o.Tag) == 2:
		return commitDeg3(f,
			f.Mul(c.Key, o.Key),
			f.Mul(c.Tag[0], o.Tag[0]),
			f.Add(f.Mul(c.Key, o.Tag[0]), f.Mul(c.Tag[0], o.Tag[1])),
			f.Add(f.Mul(c.Key, o.Tag[1]), f.Mul(c.Tag[0], o.Key)),
		)
	case len(c.Tag) == 2 && len(o.Tag) == 1:
		return commitDeg3(f,
			f.Mul(c.Key, o.Key),
			f.Mul(c.Tag[0], o.Tag[0]),
			f.Add(f.Mul(c.Tag[0], o.Key), f.Mul(c.Tag[1], o.Tag[0])),
			f.Add(f.Mul(c.Tag[1], o.Key), f.Mul(c.Key, o.Tag[0])),
		)
	}
	panic("faest: unsupported commitment multiply degrees")
}

// MulScalar scales every coefficient by s (reference deg-2 Mul<F>).
func (c Commit) MulScalar(s []uint64) Commit {
	f := c.f
	tag := make([][]uint64, len(c.Tag))
	for i := range c.Tag {
		tag[i] = f.Mul(c.Tag[i], s)
	}
	return Commit{f: f, Key: f.Mul(c.Key, s), Tag: tag}
}

// MulKey scales only the X^0 coefficient by s, leaving Tag unchanged (reference
// deg-1 Mul<F>).
func (c Commit) MulKey(s []uint64) Commit {
	return Commit{f: c.f, Key: c.f.Mul(c.Key, s), Tag: c.cloneTag()}
}

// Square returns c^2 for a degree-1 commitment. In characteristic two the cross
// term vanishes, so only the squared coefficients remain.
func (c Commit) Square() Commit {
	f := c.f
	return commitDeg2(f, f.Mul(c.Key, c.Key), f.Mul(c.Tag[0], c.Tag[0]), f.Zero())
}
