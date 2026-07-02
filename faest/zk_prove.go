package faest

import "github.com/maceip/tamayo/field"

// ZKProofHasher is the QuickSilver prover-side constraint accumulator. It hashes
// the three coefficient sequences of each degree-3 constraint (a commitment to
// zero) with three parallel ZK hashers. Transpiled from faest-rs
// src/universal_hashing.rs (ZKProofHasher).
type ZKProofHasher struct {
	f          field.Big
	a0, a1, a2 *ZKHasher
}

// NewZKProofHasher seeds the three sub-hashers from the same sd.
func NewZKProofHasher(f field.Big, sd []byte) *ZKProofHasher {
	return &ZKProofHasher{f: f, a0: NewZKHasher(f, sd), a1: NewZKHasher(f, sd), a2: NewZKHasher(f, sd)}
}

// Update folds a degree-3 constraint (whose X^0 coefficient is zero) by feeding
// its three tag coefficients to the three sub-hashers.
func (z *ZKProofHasher) Update(val Commit) {
	z.a0.Update(val.Tag[0])
	z.a1.Update(val.Tag[1])
	z.a2.Update(val.Tag[2])
}

// LiftAndProcess hashes the coefficients of <a^2>*<b> - <a> and <b^2>*<a> - <b>
// for degree-1 commitments (subtraction is XOR in characteristic two).
func (z *ZKProofHasher) LiftAndProcess(a, aSq, b, bSq Commit) {
	f := z.f
	z.a1.Update(f.Mul(aSq.Tag[0], b.Tag[0]))
	z.a1.Update(f.Mul(bSq.Tag[0], a.Tag[0]))
	z.a2.Update(f.Add(f.Add(f.Mul(aSq.Key, b.Tag[0]), f.Mul(aSq.Tag[0], b.Key)), a.Tag[0]))
	z.a2.Update(f.Add(f.Add(f.Mul(bSq.Key, a.Tag[0]), f.Mul(bSq.Tag[0], a.Key)), b.Tag[0]))
}

// OddRoundCstrnts folds the two odd-round constraints for a Rijndael S-box.
// si, siSq are degree-1; st0i, st1i are degree-2.
func (z *ZKProofHasher) OddRoundCstrnts(si, siSq, st0i, st1i Commit) {
	z.Update(siSq.Mul(st0i).Add(si))
	z.Update(si.Mul(st1i).Add(st0i))
}

// Finalize returns the three proof values (a0, a1, a2) using the VOLE u, u+v, v.
func (z *ZKProofHasher) Finalize(u, uPlusV, v []uint64) (a0, a1, a2 []uint64) {
	return z.a0.Finalize(u), z.a1.Finalize(uPlusV), z.a2.Finalize(v)
}

// ZKVerifyHasher is the QuickSilver verifier-side accumulator. It hashes each
// constraint's evaluation at the verifier mask delta with one ZK hasher.
// Transpiled from faest-rs src/universal_hashing.rs (ZKVerifyHasher).
type ZKVerifyHasher struct {
	f            field.Big
	b            *ZKHasher
	delta        []uint64
	deltaSquared []uint64
}

// NewZKVerifyHasher seeds the hasher and precomputes delta^2.
func NewZKVerifyHasher(f field.Big, sd []byte, delta []uint64) *ZKVerifyHasher {
	return &ZKVerifyHasher{f: f, b: NewZKHasher(f, sd), delta: delta, deltaSquared: f.Mul(delta, delta)}
}

// Update folds a single constraint evaluation.
func (z *ZKVerifyHasher) Update(val []uint64) { z.b.Update(val) }

// MulAndUpdate folds delta*a*b.
func (z *ZKVerifyHasher) MulAndUpdate(a, b []uint64) {
	z.b.Update(z.f.Mul(z.f.Mul(z.delta, a), b))
}

// InvNormConstraints folds y*conj[1]*conj[4] + delta^2*conj[0].
func (z *ZKVerifyHasher) InvNormConstraints(conjugates [][]uint64, y []uint64) {
	f := z.f
	z.b.Update(f.Add(f.Mul(f.Mul(y, conjugates[1]), conjugates[4]), f.Mul(z.deltaSquared, conjugates[0])))
}

// OddRoundCstrnts folds the verifier form of the two odd-round constraints.
func (z *ZKVerifyHasher) OddRoundCstrnts(si, siSq, st0i, st1i []uint64) {
	f := z.f
	z.Update(f.Add(f.Mul(z.deltaSquared, si), f.Mul(siSq, st0i)))
	z.Update(f.Add(f.Mul(z.delta, st0i), f.Mul(si, st1i)))
}

// LiftAndProcess folds delta*(a^2*b - delta*a) and delta*(a*b^2 - delta*b).
func (z *ZKVerifyHasher) LiftAndProcess(a, aSq, b, bSq []uint64) {
	f := z.f
	z.Update(f.Mul(z.delta, f.Add(f.Mul(aSq, b), f.Mul(z.delta, a))))
	z.Update(f.Mul(z.delta, f.Add(f.Mul(a, bSq), f.Mul(z.delta, b))))
}

// Finalize returns the verifier value b using the VOLE tags v.
func (z *ZKVerifyHasher) Finalize(v []uint64) []uint64 {
	return z.b.Finalize(v)
}
