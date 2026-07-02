package faest

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/maceip/tamayo/field"
)

// evalCommit evaluates the committed polynomial at delta: key + sum_p tag*delta^p
// with tag[deg-p] the coefficient of X^p. This is the verifier's key relation and
// the independent oracle for the homomorphism tests.
func evalCommit(c Commit, delta []uint64) []uint64 {
	f := c.f
	acc := append([]uint64(nil), c.Key...)
	deg := len(c.Tag)
	dp := append([]uint64(nil), delta...)
	for p := 1; p <= deg; p++ {
		acc = f.Add(acc, f.Mul(c.Tag[deg-p], dp))
		dp = f.Mul(dp, delta)
	}
	return acc
}

func randElem(f field.Big, r *rand.Rand) []uint64 {
	b := make([]byte, f.Bytes)
	r.Read(b)
	return f.FromBytes(b)
}

func randCommit(f field.Big, deg int, r *rand.Rand) Commit {
	tag := make([][]uint64, deg)
	for i := range tag {
		tag[i] = randElem(f, r)
	}
	return Commit{f: f, Key: randElem(f, r), Tag: tag}
}

// TestCommitHomomorphism verifies that add/mul/square/scale on QuickSilver
// commitments commute with evaluation at a random Delta, over every security
// field. This is the correctness property the proof system depends on.
func TestCommitHomomorphism(t *testing.T) {
	fields := []field.Big{field.Big128, field.Big192, field.Big256}
	r := rand.New(rand.NewSource(1))

	for _, f := range fields {
		for iter := 0; iter < 2000; iter++ {
			delta := randElem(f, r)

			a1 := randCommit(f, 1, r)
			b1 := randCommit(f, 1, r)
			a2 := randCommit(f, 2, r)
			b2 := randCommit(f, 2, r)
			a3 := randCommit(f, 3, r)
			b3 := randCommit(f, 3, r)

			eq := func(name string, got Commit, want []uint64) {
				if !bytes.Equal(f.ToBytes(evalCommit(got, delta)), f.ToBytes(want)) {
					t.Fatalf("%d-bit %s: eval mismatch", f.Bytes*8, name)
				}
			}
			ea1, eb1 := evalCommit(a1, delta), evalCommit(b1, delta)
			ea2, eb2 := evalCommit(a2, delta), evalCommit(b2, delta)

			// Additive homomorphism (same degree and mixed).
			eq("d1+d1", a1.Add(b1), f.Add(ea1, eb1))
			eq("d2+d2", a2.Add(b2), f.Add(ea2, eb2))
			eq("d3+d3", a3.Add(b3), f.Add(evalCommit(a3, delta), evalCommit(b3, delta)))
			eq("d2+d1", a2.Add(a1), f.Add(ea2, ea1))
			eq("d3+d1", a3.Add(a1), f.Add(evalCommit(a3, delta), ea1))
			eq("d3+d2", a3.Add(a2), f.Add(evalCommit(a3, delta), ea2))

			// Multiplicative homomorphism (the QuickSilver-critical one).
			eq("d1*d1", a1.Mul(b1), f.Mul(ea1, eb1))
			eq("d1*d2", a1.Mul(a2), f.Mul(ea1, ea2))
			eq("d2*d1", a2.Mul(a1), f.Mul(ea2, ea1))

			// Square and scalar operations.
			eq("sq(d1)", a1.Square(), f.Mul(ea1, ea1))
			s := randElem(f, r)
			eq("d2*s", a2.MulScalar(s), f.Mul(ea2, s))
			eq("d1+s", a1.AddKey(s), f.Add(ea1, s))

			// deg-1 Mul<F> scales only the key (non-homomorphic by design).
			mk := a1.MulKey(s)
			if !bytes.Equal(f.ToBytes(mk.Key), f.ToBytes(f.Mul(a1.Key, s))) ||
				!bytes.Equal(f.ToBytes(mk.Tag[0]), f.ToBytes(a1.Tag[0])) {
				t.Fatalf("%d-bit d1 MulKey: formula mismatch", f.Bytes*8)
			}
		}
	}
}

// TestCommitReference reproduces the faest-rs field_commitment unit tests
// (field_commit_mul), where ONE*2 == 0 in characteristic two.
func TestCommitReference(t *testing.T) {
	f := field.Big128
	one := f.FromBytes(append([]byte{1}, make([]byte, 15)...))
	zero := f.Zero()

	// Deg2(1,[1,1]) * Deg1(1,1) = Deg3(1,[1,0,0]).
	lhs := commitDeg2(f, one, one, one)
	rhs := CommitDeg1(f, one, one)
	got := lhs.Mul(rhs)
	if !bytes.Equal(f.ToBytes(got.Key), f.ToBytes(one)) ||
		!bytes.Equal(f.ToBytes(got.Tag[0]), f.ToBytes(one)) ||
		!bytes.Equal(f.ToBytes(got.Tag[1]), f.ToBytes(zero)) ||
		!bytes.Equal(f.ToBytes(got.Tag[2]), f.ToBytes(zero)) {
		t.Fatal("deg2*deg1 reference mismatch")
	}
	// Commutativity.
	got2 := rhs.Mul(lhs)
	for i := range got.Tag {
		if !bytes.Equal(f.ToBytes(got2.Tag[i]), f.ToBytes(got.Tag[i])) {
			t.Fatal("deg1*deg2 not commutative with deg2*deg1")
		}
	}
}
