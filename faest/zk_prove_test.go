package faest

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/maceip/tamayo/field"
)

// TestQuickSilverConsistency checks the core QuickSilver soundness relation
// between the prover and verifier hashers. For constraints that are commitments
// to zero (key = 0), with zero VOLE offsets, the verifier value b must equal
// delta^3*a0 + delta^2*a1 + delta*a2. This follows from the linearity of the ZK
// Horner hash and the eval-at-delta homomorphism, and it exercises Update and
// Finalize on both sides against independent field arithmetic.
func TestQuickSilverConsistency(t *testing.T) {
	fields := []field.Big{field.Big128, field.Big192, field.Big256}
	r := rand.New(rand.NewSource(2))

	for _, f := range fields {
		for iter := 0; iter < 200; iter++ {
			sd := make([]byte, 3*f.Bytes+8)
			r.Read(sd)
			delta := randElem(f, r)

			prover := NewZKProofHasher(f, sd)
			verifier := NewZKVerifyHasher(f, sd, delta)

			n := 1 + iter%17
			for j := 0; j < n; j++ {
				// A constraint: degree-3 commitment to zero (key = 0).
				c := Commit{f: f, Key: f.Zero(), Tag: [][]uint64{
					randElem(f, r), randElem(f, r), randElem(f, r),
				}}
				prover.Update(c)
				verifier.Update(evalCommit(c, delta))
			}

			zero := f.Zero()
			a0, a1, a2 := prover.Finalize(zero, zero, zero)
			b := verifier.Finalize(zero)

			// delta^3*a0 + delta^2*a1 + delta*a2
			d2 := f.Mul(delta, delta)
			d3 := f.Mul(d2, delta)
			want := f.Add(f.Add(f.Mul(d3, a0), f.Mul(d2, a1)), f.Mul(delta, a2))

			if !bytes.Equal(f.ToBytes(b), f.ToBytes(want)) {
				t.Fatalf("%d-bit iter %d: QuickSilver relation b != d^3 a0 + d^2 a1 + d a2", f.Bytes*8, iter)
			}
		}
	}
}
