package field

import (
	"math/rand"
	"testing"
)

// TestBigFieldAxioms directly validates the arithmetic of every large-field
// descriptor — including the extension fields GF384/576/768 — via the field
// axioms and a Fermat inverse (a·a^(2^len-2) = 1), independent of the leaf/vole
// hash KATs.
func TestBigFieldAxioms(t *testing.T) {
	r := rand.New(rand.NewSource(42))
	fields := []Big{Big128, Big192, Big256, Big384, Big576, Big768, Big512}

	for _, p := range fields {
		one := p.Zero()
		one[0] = 1

		for trial := 0; trial < 100; trial++ {
			a := randElt(r, p.N)
			b := randElt(r, p.N)
			c := randElt(r, p.N)
			if !eq(p.Mul(a, b), p.Mul(b, a)) {
				t.Fatalf("GF%d: commutativity", p.length)
			}
			if !eq(p.Mul(p.Mul(a, b), c), p.Mul(a, p.Mul(b, c))) {
				t.Fatalf("GF%d: associativity", p.length)
			}
			if !eq(p.Mul(a, p.Add(b, c)), p.Add(p.Mul(a, b), p.Mul(a, c))) {
				t.Fatalf("GF%d: distributivity", p.length)
			}
			if !eq(p.Mul(a, one), a) {
				t.Fatalf("GF%d: identity", p.length)
			}
		}

		// Fermat inverse validates it is a proper field of order 2^len - 1.
		for trial := 0; trial < 3; trial++ {
			a := randElt(r, p.N)
			allZero := true
			for _, x := range a {
				if x != 0 {
					allZero = false
				}
			}
			if allZero {
				continue
			}
			t2 := append([]uint64(nil), a...)
			inv := append([]uint64(nil), one...)
			for i := 1; i < p.length; i++ {
				t2 = p.Mul(t2, t2)
				inv = p.Mul(inv, t2)
			}
			if !eq(p.Mul(a, inv), one) {
				t.Fatalf("GF%d: a * a^-1 != 1", p.length)
			}
		}
	}
}
