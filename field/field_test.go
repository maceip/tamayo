package field

import (
	"math/rand"
	"testing"
)

type cfg struct {
	length int
	mod    uint64
	n      int
}

var cfgs = []cfg{{128, gf128Mod, 2}, {192, gf192Mod, 3}, {256, gf256Mod, 4}}

func randElt(r *rand.Rand, n int) []uint64 {
	e := make([]uint64, n)
	for i := range e {
		e[i] = r.Uint64()
	}
	return e
}

func eq(a, b []uint64) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func m(a, b []uint64, c cfg) []uint64 {
	out := make([]uint64, c.n)
	mul(out, a, b, c.length, c.mod)
	return out
}

func add(a, b []uint64) []uint64 {
	out := make([]uint64, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func one(c cfg) []uint64  { o := make([]uint64, c.n); o[0] = 1; return o }
func zero(c cfg) []uint64 { return make([]uint64, c.n) }

func TestFieldAxioms(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for _, c := range cfgs {
		for trial := 0; trial < 200; trial++ {
			a := randElt(r, c.n)
			b := randElt(r, c.n)
			d := randElt(r, c.n)
			if !eq(m(a, b, c), m(b, a, c)) {
				t.Fatalf("GF%d: commutativity", c.length)
			}
			if !eq(m(m(a, b, c), d, c), m(a, m(b, d, c), c)) {
				t.Fatalf("GF%d: associativity", c.length)
			}
			if !eq(m(a, add(b, d), c), add(m(a, b, c), m(a, d, c))) {
				t.Fatalf("GF%d: distributivity", c.length)
			}
			if !eq(m(a, one(c), c), a) {
				t.Fatalf("GF%d: identity", c.length)
			}
			if !eq(m(a, zero(c), c), zero(c)) {
				t.Fatalf("GF%d: zero", c.length)
			}
		}
	}
}

// TestFieldInverse computes a^(2^length - 2) = a^-1 via square-and-multiply and
// checks a·a^-1 = 1, which validates that mul is a correct field multiply
// (a proper multiplicative group of order 2^length - 1).
func TestFieldInverse(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	for _, c := range cfgs {
		for trial := 0; trial < 5; trial++ {
			a := randElt(r, c.n)
			if eq(a, zero(c)) {
				continue
			}
			t2 := make([]uint64, c.n)
			copy(t2, a)
			inv := one(c)
			for i := 1; i < c.length; i++ {
				t2 = m(t2, t2, c)
				inv = m(inv, t2, c)
			}
			if !eq(m(a, inv, c), one(c)) {
				t.Fatalf("GF%d: a * a^-1 != 1", c.length)
			}
		}
	}
}

func TestFieldBytesAndSquare(t *testing.T) {
	a := GF128{0x0123456789abcdef, 0xfedcba9876543210}
	ab := a.Bytes()
	if GF128FromBytes(ab[:]) != a {
		t.Fatal("GF128 byte round trip")
	}
	b := GF192{1, 2, 3}
	bb := b.Bytes()
	if GF192FromBytes(bb[:]) != b {
		t.Fatal("GF192 byte round trip")
	}
	d := GF256{4, 5, 6, 7}
	db := d.Bytes()
	if GF256FromBytes(db[:]) != d {
		t.Fatal("GF256 byte round trip")
	}
	// x * x = x^2 with no reduction (degree 2 < field degree)
	x := GF128{0x2, 0}
	if got := x.Mul(x); got != (GF128{0x4, 0}) {
		t.Fatalf("GF128 x*x = %x, want 0x4", got)
	}
	if got := x.Square(); got != (GF128{0x4, 0}) {
		t.Fatalf("GF128 x.Square() = %x, want 0x4", got)
	}
}
