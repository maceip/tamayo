package field

import (
	"math/rand"
	"testing"
)

func TestGF64(t *testing.T) {
	r := rand.New(rand.NewSource(4))

	// Field axioms.
	for trial := 0; trial < 500; trial++ {
		a := GF64(r.Uint64())
		b := GF64(r.Uint64())
		c := GF64(r.Uint64())
		if a.Mul(b) != b.Mul(a) {
			t.Fatal("GF64 commutativity")
		}
		if a.Mul(b).Mul(c) != a.Mul(b.Mul(c)) {
			t.Fatal("GF64 associativity")
		}
		if a.Mul(b.Add(c)) != a.Mul(b).Add(a.Mul(c)) {
			t.Fatal("GF64 distributivity")
		}
		if a.Mul(GF64One) != a {
			t.Fatal("GF64 identity")
		}
		if a.Mul(0) != 0 {
			t.Fatal("GF64 zero")
		}
	}

	// Fermat inverse: a^(2^64 - 2) = a^-1, so a·a^-1 = 1.
	for trial := 0; trial < 20; trial++ {
		a := GF64(r.Uint64())
		if a == 0 {
			continue
		}
		t2 := a
		inv := GF64One
		for i := 1; i < 64; i++ {
			t2 = t2.Mul(t2)
			inv = inv.Mul(t2)
		}
		if a.Mul(inv) != GF64One {
			t.Fatal("GF64 a * a^-1 != 1")
		}
	}
}

func TestMulGF64Embed(t *testing.T) {
	// a.MulGF64(b) must equal a.Mul(embed(b)) for GF128 (and the analog holds by
	// construction for GF192/GF256).
	a := GF128{0x0123456789abcdef, 0xfedcba9876543210}
	b := GF64(0xdeadbeefcafebabe)
	if a.MulGF64(b) != a.Mul(GF128{uint64(b), 0}) {
		t.Fatal("MulGF64 mismatch")
	}
}
