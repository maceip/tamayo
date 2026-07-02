package gf16

import "testing"

// refMul is an independent, deliberately different reference multiplication
// over GF(2)[x]/(x^4+x+1) (shift-and-add with per-step reduction), used to
// cross-check Mul. It is not constant time; correctness only.
func refMul(a, b byte) byte {
	a &= 0xf
	b &= 0xf
	var r byte
	for b != 0 {
		if b&1 != 0 {
			r ^= a
		}
		b >>= 1
		carry := a & 0x8
		a = (a << 1) & 0xf
		if carry != 0 {
			a ^= 0x3 // x^4 = x + 1
		}
	}
	return r
}

func TestMulExhaustive(t *testing.T) {
	for a := 0; a < 16; a++ {
		for b := 0; b < 16; b++ {
			if got, want := Mul(byte(a), byte(b)), refMul(byte(a), byte(b)); got != want {
				t.Fatalf("Mul(%d,%d) = %d, want %d", a, b, got, want)
			}
		}
	}
}

func TestMulHighNibbleIgnored(t *testing.T) {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			got := Mul(byte(a), byte(b))
			want := Mul(byte(a)&0xf, byte(b)&0xf)
			if got != want || got > 0xf {
				t.Fatalf("Mul(%#x,%#x)=%#x not reduced to low nibble", a, b, got)
			}
		}
	}
}

func TestFieldAxioms(t *testing.T) {
	for a := byte(0); a < 16; a++ {
		if Mul(a, 1) != a {
			t.Fatalf("multiplicative identity failed for %d", a)
		}
		if Mul(a, 0) != 0 {
			t.Fatalf("absorbing zero failed for %d", a)
		}
		for b := byte(0); b < 16; b++ {
			if Mul(a, b) != Mul(b, a) {
				t.Fatalf("commutativity failed for %d,%d", a, b)
			}
			for c := byte(0); c < 16; c++ {
				if Mul(Mul(a, b), c) != Mul(a, Mul(b, c)) {
					t.Fatalf("associativity failed for %d,%d,%d", a, b, c)
				}
				if Mul(a, Add(b, c)) != Add(Mul(a, b), Mul(a, c)) {
					t.Fatalf("distributivity failed for %d,%d,%d", a, b, c)
				}
			}
		}
	}
}

func TestInv(t *testing.T) {
	// Authoritative inverse table for GF(2)[x]/(x^4+x+1) from MAYO-C
	// (src/simple_arithmetic.h, inverse_f comment).
	want := [16]byte{0, 1, 9, 14, 13, 11, 7, 6, 15, 2, 12, 5, 10, 4, 3, 8}
	for a := byte(0); a < 16; a++ {
		if got := Inv(a); got != want[a] {
			t.Fatalf("Inv(%d) = %d, want %d", a, got, want[a])
		}
		if a != 0 && Mul(a, Inv(a)) != 1 {
			t.Fatalf("a*Inv(a) != 1 for a = %d", a)
		}
	}
}

func TestMulU64Lanes(t *testing.T) {
	vs := []uint64{
		0x0123456789abcdef,
		0xfedcba9876543210,
		0x0000000000000000,
		0xffffffffffffffff,
		0x1111222233334444,
	}
	for s := byte(0); s < 16; s++ {
		for _, v := range vs {
			got := MulU64(s, v)
			for lane := 0; lane < 16; lane++ {
				n := byte((v >> (4 * lane)) & 0xf)
				wantNib := Mul(s, n)
				gotNib := byte((got >> (4 * lane)) & 0xf)
				if gotNib != wantNib {
					t.Fatalf("MulU64(%d,%#016x) lane %d = %d, want %d", s, v, lane, gotNib, wantNib)
				}
			}
		}
	}
}
