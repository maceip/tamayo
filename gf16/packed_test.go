package gf16

import (
	"math/rand"
	"testing"
)

// TestMulFx8 validates the byte-packed multiply against the scalar Mul.
func TestMulFx8(t *testing.T) {
	r := rand.New(rand.NewSource(9))
	for a := 0; a < 16; a++ {
		for trial := 0; trial < 50; trial++ {
			var b uint64
			var nibs [8]byte
			for i := 0; i < 8; i++ {
				nibs[i] = byte(r.Intn(16))
				b |= uint64(nibs[i]) << (8 * i)
			}
			got := MulFx8(byte(a), b)
			for i := 0; i < 8; i++ {
				g := byte((got >> (8 * i)) & 0xf)
				if w := Mul(byte(a), nibs[i]); g != w {
					t.Fatalf("MulFx8(%d) byte %d: got %d want %d", a, i, g, w)
				}
			}
		}
	}
}
