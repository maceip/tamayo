// Package gf16 implements arithmetic over GF(16) = GF(2)[x]/(x^4 + x + 1).
//
// This is the field ("F16") used by the MAYO signature scheme. Elements are
// held in the low nibble of a byte (values 0x0..0xf); the high nibble is
// ignored on input and always zero on output.
//
// All operations are branch-free and run in time independent of their operand
// values. The package is pure Go with no imports, so it builds unchanged for
// every GOOS=tamago target (amd64, arm, arm64, riscv64).
//
// The reduction polynomial (x^4 + x + 1) and the algorithms match the MAYO
// reference implementation (MAYO-C, src/simple_arithmetic.h) so that results
// are bit-compatible with its known-answer tests.
package gf16

// Add returns a + b. In a field of characteristic two, addition, subtraction
// and negation all coincide with XOR.
func Add(a, b byte) byte { return (a ^ b) & 0xf }

// Mul returns a * b reduced modulo x^4 + x + 1.
func Mul(a, b byte) byte {
	a &= 0xf
	b &= 0xf

	// Carry-less multiply: bit i of a contributes (b << i) to the product.
	// The mask is 0x00 or 0xff, avoiding a data-dependent branch.
	var p byte
	for i := 0; i < 4; i++ {
		mask := -((a >> i) & 1)
		p ^= (b << i) & mask
	}

	// One folding step reduces the high part (bits 4..6) using x^4 = x + 1:
	//   x^4 -> 1 + x,  x^5 -> x + x^2,  x^6 -> x^2 + x^3.
	hi := p & 0xf0
	return (p ^ (hi >> 4) ^ (hi >> 3)) & 0xf
}

// Inv returns the multiplicative inverse of a, defining Inv(0) = 0.
//
// For non-zero a in GF(16), a^15 = 1, hence a^-1 = a^14. The value is computed
// through the addition chain 14 = 8 + 6, which is branch-free; the a == 0 case
// falls out naturally because 0^14 = 0.
func Inv(a byte) byte {
	a2 := Mul(a, a)   // a^2
	a4 := Mul(a2, a2) // a^4
	a8 := Mul(a4, a4) // a^8
	a6 := Mul(a4, a2) // a^6
	return Mul(a8, a6)
}

// MulU64 multiplies, in parallel, each of the sixteen GF(16) elements packed as
// little-endian nibbles in v by the scalar s, returning the packed result.
//
// This nibble-packed lane layout is the SIMD-friendly representation used by
// MAYO's vector and matrix routines; a future amd64/arm64 assembly fast path
// can widen the same lane layout without changing callers.
func MulU64(s byte, v uint64) uint64 {
	const msb = 0x8888888888888888 // high bit (x^3) of every nibble lane

	s &= 0xf
	r := v & -uint64(s&1) // bit 0 of s
	for i := 1; i < 4; i++ {
		// Multiply v by x within each nibble: clear the lane high bits, shift
		// left by one (no cross-lane carry since the high bits were cleared),
		// then fold x^4 = x + 1 (binary 0b11 = 3) back into the low bits.
		hi := v & msb
		v = ((v ^ hi) << 1) ^ ((hi >> 3) * 3)
		r ^= v & -uint64((s>>i)&1)
	}
	return r
}
