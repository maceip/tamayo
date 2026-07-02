package gf16

// MulTable returns the packed GF(16) multiplication table for scalar b.
//
// The four bytes of the result hold b*1, b*x, b*x^2, b*x^3 (i.e. Mul(b,1),
// Mul(b,2), Mul(b,4), Mul(b,8)) in their low nibbles, used by the bitsliced
// multiply-accumulate. Transpiled verbatim from MAYO-C
// src/simple_arithmetic.h: mul_table.
func MulTable(b byte) uint32 {
	x := uint32(b) * 0x08040201
	high := x & 0xf0f0f0f0
	return x ^ (high >> 4) ^ (high >> 3)
}
