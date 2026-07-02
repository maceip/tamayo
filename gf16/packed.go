package gf16

// MulFx8 multiplies the GF(16) scalar a by eight field elements packed one per
// byte (low nibble) in b, returning the eight products packed the same way.
// Used by MAYO's back-substitution. Transpiled from MAYO-C
// src/simple_arithmetic.h: mul_fx8.
func MulFx8(a byte, b uint64) uint64 {
	var p uint64
	p = uint64(a&1) * b
	p ^= uint64(a&2) * b
	p ^= uint64(a&4) * b
	p ^= uint64(a&8) * b

	topP := p & 0xf0f0f0f0f0f0f0f0
	return (p ^ (topP >> 4) ^ (topP >> 3)) & 0x0f0f0f0f0f0f0f0f
}
