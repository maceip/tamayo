package gf16

// Dense linear algebra over GF(16), one field element per byte in row-major
// order. This matches the layout of the MAYO reference (MAYO-C,
// src/simple_arithmetic.h: mat_add, lincomb, mat_mul) and is the
// correctness-oriented representation used by MAYO's map evaluation and the
// preimage solver. The nibble-packed MulU64 path handles the vectorized inner
// loops where throughput matters.

// AddVec sets dst = a + b for equal-length GF(16) vectors (element-wise XOR).
func AddVec(dst, a, b []byte) {
	for i := range dst {
		dst[i] = (a[i] ^ b[i]) & 0xf
	}
}

// MatAdd sets c = a + b for matrices of identical shape (row-major).
func MatAdd(c, a, b []byte) {
	for i := range c {
		c[i] = (a[i] ^ b[i]) & 0xf
	}
}

// MatMul sets c = a * b, where a is rows x inner, b is inner x cols and the
// result c is rows x cols, all row-major with one GF(16) element per byte.
func MatMul(c, a, b []byte, rows, inner, cols int) {
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			var acc byte
			for k := 0; k < inner; k++ {
				acc ^= Mul(a[i*inner+k], b[k*cols+j])
			}
			c[i*cols+j] = acc
		}
	}
}

// Transpose sets dst (cols x rows) to the transpose of src (rows x cols).
func Transpose(dst, src []byte, rows, cols int) {
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			dst[j*rows+i] = src[i*cols+j] & 0xf
		}
	}
}
