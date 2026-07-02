package gf16

import (
	"math/rand"
	"testing"
)

func randMat(r *rand.Rand, n int) []byte {
	m := make([]byte, n)
	for i := range m {
		m[i] = byte(r.Intn(16))
	}
	return m
}

func TestAddVec(t *testing.T) {
	a := []byte{1, 2, 3, 0xf}
	b := []byte{5, 6, 7, 0xf}
	dst := make([]byte, 4)
	AddVec(dst, a, b)
	for i := range dst {
		if dst[i] != Add(a[i], b[i]) {
			t.Fatalf("AddVec mismatch at %d: got %d", i, dst[i])
		}
	}
}

func TestMatMulIdentity(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	const n = 5
	id := make([]byte, n*n)
	for i := 0; i < n; i++ {
		id[i*n+i] = 1
	}
	a := randMat(r, n*n)
	c := make([]byte, n*n)

	MatMul(c, a, id, n, n, n)
	for i := range c {
		if c[i] != a[i] {
			t.Fatalf("A*I != A at %d", i)
		}
	}
	MatMul(c, id, a, n, n, n)
	for i := range c {
		if c[i] != a[i] {
			t.Fatalf("I*A != A at %d", i)
		}
	}
}

func TestMatMulAssociative(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	a := randMat(r, 3*4) // 3x4
	b := randMat(r, 4*2) // 4x2
	d := randMat(r, 2*5) // 2x5

	ab := make([]byte, 3*2)
	MatMul(ab, a, b, 3, 4, 2)
	abd := make([]byte, 3*5)
	MatMul(abd, ab, d, 3, 2, 5)

	bd := make([]byte, 4*5)
	MatMul(bd, b, d, 4, 2, 5)
	abd2 := make([]byte, 3*5)
	MatMul(abd2, a, bd, 3, 4, 5)

	for i := range abd {
		if abd[i] != abd2[i] {
			t.Fatalf("(A*B)*D != A*(B*D) at %d", i)
		}
	}
}

func TestTranspose(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	a := randMat(r, 3*4) // 3x4
	b := randMat(r, 4*2) // 4x2

	ab := make([]byte, 3*2)
	MatMul(ab, a, b, 3, 4, 2)
	abT := make([]byte, 2*3)
	Transpose(abT, ab, 3, 2)

	aT := make([]byte, 4*3)
	Transpose(aT, a, 3, 4)
	bT := make([]byte, 2*4)
	Transpose(bT, b, 4, 2)
	bTaT := make([]byte, 2*3)
	MatMul(bTaT, bT, aT, 2, 4, 3) // (A*B)^T = B^T * A^T

	for i := range abT {
		if abT[i] != bTaT[i] {
			t.Fatalf("(A*B)^T != B^T*A^T at %d", i)
		}
	}

	// transpose is an involution
	aTT := make([]byte, 3*4)
	Transpose(aTT, aT, 4, 3)
	for i := range a {
		if aTT[i] != a[i] {
			t.Fatalf("T(T(A)) != A at %d", i)
		}
	}
}
