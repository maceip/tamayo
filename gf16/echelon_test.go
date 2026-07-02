package gf16

import (
	"math/rand"
	"testing"
)

// TestEFSolveInvertible builds random invertible systems A·x = b (A = L·U with
// unit-triangular factors, hence invertible), reduces the augmented matrix with
// EF, back-substitutes, and checks the recovered x matches.
func TestEFSolveInvertible(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	const n = 6

	for trial := 0; trial < 100; trial++ {
		l := make([]byte, n*n)
		u := make([]byte, n*n)
		for i := 0; i < n; i++ {
			l[i*n+i] = 1
			u[i*n+i] = 1
			for j := 0; j < i; j++ {
				l[i*n+j] = byte(r.Intn(16))
			}
			for j := i + 1; j < n; j++ {
				u[i*n+j] = byte(r.Intn(16))
			}
		}
		a := make([]byte, n*n)
		MatMul(a, l, u, n, n, n) // invertible by construction

		x := make([]byte, n)
		for i := range x {
			x[i] = byte(r.Intn(16))
		}
		b := make([]byte, n)
		MatMul(b, a, x, n, n, 1)

		// augmented [A | b], n x (n+1)
		aug := make([]byte, n*(n+1))
		for i := 0; i < n; i++ {
			copy(aug[i*(n+1):i*(n+1)+n], a[i*n:i*n+n])
			aug[i*(n+1)+n] = b[i]
		}

		EF(aug, n, n+1)

		// For invertible A the A-block must be unit upper-triangular.
		for i := 0; i < n; i++ {
			if aug[i*(n+1)+i] != 1 {
				t.Fatalf("trial %d: diagonal[%d]=%d, want 1", trial, i, aug[i*(n+1)+i])
			}
			for j := 0; j < i; j++ {
				if aug[i*(n+1)+j] != 0 {
					t.Fatalf("trial %d: entry (%d,%d)=%d below diagonal, want 0", trial, i, j, aug[i*(n+1)+j])
				}
			}
		}

		// back-substitution (unit diagonal)
		xs := make([]byte, n)
		for i := n - 1; i >= 0; i-- {
			acc := aug[i*(n+1)+n]
			for j := i + 1; j < n; j++ {
				acc ^= Mul(aug[i*(n+1)+j], xs[j])
			}
			xs[i] = acc
		}
		for i := 0; i < n; i++ {
			if xs[i] != x[i] {
				t.Fatalf("trial %d: recovered x[%d]=%d, want %d", trial, i, xs[i], x[i])
			}
		}
	}
}

// TestEFLeadingOnes checks the row-echelon shape on rectangular full-rank input.
func TestEFLeadingOnes(t *testing.T) {
	r := rand.New(rand.NewSource(11))
	const rows, cols = 4, 7
	a := make([]byte, rows*cols)
	for i := range a {
		a[i] = byte(r.Intn(16))
	}
	EF(a, rows, cols)

	lastLead := -1
	for i := 0; i < rows; i++ {
		lead := -1
		for j := 0; j < cols; j++ {
			if a[i*cols+j] != 0 {
				lead = j
				break
			}
		}
		if lead == -1 {
			continue // zero row
		}
		if a[i*cols+lead] != 1 {
			t.Fatalf("row %d leading entry = %d, want 1", i, a[i*cols+lead])
		}
		if lead <= lastLead {
			t.Fatalf("row %d leading col %d not strictly after previous %d", i, lead, lastLead)
		}
		lastLead = lead
	}
}
