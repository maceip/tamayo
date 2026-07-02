package mayo

import (
	"math/rand"
	"testing"

	"github.com/maceip/tamayo/gf16"
)

// TestSampleSolution validates the constant-time linear solver on random
// systems: after solving with r = 0, the recovered x must satisfy A·x = y.
func TestSampleSolution(t *testing.T) {
	r := rand.New(rand.NewSource(5))
	p := Params{M: 4, K: 2, O: 4} // ko = 8, a_cols = 9
	m := p.M
	ko := p.K * p.O
	aCols := p.ACols()

	solved := 0
	for trial := 0; trial < 400 && solved < 25; trial++ {
		aSys := make([]byte, m*ko)
		for i := range aSys {
			aSys[i] = byte(r.Intn(16))
		}
		y := make([]byte, m)
		for i := range y {
			y[i] = byte(r.Intn(16))
		}

		a := make([]byte, m*aCols)
		for i := 0; i < m; i++ {
			copy(a[i*aCols:i*aCols+ko], aSys[i*ko:(i+1)*ko])
		}
		x := make([]byte, aCols) // r = 0

		if !sampleSolution(&p, a, y, x) {
			continue
		}
		solved++
		for i := 0; i < m; i++ {
			var acc byte
			for j := 0; j < ko; j++ {
				acc ^= gf16.Mul(aSys[i*ko+j], x[j])
			}
			if acc != y[i] {
				t.Fatalf("trial %d row %d: A*x=%d want %d", trial, i, acc, y[i])
			}
		}
	}
	if solved == 0 {
		t.Fatal("no solvable systems produced")
	}
	t.Logf("verified A*x=y on %d solved systems", solved)
}
