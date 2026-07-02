package mayo

import (
	"math/rand"
	"testing"

	"github.com/maceip/tamayo/gf16"
)

func nib(v uint64, n int) byte { return byte((v >> (4 * n)) & 0xf) }

// TestMVecMulAddPerNibble validates the bitsliced multiply-accumulate against
// the scalar gf16.Mul on every nibble lane (independent implementations).
func TestMVecMulAddPerNibble(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	const L = 5
	for a := 0; a < 16; a++ {
		src := make([]uint64, L)
		acc := make([]uint64, L)
		for i := range src {
			src[i] = r.Uint64()
			acc[i] = r.Uint64()
		}
		exp := make([]uint64, L)
		copy(exp, acc)
		for i := 0; i < L; i++ {
			for n := 0; n < 16; n++ {
				exp[i] ^= uint64(gf16.Mul(byte(a), nib(src[i], n))) << (4 * n)
			}
		}
		mVecMulAdd(src, byte(a), acc, L)
		for i := range acc {
			if acc[i] != exp[i] {
				t.Fatalf("mVecMulAdd a=%d limb %d: got %016x want %016x", a, i, acc[i], exp[i])
			}
		}
	}
}

// TestMultiplyBinsContract validates the bin-fold ladder functionally: it must
// compute out = sum_{c=1}^{15} c * bins[c] over GF(16), independent of the
// ladder's internal step offsets.
func TestMultiplyBinsContract(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	for _, mvl := range []int{4, 5, 7, 9} {
		bins := make([]uint64, 16*mvl)
		for i := range bins {
			bins[i] = r.Uint64()
		}
		exp := make([]uint64, mvl)
		for c := 1; c < 16; c++ {
			for j := 0; j < mvl; j++ {
				v := bins[c*mvl+j]
				for n := 0; n < 16; n++ {
					exp[j] ^= uint64(gf16.Mul(byte(c), nib(v, n))) << (4 * n)
				}
			}
		}
		out := make([]uint64, mvl)
		mVecMultiplyBins(bins, out, mvl) // mutates bins
		for j := range out {
			if out[j] != exp[j] {
				t.Fatalf("mVecMultiplyBins mvl=%d limb %d: got %016x want %016x", mvl, j, out[j], exp[j])
			}
		}
	}
}
