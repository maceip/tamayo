package faest

import "testing"

var allTaus = []Tau{
	Tau128Small, Tau128Fast, Tau192Small, Tau192Fast, Tau256Small, Tau256Fast,
}

// TestTauIdentities checks the defining identities of every FAEST parameter set:
// the instance counts partition Tau, and the per-instance leaf counts sum to L.
func TestTauIdentities(t *testing.T) {
	for _, p := range allTaus {
		if p.Tau0+p.Tau1 != p.Tau {
			t.Errorf("%s: Tau0+Tau1=%d != Tau=%d", p.Name, p.Tau0+p.Tau1, p.Tau)
		}
		leaves := p.Tau1*(1<<p.K) + p.Tau0*(1<<(p.K-1))
		if leaves != p.L {
			t.Errorf("%s: Tau1*2^K + Tau0*2^(K-1)=%d != L=%d", p.Name, leaves, p.L)
		}
	}
}

// TestPosInTreeBijection verifies that PosInTree, together with the per-instance
// leaf counts, is a bijection from all (i,j) entries onto the GGM-tree leaf
// range [L-1, 2L-2]. Any transcription error in the offset arithmetic breaks it.
func TestPosInTreeBijection(t *testing.T) {
	for _, p := range allTaus {
		seen := make(map[int]bool, p.L)
		for i := 0; i < p.Tau; i++ {
			for j := 0; j < p.BavcMaxNodeIndex(i); j++ {
				leaf := p.PosInTree(i, j)
				if leaf < p.L-1 || leaf > 2*p.L-2 {
					t.Fatalf("%s: PosInTree(%d,%d)=%d outside leaf range [%d,%d]", p.Name, i, j, leaf, p.L-1, 2*p.L-2)
				}
				if seen[leaf] {
					t.Fatalf("%s: PosInTree collision at leaf %d (i=%d,j=%d)", p.Name, leaf, i, j)
				}
				seen[leaf] = true
			}
		}
		if len(seen) != p.L {
			t.Errorf("%s: covered %d leaves, want L=%d", p.Name, len(seen), p.L)
		}
	}
}
