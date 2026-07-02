package faest

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

type bavcOpenVec struct {
	Name       string `json:"name"`
	Secpar     int    `json:"secpar"`
	OpenSize   int    `json:"open_size"`
	DeltaBits  int    `json:"delta_bits"`
	Seed       string `json:"seed"`
	IV         string `json:"iv"`
	Delta      string `json:"delta"`
	DeltaBytes string `json:"delta_bytes"`
	Opening    string `json:"opening"`
}

// TestMayoForestOpen verifies ggm_forest_bavc::open: given a committed forest
// and an expanded Delta, the co-path node keys + hidden leaf hashes must match
// the reference opening byte-for-byte.
func TestMayoForestOpen(t *testing.T) {
	raw, err := os.ReadFile("testdata/bavc_open.json")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var vecs []bavcOpenVec
	if err := json.Unmarshal(raw, &vecs); err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, v := range vecs {
		m := mayoForestFor(t, v.Secpar)
		_, hashedLeaves, _, forest := m.MayoForestCommit(mustHex(t, v.Seed), mustHex(t, v.IV))
		opening := m.MayoForestOpen(forest, hashedLeaves, mustHex(t, v.DeltaBytes))
		if !bytes.Equal(opening, mustHex(t, v.Opening)) {
			t.Errorf("%s: opening mismatch (len go=%d ref=%d)\n got %x\nwant %s",
				v.Name, len(opening), v.OpenSize, opening[:min(64, len(opening))], v.Opening[:min(128, len(v.Opening))])
		}
	}
	t.Logf("verified %d ggm_forest open vectors byte-exact", len(vecs))
}
