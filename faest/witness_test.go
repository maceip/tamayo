package faest

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

type aewVec struct {
	Lambda int   `json:"lambda"`
	EM     bool  `json:"em"`
	Key    []int `json:"key"`
	Input  []int `json:"input"`
	W      []int `json:"w"`
}

func owfFor(lambda int, em bool) OWFParams {
	switch {
	case lambda == 128 && !em:
		return OWF128
	case lambda == 192 && !em:
		return OWF192
	case lambda == 256 && !em:
		return OWF256
	case lambda == 128:
		return OWF128EM
	case lambda == 192:
		return OWF192EM
	default:
		return OWF256EM
	}
}

// TestAesExtendedWitnessKAT validates the FAEST extended-witness derivation
// against faest-rs vectors (tests/data/AesExtendedWitness.json), covering both
// the AES and Even-Mansour parameter sets.
func TestAesExtendedWitnessKAT(t *testing.T) {
	raw, err := os.ReadFile("testdata/AesExtendedWitness.json")
	if err != nil {
		t.Fatalf("read AesExtendedWitness.json: %v", err)
	}
	var vecs []aewVec
	if err := json.Unmarshal(raw, &vecs); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(vecs) == 0 {
		t.Fatal("no vectors")
	}

	for _, v := range vecs {
		o := owfFor(v.Lambda, v.EM)
		got := ExtendWitness(o, ints2bytes(v.Key), ints2bytes(v.Input))
		if !bytes.Equal(got, ints2bytes(v.W)) {
			t.Fatalf("%s (lambda=%d em=%v): witness mismatch (got %d bytes, want %d)",
				o.Name, v.Lambda, v.EM, len(got), len(v.W))
		}
	}
	t.Logf("verified %d extended-witness vectors", len(vecs))
}
