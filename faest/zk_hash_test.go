package faest

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/maceip/tamayo/field"
)

type zkHashVec struct {
	Sd []int   `json:"sd"`
	X0 [][]int `json:"x0"`
	X1 []int   `json:"x1"`
	H  []int   `json:"h"`
}

// TestZKHashKAT validates the ZK universal hash against faest-rs vectors
// (tests/data/zkhash_{128,192,256}.json).
func TestZKHashKAT(t *testing.T) {
	cases := []struct {
		file string
		f    field.Big
	}{
		{"testdata/zkhash_128.json", field.Big128},
		{"testdata/zkhash_192.json", field.Big192},
		{"testdata/zkhash_256.json", field.Big256},
	}

	for _, c := range cases {
		raw, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatalf("read %s: %v", c.file, err)
		}
		var vecs []zkHashVec
		if err := json.Unmarshal(raw, &vecs); err != nil {
			t.Fatalf("parse %s: %v", c.file, err)
		}
		if len(vecs) == 0 {
			t.Fatalf("%s: no vectors", c.file)
		}
		for i, v := range vecs {
			h := NewZKHasher(c.f, ints2bytes(v.Sd))
			for _, e := range v.X0 {
				h.Update(c.f.FromBytes(ints2bytes(e)))
			}
			got := h.Finalize(c.f.FromBytes(ints2bytes(v.X1)))
			if !bytes.Equal(c.f.ToBytes(got), ints2bytes(v.H)) {
				t.Fatalf("%s case %d: hash mismatch", c.file, i)
			}
		}
		t.Logf("%s: verified %d ZK-hash vectors", c.file, len(vecs))
	}
}
