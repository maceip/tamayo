package faest

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/maceip/tamayo/field"
)

type leafHashVec struct {
	UHash []int `json:"uhash"`
	X     []int `json:"x"`
	H     []int `json:"expected_h"`
}

// TestLeafHashKAT validates the leaf commitment hash (and thereby the extension
// fields GF384/576/768 and their base-field multiply) against the faest-rs
// vectors (tests/data/leafhash_{128,192,256}.json).
func TestLeafHashKAT(t *testing.T) {
	cases := []struct {
		ext  field.Big
		file string
	}{
		{field.Big384, "testdata/leafhash_128.json"},
		{field.Big576, "testdata/leafhash_192.json"},
		{field.Big768, "testdata/leafhash_256.json"},
	}
	for _, c := range cases {
		raw, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatalf("read %s: %v", c.file, err)
		}
		var vecs []leafHashVec
		if err := json.Unmarshal(raw, &vecs); err != nil {
			t.Fatalf("parse %s: %v", c.file, err)
		}
		if len(vecs) == 0 {
			t.Fatalf("%s: no vectors", c.file)
		}
		for i, v := range vecs {
			got := LeafHash(c.ext, ints2bytes(v.UHash), ints2bytes(v.X))
			if want := ints2bytes(v.H); !bytes.Equal(got, want) {
				t.Fatalf("%s[%d]: mismatch\n got  %x\n want %x", c.file, i, got, want)
			}
		}
		t.Logf("%s: %d vectors verified", c.file, len(vecs))
	}
}
