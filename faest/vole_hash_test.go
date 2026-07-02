package faest

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/maceip/tamayo/field"
)

type voleHashVec struct {
	SD []int `json:"sd"`
	XS []int `json:"xs"`
	H  []int `json:"h"`
}

func ints2bytes(a []int) []byte {
	b := make([]byte, len(a))
	for i, v := range a {
		b[i] = byte(v)
	}
	return b
}

// TestVoleHashKAT validates the VOLE universal hash against the faest-rs vectors
// (tests/data/volehash_{128,192,256}.json), vendored under testdata/.
func TestVoleHashKAT(t *testing.T) {
	cases := []struct {
		f    field.Big
		file string
	}{
		{field.Big128, "testdata/volehash_128.json"},
		{field.Big192, "testdata/volehash_192.json"},
		{field.Big256, "testdata/volehash_256.json"},
	}
	for _, c := range cases {
		raw, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatalf("read %s: %v", c.file, err)
		}
		var vecs []voleHashVec
		if err := json.Unmarshal(raw, &vecs); err != nil {
			t.Fatalf("parse %s: %v", c.file, err)
		}
		if len(vecs) == 0 {
			t.Fatalf("%s: no vectors", c.file)
		}
		for i, v := range vecs {
			vh := NewVoleHasher(c.f, ints2bytes(v.SD))
			got := vh.Process(ints2bytes(v.XS))
			if want := ints2bytes(v.H); !bytes.Equal(got, want) {
				t.Fatalf("%s[%d]: mismatch\n got  %x\n want %x", c.file, i, got, want)
			}
		}
		t.Logf("%s: %d vectors verified", c.file, len(vecs))
	}
}
