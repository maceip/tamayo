package mayo

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type preimageVec struct {
	Name     string `json:"name"`
	M        int    `json:"m"`
	N        int    `json:"n"`
	O        int    `json:"o"`
	K        int    `json:"k"`
	MBytes   int    `json:"m_bytes"`
	SigBytes int    `json:"sig_bytes"`
	CSK      string `json:"csk"`
	CPK      string `json:"cpk"`
	T        string `json:"t"`
	BSig     string `json:"bsig"`
}

func mh(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

func paramsForName(name string) *Params {
	switch name {
	case "mayo_1":
		return &Mayo1
	case "mayo_3":
		return &Mayo3
	case "mayo_5":
		return &Mayo5
	}
	return nil
}

// TestSignWithoutHashingKAT verifies the MAYO preimage sampler
// (mayo_sign_without_hashing) byte-exact against MAYO-C reference vectors: for
// a fixed compact secret key and target t, SignWithoutHashing must reproduce
// the reference preimage bytes exactly.
func TestSignWithoutHashingKAT(t *testing.T) {
	raw, err := os.ReadFile("testdata/mayo_preimage.json")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var vecs []preimageVec
	if err := json.Unmarshal(raw, &vecs); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(vecs) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range vecs {
		p := paramsForName(v.Name)
		if p == nil {
			t.Fatalf("unknown %s", v.Name)
		}
		got := p.SignWithoutHashing(mh(t, v.T), mh(t, v.CSK))
		if !bytes.Equal(got, mh(t, v.BSig)) {
			t.Errorf("%s: preimage mismatch (len go=%d ref=%d)", v.Name, len(got), v.SigBytes)
		}
	}
	t.Logf("verified %d MAYO preimage (sign_without_hashing) vectors byte-exact", len(vecs))
}

func TestSignWithoutHashingRejectsMalformedInput(t *testing.T) {
	for _, p := range []*Params{&Mayo1, &Mayo3, &Mayo5} {
		seed := make([]byte, p.SKSeedBytes)
		_, csk, err := p.CompactKeyGen(seed)
		if err != nil {
			t.Fatalf("%s: CompactKeyGen: %v", p.Name, err)
		}

		if got := p.SignWithoutHashing(make([]byte, p.MBytes-1), csk); got != nil {
			t.Fatalf("%s: accepted short target", p.Name)
		}
		if got := p.SignWithoutHashing(make([]byte, p.MBytes+1), csk); got != nil {
			t.Fatalf("%s: accepted overlong target", p.Name)
		}
		if got := p.SignWithoutHashing(make([]byte, p.MBytes), csk[:len(csk)-1]); got != nil {
			t.Fatalf("%s: accepted short csk", p.Name)
		}
	}
}
