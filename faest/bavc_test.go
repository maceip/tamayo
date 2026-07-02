package faest

import (
	"bytes"
	"crypto/sha3"
	"encoding/json"
	"os"
	"testing"

	"github.com/maceip/tamayo/field"
)

type bavcVec struct {
	Lambda       int      `json:"lambda"`
	Mode         string   `json:"mode"`
	H            []int    `json:"h"`
	HashedK      []int    `json:"hashedK"`
	HashedCom    []int    `json:"hashedCom"`
	HashedSd     []int    `json:"hashedSd"`
	IDelta       []uint16 `json:"iDelta"`
	HashedDecomI []int    `json:"hashedDecomI"`
	HashedRecSd  []int    `json:"hashedRecSd"`
}

func shake256x64(data []byte) []byte {
	h := sha3.NewSHAKE256()
	h.Write(data)
	out := make([]byte, 64)
	h.Read(out)
	return out
}

func concatBytes(parts [][]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func bavcForVec(v bavcVec) *Bavc {
	var ext field.Big
	switch v.Lambda {
	case 128:
		ext = field.Big384
	case 192:
		ext = field.Big576
	default:
		ext = field.Big768
	}
	var t Tau
	switch {
	case v.Lambda == 128 && v.Mode == "s":
		t = Tau128Small
	case v.Lambda == 128:
		t = Tau128Fast
	case v.Lambda == 192 && v.Mode == "s":
		t = Tau192Small
	case v.Lambda == 192:
		t = Tau192Fast
	case v.Lambda == 256 && v.Mode == "s":
		t = Tau256Small
	default:
		t = Tau256Fast
	}
	return NewBavc(t, ext)
}

// TestBavcKAT validates the full batch all-but-one vector commitment
// (commit/open/reconstruct) against faest-rs vectors (tests/data/bavc.json).
// r and iv are the fixed values from the reference bavc_test.
func TestBavcKAT(t *testing.T) {
	raw, err := os.ReadFile("testdata/bavc.json")
	if err != nil {
		t.Fatalf("read bavc.json: %v", err)
	}
	var vecs []bavcVec
	if err := json.Unmarshal(raw, &vecs); err != nil {
		t.Fatalf("parse bavc.json: %v", err)
	}
	if len(vecs) == 0 {
		t.Fatal("no vectors")
	}

	rFull := make([]byte, 32)
	for i := range rFull {
		rFull[i] = byte(i)
	}
	iv := []byte{
		0x64, 0x2b, 0xb1, 0xf9, 0x7c, 0x5f, 0x97, 0x9a,
		0x72, 0xb1, 0xee, 0x39, 0xbe, 0x4e, 0x78, 0x22,
	}

	for _, v := range vecs {
		name := v.Mode
		b := bavcForVec(v)
		lam := b.lam()
		r := rFull[:lam]

		// Commit.
		com := b.Commit(r, iv)
		if !bytes.Equal(com.Com, ints2bytes(v.H)) {
			t.Fatalf("l=%d/%s: h mismatch", v.Lambda, name)
		}
		if !bytes.Equal(shake256x64(concatBytes(com.Seeds)), ints2bytes(v.HashedSd)) {
			t.Fatalf("l=%d/%s: hashedSd mismatch", v.Lambda, name)
		}
		if !bytes.Equal(shake256x64(concatBytes(com.Keys)), ints2bytes(v.HashedK)) {
			t.Fatalf("l=%d/%s: hashedK mismatch", v.Lambda, name)
		}
		if !bytes.Equal(shake256x64(concatBytes(com.Coms)), ints2bytes(v.HashedCom)) {
			t.Fatalf("l=%d/%s: hashedCom mismatch", v.Lambda, name)
		}

		// Open.
		op, ok := b.Open(com.Keys, com.Coms, v.IDelta)
		if !ok {
			t.Fatalf("l=%d/%s: open failed", v.Lambda, name)
		}
		dataDecom := append(concatBytes(op.Coms), concatBytes(op.Nodes)...)
		total := 3*lam*b.Tau.Tau + b.Tau.Topen*lam
		for len(dataDecom) < total {
			dataDecom = append(dataDecom, 0)
		}
		if !bytes.Equal(shake256x64(dataDecom), ints2bytes(v.HashedDecomI)) {
			t.Fatalf("l=%d/%s: hashedDecomI mismatch", v.Lambda, name)
		}

		// Reconstruct.
		rec, ok := b.Reconstruct(op, v.IDelta, iv)
		if !ok {
			t.Fatalf("l=%d/%s: reconstruct failed", v.Lambda, name)
		}
		if !bytes.Equal(shake256x64(concatBytes(rec.Seeds)), ints2bytes(v.HashedRecSd)) {
			t.Fatalf("l=%d/%s: hashedRecSd mismatch", v.Lambda, name)
		}
		if !bytes.Equal(rec.Com, ints2bytes(v.H)) {
			t.Fatalf("l=%d/%s: reconstructed com != h", v.Lambda, name)
		}
	}
	t.Logf("verified %d BAVC vectors (commit/open/reconstruct)", len(vecs))
}
