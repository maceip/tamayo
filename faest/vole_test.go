package faest

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

type voleVec struct {
	Lambda  int    `json:"lambda"`
	Mode    string `json:"mode"`
	H       []int  `json:"h"`
	HashedC []int  `json:"hashedC"`
	HashedU []int  `json:"hashedU"`
	HashedV []int  `json:"hashedV"`
	Chall   []int  `json:"chall"`
	HashedQ []int  `json:"hashedQ"`
}

func lHatFor(lambda int) int {
	switch lambda {
	case 128:
		return 210 // LBytes(160) + 3*16 + B/8(2)
	case 192:
		return 386 // LBytes(312) + 3*24 + 2
	default:
		return 486 // LBytes(388) + 3*32 + 2
	}
}

func bavcForVole(v voleVec) *Bavc {
	return bavcForVec(bavcVec{Lambda: v.Lambda, Mode: v.Mode})
}

// TestVoleKAT validates volecommit/volereconstruct against faest-rs vectors
// (tests/data/vole.json). r is the fixed 0x00..0x1f prefix, iv is all zero.
func TestVoleKAT(t *testing.T) {
	raw, err := os.ReadFile("testdata/vole.json")
	if err != nil {
		t.Fatalf("read vole.json: %v", err)
	}
	var vecs []voleVec
	if err := json.Unmarshal(raw, &vecs); err != nil {
		t.Fatalf("parse vole.json: %v", err)
	}
	if len(vecs) == 0 {
		t.Fatal("no vectors")
	}

	rFull := make([]byte, 32)
	for i := range rFull {
		rFull[i] = byte(i)
	}
	iv := make([]byte, 16)

	for _, v := range vecs {
		b := bavcForVole(v)
		lam := b.lam()
		lHat := lHatFor(v.Lambda)
		r := rFull[:lam]
		chall := ints2bytes(v.Chall)

		// Prover: commit.
		com := b.VoleCommit(r, iv, lHat)
		if !bytes.Equal(com.Com, ints2bytes(v.H)) {
			t.Fatalf("l=%d/%s: h mismatch", v.Lambda, v.Mode)
		}
		if !bytes.Equal(shake256x64(concatBytes(com.C)), ints2bytes(v.HashedC)) {
			t.Fatalf("l=%d/%s: hashedC mismatch", v.Lambda, v.Mode)
		}
		if !bytes.Equal(shake256x64(com.U), ints2bytes(v.HashedU)) {
			t.Fatalf("l=%d/%s: hashedU mismatch", v.Lambda, v.Mode)
		}
		if !bytes.Equal(shake256x64(concatBytes(com.V)), ints2bytes(v.HashedV)) {
			t.Fatalf("l=%d/%s: hashedV mismatch", v.Lambda, v.Mode)
		}

		// Verifier: open + reconstruct.
		iDelta := b.Tau.DecodeChallenge(chall)
		op, ok := b.Open(com.Keys, com.Coms, iDelta)
		if !ok {
			t.Fatalf("l=%d/%s: open failed", v.Lambda, v.Mode)
		}
		rec, ok := b.VoleReconstruct(chall, op, com.C, iv, lHat)
		if !ok {
			t.Fatalf("l=%d/%s: reconstruct failed", v.Lambda, v.Mode)
		}
		if !bytes.Equal(rec.Com, ints2bytes(v.H)) {
			t.Fatalf("l=%d/%s: reconstructed com != h", v.Lambda, v.Mode)
		}
		if !bytes.Equal(shake256x64(concatBytes(rec.Q)), ints2bytes(v.HashedQ)) {
			t.Fatalf("l=%d/%s: hashedQ mismatch", v.Lambda, v.Mode)
		}
	}
	t.Logf("verified %d VOLE vectors (commit/reconstruct)", len(vecs))
}
