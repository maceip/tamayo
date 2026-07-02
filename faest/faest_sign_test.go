package faest

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

type faestProveVec struct {
	Lambda     int   `json:"lambda"`
	EM         bool  `json:"em"`
	Sk         []int `json:"sk"`
	HashedSigS []int `json:"hashedSigS"`
	HashedSigF []int `json:"hashedSigF"`
}

var faestMsg = []byte("This document describes and specifies the FAEST digital signature algorithm.")

func faestRho() []byte {
	r := make([]byte, 16)
	for i := range r {
		r[i] = byte(i)
	}
	return r
}

// TestFaestSignKAT validates the full FAEST signer/verifier against faest-rs
// vectors (tests/data/FaestProve.json): sign with the small and fast parameter
// sets, hash the signature, compare to the reference, and verify.
func TestFaestSignKAT(t *testing.T) {
	raw, err := os.ReadFile("testdata/FaestProve.json")
	if err != nil {
		t.Fatalf("read FaestProve.json: %v", err)
	}
	var vecs []faestProveVec
	if err := json.Unmarshal(raw, &vecs); err != nil {
		t.Fatalf("parse: %v", err)
	}

	sets := map[int][2]FaestParams{
		128: {FAEST128s, FAEST128f},
		192: {FAEST192s, FAEST192f},
		256: {FAEST256s, FAEST256f},
	}

	msg := faestMsg
	rho := faestRho()
	n := 0
	for _, v := range vecs {
		if v.EM {
			continue // Even-Mansour not yet ported
		}
		ps, pf := sets[v.Lambda][0], sets[v.Lambda][1]
		sk := ints2bytes(v.Sk)
		_, _, pk := ps.PublicKeyFromSecret(sk)

		sigS := ps.Sign(msg, sk, rho)
		if !bytes.Equal(shake256x64(sigS), ints2bytes(v.HashedSigS)) {
			t.Fatalf("%s: signature hash mismatch (len %d, want sig size %d)", ps.Name, len(sigS), ps.SigSize)
		}
		if !ps.Verify(msg, pk, sigS) {
			t.Fatalf("%s: verify failed", ps.Name)
		}

		sigF := pf.Sign(msg, sk, rho)
		if !bytes.Equal(shake256x64(sigF), ints2bytes(v.HashedSigF)) {
			t.Fatalf("%s: signature hash mismatch", pf.Name)
		}
		if !pf.Verify(msg, pk, sigF) {
			t.Fatalf("%s: verify failed", pf.Name)
		}
		n += 2
	}
	t.Logf("verified %d FAEST sign+verify vectors", n)
}
