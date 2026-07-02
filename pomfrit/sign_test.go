package pomfrit

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

type fullProofVec struct {
	Name        string `json:"name"`
	Secpar      int    `json:"secpar"`
	ProofBytes  int    `json:"proof_bytes"`
	RAdditional string `json:"r_additional"`
	Pk          string `json:"pk"`
	Sk          string `json:"sk"`
	Proof       string `json:"proof"`
}

func mayoOWFFor(t *testing.T, secpar int) MayoOWF {
	t.Helper()
	switch secpar {
	case 128:
		return MayoOWFL1
	case 192:
		return MayoOWFL3
	case 256:
		return MayoOWFL5
	}
	t.Fatalf("unknown secpar %d", secpar)
	return MayoOWF{}
}

// TestMayoProveKAT verifies the full One-More-MAYO VOLE prover transcript
// (vole_prove_1 + vole_prove_2) against the reference: given the same packed
// sk/pk and r_additional, o.Prove must reproduce the entire proof byte-for-byte.
func TestMayoProveKAT(t *testing.T) {
	raw, err := os.ReadFile("testdata/full_proof.json")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var vecs []fullProofVec
	if err := json.Unmarshal(raw, &vecs); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(vecs) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range vecs {
		o := mayoOWFFor(t, v.Secpar)
		sk := mustHex(t, v.Sk)
		pk := mustHex(t, v.Pk)
		rAdd := mustHex(t, v.RAdditional)
		got := o.Prove(sk, pk, rAdd)
		want := mustHex(t, v.Proof)
		if !bytes.Equal(got.Bytes, want) {
			// Localize the first differing segment.
			n := len(got.Bytes)
			if len(want) < n {
				n = len(want)
			}
			diff := -1
			for i := 0; i < n; i++ {
				if got.Bytes[i] != want[i] {
					diff = i
					break
				}
			}
			t.Errorf("%s: proof mismatch (len go=%d ref=%d, first diff at byte %d of %d)",
				v.Name, len(got.Bytes), len(want), diff, v.ProofBytes)
			continue
		}
	}
	t.Logf("verified %d full One-More-MAYO prover proofs byte-exact", len(vecs))
}

// TestMayoVerifyKAT checks the interop direction: the Go verifier accepts the
// reference proof (vole_verify == true), and rejects a tampered proof.
func TestMayoVerifyKAT(t *testing.T) {
	raw, err := os.ReadFile("testdata/full_proof.json")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var vecs []fullProofVec
	if err := json.Unmarshal(raw, &vecs); err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, v := range vecs {
		o := mayoOWFFor(t, v.Secpar)
		pk := mustHex(t, v.Pk)
		rAdd := mustHex(t, v.RAdditional)
		proof := mustHex(t, v.Proof)
		if !o.Verify(pk, rAdd, proof) {
			t.Errorf("%s: Verify rejected the reference proof", v.Name)
			continue
		}
		bad := append([]byte(nil), proof...)
		bad[len(bad)/2] ^= 0x01
		if o.Verify(pk, rAdd, bad) {
			t.Errorf("%s: Verify accepted a tampered proof", v.Name)
		}
	}
	t.Logf("verified %d One-More-MAYO proofs accepted (interop) + tamper-rejected", len(vecs))
}
