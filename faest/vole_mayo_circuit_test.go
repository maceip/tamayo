package faest

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

type mayoCircuitVec struct {
	Name          string `json:"name"`
	Secpar        int    `json:"secpar"`
	WitnessBits   int    `json:"witness_bits"`
	NumConstr     int    `json:"num_constraints"`
	N             int    `json:"n"`
	M             int    `json:"m"`
	O             int    `json:"o"`
	K             int    `json:"k"`
	Witness       string `json:"witness"`
	Tags          string `json:"tags"`
	Keys          string `json:"keys"`
	Delta         string `json:"delta"`
	Chal2         string `json:"chal2"`
	Pk            string `json:"pk"`
	H             string `json:"h"`
	Proof         string `json:"proof"`
	CheckProver   string `json:"check_prover"`
	CheckVerifier string `json:"check_verifier"`
}

func mayoParamsFor(t *testing.T, secpar int) MayoParams {
	t.Helper()
	switch secpar {
	case 128:
		return VoleMayoL1
	case 192:
		return VoleMayoL3
	case 256:
		return VoleMayoL5
	}
	t.Fatalf("unknown secpar %d", secpar)
	return MayoParams{}
}

// TestMayoCircuitKAT verifies the MAYO-eval OWF circuit (owf_proof.inc
// enc_constraints) on the degree-2 QuickSilver against reference vectors: the
// Go prover must reproduce the reference qs proof and check bytes, and the Go
// verifier, given the reference proof, must reproduce the reference check
// (interop direction). Vectors come from tools/mayo_circuit_dump.cpp.
func TestMayoCircuitKAT(t *testing.T) {
	raw, err := os.ReadFile("testdata/mayo_circuit.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vecs []mayoCircuitVec
	if err := json.Unmarshal(raw, &vecs); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(vecs) == 0 {
		t.Fatal("no vectors")
	}

	for _, v := range vecs {
		f := qs2Field(t, v.Secpar)
		mp := mayoParamsFor(t, v.Secpar)
		witness := mustHex(t, v.Witness)
		tags := splitElems(f, mustHex(t, v.Tags))
		keys := splitElems(f, mustHex(t, v.Keys))
		delta := f.FromBytes(mustHex(t, v.Delta))
		chal2 := mustHex(t, v.Chal2)
		pk := mustHex(t, v.Pk)
		h := mustHex(t, v.H)
		refProof := mustHex(t, v.Proof)
		refCheckP := mustHex(t, v.CheckProver)
		refCheckV := mustHex(t, v.CheckVerifier)

		prover := NewQS2Prover(f, witness, tags, chal2)
		verifier := NewQS2Verifier(f, keys, delta, chal2)
		mp.MayoConstraintProve(prover, pk, h, chal2)
		mp.MayoConstraintVerify(verifier, pk, h, chal2)

		proof, checkP := prover.Prove(v.WitnessBits)
		if !bytes.Equal(proof, refProof) {
			t.Errorf("%s: prover proof(a1) mismatch\n got %x\nwant %s", v.Name, proof, v.Proof)
		}
		if !bytes.Equal(checkP, refCheckP) {
			t.Errorf("%s: prover check(a0) mismatch\n got %x\nwant %s", v.Name, checkP, v.CheckProver)
		}
		if !bytes.Equal(proof, refProof) || !bytes.Equal(checkP, refCheckP) {
			continue
		}
		checkV := verifier.Verify(v.WitnessBits, refProof)
		if !bytes.Equal(checkV, refCheckV) {
			t.Errorf("%s: verifier check mismatch\n got %x\nwant %s", v.Name, checkV, v.CheckVerifier)
		}
	}
	t.Logf("verified %d MAYO-circuit reference vectors byte-exact", len(vecs))
}
