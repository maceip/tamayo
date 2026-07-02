package pomfrit

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/maceip/tamayo/mayo"
)

type blindLoopVec struct {
	Name        string `json:"name"`
	Secpar      int    `json:"secpar"`
	ProofBytes  int    `json:"proof_bytes"`
	Proof1Size  int    `json:"proof1_size"`
	HSize       int    `json:"h_size"`
	MBytes      int    `json:"m_bytes"`
	CPK         string `json:"cpk"`
	CSK         string `json:"csk"`
	EPK         string `json:"epk"`
	M           string `json:"m"`
	RAdditional string `json:"r_additional"`
	R           string `json:"r"`
	H           string `json:"h"`
	T           string `json:"t"`
	BSig        string `json:"bsig"`
	Proof       string `json:"proof"`
}

func mayoParamsForSecpar(secpar int) *mayo.Params {
	switch secpar {
	case 128:
		return &mayo.Mayo1
	case 192:
		return &mayo.Mayo3
	case 256:
		return &mayo.Mayo5
	}
	return nil
}

// TestBlindLoopKAT verifies the full One-More-MAYO blind signature loop
// (sign_1 -> sign_2 -> sign_3 -> verify) byte-exact against the authoritative
// reference (tools/blind_loop_dump.cpp, which runs blind_sig_optimized end to
// end). Using the reference keypair, message and r_additional, the Go path must
// reproduce the blinded message t, the MAYO preimage bsig, and the entire proof
// byte-for-byte, and BlindVerify must accept both the Go and reference proofs.
func TestBlindLoopKAT(t *testing.T) {
	raw, err := os.ReadFile("testdata/blind_loop.json")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var vecs []blindLoopVec
	if err := json.Unmarshal(raw, &vecs); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(vecs) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range vecs {
		o := mayoOWFFor(t, v.Secpar)
		mp := mayoParamsForSecpar(v.Secpar)
		csk := mustHex(t, v.CSK)
		epk := mustHex(t, v.EPK)
		m := mustHex(t, v.M)
		rAdd := mustHex(t, v.RAdditional)

		// sign_1: blinded message t and carried state.
		gotT, st, h := o.Sign1(m, rAdd)
		if !bytes.Equal(gotT, mustHex(t, v.T)) {
			t.Errorf("%s: blinded message t mismatch", v.Name)
			continue
		}
		if !bytes.Equal(h, mustHex(t, v.H)) {
			t.Errorf("%s: h mismatch", v.Name)
		}
		if !bytes.Equal(st.R, mustHex(t, v.R)) {
			t.Errorf("%s: r mismatch", v.Name)
		}

		// sign_2: MAYO preimage of t.
		bsig := mp.SignWithoutHashing(gotT, csk)
		if !bytes.Equal(bsig, mustHex(t, v.BSig)) {
			t.Errorf("%s: bsig (preimage) mismatch", v.Name)
			continue
		}

		// sign_3: full proof.
		sig := o.Sign3(epk, h, bsig, st, rAdd)
		if !bytes.Equal(sig.Bytes, mustHex(t, v.Proof)) {
			t.Errorf("%s: blind proof mismatch (len go=%d ref=%d)", v.Name, len(sig.Bytes), v.ProofBytes)
			continue
		}

		// verify: Go verifier accepts the Go proof and the reference proof.
		if !o.BlindVerify(epk, m, sig.Bytes, rAdd) {
			t.Errorf("%s: BlindVerify rejected the Go proof", v.Name)
		}
		if !o.BlindVerify(epk, m, mustHex(t, v.Proof), rAdd) {
			t.Errorf("%s: BlindVerify rejected the reference proof", v.Name)
		}
		bad := append([]byte(nil), sig.Bytes...)
		bad[0] ^= 1
		if o.BlindVerify(epk, m, bad, rAdd) {
			t.Errorf("%s: BlindVerify accepted a tampered proof", v.Name)
		}
	}
	t.Logf("verified %d full blind-signature loops byte-exact (t, bsig, proof) + accepting", len(vecs))
}
