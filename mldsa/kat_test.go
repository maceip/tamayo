package mldsa

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// The vendored vectors are the NIST ACVP ML-DSA-FIPS204 internal projections
// (see testdata provenance field and SOURCES.md): every non-pre-hash group
// for all three parameter sets.
type acvpFile struct {
	KeyGen []struct {
		ParameterSet string `json:"parameterSet"`
		Tests        []struct {
			TcID int    `json:"tcId"`
			Seed string `json:"seed"`
			PK   string `json:"pk"`
			SK   string `json:"sk"`
		} `json:"tests"`
	} `json:"keyGen"`
	SigGen []struct {
		ParameterSet  string `json:"parameterSet"`
		Deterministic bool   `json:"deterministic"`
		Interface     string `json:"signatureInterface"`
		ExternalMu    bool   `json:"externalMu"`
		PreHash       string `json:"preHash"`
		Tests         []struct {
			TcID      int    `json:"tcId"`
			SK        string `json:"sk"`
			Message   string `json:"message"`
			Mu        string `json:"mu"`
			Context   string `json:"context"`
			Rnd       string `json:"rnd"`
			HashAlg   string `json:"hashAlg"`
			Signature string `json:"signature"`
		} `json:"tests"`
	} `json:"sigGen"`
	SigVer []struct {
		ParameterSet string `json:"parameterSet"`
		Interface    string `json:"signatureInterface"`
		ExternalMu   bool   `json:"externalMu"`
		PreHash      string `json:"preHash"`
		Tests        []struct {
			TcID       int    `json:"tcId"`
			PK         string `json:"pk"`
			Message    string `json:"message"`
			Mu         string `json:"mu"`
			Context    string `json:"context"`
			HashAlg    string `json:"hashAlg"`
			Signature  string `json:"signature"`
			TestPassed bool   `json:"testPassed"`
			Reason     string `json:"reason"`
		} `json:"tests"`
	} `json:"sigVer"`
}

func preHashByName(t *testing.T, name string) PreHash {
	m := map[string]PreHash{
		"SHA2-224": PreHashSHA224, "SHA2-256": PreHashSHA256, "SHA2-384": PreHashSHA384,
		"SHA2-512": PreHashSHA512, "SHA2-512/224": PreHashSHA512_224, "SHA2-512/256": PreHashSHA512_256,
		"SHA3-224": PreHashSHA3_224, "SHA3-256": PreHashSHA3_256, "SHA3-384": PreHashSHA3_384,
		"SHA3-512": PreHashSHA3_512, "SHAKE-128": PreHashSHAKE128, "SHAKE-256": PreHashSHAKE256,
	}
	ph, ok := m[name]
	if !ok {
		t.Fatalf("unknown pre-hash %q", name)
	}
	return ph
}

func paramsByName(t *testing.T, name string) *Params {
	switch name {
	case "ML-DSA-44":
		return MLDSA44
	case "ML-DSA-65":
		return MLDSA65
	case "ML-DSA-87":
		return MLDSA87
	}
	t.Fatalf("unknown parameter set %q", name)
	return nil
}

func loadACVP(t *testing.T) *acvpFile {
	f, err := os.Open("testdata/acvp_mldsa.json.gz")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gunzip vectors: %v", err)
	}
	var out acvpFile
	if err := json.NewDecoder(zr).Decode(&out); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return &out
}

func unhex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// trim returns at most lim tests under -short, mirroring the KAT trimming
// convention of the mayo and faest packages.
func trim[T any](tests []T, short bool) []T {
	const lim = 3
	if short && len(tests) > lim {
		return tests[:lim]
	}
	return tests
}

func TestKeyGenACVP(t *testing.T) {
	vecs := loadACVP(t)
	total := 0
	for _, g := range vecs.KeyGen {
		p := paramsByName(t, g.ParameterSet)
		for _, tc := range trim(g.Tests, testing.Short()) {
			pk, sk, err := p.KeyGen(unhex(t, tc.Seed))
			if err != nil {
				t.Fatalf("%s tc%d: %v", p.Name, tc.TcID, err)
			}
			if !bytes.Equal(pk, unhex(t, tc.PK)) {
				t.Errorf("%s tc%d: pk mismatch", p.Name, tc.TcID)
			}
			if !bytes.Equal(sk, unhex(t, tc.SK)) {
				t.Errorf("%s tc%d: sk mismatch", p.Name, tc.TcID)
			}
			total++
		}
	}
	t.Logf("verified %d keyGen vectors byte-exact", total)
}

func TestSigGenACVP(t *testing.T) {
	vecs := loadACVP(t)
	zero := make([]byte, 32)
	total := 0
	for _, g := range vecs.SigGen {
		p := paramsByName(t, g.ParameterSet)
		for _, tc := range trim(g.Tests, testing.Short()) {
			rnd := zero
			if !g.Deterministic {
				rnd = unhex(t, tc.Rnd)
			}
			var sig []byte
			var err error
			switch {
			case g.PreHash == "preHash":
				sig, err = p.SignPreHash(unhex(t, tc.SK), unhex(t, tc.Message), unhex(t, tc.Context), preHashByName(t, tc.HashAlg), rnd)
			case g.ExternalMu:
				sig, err = p.SignMu(unhex(t, tc.SK), unhex(t, tc.Mu), rnd)
			case g.Interface == "internal":
				sig, err = p.SignInternal(unhex(t, tc.SK), unhex(t, tc.Message), rnd)
			default: // external, pure
				sig, err = p.Sign(unhex(t, tc.SK), unhex(t, tc.Message), unhex(t, tc.Context), rnd)
			}
			if err != nil {
				t.Fatalf("%s tc%d: %v", p.Name, tc.TcID, err)
			}
			if !bytes.Equal(sig, unhex(t, tc.Signature)) {
				t.Errorf("%s tc%d (%s externalMu=%v det=%v): signature mismatch",
					p.Name, tc.TcID, g.Interface, g.ExternalMu, g.Deterministic)
			}
			total++
		}
	}
	t.Logf("verified %d sigGen vectors byte-exact", total)
}

func TestSigVerACVP(t *testing.T) {
	vecs := loadACVP(t)
	total := 0
	for _, g := range vecs.SigVer {
		p := paramsByName(t, g.ParameterSet)
		for _, tc := range trim(g.Tests, testing.Short()) {
			var ok bool
			switch {
			case g.PreHash == "preHash":
				ok = p.VerifyPreHash(unhex(t, tc.PK), unhex(t, tc.Message), unhex(t, tc.Signature), unhex(t, tc.Context), preHashByName(t, tc.HashAlg))
			case g.ExternalMu:
				ok = p.VerifyMu(unhex(t, tc.PK), unhex(t, tc.Mu), unhex(t, tc.Signature))
			case g.Interface == "internal":
				ok = p.VerifyInternal(unhex(t, tc.PK), unhex(t, tc.Message), unhex(t, tc.Signature))
			default:
				ok = p.Verify(unhex(t, tc.PK), unhex(t, tc.Message), unhex(t, tc.Signature), unhex(t, tc.Context))
			}
			if ok != tc.TestPassed {
				t.Errorf("%s tc%d: verify=%v want %v (%s)", p.Name, tc.TcID, ok, tc.TestPassed, tc.Reason)
			}
			total++
		}
	}
	t.Logf("verified %d sigVer vectors", total)
}

// TestVerifyRejectsMalformedInputs mirrors the malformed-input probes of the
// other signature packages: truncated, empty and oversized inputs must be
// rejected without panicking.
func TestVerifyRejectsMalformedInputs(t *testing.T) {
	p := MLDSA44
	seed := make([]byte, 32)
	pk, sk, err := p.KeyGen(seed)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("m")
	sig, err := p.Sign(sk, msg, nil, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if !p.Verify(pk, msg, sig, nil) {
		t.Fatal("valid signature rejected")
	}
	for _, tc := range [][2][]byte{
		{nil, sig}, {pk[:31], sig}, {pk, nil}, {pk, sig[:len(sig)-1]},
		{append(append([]byte{}, pk...), 0), sig}, {pk, append(append([]byte{}, sig...), 0)},
	} {
		if p.Verify(tc[0], msg, tc[1], nil) {
			t.Error("malformed input accepted")
		}
	}
	// Corrupt hint padding (non-malleability of the hint encoding).
	bad := append([]byte{}, sig...)
	bad[len(bad)-p.K-1] ^= 1
	if p.Verify(pk, msg, bad, nil) {
		t.Error("corrupted hint padding accepted")
	}
	if _, _, err := p.KeyGen(seed[:16]); err == nil {
		t.Error("short seed accepted")
	}
	if _, err := p.Sign(sk[:100], msg, nil, make([]byte, 32)); err == nil {
		t.Error("short sk accepted")
	}
	if _, err := p.Sign(sk, msg, make([]byte, 256), make([]byte, 32)); err == nil {
		t.Error("oversized context accepted")
	}
}
