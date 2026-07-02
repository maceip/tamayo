package mayo

import (
	"bytes"
	"testing"
)

// TestKeygenRunsDeterministic exercises the full keygen path (SHAKE256 seed
// expansion, AES-CTR P1/P2 expansion, compute_p3, m_upper, packing) for every
// parameter set, and checks determinism, csk == seed, and non-trivial output.
// KAT (correctness) validation is wired separately once the NIST DRBG is added.
func TestKeygenRunsDeterministic(t *testing.T) {
	for _, p := range []Params{Mayo1, Mayo2, Mayo3, Mayo5} {
		seed := make([]byte, p.SKSeedBytes)
		for i := range seed {
			seed[i] = byte(i*7 + 1)
		}
		cpk1 := make([]byte, p.CPKBytes)
		csk1 := make([]byte, p.CSKBytes)
		cpk2 := make([]byte, p.CPKBytes)
		csk2 := make([]byte, p.CSKBytes)

		keypairCompact(&p, seed, cpk1, csk1)
		keypairCompact(&p, seed, cpk2, csk2)

		if !bytes.Equal(cpk1, cpk2) || !bytes.Equal(csk1, csk2) {
			t.Fatalf("%s: keygen not deterministic", p.Name)
		}
		if !bytes.Equal(csk1, seed) {
			t.Fatalf("%s: csk != seed_sk", p.Name)
		}
		if bytes.Equal(cpk1, make([]byte, p.CPKBytes)) {
			t.Fatalf("%s: cpk is all zero", p.Name)
		}
	}
}
