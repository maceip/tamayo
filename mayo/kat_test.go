package mayo

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// katDir points at the vendored MAYO-C round 2 known-answer tests.
const katDir = "testdata/"

// katCases maps our parameter sets to their KAT response files.
var katCases = []struct {
	p    Params
	file string
}{
	{Mayo1, "PQCsignKAT_24_MAYO_1.rsp"},
	{Mayo2, "PQCsignKAT_24_MAYO_2.rsp"},
	{Mayo3, "PQCsignKAT_32_MAYO_3.rsp"},
	{Mayo5, "PQCsignKAT_40_MAYO_5.rsp"},
}

type katEntry struct{ seed, pk, sk, msg, sm []byte }

func parseKAT(t *testing.T, path string) []katEntry {
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("KAT file not available: %v", err)
	}
	defer f.Close()

	var entries []katEntry
	var cur katEntry
	have := false
	flush := func() {
		if have {
			entries = append(entries, cur)
			cur = katEntry{}
			have = false
		}
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "count = "):
			flush()
			have = true
		case strings.HasPrefix(line, "seed = "):
			cur.seed = mustHex(t, line[len("seed = "):])
		case strings.HasPrefix(line, "msg = "):
			cur.msg = mustHex(t, line[len("msg = "):])
		case strings.HasPrefix(line, "pk = "):
			cur.pk = mustHex(t, line[len("pk = "):])
		case strings.HasPrefix(line, "sk = "):
			cur.sk = mustHex(t, line[len("sk = "):])
		case strings.HasPrefix(line, "sm = "):
			cur.sm = mustHex(t, line[len("sm = "):])
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return entries
}

func mustHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// variantMatches reports whether the KAT file describes the same parameter
// variant as our params (MAYO_2 in the vendored round 2 KAT is the original,
// pre-wedge-attack variant and is skipped; PoMFRIT uses MAYO 1/3/5).
func variantMatches(t *testing.T, p Params, entries []katEntry) bool {
	if len(entries) == 0 {
		t.Errorf("%s: no KAT entries parsed", p.Name)
		return false
	}
	if len(entries[0].pk) != p.CPKBytes {
		t.Logf("%s: KAT is a different variant (pk=%d vs our %d) — skipped (not used by PoMFRIT)",
			p.Name, len(entries[0].pk), p.CPKBytes)
		return false
	}
	return true
}

// TestKeygenKAT validates keygen: keypair(sk) must reproduce the published pk.
func TestKeygenKAT(t *testing.T) {
	for _, c := range katCases {
		entries := parseKAT(t, katDir+c.file)
		if !variantMatches(t, c.p, entries) {
			continue
		}
		n := len(entries)
		if testing.Short() {
			n = min(n, 5)
		}
		for i := 0; i < n; i++ {
			e := entries[i]
			cpk := make([]byte, c.p.CPKBytes)
			csk := make([]byte, c.p.CSKBytes)
			keypairCompact(&c.p, e.sk, cpk, csk)
			if !bytes.Equal(cpk, e.pk) {
				t.Fatalf("%s count %d: cpk mismatch\n got  %x...\n want %x...", c.p.Name, i, cpk[:24], e.pk[:24])
			}
			if !bytes.Equal(csk, e.sk) {
				t.Fatalf("%s count %d: csk mismatch", c.p.Name, i)
			}
		}
		t.Logf("%s: verified %d/%d KAT keygen vectors", c.p.Name, n, len(entries))
	}
}

// TestVerifyKAT validates verification against the published signatures: the
// KAT sm is sig‖msg, and verify(msg, sig, pk) must accept; a one-bit tamper of
// the signature must be rejected.
func TestVerifyKAT(t *testing.T) {
	for _, c := range katCases {
		entries := parseKAT(t, katDir+c.file)
		if !variantMatches(t, c.p, entries) {
			continue
		}
		n := len(entries)
		if testing.Short() {
			n = min(n, 5)
		}
		for i := 0; i < n; i++ {
			e := entries[i]
			if len(e.sm) < c.p.SigBytes {
				t.Fatalf("%s count %d: sm shorter than signature", c.p.Name, i)
			}
			sig := e.sm[:c.p.SigBytes]
			msg := e.sm[c.p.SigBytes:]
			if !bytes.Equal(msg, e.msg) {
				t.Fatalf("%s count %d: sm message != msg field", c.p.Name, i)
			}
			if !mayoVerify(&c.p, msg, sig, e.pk) {
				t.Fatalf("%s count %d: valid signature rejected", c.p.Name, i)
			}
			bad := append([]byte(nil), sig...)
			bad[0] ^= 1
			if mayoVerify(&c.p, msg, bad, e.pk) {
				t.Fatalf("%s count %d: tampered signature accepted", c.p.Name, i)
			}
		}
		t.Logf("%s: verified %d/%d KAT signatures", c.p.Name, n, len(entries))
	}
}

// TestSignKAT reproduces the published signed messages byte-for-byte: reseeding
// the NIST DRBG with each vector's seed yields the sk seed (== sk) and then the
// salt randomizer; signing must reproduce sm = sig‖msg.
func TestSignKAT(t *testing.T) {
	for _, c := range katCases {
		entries := parseKAT(t, katDir+c.file)
		if !variantMatches(t, c.p, entries) {
			continue
		}
		n := len(entries)
		if testing.Short() {
			n = min(n, 3) // signing is heavier
		}
		for i := 0; i < n; i++ {
			e := entries[i]
			d := newDRBG(e.seed)
			skSeed := make([]byte, c.p.SKSeedBytes)
			d.randombytes(skSeed) // keygen draws the sk seed first
			if !bytes.Equal(skSeed, e.sk) {
				t.Fatalf("%s count %d: DRBG sk seed != KAT sk", c.p.Name, i)
			}
			randomizer := make([]byte, c.p.SaltBytes)
			d.randombytes(randomizer) // sign draws the salt randomizer next

			msg := e.sm[c.p.SigBytes:]
			sig := make([]byte, c.p.SigBytes)
			if err := signSignature(&c.p, sig, msg, e.sk, randomizer); err != nil {
				t.Fatalf("%s count %d: sign: %v", c.p.Name, i, err)
			}
			gotSM := append(append([]byte(nil), sig...), msg...)
			if !bytes.Equal(gotSM, e.sm) {
				t.Fatalf("%s count %d: sm mismatch\n got  %x...\n want %x...", c.p.Name, i, gotSM[:24], e.sm[:24])
			}
		}
		t.Logf("%s: reproduced %d/%d KAT signatures", c.p.Name, n, len(entries))
	}
}
