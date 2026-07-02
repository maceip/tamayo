package faest

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"testing"
)

// External-oracle test: replay the FAEST NIST known-answer tests and
// byte-compare keygen, signature, and verification. Each .rsp holds the full
// 100 deterministic vectors seeded by the NIST AES-256 CTR-DRBG (entropy
// input 00..2F), regenerated from the authoritative reference implementation
// (ait-crypto/faest-rs v0.3.0) by tools/faest_kat_gen; vector 0 of every set
// was diffed byte-identical against the reference-shipped
// tests/data/reduced_PQCsignKAT_faest_*.rsp before vendoring. This is a real
// external oracle, not self-consistency.

// katDRBG is the NIST AES-256 CTR-DRBG (no df) used by the PQC KAT harness.
type katDRBG struct {
	key [32]byte
	v   [16]byte
}

func (d *katDRBG) incV() {
	for j := 15; j >= 0; j-- {
		d.v[j]++
		if d.v[j] != 0 {
			break
		}
	}
}

func (d *katDRBG) update(provided []byte) {
	blk, _ := aes.NewCipher(d.key[:])
	var temp [48]byte
	for i := 0; i < 3; i++ {
		d.incV()
		blk.Encrypt(temp[i*16:(i+1)*16], d.v[:])
	}
	if provided != nil {
		for i := 0; i < 48; i++ {
			temp[i] ^= provided[i]
		}
	}
	copy(d.key[:], temp[:32])
	copy(d.v[:], temp[32:48])
}

func newKATDRBG(seed []byte) *katDRBG {
	d := &katDRBG{}
	var sm [48]byte
	copy(sm[:], seed)
	d.update(sm[:])
	return d
}

func (d *katDRBG) bytes(n int) []byte {
	x := make([]byte, n)
	blk, _ := aes.NewCipher(d.key[:])
	var block [16]byte
	i, xlen := 0, n
	for xlen > 0 {
		d.incV()
		blk.Encrypt(block[:], d.v[:])
		if xlen > 15 {
			copy(x[i:i+16], block[:])
			i += 16
			xlen -= 16
		} else {
			copy(x[i:i+xlen], block[:xlen])
			xlen = 0
		}
	}
	d.update(nil)
	return x
}

type faestKAT struct{ seed, msg, pk, sk, sm []byte }

func parseFaestKAT(t *testing.T, path string) []faestKAT {
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("KAT not available: %v", err)
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			t.Fatalf("gzip: %v", err)
		}
		defer gz.Close()
		r = gz
	}

	var out []faestKAT
	var cur faestKAT
	have := false
	hx := func(s string) []byte { b, _ := hex.DecodeString(strings.TrimSpace(s)); return b }

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "count = "):
			if have {
				out = append(out, cur)
			}
			cur = faestKAT{}
			have = true
		case strings.HasPrefix(line, "seed = "):
			cur.seed = hx(line[len("seed = "):])
		case strings.HasPrefix(line, "msg = "):
			cur.msg = hx(line[len("msg = "):])
		case strings.HasPrefix(line, "pk = "):
			cur.pk = hx(line[len("pk = "):])
		case strings.HasPrefix(line, "sk = "):
			cur.sk = hx(line[len("sk = "):])
		case strings.HasPrefix(line, "sm = "):
			cur.sm = hx(line[len("sm = "):])
		}
	}
	if have {
		out = append(out, cur)
	}
	return out
}

func TestFaestNISTKAT(t *testing.T) {
	cases := []struct {
		p    FaestParams
		file string
	}{
		{FAEST128s, "PQCsignKAT_faest_128s.rsp.gz"},
		{FAEST128f, "PQCsignKAT_faest_128f.rsp.gz"},
		{FAEST192s, "PQCsignKAT_faest_192s.rsp.gz"},
		{FAEST192f, "PQCsignKAT_faest_192f.rsp.gz"},
		{FAEST256s, "PQCsignKAT_faest_256s.rsp.gz"},
		{FAEST256f, "PQCsignKAT_faest_256f.rsp.gz"},
	}
	const dir = "testdata/"

	for _, c := range cases {
		c := c
		t.Run(c.p.Name, func(t *testing.T) {
			t.Parallel()
			o := c.p.OWF
			kats := parseFaestKAT(t, dir+c.file)
			if len(kats) != 100 {
				t.Fatalf("expected 100 vectors, got %d", len(kats))
			}
			if testing.Short() {
				kats = kats[:5]
			}
			skOK, pkOK, smOK, verOK := 0, 0, 0, 0
			for i, k := range kats {
				d := newKATDRBG(k.seed)
				// Reference keygen order: owf_key (lambda) with rejection when the
				// low two bits of byte 0 are both set, then owf_input (InputSize).
				var owfKey []byte
				for {
					owfKey = d.bytes(o.LambdaBytes)
					if owfKey[0]&0b11 != 0b11 {
						break
					}
				}
				owfInput := d.bytes(o.InputSize)
				sk := append(append([]byte(nil), owfInput...), owfKey...)
				if bytes.Equal(sk, k.sk) {
					skOK++
				} else {
					t.Errorf("vector %d: sk mismatch", i)
				}
				_, _, pk := c.p.PublicKeyFromSecret(sk)
				pkBytes := append(append([]byte(nil), pk.OwfInput...), pk.OwfOutput...)
				if bytes.Equal(pkBytes, k.pk) {
					pkOK++
				} else {
					t.Errorf("vector %d: pk mismatch", i)
				}
				rho := d.bytes(o.LambdaBytes)
				sig := c.p.Sign(k.msg, sk, rho)
				if bytes.Equal(append(append([]byte(nil), k.msg...), sig...), k.sm) {
					smOK++
				} else {
					t.Errorf("vector %d: sm not byte-exact", i)
				}
				if c.p.Verify(k.msg, pk, sig) {
					verOK++
				} else {
					t.Errorf("vector %d: verify failed", i)
				}
			}
			n := len(kats)
			t.Logf("%-6s n=%d  sk=%d/%d  pk=%d/%d  sm(byte-exact)=%d/%d  verify=%d/%d",
				c.p.Name, n, skOK, n, pkOK, n, smOK, n, verOK, n)
		})
	}
}
