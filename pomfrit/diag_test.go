package pomfrit

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

type mayoDiagVec struct {
	Name      string `json:"name"`
	Secpar    int    `json:"secpar"`
	Chal2     string `json:"chal2"`
	Pk        string `json:"pk"`
	H         string `json:"h"`
	EmbRand   string `json:"emb_randomness"`
	HEmbedded string `json:"h_embedded"`
	TableRow0 string `json:"table_row0"`
}

// TestMayoEmbeddingDiag localizes any circuit divergence to the embedding
// layer: it checks the SHAKE randomness that seeds the embedding table and the
// public embedding of h against the reference.
func TestMayoEmbeddingDiag(t *testing.T) {
	raw, err := os.ReadFile("testdata/mayo_circuit.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vecs []mayoDiagVec
	if err := json.Unmarshal(raw, &vecs); err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, v := range vecs {
		if v.EmbRand == "" {
			t.Skip("no diag fields")
		}
		f := qs2Field(t, v.Secpar)
		mp := mayoParamsFor(t, v.Secpar)
		chal2 := mustHex(t, v.Chal2)

		// Reproduce sample_random_embedding's raw SHAKE.
		x := f.Bytes
		var xof = mp.newSHAKEForDiag(f.Bytes)
		xof.Write(chal2[:2*x])
		rnd := make([]byte, mp.M*x)
		xof.Read(rnd)
		if !bytes.Equal(rnd, mustHex(t, v.EmbRand)) {
			t.Errorf("%s: emb randomness mismatch", v.Name)
		}

		table := mp.sampleRandomEmbedding(f, chal2)
		if v.TableRow0 != "" {
			var got []byte
			for n := 0; n < 16; n++ {
				got = append(got, f.ToBytes(table[n])...)
			}
			want := mustHex(t, v.TableRow0)
			if !bytes.Equal(got, want) {
				for n := 0; n < 16; n++ {
					g := f.ToBytes(table[n])
					w := want[n*f.Bytes : (n+1)*f.Bytes]
					if !bytes.Equal(g, w) {
						t.Errorf("%s: table[%d] mismatch\n got %x\nwant %x", v.Name, n, g, w)
					}
				}
			}
		}
		hEmb := mp.embedGF16Vec(f, table, mustHex(t, v.H))
		if !bytes.Equal(f.ToBytes(hEmb), mustHex(t, v.HEmbedded)) {
			t.Errorf("%s: h_embedded mismatch\n got %x\nwant %s", v.Name, f.ToBytes(hEmb), v.HEmbedded)
		}
	}
	t.Logf("embedding diagnostics checked for %d vectors", len(vecs))
}
