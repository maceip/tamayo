package faest

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"testing"
)

type rijndaelVec struct {
	KC     int   `json:"kc"`
	BC     int   `json:"bc"`
	Key    []int `json:"key"`
	Text   []int `json:"text"`
	Output []int `json:"output"`
}

// TestRijndaelKAT validates the bitsliced Rijndael against faest-rs vectors
// (tests/data/rijndael_data.json): all nine key/block-column combinations.
func TestRijndaelKAT(t *testing.T) {
	raw, err := os.ReadFile("testdata/rijndael_data.json")
	if err != nil {
		t.Fatalf("read rijndael_data.json: %v", err)
	}
	var vecs []rijndaelVec
	if err := json.Unmarshal(raw, &vecs); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(vecs) == 0 {
		t.Fatal("no vectors")
	}

	max := func(a, b int) int {
		if a > b {
			return a
		}
		return b
	}

	for _, v := range vecs {
		key := ints2bytes(v.Key)
		text := ints2bytes(v.Text)
		want := ints2bytes(v.Output)

		input := make([]byte, 32)
		copy(input, text)

		r := max(v.BC, v.KC) + 6
		ske := 4 * (((r + 1) * v.BC) / v.KC)

		rkeys := rijndaelKeySchedule(key, v.BC, v.KC, r, ske)
		res := rijndaelEncrypt(rkeys, input, v.BC, r)

		for i := 0; i < v.BC; i++ {
			got := binary.LittleEndian.Uint32(res[i/4][(i%4)*4 : (i%4)*4+4])
			exp := binary.LittleEndian.Uint32(want[i*4 : (i+1)*4])
			if got != exp {
				t.Fatalf("kc=%d bc=%d: word %d mismatch: got %08x want %08x", v.KC, v.BC, i, got, exp)
			}
		}
	}
	t.Logf("verified %d Rijndael vectors", len(vecs))
}
