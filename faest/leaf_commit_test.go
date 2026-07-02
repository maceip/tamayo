package faest

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/maceip/tamayo/field"
)

type leafCommitVec struct {
	Lambda      int    `json:"lambda"`
	Key         []int  `json:"key"`
	IV          []int  `json:"iv"`
	Tweak       uint32 `json:"tweak"`
	UHash       []int  `json:"uhash"`
	ExpectedCom []int  `json:"expectedCom"`
	ExpectedSd  []int  `json:"expectedSd"`
}

func extForLambda(l int) field.Big {
	switch l {
	case 128:
		return field.Big384
	case 192:
		return field.Big576
	default:
		return field.Big768
	}
}

// TestLeafCommitKAT validates the BAVC leaf commitment against faest-rs vectors
// (tests/data/leaf_com.json).
func TestLeafCommitKAT(t *testing.T) {
	raw, err := os.ReadFile("testdata/leaf_com.json")
	if err != nil {
		t.Fatalf("read leaf_com.json: %v", err)
	}
	var vecs []leafCommitVec
	if err := json.Unmarshal(raw, &vecs); err != nil {
		t.Fatalf("parse leaf_com.json: %v", err)
	}
	if len(vecs) == 0 {
		t.Fatal("no vectors")
	}
	for i, v := range vecs {
		ext := extForLambda(v.Lambda)
		sd, com := LeafCommit(ext, ints2bytes(v.Key), ints2bytes(v.IV), v.Tweak, ints2bytes(v.UHash))
		if !bytes.Equal(sd, ints2bytes(v.ExpectedSd)) {
			t.Fatalf("case %d (lambda=%d): sd mismatch", i, v.Lambda)
		}
		if !bytes.Equal(com, ints2bytes(v.ExpectedCom)) {
			t.Fatalf("case %d (lambda=%d): com mismatch", i, v.Lambda)
		}
	}
	t.Logf("verified %d leaf-commit vectors", len(vecs))
}
