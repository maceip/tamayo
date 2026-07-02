package field

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type largeMulSet struct {
	Lambda   int         `json:"lambda"`
	Database [][3]string `json:"database"`
}

// TestLargeFieldMulKAT validates GF(2^128/192/256) multiplication against the
// de-facto faest-rs vectors (tests/data/LargeFieldMul.json): each case is a
// [lhs, rhs, product] triple of little-endian hex. Big.Mul shares its core with
// the concrete GF128/192/256.Mul, so this gates both.
func TestLargeFieldMulKAT(t *testing.T) {
	raw, err := os.ReadFile("testdata/LargeFieldMul.json")
	if err != nil {
		t.Fatalf("read LargeFieldMul.json: %v", err)
	}
	var sets []largeMulSet
	if err := json.Unmarshal(raw, &sets); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(sets) == 0 {
		t.Fatal("no vectors")
	}

	fieldFor := func(l int) Big {
		switch l {
		case 128:
			return Big128
		case 192:
			return Big192
		default:
			return Big256
		}
	}

	total := 0
	for _, set := range sets {
		f := fieldFor(set.Lambda)
		for i, tc := range set.Database {
			lhsB, _ := hex.DecodeString(tc[0])
			rhsB, _ := hex.DecodeString(tc[1])
			wantB, _ := hex.DecodeString(tc[2])
			if len(lhsB) != f.Bytes || len(rhsB) != f.Bytes || len(wantB) != f.Bytes {
				t.Fatalf("l=%d case %d: bad hex length", set.Lambda, i)
			}
			lhs := f.FromBytes(lhsB)
			rhs := f.FromBytes(rhsB)
			want := f.FromBytes(wantB)

			got := f.Mul(lhs, rhs)
			if !bytes.Equal(f.ToBytes(got), f.ToBytes(want)) {
				t.Fatalf("l=%d case %d: %s * %s = %s, want %s",
					set.Lambda, i, tc[0], tc[1], hex.EncodeToString(f.ToBytes(got)), tc[2])
			}
			// Multiplication is commutative.
			if !bytes.Equal(f.ToBytes(f.Mul(rhs, lhs)), f.ToBytes(want)) {
				t.Fatalf("l=%d case %d: not commutative", set.Lambda, i)
			}
			total++
		}
	}
	t.Logf("verified %d large-field multiplications", total)
}
