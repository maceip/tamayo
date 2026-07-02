package pomfrit

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

type voleCommitVec struct {
	Name          string `json:"name"`
	Secpar        int    `json:"secpar"`
	Tau           int    `json:"tau"`
	VoleColBlocks int    `json:"vole_col_blocks"`
	VoleRows      int    `json:"vole_rows"`
	VoleCommit    int    `json:"vole_commit_size"`
	WitnessBits   int    `json:"witness_bits"`
	MinK          int    `json:"min_k"`
	MaxK          int    `json:"max_k"`
	NumMaxK       int    `json:"num_max_k"`
	NumMinK       int    `json:"num_min_k"`
	Seed          string `json:"seed"`
	IV            string `json:"iv"`
	U             string `json:"u"`
	V             string `json:"v"`
	Commitment    string `json:"commitment"`
	Check         string `json:"check"`
	VCChalBytes   int    `json:"vole_check_challenge_bytes"`
	VCChallenge   string `json:"vole_check_challenge"`
	VCProof       string `json:"vole_check_proof"`
	VCHash        string `json:"vole_check_hash"`
	TransposeRows int    `json:"transpose_rows"`
	Macs          string `json:"macs"`
}

func loadVoleCommitVecs(t *testing.T) []voleCommitVec {
	t.Helper()
	raw, err := os.ReadFile("testdata/vole_commit.json")
	if err != nil {
		t.Fatalf("read vole_commit vectors: %v", err)
	}
	var vecs []voleCommitVec
	if err := json.Unmarshal(raw, &vecs); err != nil {
		t.Fatalf("parse vole_commit vectors: %v", err)
	}
	return vecs
}

func mayoForestFor(t *testing.T, secpar int) MayoForest {
	t.Helper()
	switch secpar {
	case 128:
		return MayoForestL1
	case 192:
		return MayoForestL3
	case 256:
		return MayoForestL5
	}
	t.Fatalf("unknown secpar %d", secpar)
	return MayoForest{}
}

// TestMayoForestCommitCheck verifies the ggm_forest BAVC leaf-hash chain
// (tree expansion + shake leaf hash + hash-of-hashes) against the reference
// vole_commit `check` output. A match certifies the AES-CTR tree PRG, the
// per-(level,tree) tweak schedule, the shake leaf hash, and the hash_hashed_leaves
// composition are all byte-exact.
func TestMayoForestCommitCheck(t *testing.T) {
	vecs := loadVoleCommitVecs(t)
	if len(vecs) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range vecs {
		m := mayoForestFor(t, v.Secpar)
		if m.Tau != v.Tau || m.minK != v.MinK || m.maxK != v.MaxK || m.numMaxK != v.NumMaxK || m.numMinK != v.NumMinK {
			t.Fatalf("%s: parameter mismatch: go{tau=%d,min=%d,max=%d,nmax=%d,nmin=%d} ref{tau=%d,min=%d,max=%d,nmax=%d,nmin=%d}",
				v.Name, m.Tau, m.minK, m.maxK, m.numMaxK, m.numMinK, v.Tau, v.MinK, v.MaxK, v.NumMaxK, v.NumMinK)
		}
		seed := mustHex(t, v.Seed)
		iv := mustHex(t, v.IV)
		_, _, check, _ := m.MayoForestCommit(seed, iv)
		if !bytes.Equal(check, mustHex(t, v.Check)) {
			t.Errorf("%s: BAVC check mismatch\n got %x\nwant %s", v.Name, check, v.Check)
		}
	}
	t.Logf("verified %d ggm_forest BAVC commit-check vectors byte-exact", len(vecs))
}

// TestMayoVoleCommitSender verifies the full sender VOLE commitment (ggm_forest
// BAVC + small_vole + Gray-code column mapping + corrections) against the
// reference vole_commit outputs u, v and the corrections commitment.
func TestMayoVoleCommitSender(t *testing.T) {
	vecs := loadVoleCommitVecs(t)
	for _, v := range vecs {
		m := mayoForestFor(t, v.Secpar)
		if m.colLen() != v.VoleColBlocks || m.voleRows() != v.VoleRows {
			t.Fatalf("%s: col/row mismatch go{col=%d,rows=%d} ref{col=%d,rows=%d}",
				v.Name, m.colLen(), m.voleRows(), v.VoleColBlocks, v.VoleRows)
		}
		u, vv, commitment, check := m.VoleCommitSender(mustHex(t, v.Seed), mustHex(t, v.IV))
		if !bytes.Equal(check, mustHex(t, v.Check)) {
			t.Errorf("%s: check mismatch", v.Name)
		}
		if !bytes.Equal(u, mustHex(t, v.U)) {
			t.Errorf("%s: u mismatch\n got %x\nwant %s", v.Name, u, v.U)
		}
		if !bytes.Equal(vv, mustHex(t, v.V)) {
			t.Errorf("%s: v mismatch (len go=%d ref=%d)", v.Name, len(vv), len(v.V)/2)
		}
		if !bytes.Equal(commitment, mustHex(t, v.Commitment)) {
			t.Errorf("%s: commitment mismatch (len go=%d ref=%d)", v.Name, len(commitment), len(v.Commitment)/2)
		}
	}
	t.Logf("verified %d sender vole_commit (u,v,corrections) vectors byte-exact", len(vecs))
}

// TestMayoVoleCheckSender verifies the sender vole_check (gfsecpar + gf64
// universal hash, 2x2 map, column masking) against the reference: the u_tilde
// proof bytes and the transcript hash absorbing u_tilde ++ the lambda v-column
// hashes must both match. Also checks transpose_secpar (v -> row-major macs).
func TestMayoVoleCheckSender(t *testing.T) {
	vecs := loadVoleCommitVecs(t)
	for _, v := range vecs {
		if v.VCChallenge == "" {
			t.Skip("vectors predate vole_check fields; regenerate testdata")
		}
		m := mayoForestFor(t, v.Secpar)
		u, vv, _, _ := m.VoleCommitSender(mustHex(t, v.Seed), mustHex(t, v.IV))
		proof, transcript := m.VoleCheckSender(u, vv, mustHex(t, v.VCChallenge))
		if !bytes.Equal(proof, mustHex(t, v.VCProof)) {
			t.Errorf("%s: vole_check proof mismatch\n got %x\nwant %s", v.Name, proof, v.VCProof)
		}
		if !bytes.Equal(transcript, mustHex(t, v.VCHash)) {
			t.Errorf("%s: vole_check transcript hash mismatch\n got %x\nwant %s", v.Name, transcript, v.VCHash)
		}
		macs := m.TransposeToMacs(vv, v.TransposeRows)
		var flat []byte
		for _, e := range macs {
			flat = append(flat, e...)
		}
		if !bytes.Equal(flat, mustHex(t, v.Macs)) {
			t.Errorf("%s: transpose macs mismatch", v.Name)
		}
	}
	t.Logf("verified %d vole_check + transpose vectors byte-exact", len(vecs))
}
