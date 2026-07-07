package transparency

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// TestEatPassInterop verifies a log generated and FAEST-128f-signed by the
// verbatim eat-pass reference (tools/kt_dump, every prefix head certified by
// the reference's own verify_log at dump time): the Go verifier must accept
// the Rust chain and signatures byte-exact.
func TestEatPassInterop(t *testing.T) {
	raw, err := os.ReadFile("testdata/eatpass_kt.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var vec struct {
		LogPublicKeyHex   string       `json:"log_public_key_hex"`
		Records           []KeyRecord  `json:"records"`
		ChainHeadsHex     []string     `json:"chain_heads_hex"`
		PrefixSignedHeads []SignedHead `json:"prefix_signed_heads"`
	}
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	pubBytes, err := hex.DecodeString(vec.LogPublicKeyHex)
	if err != nil || len(pubBytes) != 32 {
		t.Fatalf("log public key: %v (%d bytes)", err, len(pubBytes))
	}
	var logPub [32]byte
	copy(logPub[:], pubBytes)

	for i := range vec.Records {
		prefix := vec.Records[:i+1]
		// The Go chain reproduces the reference intermediate heads.
		head, err := HeadOf(prefix)
		if err != nil {
			t.Fatalf("HeadOf prefix %d: %v", i, err)
		}
		if hex.EncodeToString(head[:]) != vec.ChainHeadsHex[i] {
			t.Fatalf("prefix %d: chain head mismatch\n got %x\nwant %s", i, head, vec.ChainHeadsHex[i])
		}
		// The Go verifier accepts the reference-signed head (FAEST interop).
		if err := VerifyLog(logPub, prefix, vec.PrefixSignedHeads[i]); err != nil {
			t.Fatalf("VerifyLog prefix %d: %v", i, err)
		}
	}

	// Inclusion of each reference key, and rejection of a stranger.
	for i, fill := range []byte{0xA1, 0xB2, 0xC3} {
		var tkid [32]byte
		for j := range tkid {
			tkid[j] = fill
		}
		seq, err := VerifyInclusion(vec.Records, tkid)
		if err != nil || seq != uint64(i) {
			t.Fatalf("inclusion of key %d: seq=%d err=%v", i, seq, err)
		}
	}
	if _, err := VerifyInclusion(vec.Records, [32]byte{0xEE}); !errors.Is(err, ErrNotIncluded) {
		t.Fatalf("stranger inclusion error = %v", err)
	}

	// Every earlier reference head is consistent with the full log.
	for i, old := range vec.PrefixSignedHeads {
		if err := VerifyConsistency(old, vec.Records); err != nil {
			t.Fatalf("consistency from prefix %d: %v", i, err)
		}
	}

	// A tampered record breaks the head against the reference signature.
	tampered := append([]KeyRecord(nil), vec.Records...)
	tampered[0].TokenKeyID = hex.EncodeToString(make([]byte, 32))
	if err := VerifyLog(logPub, tampered, vec.PrefixSignedHeads[len(vec.Records)-1]); !errors.Is(err, ErrHeadMismatch) {
		t.Fatalf("tampered record error = %v", err)
	}

	t.Logf("verified %d reference-signed prefix heads byte-exact (FAEST-128f interop)", len(vec.Records))
}

func testTkid(fill byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = fill
	}
	return out
}

func TestBuildSignVerifyRoundTrip(t *testing.T) {
	signer, err := NewLogSigner(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	log := NewKeyLog()
	log.Append(1, testTkid(0x11), 1000)
	log.Append(2, testTkid(0x22), 2000)
	sth := signer.Sign(log, nil)

	if err := VerifyLog(signer.Public(), log.Records(), sth); err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	seq0, err := VerifyInclusion(log.Records(), testTkid(0x11))
	if err != nil || seq0 != 0 {
		t.Fatalf("inclusion 0: %d %v", seq0, err)
	}
	seq1, err := VerifyInclusion(log.Records(), testTkid(0x22))
	if err != nil || seq1 != 1 {
		t.Fatalf("inclusion 1: %d %v", seq1, err)
	}
}

func TestWrongLogKeyRejected(t *testing.T) {
	signer, _ := NewLogSigner(make([]byte, 32))
	attacker, _ := NewLogSigner(append(make([]byte, 31), 1))
	log := NewKeyLog()
	log.Append(1, testTkid(0x11), 1)
	sth := signer.Sign(log, nil)
	if err := VerifyLog(attacker.Public(), log.Records(), sth); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong key error = %v", err)
	}
}

func TestConsistencyAcceptsAppendRejectsRewrite(t *testing.T) {
	signer, _ := NewLogSigner(make([]byte, 32))
	log := NewKeyLog()
	log.Append(1, testTkid(0x11), 1)
	old := signer.Sign(log, nil)

	// Append extends the old head.
	log.Append(2, testTkid(0x22), 2)
	newSth := signer.Sign(log, nil)
	if err := VerifyLog(signer.Public(), log.Records(), newSth); err != nil {
		t.Fatalf("VerifyLog new: %v", err)
	}
	if err := VerifyConsistency(old, log.Records()); err != nil {
		t.Fatalf("append must extend: %v", err)
	}

	// A rewritten history must fail consistency.
	rewritten := NewKeyLog()
	rewritten.Append(9, testTkid(0x99), 1)
	rewritten.Append(2, testTkid(0x22), 2)
	if err := VerifyConsistency(old, rewritten.Records()); !errors.Is(err, ErrNotConsistent) {
		t.Fatalf("rewrite error = %v", err)
	}

	// A shorter log than already seen cannot extend it.
	if err := VerifyConsistency(newSth, log.Records()[:1]); !errors.Is(err, ErrNotConsistent) {
		t.Fatalf("truncation error = %v", err)
	}
}

func TestMultiRotationConsistentFromEveryPrefix(t *testing.T) {
	signer, _ := NewLogSigner(make([]byte, 32))
	log := NewKeyLog()
	var heads []SignedHead
	for v := uint32(1); v <= 4; v++ {
		log.Append(v, testTkid(byte(v)), uint64(v)*1000)
		heads = append(heads, signer.Sign(log, nil))
	}
	if err := VerifyLog(signer.Public(), log.Records(), heads[len(heads)-1]); err != nil {
		t.Fatalf("VerifyLog final: %v", err)
	}
	for i, old := range heads {
		if err := VerifyConsistency(old, log.Records()); err != nil {
			t.Fatalf("head after rotation %d should extend: %v", i, err)
		}
	}
	seq, err := VerifyInclusion(log.Records(), testTkid(4))
	if err != nil || seq != 3 {
		t.Fatalf("current key inclusion: %d %v", seq, err)
	}
}

// TestVerifyLogRejectsMalformed pins the reject paths: seq mismatch, bad
// hex, wrong lengths, bad base64 — no panics.
func TestVerifyLogRejectsMalformed(t *testing.T) {
	signer, _ := NewLogSigner(make([]byte, 32))
	log := NewKeyLog()
	log.Append(1, testTkid(0x11), 1)
	sth := signer.Sign(log, nil)

	if err := VerifyLog(signer.Public(), log.Records(), SignedHead{Seq: 5, Head: sth.Head, Sig: sth.Sig}); err == nil {
		t.Fatal("seq mismatch accepted")
	}
	if err := VerifyLog(signer.Public(), log.Records(), SignedHead{Seq: 0, Head: "zz", Sig: sth.Sig}); err == nil {
		t.Fatal("bad head hex accepted")
	}
	if err := VerifyLog(signer.Public(), log.Records(), SignedHead{Seq: 0, Head: sth.Head, Sig: "%%%"}); err == nil {
		t.Fatal("bad sig base64 accepted")
	}
	bad := []KeyRecord{{Seq: 0, KeyVersion: 1, TokenKeyID: "abcd", NotBefore: 1}}
	if _, err := HeadOf(bad); err == nil {
		t.Fatal("short token_key_id accepted")
	}
	if _, err := NewLogSigner(make([]byte, 16)); err == nil {
		t.Fatal("short seed accepted")
	}
}
