// Package transparency is the key transparency log for token issuer keys,
// ported from eat-pass core/src/transparency.rs and wire-compatible with it
// (domain strings, leaf/chain/sth hashing, JSON field names, FAEST-128f
// signed heads — verified against a reference-generated vector in
// testdata/).
//
// Pinning one issuer key begs the question of how a client learns the right
// key and notices a silent rotation to an attacker key. The answer is a
// small, gossip-able append-only log: the operator publishes a hash-chained
// list of KeyRecords — one per issuer key it has ever vouched for — and a
// FAEST-128f SignedHead over the chain head. Clients pin the log's public
// key (one key, long-lived) instead of every issuer key, then run three
// checks: VerifyLog (the served records reproduce the signed head),
// VerifyInclusion (the key the issuer is serving is in the log), and, across
// time, VerifyConsistency (the new head extends the previously seen one —
// history was appended to, never rewritten).
//
// This is a deliberately linear hash chain rather than an RFC 6962 Merkle
// tree: issuer keys rotate rarely (tens of records), so shipping the whole
// record list is cheap and the proofs are trivial to audit by hand.
package transparency

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/maceip/tamayo/faest"
)

// Domain separators, byte-identical to the eat-pass reference.
const (
	leafDomain = "eat-pass/kt/leaf\x00"
	headDomain = "eat-pass/kt/head\x00"
	sthDomain  = "eat-pass/kt/sth\x00"
)

// Errors mirroring the reference TransparencyError variants.
var (
	ErrHeadMismatch  = errors.New("signed head does not match the served records")
	ErrBadSignature  = errors.New("signed-head signature invalid")
	ErrNotIncluded   = errors.New("token_key_id not present in the log")
	ErrNotConsistent = errors.New("new log does not extend the previously-seen head (history rewritten)")
)

// KeyRecord is one published issuer key in the log.
type KeyRecord struct {
	// Seq is the record's position in the chain, 0-based.
	Seq uint64 `json:"seq"`
	// KeyVersion is the issuer key_version this record vouches for.
	KeyVersion uint32 `json:"key_version"`
	// TokenKeyID is the hex of the 32-byte issuer key id — the same id
	// pinned into tokens.
	TokenKeyID string `json:"token_key_id"`
	// NotBefore is Unix seconds the key becomes valid (informational).
	NotBefore uint64 `json:"not_before"`
}

func (r KeyRecord) tokenKeyIDBytes() ([32]byte, error) {
	var out [32]byte
	v, err := hex.DecodeString(strings.TrimSpace(r.TokenKeyID))
	if err != nil {
		return out, fmt.Errorf("bad hex in token_key_id: %w", err)
	}
	if len(v) != 32 {
		return out, errors.New("record token_key_id wrong length")
	}
	copy(out[:], v)
	return out, nil
}

// leafHash is the domain-separated hash binding all record fields.
func (r KeyRecord) leafHash() ([32]byte, error) {
	tkid, err := r.tokenKeyIDBytes()
	if err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	h.Write([]byte(leafDomain))
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], r.Seq)
	h.Write(b8[:])
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], r.KeyVersion)
	h.Write(b4[:])
	h.Write(tkid[:])
	binary.BigEndian.PutUint64(b8[:], r.NotBefore)
	h.Write(b8[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// SignedHead is the operator's FAEST-128f commitment to the chain head.
type SignedHead struct {
	// Seq is the index of the last record covered (records count - 1).
	Seq uint64 `json:"seq"`
	// Head is the chain head hash, hex.
	Head string `json:"head"`
	// Sig is the FAEST-128f signature over sthDomain||seq_be||head,
	// standard base64.
	Sig string `json:"sig"`
}

func genesisHead() [32]byte {
	h := sha256.New()
	h.Write([]byte(headDomain))
	h.Write([]byte("genesis"))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func step(prev, leaf [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(headDomain))
	h.Write(prev[:])
	h.Write(leaf[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// chainHeads recomputes every intermediate head; heads[i] covers records
// 0..=i.
func chainHeads(records []KeyRecord) ([][32]byte, error) {
	heads := make([][32]byte, 0, len(records))
	cur := genesisHead()
	for _, r := range records {
		leaf, err := r.leafHash()
		if err != nil {
			return nil, err
		}
		cur = step(cur, leaf)
		heads = append(heads, cur)
	}
	return heads, nil
}

// HeadOf is the head over records (genesis if empty).
func HeadOf(records []KeyRecord) ([32]byte, error) {
	heads, err := chainHeads(records)
	if err != nil {
		return [32]byte{}, err
	}
	if len(heads) == 0 {
		return genesisHead(), nil
	}
	return heads[len(heads)-1], nil
}

// KeyLog is the operator-side builder for the append-only log.
type KeyLog struct {
	records []KeyRecord
}

func NewKeyLog() *KeyLog { return &KeyLog{} }

// Append vouches for an issuer key (its key version and 32-byte token key
// id, e.g. tokenprofile Issuer.KeyVersion() and TokenKeyID()). Returns the
// record's seq.
func (l *KeyLog) Append(keyVersion uint32, tokenKeyID [32]byte, notBefore uint64) uint64 {
	seq := uint64(len(l.records))
	l.records = append(l.records, KeyRecord{
		Seq:        seq,
		KeyVersion: keyVersion,
		TokenKeyID: hex.EncodeToString(tokenKeyID[:]),
		NotBefore:  notBefore,
	})
	return seq
}

// Records returns the log's records (the caller must not mutate them).
func (l *KeyLog) Records() []KeyRecord { return l.records }

// Head returns the current chain head.
func (l *KeyLog) Head() [32]byte {
	h, err := HeadOf(l.records)
	if err != nil {
		panic("transparency: operator records are well-formed: " + err.Error())
	}
	return h
}

// LogSigner is the log operator's FAEST-128f signing key. Clients pin
// Public(). The seed-to-key derivation is Go-specific (SHAKE256 keystream
// into faest KeyGen; the reference uses a ChaCha20 rng) — keys derived from
// the same seed differ across the two stacks, but published keys, logs, and
// signatures are fully wire-compatible.
type LogSigner struct {
	sk []byte
	pk *faest.PublicKey
}

// NewLogSigner derives the operator key pair from a 32-byte seed.
func NewLogSigner(seed []byte) (*LogSigner, error) {
	if len(seed) != 32 {
		return nil, errors.New("transparency: log signer seed must be 32 bytes")
	}
	x := sha3.NewSHAKE256()
	x.Write([]byte("tamayo/kt/log-signer\x00"))
	x.Write(seed)
	sk, pk, err := faest.FAEST128f.KeyGen(x)
	if err != nil {
		return nil, err
	}
	return &LogSigner{sk: sk, pk: pk}, nil
}

// Public returns the 32-byte log public key (FAEST-128f owf input || owf
// output, the reference's to_bytes encoding).
func (s *LogSigner) Public() [32]byte {
	var out [32]byte
	copy(out[:16], s.pk.OwfInput)
	copy(out[16:], s.pk.OwfOutput)
	return out
}

// Sign commits to the log's current head. rho is the FAEST signer
// randomness (LambdaBytes; nil selects deterministic signing).
func (s *LogSigner) Sign(log *KeyLog, rho []byte) SignedHead {
	if rho == nil {
		rho = make([]byte, faest.FAEST128f.OWF.LambdaBytes)
	}
	head := log.Head()
	seq := uint64(0)
	if n := len(log.Records()); n > 0 {
		seq = uint64(n - 1)
	}
	sig := faest.FAEST128f.Sign(sthMessage(seq, head), s.sk, rho)
	return SignedHead{
		Seq:  seq,
		Head: hex.EncodeToString(head[:]),
		Sig:  base64.StdEncoding.EncodeToString(sig),
	}
}

func sthMessage(seq uint64, head [32]byte) []byte {
	m := make([]byte, 0, len(sthDomain)+8+32)
	m = append(m, sthDomain...)
	m = binary.BigEndian.AppendUint64(m, seq)
	return append(m, head[:]...)
}

func parseHead(sth SignedHead) ([32]byte, error) {
	var out [32]byte
	v, err := hex.DecodeString(strings.TrimSpace(sth.Head))
	if err != nil {
		return out, fmt.Errorf("bad hex in head: %w", err)
	}
	if len(v) != 32 {
		return out, errors.New("signed head wrong length")
	}
	copy(out[:], v)
	return out, nil
}

// VerifyLog is client check #1: the served records reproduce the signed
// head, and the head is genuinely signed by the pinned log key. After this
// returns nil, the records are exactly what the operator committed to.
func VerifyLog(logPub [32]byte, records []KeyRecord, sth SignedHead) error {
	if int(sth.Seq)+1 != len(records) {
		return fmt.Errorf("signed-head seq %d != record count %d", sth.Seq, len(records))
	}
	head, err := HeadOf(records)
	if err != nil {
		return err
	}
	want, err := parseHead(sth)
	if err != nil {
		return err
	}
	if head != want {
		return ErrHeadMismatch
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sth.Sig))
	if err != nil {
		return fmt.Errorf("bad base64 in sig: %w", err)
	}
	pk := &faest.PublicKey{OwfInput: logPub[:16], OwfOutput: logPub[16:]}
	if !faest.FAEST128f.Verify(sthMessage(sth.Seq, head), pk, sig) {
		return ErrBadSignature
	}
	return nil
}

// VerifyInclusion is client check #2: the issuer key the client is about to
// use is present in the verified log (call VerifyLog first). Returns the
// record seq.
func VerifyInclusion(records []KeyRecord, tokenKeyID [32]byte) (uint64, error) {
	want := hex.EncodeToString(tokenKeyID[:])
	for _, r := range records {
		if strings.EqualFold(strings.TrimSpace(r.TokenKeyID), want) {
			return r.Seq, nil
		}
	}
	return 0, ErrNotIncluded
}

// VerifyConsistency is client check #3, across time: newRecords extend the
// previously seen old head — the old head reappears as the intermediate head
// after old.Seq. Detects an operator that rewrites earlier records. Call
// VerifyLog on the new pair first.
func VerifyConsistency(old SignedHead, newRecords []KeyRecord) error {
	oldIdx := int(old.Seq)
	if oldIdx >= len(newRecords) {
		// The new log is shorter than what we already saw.
		return ErrNotConsistent
	}
	heads, err := chainHeads(newRecords)
	if err != nil {
		return err
	}
	want, err := parseHead(old)
	if err != nil {
		return err
	}
	if !bytes.Equal(heads[oldIdx][:], want[:]) {
		return ErrNotConsistent
	}
	return nil
}
