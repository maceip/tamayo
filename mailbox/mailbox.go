// Package mailbox is the mailbox-control eligibility gate, ported from
// eat-pass core/src/mailbox.rs and wire-compatible with it (canonicalization
// rules, the keyed bucket-id HMAC and its domain string, code length and
// attempt limits).
//
// It is deliberately separate from hardware attestation: nothing here
// touches TEEs or measurements. It is an alternative eligibility gate for
// the same issuer — instead of "prove you run an accepted build", the client
// proves "I control this mailbox" via a challenge code sent to the address.
// Downstream the pipeline is identical: the gate's keyed bucket id becomes
// the tokenauth eligibility bucket, the issuer blind-signs on an authorized
// decision, and the issuer never learns the email — only the HMAC bucket.
// Blindness means the mailbox is linked to issuance eligibility, never to
// any token.
//
// What the gate is (and is not): exclusivity — only someone who can read the
// mailbox gets the code; stability — one canonical address maps to one
// issuance budget bucket per window; NOT sybil resistance — like EVP, this
// does not prove personhood: anyone can make a million mailboxes, real users
// keep one.
//
// Mail delivery (SMTP, templating) and durable challenge storage are product
// work; the ChallengeStore here is in-memory, matching the reference.
package mailbox

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode"
)

const (
	// Platform is the tokenauth subject platform label for mailbox
	// eligibility, distinguishing its rate-limit buckets from every
	// attestation platform.
	Platform = "mailbox"
	// PolicyLabel is bound into authorizations minted through this gate.
	PolicyLabel = "mailbox@v1"
	// CodeLen is the verification code length: 6 decimal digits,
	// human-copyable from a mail body.
	CodeLen = 6
	// MaxCodeAttempts consumes a pending challenge after this many wrong
	// codes.
	MaxCodeAttempts = 3

	bucketDomain = "eat-pass/v1/mailbox-id\x00"
)

// Errors mirroring the reference GateError semantics.
var (
	ErrMalformedEmail  = errors.New("mailbox: malformed email address")
	ErrNoPending       = errors.New("mailbox: no pending mail challenge")
	ErrExpired         = errors.New("mailbox: mail challenge expired")
	ErrBindingMismatch = errors.New("mailbox: challenge is bound to a different mint binding")
	ErrWrongCode       = errors.New("mailbox: wrong code")
)

// CanonicalEmail canonicalizes an address for rate-limit identity: trim,
// lowercase, exactly one @ with non-empty local part and domain, no
// whitespace or control characters. Provider-specific normalization (gmail
// dot/plus folding, etc.) is deployment policy layered on top; the gate
// itself stays neutral.
func CanonicalEmail(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	local, domain, ok := strings.Cut(s, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return "", ErrMalformedEmail
	}
	for _, c := range s {
		if unicode.IsSpace(c) || unicode.IsControl(c) {
			return "", ErrMalformedEmail
		}
	}
	return s, nil
}

// BucketID is the keyed rate-limit identity for a verified mailbox:
// HMAC-SHA256(gateKey, domain || canonical). Keyed, so an issuer (which sees
// only the bucket, or a further hash of it) cannot run a dictionary over
// addresses. One mailbox, one bucket.
func BucketID(gateKey [32]byte, canonical string) [32]byte {
	mac := hmac.New(sha256.New, gateKey[:])
	mac.Write([]byte(bucketDomain))
	mac.Write([]byte(canonical))
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func hashCode(code string) [32]byte {
	return sha256.Sum256([]byte(code))
}

type pending struct {
	codeHash [32]byte
	binding  [32]byte
	exp      uint64
	attempts int
}

// ChallengeStore holds outstanding mail challenges in memory, keyed by
// canonical email. One pending challenge per address; a new request replaces
// the old one. Multi-replica deployments must back this with shared storage.
type ChallengeStore struct {
	mu      sync.Mutex
	pending map[string]*pending
	ttl     uint64
}

// NewChallengeStore creates a store whose challenges live ttlSeconds
// (minimum one second).
func NewChallengeStore(ttlSeconds uint64) *ChallengeStore {
	if ttlSeconds == 0 {
		ttlSeconds = 1
	}
	return &ChallengeStore{pending: make(map[string]*pending), ttl: ttlSeconds}
}

// Create issues a challenge for email, bound to the mint's channel binding.
// It returns the 6-digit code to be delivered to the mailbox; the store
// retains only the code's hash. now is Unix seconds.
func (s *ChallengeStore) Create(email string, binding [32]byte, now uint64) (string, error) {
	canonical, err := CanonicalEmail(email)
	if err != nil {
		return "", err
	}
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	code := fmt.Sprintf("%06d", binary.BigEndian.Uint32(raw[:])%1_000_000)
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, p := range s.pending {
		if p.exp <= now {
			delete(s.pending, k)
		}
	}
	s.pending[canonical] = &pending{
		codeHash: hashCode(code),
		binding:  binding,
		exp:      now + s.ttl,
	}
	return code, nil
}

// Verify checks code for email against expectedBinding, consuming the
// challenge on success (single-use) and after MaxCodeAttempts failures. A
// code requested for one mint must not authorize another. Returns the
// canonical address on success.
func (s *ChallengeStore) Verify(email, code string, expectedBinding [32]byte, now uint64) (string, error) {
	canonical, err := CanonicalEmail(email)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.pending[canonical]
	if !ok {
		return "", ErrNoPending
	}
	if entry.exp <= now {
		delete(s.pending, canonical)
		return "", ErrExpired
	}
	if entry.binding != expectedBinding {
		return "", ErrBindingMismatch
	}
	want := hashCode(strings.TrimSpace(code))
	if subtle.ConstantTimeCompare(entry.codeHash[:], want[:]) != 1 {
		entry.attempts++
		if entry.attempts >= MaxCodeAttempts {
			delete(s.pending, canonical)
		}
		return "", ErrWrongCode
	}
	delete(s.pending, canonical)
	return canonical, nil
}
