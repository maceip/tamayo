package main

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/maceip/tamayo/tokenauth"
	"github.com/maceip/tamayo/tokenprofile"
)

// withJournal attaches a state journal (replaying whatever dir holds) to a
// fresh test server, mimicking a runtime restart when called twice on the
// same dir.
func withJournal(t *testing.T, s *server, dir string) {
	t.Helper()
	j, err := openJournal(dir, s.spent, s.seenPvt, s.budgets)
	if err != nil {
		t.Fatalf("openJournal: %v", err)
	}
	s.journal = j
	s.budgets = &journaledBudgets{inner: s.budgets, j: j}
}

// TestStateSurvivesRestart proves the fallback: a burn spend, a
// presentation nonce, and budget consumption all survive a process restart
// via journal replay.
func TestStateSurvivesRestart(t *testing.T) {
	dir := t.TempDir()

	// Instance one: mint and spend a burn token.
	s1, ts1, issuer := testServer(t)
	withJournal(t, s1, dir)
	ts1.Config.Handler = s1.routes()

	var nonce, additionalR [32]byte
	nonce[0], additionalR[0] = 0x31, 0x32
	challenge := sha256.Sum256([]byte("restart challenge"))
	input := tokenprofile.BurnInput(nonce, challenge, issuer.TokenKeyID())
	target, state := tokenprofile.PrepareBlind(input, additionalR)
	sigs, err := issuer.BlindSign([][]byte{target})
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := tokenprofile.FinalizeBlind(issuer.ExpandedPublicKey(), sigs[0], state)
	if err != nil {
		t.Fatal(err)
	}
	token := tokenprofile.BurnToken{
		TokenType: tokenprofile.BurnTokenType, Nonce: nonce,
		ChallengeDigest: challenge, TokenKeyID: issuer.TokenKeyID(),
		Authenticator: authenticator,
	}
	spend := map[string]any{
		"token_b64":     base64.RawURLEncoding.EncodeToString(token.Bytes()),
		"challenge_b64": base64.RawURLEncoding.EncodeToString([]byte("restart challenge")),
	}
	if status, _ := postJSON(t, ts1.URL+"/v1/verify/burn", spend); status != http.StatusOK {
		t.Fatal("first spend must succeed")
	}
	// Consume budget in instance one too.
	if err := s1.budgets.Reserve("restart:bucket:g", 3, 3, time.Hour, time.Now()); err != nil {
		t.Fatalf("budget reserve: %v", err)
	}

	// Instance two: same state dir, fresh in-memory stores ("restart").
	// The issuer key differs, but the journal replay is what we test.
	s2, ts2, _ := testServer(t)
	withJournal(t, s2, dir)
	ts2.Config.Handler = s2.routes()

	if err := s2.spent.CheckAndMark(issuer.KeyVersion(), nonce); err == nil {
		t.Fatal("spent nonce must survive the restart")
	}
	if err := s2.budgets.Reserve("restart:bucket:g", 1, 3, time.Hour, time.Now()); err == nil {
		t.Fatal("budget consumption must survive the restart")
	}

	// Presentation nonces replay too.
	s1.mu.Lock()
	s1.seenPvt["rp.example\x00nonce-1"] = true
	s1.mu.Unlock()
	if err := s1.journal.pvt("rp.example\x00nonce-1"); err != nil {
		t.Fatal(err)
	}
	s3, _, _ := testServer(t)
	withJournal(t, s3, dir)
	if !s3.seenPvt["rp.example\x00nonce-1"] {
		t.Fatal("presentation nonce must survive the restart")
	}
}

// TestNilJournalIsNoop pins that the default (no -state-dir) path is
// unchanged: nil journal appends succeed silently.
func TestNilJournalIsNoop(t *testing.T) {
	var j *journal
	if err := j.spend(1, [32]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := j.pvt("k"); err != nil {
		t.Fatal(err)
	}
	b := &journaledBudgets{inner: tokenauth.NewMemoryBudgetStore(), j: nil}
	if err := b.Reserve("k", 1, 2, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
}
