package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/maceip/tamayo/tokenprofile"
)

func testServer(t *testing.T) (*server, *httptest.Server) {
	t.Helper()
	cfg := config{
		MailDomain:      "issuer.test",
		VerifyLocalPart: "verify",
		Dev:             true,
		SessionTTL:      time.Minute,
	}
	log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	srv, err := newServer(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)
	return srv, ts
}

func postJSON(t *testing.T, url string, body any) (int, map[string]json.RawMessage) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := http.Post(url, "application/json", &buf)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp.StatusCode, out
}

func str(t *testing.T, m map[string]json.RawMessage, key string) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(m[key], &s); err != nil {
		t.Fatalf("field %q: %v (raw %s)", key, err, m[key])
	}
	return s
}

func mintAndVerify(t *testing.T, srv *server, ts *httptest.Server, sessionID string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	status, resp := postJSON(t, ts.URL+"/v1/sessions/"+sessionID+"/mint",
		map[string]string{"holder_pub_b64": b64.EncodeToString(pub)})
	if status != http.StatusOK {
		t.Fatalf("mint: status %d: %v", status, resp)
	}
	tokenRaw, err := b64.DecodeString(str(t, resp, "token_b64"))
	if err != nil {
		t.Fatal(err)
	}
	token, err := tokenprofile.ParsePrivateIdentityToken(tokenRaw)
	if err != nil {
		t.Fatal(err)
	}

	// Verify like a remote consumer: public key only, then a full
	// presentation with a holder PoP.
	verifier, err := tokenprofile.NewVerifierFromPublic(srv.issuer.KeyVersion(), srv.issuer.CompactPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyPrivateIdentityToken(token); err != nil {
		t.Fatalf("token rejected by public-key verifier: %v", err)
	}

	origin := "https://consumer.test"
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	msg := tokenprofile.PrivateIdentityPresentationMessage(origin, nonce, token.Digest(), now.Unix())
	pseudonym, err := verifier.VerifyPrivateIdentityPresentation(tokenprofile.PrivateIdentityPresentation{
		Token:     token,
		Origin:    origin,
		Nonce:     nonce,
		IssuedAt:  now.Unix(),
		Signature: ed25519.Sign(priv, msg),
	}, now, time.Minute)
	if err != nil {
		t.Fatalf("presentation rejected: %v", err)
	}
	if pseudonym == [32]byte{} {
		t.Fatal("empty pseudonym")
	}
}

func TestSendDirectionEndToEnd(t *testing.T) {
	srv, ts := testServer(t)

	status, resp := postJSON(t, ts.URL+"/v1/sessions", map[string]string{"mode": "send"})
	if status != http.StatusOK {
		t.Fatalf("create session: status %d", status)
	}
	sessionID := str(t, resp, "session_id")
	verifyAddr := str(t, resp, "verify_address")
	if want := "verify+" + sessionID + "@issuer.test"; verifyAddr != want {
		t.Fatalf("verify_address = %q, want %q", verifyAddr, want)
	}

	// Mint before verification must be refused.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	status, _ = postJSON(t, ts.URL+"/v1/sessions/"+sessionID+"/mint",
		map[string]string{"holder_pub_b64": b64.EncodeToString(pub)})
	if status != http.StatusForbidden {
		t.Fatalf("mint before verify: status %d, want 403", status)
	}

	// A verification email arrives via the webhook (dev mode: no DKIM).
	raw := "From: Alice <alice@example.org>\r\n" +
		"To: " + verifyAddr + "\r\n" +
		"Subject: verify " + sessionID + "\r\n" +
		"\r\nhi\r\n"
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/ingress/webhook", strings.NewReader(raw))
	req.Header.Set("Content-Type", "message/rfc822")
	httpResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("webhook: status %d", httpResp.StatusCode)
	}

	// Session flips to verified, and stores only the bucket.
	sess, ok := srv.getSession(sessionID)
	if !ok || sess.Status != statusVerified {
		t.Fatalf("session not verified: %+v", sess)
	}
	if sess.Bucket == "" || strings.Contains(sess.Bucket, "alice") || strings.Contains(sess.Bucket, "@") {
		t.Fatalf("bucket should be an opaque hash, got %q", sess.Bucket)
	}

	mintAndVerify(t, srv, ts, sessionID)
}

func TestCodeDirectionEndToEnd(t *testing.T) {
	srv, ts := testServer(t)
	var sentTo, sentCode string
	srv.sendCode = func(to, code string) error {
		sentTo, sentCode = to, code
		return nil
	}

	status, resp := postJSON(t, ts.URL+"/v1/sessions", map[string]string{"mode": "code"})
	if status != http.StatusOK {
		t.Fatalf("create session: status %d", status)
	}
	sessionID := str(t, resp, "session_id")

	status, _ = postJSON(t, ts.URL+"/v1/sessions/"+sessionID+"/send-code",
		map[string]string{"email": "Bob@Example.org"})
	if status != http.StatusOK {
		t.Fatalf("send-code: status %d", status)
	}
	if sentTo != "Bob@Example.org" || len(sentCode) != 6 {
		t.Fatalf("code not delivered: to=%q code=%q", sentTo, sentCode)
	}

	// Wrong code fails, right code verifies.
	wrong := "000000"
	if wrong == sentCode {
		wrong = "000001"
	}
	status, _ = postJSON(t, ts.URL+"/v1/sessions/"+sessionID+"/verify-code",
		map[string]string{"email": "bob@example.org", "code": wrong})
	if status != http.StatusForbidden {
		t.Fatalf("wrong code: status %d, want 403", status)
	}
	status, _ = postJSON(t, ts.URL+"/v1/sessions/"+sessionID+"/verify-code",
		map[string]string{"email": "bob@example.org", "code": sentCode})
	if status != http.StatusOK {
		t.Fatalf("verify-code: status %d", status)
	}

	mintAndVerify(t, srv, ts, sessionID)
}

func TestBudgetCapsMintsPerMailbox(t *testing.T) {
	srv, ts := testServer(t)
	srv.sendCode = func(_, _ string) error { return nil }

	// Verify sessions for the same mailbox until the mailproof budget (8/h)
	// runs out. Every session lands in the same HMAC bucket.
	mintOnce := func(i int) int {
		_, resp := postJSON(t, ts.URL+"/v1/sessions", map[string]string{"mode": "send"})
		sessionID := str(t, resp, "session_id")
		raw := fmt.Sprintf("From: spam@example.org\r\nTo: verify+%s@issuer.test\r\n\r\nx\r\n", sessionID)
		if err := srv.handleIncomingMail([]byte(raw)); err != nil {
			t.Fatalf("mail %d: %v", i, err)
		}
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		status, _ := postJSON(t, ts.URL+"/v1/sessions/"+sessionID+"/mint",
			map[string]string{"holder_pub_b64": b64.EncodeToString(pub)})
		return status
	}
	for i := 0; i < 8; i++ {
		if status := mintOnce(i); status != http.StatusOK {
			t.Fatalf("mint %d: status %d, want 200", i, status)
		}
	}
	if status := mintOnce(8); status != http.StatusForbidden {
		t.Fatalf("mint 9 should exhaust the mailbox budget, got status %d", status)
	}
}

func TestWebhookRequiresDKIMOutsideDev(t *testing.T) {
	cfg := config{
		MailDomain:      "issuer.test",
		VerifyLocalPart: "verify",
		WebhookSecret:   "s3cret",
		Dev:             false,
		SessionTTL:      time.Minute,
	}
	log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	srv, err := newServer(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	_, resp := postJSON(t, ts.URL+"/v1/sessions", map[string]string{"mode": "send"})
	sessionID := str(t, resp, "session_id")
	raw := "From: mallory@example.org\r\nTo: verify+" + sessionID + "@issuer.test\r\n\r\nx\r\n"

	// No secret: refused outright.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/ingress/webhook", strings.NewReader(raw))
	httpResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing secret: status %d, want 403", httpResp.StatusCode)
	}

	// Right secret but no DKIM signature: the mail is rejected.
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/v1/ingress/webhook", strings.NewReader(raw))
	req.Header.Set("X-Issuerd-Secret", "s3cret")
	httpResp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("unsigned mail: status %d, want 422", httpResp.StatusCode)
	}
	if sess, _ := srv.getSession(sessionID); sess == nil || sess.Status != statusPending {
		t.Fatal("session must stay pending after rejected mail")
	}
}
