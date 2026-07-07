package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/maceip/tamayo/emailtoken"
	"github.com/maceip/tamayo/mailbox"
)

// evpTestServer mounts the EVP rail with a capturing code-delivery hook.
func evpTestServer(t *testing.T) (*server, *httptest.Server, *string) {
	t.Helper()
	s, ts, _ := testServer(t)
	signer, err := emailtoken.NewSigner("issuer.test", bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	var lastCode string
	s.evp = &evpRail{
		signer:       signer,
		issuerID:     "issuer.test",
		publicBase:   ts.URL,
		store:        mailbox.NewChallengeStore(600),
		gateKey:      [32]byte{0x42},
		budgetLimit:  2,
		budgetWindow: time.Hour,
		deliver: func(_, code string) error {
			lastCode = code
			return nil
		},
	}
	// Remount routes so the EVP handlers are registered.
	ts.Config.Handler = s.routes()
	return s, ts, &lastCode
}

// evpPost performs a browser-shaped issuance request: RFC 9421-signed with
// the holder key, Sec-Fetch-Dest set.
func evpPost(t *testing.T, ts *httptest.Server, priv ed25519.PrivateKey, body map[string]string, mutate func(*http.Request)) (int, map[string]string) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", ts.URL+"/email-verification/issuance", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	authority := strings.TrimPrefix(ts.URL, "http://")
	sigInput, sig, sigKey := signEVPRequest(priv, authority, "/email-verification/issuance", uint64(time.Now().Unix()))
	req.Header.Set("Signature-Input", sigInput)
	req.Header.Set("Signature", sig)
	req.Header.Set("Signature-Key", sigKey)
	req.Header.Set("Sec-Fetch-Dest", "email-verification")
	req.Header.Set("Content-Type", "application/json")
	if mutate != nil {
		mutate(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp.StatusCode, out
}

// TestEVPDiscoveryAndIssuance drives the full browser flow: discovery,
// jwks, signed issuance request -> code mailed -> signed request with code
// -> EVT bound to the browser key, verifiable against the served JWKS.
func TestEVPDiscoveryAndIssuance(t *testing.T) {
	s, ts, lastCode := evpTestServer(t)

	// Discovery document points at the live endpoints.
	resp, err := http.Get(ts.URL + "/.well-known/email-verification")
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if meta["issuer"] != "issuer.test" || meta["issuance_endpoint"] != ts.URL+"/email-verification/issuance" {
		t.Fatalf("metadata = %v", meta)
	}

	browserPub, browserPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// First signed request: no code yet -> 401 + code delivered.
	status, out := evpPost(t, ts, browserPriv, map[string]string{"email": "Alice@Example.com"}, nil)
	if status != http.StatusUnauthorized || out["error"] != "verification_code_sent" {
		t.Fatalf("first request = %d %v", status, out)
	}
	if len(*lastCode) != mailbox.CodeLen {
		t.Fatalf("delivered code %q", *lastCode)
	}

	// A different browser key must not be able to redeem the code.
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	status, out = evpPost(t, ts, otherPriv, map[string]string{"email": "alice@example.com", "code": *lastCode}, nil)
	if status != http.StatusForbidden {
		t.Fatalf("cross-key redemption = %d %v", status, out)
	}

	// The right key redeems it and gets an EVT bound to itself.
	status, out = evpPost(t, ts, browserPriv, map[string]string{"email": "alice@example.com", "code": *lastCode}, nil)
	if status != http.StatusOK {
		t.Fatalf("issuance = %d %v", status, out)
	}
	evt := out["issuance_token"]
	claims, err := s.evp.signer.Verifier().VerifyEVT(evt, emailtoken.VerifyOptions{Now: time.Now(), MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("VerifyEVT: %v", err)
	}
	if claims.Email != "alice@example.com" || !claims.EmailVerified {
		t.Fatalf("claims = %+v", claims)
	}
	holderPub, err := claims.CNF.JWK.Ed25519PublicKey()
	if err != nil || !bytes.Equal(holderPub, browserPub) {
		t.Fatalf("cnf key mismatch (%v)", err)
	}

	// The code is single-use.
	status, _ = evpPost(t, ts, browserPriv, map[string]string{"email": "alice@example.com", "code": *lastCode}, nil)
	if status != http.StatusForbidden {
		t.Fatalf("code replay = %d", status)
	}
}

// TestEVPIssuanceRejections pins the request-verification layers.
func TestEVPIssuanceRejections(t *testing.T) {
	_, ts, _ := evpTestServer(t)
	_, priv, _ := ed25519.GenerateKey(nil)

	// Missing Sec-Fetch-Dest.
	status, _ := evpPost(t, ts, priv, map[string]string{"email": "a@b.c"}, func(r *http.Request) {
		r.Header.Del("Sec-Fetch-Dest")
	})
	if status != http.StatusBadRequest {
		t.Fatalf("missing dest = %d", status)
	}

	// Tampered signature.
	status, _ = evpPost(t, ts, priv, map[string]string{"email": "a@b.c"}, func(r *http.Request) {
		sig := r.Header.Get("Signature")
		raw, _ := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(sig, "sig=:"), ":"))
		raw[0] ^= 1
		r.Header.Set("Signature", "sig=:"+base64.StdEncoding.EncodeToString(raw)+":")
	})
	if status != http.StatusBadRequest {
		t.Fatalf("tampered signature = %d", status)
	}

	// Stale created timestamp.
	status, _ = evpPost(t, ts, priv, map[string]string{"email": "a@b.c"}, func(r *http.Request) {
		authority := strings.TrimPrefix(ts.URL, "http://")
		sigInput, sig, sigKey := signEVPRequest(priv, authority, "/email-verification/issuance", uint64(time.Now().Unix())-3600)
		r.Header.Set("Signature-Input", sigInput)
		r.Header.Set("Signature", sig)
		r.Header.Set("Signature-Key", sigKey)
	})
	if status != http.StatusBadRequest {
		t.Fatalf("stale created = %d", status)
	}

	// Malformed email.
	status, _ = evpPost(t, ts, priv, map[string]string{"email": "not-an-email"}, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("bad email = %d", status)
	}
}

// TestEVPBudget pins the per-mailbox issuance budget: the limit is 2 in the
// test rail, so the third EVT for the same mailbox is refused.
func TestEVPBudget(t *testing.T) {
	_, ts, lastCode := evpTestServer(t)
	_, priv, _ := ed25519.GenerateKey(nil)

	for i := 0; i < 2; i++ {
		if status, out := evpPost(t, ts, priv, map[string]string{"email": "bob@example.com"}, nil); status != http.StatusUnauthorized {
			t.Fatalf("request %d = %d %v", i, status, out)
		}
		if status, out := evpPost(t, ts, priv, map[string]string{"email": "bob@example.com", "code": *lastCode}, nil); status != http.StatusOK {
			t.Fatalf("issuance %d = %d %v", i, status, out)
		}
	}
	if status, _ := evpPost(t, ts, priv, map[string]string{"email": "bob@example.com"}, nil); status != http.StatusUnauthorized {
		t.Fatal("code request should still be accepted")
	}
	if status, _ := evpPost(t, ts, priv, map[string]string{"email": "bob@example.com", "code": *lastCode}, nil); status != http.StatusTooManyRequests {
		t.Fatal("third EVT must exceed the budget")
	}
}
