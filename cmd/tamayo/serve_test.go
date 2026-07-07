package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/maceip/tamayo/mayo"
	"github.com/maceip/tamayo/tokenauth"
	"github.com/maceip/tamayo/tokenprofile"
	"github.com/maceip/tamayo/tokenservice"
)

func testServer(t *testing.T) (*server, *httptest.Server, *tokenprofile.Issuer) {
	t.Helper()
	issuer, err := tokenprofile.NewIssuer(1, make([]byte, mayo.Mayo1.SKSeedBytes))
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	svc, err := tokenservice.NewIssuer(issuer, nil)
	if err != nil {
		t.Fatalf("tokenservice.NewIssuer: %v", err)
	}
	raw, err := json.Marshal(examplePolicy())
	if err != nil {
		t.Fatal(err)
	}
	policy, err := tokenauth.CompileJSON(raw)
	if err != nil {
		t.Fatalf("example policy must compile: %v", err)
	}
	s := &server{
		issuer:    issuer,
		svc:       svc,
		policy:    policy,
		budgets:   tokenauth.NewMemoryBudgetStore(),
		maxSkew:   2 * time.Minute,
		spentBurn: make(map[[32]byte]bool),
		seenPvt:   make(map[string]bool),
		mu:        sync.Mutex{},
	}
	ts := httptest.NewServer(s.routes())
	t.Cleanup(ts.Close)
	return s, ts, issuer
}

func postJSON(t *testing.T, url string, body any) (int, map[string]json.RawMessage) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	var out map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("POST %s: decode: %v", url, err)
	}
	return resp.StatusCode, out
}

// TestServeBlindMintAndBurnSpend drives the real client flow over HTTP:
// blind locally, get a policy-gated blind signature, finalize locally, then
// spend the burn token once (accepted) and twice (rejected).
func TestServeBlindMintAndBurnSpend(t *testing.T) {
	_, ts, issuer := testServer(t)

	var nonce, additionalR [32]byte
	nonce[0], additionalR[0] = 0x11, 0x22
	challenge := sha256.Sum256([]byte("http origin challenge"))
	input := tokenprofile.BurnInput(nonce, challenge, issuer.TokenKeyID())
	target, state := tokenprofile.PrepareBlind(input, additionalR)

	status, out := postJSON(t, ts.URL+"/v1/blind-sign", map[string]any{
		"token_family": "burn",
		"blinded_b64":  []string{base64.RawURLEncoding.EncodeToString(target)},
		"subject":      map[string]any{"value_x": "dev-measurement", "platform": "software-witness"},
		"eligibility": []map[string]any{{
			"bridge_kind": "tee", "bucket_id": "runtime-1", "assurance": "verified",
		}},
	})
	if status != http.StatusOK {
		t.Fatalf("blind-sign status = %d body %s", status, out)
	}
	var sigsB64 []string
	if err := json.Unmarshal(out["blind_signatures_b64"], &sigsB64); err != nil || len(sigsB64) != 1 {
		t.Fatalf("blind_signatures_b64 = %s (%v)", out["blind_signatures_b64"], err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigsB64[0])
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := tokenprofile.FinalizeBlind(issuer.ExpandedPublicKey(), sig, state)
	if err != nil {
		t.Fatalf("FinalizeBlind: %v", err)
	}
	token := tokenprofile.BurnToken{
		TokenType:       tokenprofile.BurnTokenType,
		Nonce:           nonce,
		ChallengeDigest: challenge,
		TokenKeyID:      issuer.TokenKeyID(),
		Authenticator:   authenticator,
	}

	spend := map[string]any{
		"token_b64":     base64.RawURLEncoding.EncodeToString(token.Bytes()),
		"challenge_b64": base64.RawURLEncoding.EncodeToString([]byte("http origin challenge")),
	}
	if status, _ := postJSON(t, ts.URL+"/v1/verify/burn", spend); status != http.StatusOK {
		t.Fatalf("first spend status = %d", status)
	}
	if status, _ := postJSON(t, ts.URL+"/v1/verify/burn", spend); status != http.StatusConflict {
		t.Fatalf("double spend status = %d, want 409", status)
	}
}

// TestServeBlindSignDenials pins the two refusal layers: policy denial for a
// non-allowlisted measurement, and issuer refusal when the decision's
// binding does not match the presented batch.
func TestServeBlindSignDenials(t *testing.T) {
	s, ts, _ := testServer(t)

	status, out := postJSON(t, ts.URL+"/v1/blind-sign", map[string]any{
		"token_family": "burn",
		"blinded_b64":  []string{base64.RawURLEncoding.EncodeToString(make([]byte, 8))},
		"subject":      map[string]any{"value_x": "not-allowlisted"},
		"eligibility": []map[string]any{{
			"bridge_kind": "tee", "bucket_id": "runtime-1", "assurance": "verified",
		}},
	})
	if status != http.StatusForbidden {
		t.Fatalf("unauthorized measurement status = %d body %s", status, out)
	}

	// A decision minted for one batch must not sign another: exercise the
	// service-layer binding check straight through SignAuthorizedBlind.
	binding := tokenprofile.BindingOf([][]byte{[]byte("batch A")})
	decision := s.policy.AuthorizeMint(tokenauth.MintRequest{
		Subject:     tokenauth.Subject{ValueX: "dev-measurement", Platform: "software-witness"},
		Eligibility: []tokenauth.Eligibility{{BridgeKind: tokenauth.BridgeTEE, BucketID: "runtime-1", Assurance: tokenauth.AssuranceVerified}},
		TokenFamily: tokenauth.TokenBurn,
		Count:       1,
		KeyVersion:  1,
		Binding:     binding[:],
	}, nil, time.Now())
	if !decision.Allow {
		t.Fatalf("decision denied: %s", decision.Reason)
	}
	if _, err := s.svc.SignAuthorizedBlind(tokenservice.BlindMintRequest{
		Decision: decision,
		Family:   tokenauth.TokenBurn,
		Blinded:  [][]byte{[]byte("batch B")},
		Now:      time.Now(),
	}); err == nil {
		t.Fatal("decision for batch A must not sign batch B")
	}
}
