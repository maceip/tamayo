package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/maceip/tamayo/mayo"
	"github.com/maceip/tamayo/tokenauth"
	"github.com/maceip/tamayo/tokenprofile"
	"github.com/maceip/tamayo/tokenservice"
	"github.com/maceip/tamayo/transparency"
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
		verifiers: []*tokenprofile.Issuer{issuer},
		svc:       svc,
		policy:    policy,
		budgets:   tokenauth.NewMemoryBudgetStore(),
		maxSkew:   2 * time.Minute,
		spent:     tokenservice.NewMemorySpentStore(),
		seenPvt:   make(map[string]bool),
	}
	if err := s.initKT(); err != nil {
		t.Fatalf("initKT: %v", err)
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
			"gate_kind": "tee", "bucket_id": "runtime-1", "assurance": "verified",
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
			"gate_kind": "tee", "bucket_id": "runtime-1", "assurance": "verified",
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
		Eligibility: []tokenauth.Eligibility{{GateKind: tokenauth.GateTEE, BucketID: "runtime-1", Assurance: tokenauth.AssuranceVerified}},
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

// TestServeKT verifies the served key-transparency log: a client can pin
// the log key, verify the signed head, and find the issuer's current key.
func TestServeKT(t *testing.T) {
	_, ts, issuer := testServer(t)
	resp, err := http.Get(ts.URL + "/v1/kt")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		LogPublicKeyHex string                   `json:"log_public_key_hex"`
		Records         []transparency.KeyRecord `json:"records"`
		SignedHead      transparency.SignedHead  `json:"signed_head"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	pubBytes, err := hex.DecodeString(out.LogPublicKeyHex)
	if err != nil || len(pubBytes) != 32 {
		t.Fatalf("log public key: %v", err)
	}
	var logPub [32]byte
	copy(logPub[:], pubBytes)
	if err := transparency.VerifyLog(logPub, out.Records, out.SignedHead); err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	seq, err := transparency.VerifyInclusion(out.Records, issuer.TokenKeyID())
	if err != nil || seq != 0 {
		t.Fatalf("inclusion: %d %v", seq, err)
	}
}

// TestKeyRotationOverlap proves the rotation window: a burn token minted
// under epoch v1 still verifies after v2 becomes the signer, as long as v1
// stays in the verifier set, and /v1/kt lists both epochs.
func TestKeyRotationOverlap(t *testing.T) {
	v1, err := tokenprofile.NewIssuer(1, make([]byte, mayo.Mayo1.SKSeedBytes))
	if err != nil {
		t.Fatal(err)
	}
	// Mint a burn token under v1 directly.
	var nonce, addR [32]byte
	nonce[0] = 0x51
	challenge := sha256.Sum256([]byte("rotate"))
	input := tokenprofile.BurnInput(nonce, challenge, v1.TokenKeyID())
	target, state := tokenprofile.PrepareBlind(input, addR)
	sigs, err := v1.BlindSign([][]byte{target})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := tokenprofile.FinalizeBlind(v1.ExpandedPublicKey(), sigs[0], state)
	if err != nil {
		t.Fatal(err)
	}
	tokenBytes := tokenprofile.BurnToken{
		TokenType: tokenprofile.BurnTokenType, Nonce: nonce,
		ChallengeDigest: challenge, TokenKeyID: v1.TokenKeyID(), Authenticator: auth,
	}.Bytes()

	// Stand up a server where v2 signs but v1 is still a live verifier.
	v2, err := tokenprofile.NewIssuer(2, make([]byte, mayo.Mayo1.SKSeedBytes))
	if err != nil {
		t.Fatal(err)
	}
	// v2 uses the same seed → same token_key_id; give it a distinct seed.
	v2b := make([]byte, mayo.Mayo1.SKSeedBytes)
	v2b[0] = 0x99
	v2, err = tokenprofile.NewIssuer(2, v2b)
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := tokenservice.NewIssuer(v2, nil)
	raw, _ := json.Marshal(examplePolicy())
	policy, _ := tokenauth.CompileJSON(raw)
	s := &server{
		issuer:    v2,
		verifiers: []*tokenprofile.Issuer{v2, v1}, // v2 current, v1 retired-but-live
		svc:       svc,
		policy:    policy,
		budgets:   tokenauth.NewMemoryBudgetStore(),
		maxSkew:   2 * time.Minute,
		spent:     tokenservice.NewMemorySpentStore(),
		seenPvt:   make(map[string]bool),
	}
	if err := s.initKT(); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.routes())
	defer ts.Close()

	// The v1 token still verifies during the overlap.
	spend := map[string]any{
		"token_b64":     base64.RawURLEncoding.EncodeToString(tokenBytes),
		"challenge_b64": base64.RawURLEncoding.EncodeToString([]byte("rotate")),
	}
	if status, _ := postJSON(t, ts.URL+"/v1/verify/burn", spend); status != http.StatusOK {
		t.Fatalf("retired-epoch token must still verify, got %d", status)
	}
	// Spent under v1's epoch — double spend still caught.
	if status, _ := postJSON(t, ts.URL+"/v1/verify/burn", spend); status != http.StatusConflict {
		t.Fatalf("double spend across rotation = %d", status)
	}

	// KT lists both epochs, oldest first, and both are included.
	resp, err := http.Get(ts.URL + "/v1/kt")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var kt struct {
		Records []transparency.KeyRecord `json:"records"`
	}
	json.NewDecoder(resp.Body).Decode(&kt)
	if len(kt.Records) != 2 || kt.Records[0].KeyVersion != 1 || kt.Records[1].KeyVersion != 2 {
		t.Fatalf("kt records = %+v", kt.Records)
	}
}
