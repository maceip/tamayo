package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/maceip/tamayo/tokenprofile"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestHost builds an imagehost wired to a throwaway issuer, returning the
// pieces a client would hold: the issuer (to mint a test token) and the
// running consumer.
func newTestHost(t *testing.T) (*tokenprofile.Issuer, *host, *httptest.Server) {
	t.Helper()
	issuer, err := tokenprofile.NewIssuer(1, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The consumer only ever receives public material.
	verifier, err := tokenprofile.NewVerifierFromPublic(issuer.KeyVersion(), issuer.CompactPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	h := &host{
		origin:   "https://imagehost.test",
		verifier: verifier,
		log:      testLogger(),
		nonces:   make(map[[32]byte]time.Time),
		images:   make(map[string]storedImage),
		perPseud: make(map[string]int),
	}
	ts := httptest.NewServer(h.routes())
	t.Cleanup(ts.Close)
	return issuer, h, ts
}

// mintTestToken plays both client and issuer: blind, sign, finalize.
func mintTestToken(t *testing.T, issuer *tokenprofile.Issuer) (tokenprofile.PrivateIdentityToken, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	input := tokenprofile.NewPrivateIdentityInput(issuer.KeyVersion(), issuer.TokenKeyID(), tokenprofile.HolderAlgEd25519, pub)
	var additionalR [32]byte
	if _, err := rand.Read(additionalR[:]); err != nil {
		t.Fatal(err)
	}
	target, state := tokenprofile.PrepareBlind(input.Bytes(), additionalR)
	sigs, err := issuer.BlindSign([][]byte{target})
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := tokenprofile.FinalizeBlind(issuer.ExpandedPublicKey(), sigs[0], state)
	if err != nil {
		t.Fatal(err)
	}
	return tokenprofile.PrivateIdentityToken{Input: input, Authenticator: authenticator}, priv
}

func getChallenge(t *testing.T, ts *httptest.Server) [32]byte {
	t.Helper()
	resp, err := http.Post(ts.URL+"/v1/challenges", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		NonceB64 string `json:"nonce_b64"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	raw, err := b64.DecodeString(out.NonceB64)
	if err != nil || len(raw) != 32 {
		t.Fatalf("bad nonce: %v", err)
	}
	var nonce [32]byte
	copy(nonce[:], raw)
	return nonce
}

func uploadWith(t *testing.T, ts *httptest.Server, token tokenprofile.PrivateIdentityToken, priv ed25519.PrivateKey, nonce [32]byte, image []byte) (*http.Response, map[string]any) {
	t.Helper()
	issuedAt := time.Now().Unix()
	msg := tokenprofile.PrivateIdentityPresentationMessage("https://imagehost.test", nonce, token.Digest(), issuedAt)
	req := uploadRequest{
		TokenB64:     b64.EncodeToString(token.Bytes()),
		NonceB64:     b64.EncodeToString(nonce[:]),
		IssuedAt:     issuedAt,
		SignatureB64: b64.EncodeToString(ed25519.Sign(priv, msg)),
		ImageB64:     base64.StdEncoding.EncodeToString(image),
		ContentType:  "image/png",
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(req); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(ts.URL+"/v1/images", "application/json", &buf)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func TestUploadAndServeEndToEnd(t *testing.T) {
	issuer, _, ts := newTestHost(t)
	token, priv := mintTestToken(t, issuer)

	image := []byte("\x89PNG\r\n\x1a\nfake image body")
	resp, out := uploadWith(t, ts, token, priv, getChallenge(t, ts), image)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload: status %d: %v", resp.StatusCode, out)
	}
	url, _ := out["url"].(string)
	if url == "" {
		t.Fatalf("no url in response: %v", out)
	}
	pseud, _ := out["pseudonym_hex"].(string)
	if len(pseud) != 64 {
		t.Fatalf("pseudonym_hex = %q", pseud)
	}

	got, err := http.Get(ts.URL + url)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Body.Close()
	var body bytes.Buffer
	if _, err := body.ReadFrom(got.Body); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body.Bytes(), image) {
		t.Fatal("served image differs from upload")
	}
}

func TestNonceIsSingleUse(t *testing.T) {
	issuer, _, ts := newTestHost(t)
	token, priv := mintTestToken(t, issuer)
	nonce := getChallenge(t, ts)

	if resp, out := uploadWith(t, ts, token, priv, nonce, []byte("img-1")); resp.StatusCode != http.StatusOK {
		t.Fatalf("first upload: status %d: %v", resp.StatusCode, out)
	}
	if resp, _ := uploadWith(t, ts, token, priv, nonce, []byte("img-2")); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("replayed nonce: status %d, want 403", resp.StatusCode)
	}
}

func TestForeignTokenRejected(t *testing.T) {
	_, _, ts := newTestHost(t)
	// Token from a different issuer entirely.
	rogue, err := tokenprofile.NewIssuer(1, nil)
	if err != nil {
		t.Fatal(err)
	}
	token, priv := mintTestToken(t, rogue)
	if resp, _ := uploadWith(t, ts, token, priv, getChallenge(t, ts), []byte("x")); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign token: status %d, want 403", resp.StatusCode)
	}
}

func TestPerPseudonymQuota(t *testing.T) {
	issuer, h, ts := newTestHost(t)
	token, priv := mintTestToken(t, issuer)

	for i := 0; i < maxImagesPerPseudo; i++ {
		resp, out := uploadWith(t, ts, token, priv, getChallenge(t, ts), []byte{byte(i), 1, 2, 3})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("upload %d: status %d: %v", i, resp.StatusCode, out)
		}
	}
	if resp, _ := uploadWith(t, ts, token, priv, getChallenge(t, ts), []byte("over-quota")); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("over quota: status %d, want 429", resp.StatusCode)
	}
	if len(h.perPseud) != 1 {
		t.Fatalf("one holder key should map to exactly one pseudonym, got %d", len(h.perPseud))
	}
}
