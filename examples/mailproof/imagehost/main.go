// Command imagehost is the mailproof demo consumer: an anonymous image host
// that accepts uploads gated on a tamayo private-identity token.
//
// The point this service proves: it never talks to the issuer at runtime and
// never sees an email address. At startup it fetches the issuer's *public*
// key once (GET /v1/issuer); after that every upload is verified locally.
// All the host ever learns about a client is an origin-bound pseudonym —
// a hash of the client's own holder key and this host's origin. The issuer
// can't link that pseudonym to a mailbox either: it only ever saw a keyed
// HMAC bucket, and (with client-side minting) a blinded signing target.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/maceip/tamayo/tokenprofile"
)

var b64 = base64.RawURLEncoding

const (
	maxImageBytes        = 2 << 20
	challengeTTL         = 5 * time.Minute
	maxImagesPerPseudo   = 10
	presentationMaxSkew  = 2 * time.Minute
	maxOutstandingNonces = 4096
)

func main() {
	addr := flag.String("http", envOr("IMAGEHOST_HTTP", ":8789"), "HTTP listen address")
	issuerURL := flag.String("issuer", envOr("IMAGEHOST_ISSUER", "http://127.0.0.1:8788"), "issuerd base URL (public key fetched once at startup)")
	origin := flag.String("origin", envOr("IMAGEHOST_ORIGIN", "https://imagehost.local"), "this host's origin string; pseudonyms are bound to it")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	verifier, err := fetchVerifier(*issuerURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "imagehost:", err)
		os.Exit(1)
	}

	h := &host{
		origin:   *origin,
		verifier: verifier,
		log:      log,
		nonces:   make(map[[32]byte]time.Time),
		images:   make(map[string]storedImage),
		perPseud: make(map[string]int),
	}

	fmt.Printf("imagehost — mailproof demo consumer\n")
	fmt.Printf("  http:   %s\n", *addr)
	fmt.Printf("  origin: %s\n", *origin)
	fmt.Printf("  issuer: %s (public key pinned at startup; no further contact)\n", *issuerURL)

	server := &http.Server{Addr: *addr, Handler: h.routes(), ReadHeaderTimeout: 10 * time.Second}
	if err := server.ListenAndServe(); err != nil {
		log.Error("http server exited", "err", err)
		os.Exit(1)
	}
}

// fetchVerifier pins the issuer's public key. This is the only issuer
// contact the consumer ever makes.
func fetchVerifier(issuerURL string) (*tokenprofile.Issuer, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(issuerURL + "/v1/issuer")
	if err != nil {
		return nil, fmt.Errorf("fetch issuer info: %w", err)
	}
	defer resp.Body.Close()
	var info struct {
		KeyVersion          uint32 `json:"key_version"`
		CompactPublicKeyB64 string `json:"compact_public_key_b64"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode issuer info: %w", err)
	}
	cpk, err := b64.DecodeString(info.CompactPublicKeyB64)
	if err != nil {
		return nil, fmt.Errorf("issuer public key: %w", err)
	}
	return tokenprofile.NewVerifierFromPublic(info.KeyVersion, cpk)
}

type storedImage struct {
	data        []byte
	contentType string
	pseudonym   string
}

type host struct {
	origin   string
	verifier *tokenprofile.Issuer
	log      *slog.Logger

	mu       sync.Mutex
	nonces   map[[32]byte]time.Time // outstanding challenge nonces
	images   map[string]storedImage
	perPseud map[string]int
}

func (h *host) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("POST /v1/challenges", h.handleChallenge)
	mux.HandleFunc("POST /v1/images", h.handleUpload)
	mux.HandleFunc("GET /i/{id}", h.handleServe)
	return mux
}

// handleChallenge hands out a single-use presentation nonce. Nonces are what
// make a stolen presentation worthless: each one authorizes exactly one
// upload at exactly this origin.
func (h *host) handleChallenge(w http.ResponseWriter, _ *http.Request) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		writeErr(w, http.StatusInternalServerError, "entropy")
		return
	}
	now := time.Now()
	h.mu.Lock()
	for n, exp := range h.nonces {
		if now.After(exp) {
			delete(h.nonces, n)
		}
	}
	if len(h.nonces) >= maxOutstandingNonces {
		h.mu.Unlock()
		writeErr(w, http.StatusTooManyRequests, "too many outstanding challenges")
		return
	}
	h.nonces[nonce] = now.Add(challengeTTL)
	h.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"nonce_b64":  b64.EncodeToString(nonce[:]),
		"origin":     h.origin,
		"expires_at": now.Add(challengeTTL).Unix(),
	})
}

type uploadRequest struct {
	TokenB64     string `json:"token_b64"`
	NonceB64     string `json:"nonce_b64"`
	IssuedAt     int64  `json:"issued_at"`
	SignatureB64 string `json:"signature_b64"`
	ImageB64     string `json:"image_b64"`
	ContentType  string `json:"content_type"`
}

func (h *host) handleUpload(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, maxImageBytes*2)
	defer body.Close()
	var req uploadRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "json: "+err.Error())
		return
	}

	tokenRaw, err := b64.DecodeString(req.TokenB64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "token_b64: "+err.Error())
		return
	}
	token, err := tokenprofile.ParsePrivateIdentityToken(tokenRaw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "token: "+err.Error())
		return
	}
	nonceRaw, err := b64.DecodeString(req.NonceB64)
	if err != nil || len(nonceRaw) != 32 {
		writeErr(w, http.StatusBadRequest, "nonce_b64 must be 32 bytes")
		return
	}
	var nonce [32]byte
	copy(nonce[:], nonceRaw)
	signature, err := b64.DecodeString(req.SignatureB64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "signature_b64: "+err.Error())
		return
	}

	// Consume the nonce first: even a failed verification burns it.
	now := time.Now()
	h.mu.Lock()
	exp, ok := h.nonces[nonce]
	delete(h.nonces, nonce)
	h.mu.Unlock()
	if !ok || now.After(exp) {
		writeErr(w, http.StatusForbidden, "unknown, expired, or already-spent nonce")
		return
	}

	pseudonym, err := h.verifier.VerifyPrivateIdentityPresentation(tokenprofile.PrivateIdentityPresentation{
		Token:     token,
		Origin:    h.origin,
		Nonce:     nonce,
		IssuedAt:  req.IssuedAt,
		Signature: signature,
	}, now, presentationMaxSkew)
	if err != nil {
		writeErr(w, http.StatusForbidden, "presentation rejected: "+err.Error())
		return
	}
	pseudHex := hex.EncodeToString(pseudonym[:])

	image, err := base64.StdEncoding.DecodeString(req.ImageB64)
	if err != nil {
		if image, err = b64.DecodeString(req.ImageB64); err != nil {
			writeErr(w, http.StatusBadRequest, "image_b64: "+err.Error())
			return
		}
	}
	if len(image) == 0 || len(image) > maxImageBytes {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("image must be 1..%d bytes", maxImageBytes))
		return
	}
	contentType := req.ContentType
	if contentType == "" {
		contentType = http.DetectContentType(image)
	}

	sum := sha256.Sum256(image)
	id := hex.EncodeToString(sum[:16])

	h.mu.Lock()
	if h.perPseud[pseudHex] >= maxImagesPerPseudo {
		h.mu.Unlock()
		writeErr(w, http.StatusTooManyRequests, "per-pseudonym image quota reached")
		return
	}
	if _, exists := h.images[id]; !exists {
		h.images[id] = storedImage{data: image, contentType: contentType, pseudonym: pseudHex}
		h.perPseud[pseudHex]++
	}
	h.mu.Unlock()

	// This log line is the whole demo: the host attributes the upload to a
	// pseudonym it cannot resolve to a person, and neither can the issuer.
	h.log.Info("image stored",
		"id", id,
		"bytes", len(image),
		"pseudonym", pseudHex[:16],
		"note", "origin-bound pseudonym; no account, no email, no IP retention")

	writeJSON(w, http.StatusOK, map[string]any{
		"url":           "/i/" + id,
		"id":            id,
		"pseudonym_hex": pseudHex,
	})
}

func (h *host) handleServe(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	img, ok := h.images[r.PathValue("id")]
	h.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", img.contentType)
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	_, _ = w.Write(img.data)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
