package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"time"

	"github.com/maceip/tamayo/mailbox"
	"github.com/maceip/tamayo/tokenauth"
	"github.com/maceip/tamayo/tokenprofile"
	"github.com/maceip/tamayo/tokenservice"
)

type mintRequest struct {
	HolderPubB64 string `json:"holder_pub_b64"`
}

type mintResponse struct {
	TokenFamily  string `json:"token_family"`
	TokenB64     string `json:"token_b64"`
	HolderAlg    string `json:"holder_alg"`
	HolderPubB64 string `json:"holder_pub_b64"`
	KeyVersion   uint32 `json:"key_version"`
	Note         string `json:"note"`
}

// handleMint is the assisted mint: the client generates the holder keypair
// on-device and sends only the public key; this service blinds, has the
// policy authorize against the mailbox bucket's budget, blind-signs, and
// finalizes the token. Assisted minting means the issuer performs the
// blinding, so mint→spend unlinkability from the issuer is NOT yet a
// property of this deployment — client-side minting is the upgrade path.
func (s *server) handleMint(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.getSession(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "unknown or expired session")
		return
	}
	s.mu.Lock()
	verified := sess.Status == statusVerified
	bucket := sess.Bucket
	s.mu.Unlock()
	if !verified {
		writeErr(w, http.StatusForbidden, "session is not mailbox-verified yet")
		return
	}

	var req mintRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.HolderPubB64 == "" {
		writeErr(w, http.StatusBadRequest, "holder_pub_b64 required: generate the keypair on the client, send only the public key")
		return
	}
	raw, err := b64.DecodeString(req.HolderPubB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		writeErr(w, http.StatusBadRequest, "holder_pub_b64 must be 32 raw bytes (base64url)")
		return
	}

	var additionalR [32]byte
	if _, err := rand.Read(additionalR[:]); err != nil {
		writeErr(w, http.StatusInternalServerError, "entropy")
		return
	}
	input := tokenprofile.NewPrivateIdentityInput(
		s.issuer.KeyVersion(),
		s.issuer.TokenKeyID(),
		tokenprofile.HolderAlgEd25519,
		raw,
	)
	target, state := tokenprofile.PrepareBlind(input.Bytes(), additionalR)
	binding := tokenprofile.BindingOf([][]byte{target})

	now := time.Now()
	decision := s.policy.AuthorizeMint(tokenauth.MintRequest{
		Subject: tokenauth.Subject{Platform: mailbox.Platform},
		Eligibility: []tokenauth.Eligibility{{
			GateKind:  tokenauth.GateEmail,
			BucketID:  bucket,
			Assurance: tokenauth.AssuranceVerified,
		}},
		TokenFamily: tokenauth.TokenPrivateIdentity,
		Count:       1,
		KeyVersion:  s.issuer.KeyVersion(),
		Binding:     binding[:],
	}, s.budgets, now)
	if !decision.Allow {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "mint denied", "decision": decision})
		return
	}

	sigs, err := s.svc.SignAuthorizedBlind(tokenservice.BlindMintRequest{
		Decision: decision,
		Family:   tokenauth.TokenPrivateIdentity,
		Blinded:  [][]byte{target},
		Now:      now,
	})
	if err != nil {
		writeErr(w, http.StatusForbidden, "blind-sign: "+err.Error())
		return
	}
	authenticator, err := tokenprofile.FinalizeBlind(s.issuer.ExpandedPublicKey(), sigs[0], state)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "finalize: "+err.Error())
		return
	}
	token := tokenprofile.PrivateIdentityToken{Input: input, Authenticator: authenticator}

	s.mu.Lock()
	sess.Minted = true
	s.mu.Unlock()
	s.log.Info("minted", "session", sess.ID, "bucket", bucket[:12])

	writeJSON(w, http.StatusOK, mintResponse{
		TokenFamily:  string(tokenauth.TokenPrivateIdentity),
		TokenB64:     b64.EncodeToString(token.Bytes()),
		HolderAlg:    "ed25519",
		HolderPubB64: b64.EncodeToString(raw),
		KeyVersion:   s.issuer.KeyVersion(),
		Note: "Blinded PoMFRIT/MAYO signature over the client-held holder key. " +
			"No email address is in the token; presenting it reveals only an origin-bound pseudonym.",
	})
}
