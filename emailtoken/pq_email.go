package emailtoken

// The post-quantum email-signing profile (token-roadmap cleanup item 5): the
// policy-bound email token signed with ML-DSA-44 instead of Ed25519. JOSE
// representation follows draft-ietf-cose-dilithium: alg "ML-DSA-44", holder
// and issuer keys as kty "AKP" JWKs with the raw public key in "pub". Those
// registrations are still IETF drafts, not final IANA entries; the profile
// is documented in docs/pq-email-profile.md and must be versioned if the
// draft names change. The Google EVT rail intentionally stays classical
// (roadmap row 4).

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/maceip/tamayo/mldsa"
)

const (
	AlgMLDSA44 = "ML-DSA-44" // draft-ietf-cose-dilithium JOSE alg
	KtyAKP     = "AKP"       // Algorithm Key Pair key type
)

// PublicJWKMLDSA44 wraps a raw ML-DSA-44 public key as an AKP JWK.
func PublicJWKMLDSA44(pub []byte, kid string) (JWK, error) {
	if len(pub) != mldsa.MLDSA44.PublicKeySize {
		return JWK{}, fmt.Errorf("ml-dsa-44 public key is %d bytes, want %d", len(pub), mldsa.MLDSA44.PublicKeySize)
	}
	return JWK{
		Kty: KtyAKP,
		Pub: encode(pub),
		Kid: kid,
		Alg: AlgMLDSA44,
		Use: "sig",
	}, nil
}

// MLDSA44PublicKey extracts the raw public key from an AKP/ML-DSA-44 JWK.
func (j JWK) MLDSA44PublicKey() ([]byte, error) {
	if j.Kty != KtyAKP || (j.Alg != "" && j.Alg != AlgMLDSA44) {
		return nil, errors.New("jwk must be AKP/ML-DSA-44")
	}
	pub, err := decode(j.Pub)
	if err != nil {
		return nil, fmt.Errorf("jwk pub: %w", err)
	}
	if len(pub) != mldsa.MLDSA44.PublicKeySize {
		return nil, fmt.Errorf("jwk pub is %d bytes, want %d", len(pub), mldsa.MLDSA44.PublicKeySize)
	}
	return pub, nil
}

// checkHolderJWK accepts the two supported cnf key shapes: OKP/Ed25519
// (classical) and, when allowAKP is set, AKP/ML-DSA-44 (post-quantum).
func checkHolderJWK(j JWK, allowAKP bool) error {
	if j.Kty == KtyAKP {
		if !allowAKP {
			return errors.New("AKP holder keys require the PQ profile")
		}
		_, err := j.MLDSA44PublicKey()
		return err
	}
	_, err := j.Ed25519PublicKey()
	return err
}

var zeroRnd [32]byte

// pqSignJWS mirrors signJWS with a deterministic-by-default ML-DSA-44
// signature; pass 32 bytes of fresh randomness as rnd for hedged signing.
func pqSignJWS(header Header, claims any, priv, rnd []byte) (string, error) {
	if len(priv) != mldsa.MLDSA44.PrivateKeySize {
		return "", fmt.Errorf("ml-dsa-44 private key is %d bytes, want %d", len(priv), mldsa.MLDSA44.PrivateKeySize)
	}
	if rnd == nil {
		rnd = zeroRnd[:]
	}
	header.Alg = AlgMLDSA44
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := encode(h) + "." + encode(p)
	sig, err := mldsa.MLDSA44.Sign(priv, []byte(signingInput), nil, rnd)
	if err != nil {
		return "", err
	}
	return signingInput + "." + encode(sig), nil
}

// pqVerifyJWS mirrors verifyJWS for alg ML-DSA-44.
func pqVerifyJWS(compact string, pub []byte) (Header, []byte, error) {
	if len(pub) != mldsa.MLDSA44.PublicKeySize {
		return Header{}, nil, fmt.Errorf("ml-dsa-44 public key is %d bytes, want %d", len(pub), mldsa.MLDSA44.PublicKeySize)
	}
	parts := strings.Split(strings.TrimSpace(compact), ".")
	if len(parts) != 3 {
		return Header{}, nil, errors.New("jws must have three segments")
	}
	headerBytes, err := decode(parts[0])
	if err != nil {
		return Header{}, nil, fmt.Errorf("jws header: %w", err)
	}
	var header Header
	dec := json.NewDecoder(bytes.NewReader(headerBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&header); err != nil {
		return Header{}, nil, err
	}
	if header.Alg != AlgMLDSA44 {
		return Header{}, nil, fmt.Errorf("jws alg %q unsupported", header.Alg)
	}
	sig, err := decode(parts[2])
	if err != nil {
		return Header{}, nil, fmt.Errorf("jws signature: %w", err)
	}
	if len(sig) != mldsa.MLDSA44.SignatureSize {
		return Header{}, nil, fmt.Errorf("jws signature is %d bytes, want %d", len(sig), mldsa.MLDSA44.SignatureSize)
	}
	signingInput := parts[0] + "." + parts[1]
	if !mldsa.MLDSA44.Verify(pub, []byte(signingInput), sig, nil) {
		return Header{}, nil, errors.New("jws signature rejected")
	}
	payload, err := decode(parts[1])
	if err != nil {
		return Header{}, nil, fmt.Errorf("jws payload: %w", err)
	}
	return header, payload, nil
}

// PQSigner issues policy-bound email tokens under the ML-DSA-44 profile.
type PQSigner struct {
	issuer string
	kid    string
	pub    []byte
	priv   []byte
}

// PQVerifier verifies tokens issued by a PQSigner.
type PQVerifier struct {
	issuer string
	kid    string
	pub    []byte
}

// NewPQSigner derives the ML-DSA-44 key pair from a 32-byte seed, or from
// crypto/rand when seed is empty.
func NewPQSigner(issuer string, seed []byte) (*PQSigner, error) {
	if issuer == "" {
		return nil, errors.New("issuer required")
	}
	if len(seed) == 0 {
		seed = make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
	}
	pub, priv, err := mldsa.MLDSA44.KeyGen(seed)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(pub)
	return &PQSigner{
		issuer: issuer,
		kid:    "ml-dsa-44-" + hex.EncodeToString(sum[:8]),
		pub:    pub,
		priv:   priv,
	}, nil
}

func (s *PQSigner) Issuer() string    { return s.issuer }
func (s *PQSigner) KeyID() string     { return s.kid }
func (s *PQSigner) PublicKey() []byte { return append([]byte(nil), s.pub...) }
func (s *PQSigner) PublicJWK() JWK    { j, _ := PublicJWKMLDSA44(s.pub, s.kid); return j }
func (s *PQSigner) Verifier() *PQVerifier {
	return &PQVerifier{issuer: s.issuer, kid: s.kid, pub: append([]byte(nil), s.pub...)}
}

// NewPQVerifier pins an issuer name and raw ML-DSA-44 public key; kid may be
// empty to skip the header check.
func NewPQVerifier(issuer string, pub []byte, kid string) (*PQVerifier, error) {
	if issuer == "" {
		return nil, errors.New("issuer required")
	}
	if len(pub) != mldsa.MLDSA44.PublicKeySize {
		return nil, fmt.Errorf("ml-dsa-44 public key is %d bytes, want %d", len(pub), mldsa.MLDSA44.PublicKeySize)
	}
	return &PQVerifier{issuer: issuer, kid: kid, pub: append([]byte(nil), pub...)}, nil
}

// IssuePolicyEmail issues the policy-bound email token with an ML-DSA-44
// issuer signature. The holder cnf key may be OKP/Ed25519 or AKP/ML-DSA-44;
// only the latter makes the whole presentation chain post-quantum.
func (s *PQSigner) IssuePolicyEmail(opts PolicyEmailIssueOptions) (string, error) {
	if opts.Email == "" {
		return "", errors.New("email required")
	}
	if opts.IssuedAt.IsZero() {
		return "", errors.New("issued_at required")
	}
	if err := checkHolderJWK(opts.HolderJWK, true); err != nil {
		return "", fmt.Errorf("holder jwk: %w", err)
	}
	if err := checkPolicyBinding(opts.Policy); err != nil {
		return "", err
	}
	claims := PolicyEmailClaims{
		Iss:           s.issuer,
		Iat:           opts.IssuedAt.Unix(),
		CNF:           Confirmation{JWK: opts.HolderJWK},
		Email:         opts.Email,
		EmailVerified: true,
		Policy:        opts.Policy,
	}
	if opts.TTL > 0 {
		claims.Exp = opts.IssuedAt.Add(opts.TTL).Unix()
	}
	jws, err := pqSignJWS(Header{Typ: TypPolicyEmail, Kid: s.kid}, claims, s.priv, opts.Rnd)
	if err != nil {
		return "", err
	}
	return jws + "~", nil
}

// VerifyPolicyEmail verifies an ML-DSA-44-signed policy-bound email token.
func (v *PQVerifier) VerifyPolicyEmail(token string, opts VerifyOptions) (PolicyEmailClaims, error) {
	token = strings.TrimSpace(token)
	if !strings.HasSuffix(token, "~") {
		return PolicyEmailClaims{}, errors.New("policy email token must include trailing tilde")
	}
	header, payload, err := pqVerifyJWS(strings.TrimSuffix(token, "~"), v.pub)
	if err != nil {
		return PolicyEmailClaims{}, err
	}
	if header.Typ != TypPolicyEmail {
		return PolicyEmailClaims{}, fmt.Errorf("policy email typ %q unsupported", header.Typ)
	}
	if v.kid != "" && header.Kid != v.kid {
		return PolicyEmailClaims{}, errors.New("policy email kid mismatch")
	}
	return checkPolicyEmailClaims(payload, v.issuer, true, opts)
}

// VerifyPolicyEmailPresentation verifies <token>~<KB-JWT> where the token is
// ML-DSA-44-signed and the KB-JWT is signed by the cnf holder key (Ed25519
// or ML-DSA-44).
func (v *PQVerifier) VerifyPolicyEmailPresentation(presentation string, opts PresentationVerifyOptions) (VerifiedPolicyEmailPresentation, error) {
	token, kb, err := splitPresentation(presentation)
	if err != nil {
		return VerifiedPolicyEmailPresentation{}, err
	}
	claims, err := v.VerifyPolicyEmail(token, VerifyOptions{Now: opts.Now, MaxAge: opts.EVTMaxAge})
	if err != nil {
		return VerifiedPolicyEmailPresentation{}, fmt.Errorf("policy email: %w", err)
	}
	kbClaims, err := verifyKBJWTJWK(kb, token, claims.CNF.JWK, opts)
	if err != nil {
		return VerifiedPolicyEmailPresentation{}, err
	}
	return VerifiedPolicyEmailPresentation{
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Token:         claims,
		KB:            kbClaims,
	}, nil
}

// SignKBJWTMLDSA44 is SignKBJWT for an ML-DSA-44 holder key. rnd selects
// hedged signing; nil means deterministic.
func SignKBJWTMLDSA44(holderPriv []byte, tokenWithTilde string, opts PresentationOptions, rnd []byte) (string, error) {
	if opts.Audience == "" {
		return "", errors.New("audience required")
	}
	if opts.IssuedAt.IsZero() {
		return "", errors.New("issued_at required")
	}
	if !strings.HasSuffix(tokenWithTilde, "~") {
		return "", errors.New("token must include trailing tilde")
	}
	claims := KBClaims{
		Aud:    opts.Audience,
		Nonce:  encode(opts.Nonce[:]),
		Iat:    opts.IssuedAt.Unix(),
		SDHash: SDHash(tokenWithTilde),
	}
	return pqSignJWS(Header{Typ: TypKBJWT}, claims, holderPriv, rnd)
}

// verifyKBJWTJWK dispatches KB-JWT verification on the holder cnf key type.
func verifyKBJWTJWK(kbJWT, tokenWithTilde string, holder JWK, opts PresentationVerifyOptions) (KBClaims, error) {
	if holder.Kty == KtyAKP {
		pub, err := holder.MLDSA44PublicKey()
		if err != nil {
			return KBClaims{}, fmt.Errorf("cnf.jwk: %w", err)
		}
		header, payload, err := pqVerifyJWS(kbJWT, pub)
		if err != nil {
			return KBClaims{}, fmt.Errorf("kb-jwt: %w", err)
		}
		return checkKBClaims(header, payload, tokenWithTilde, opts)
	}
	holderPub, err := holder.Ed25519PublicKey()
	if err != nil {
		return KBClaims{}, fmt.Errorf("cnf.jwk: %w", err)
	}
	return verifyKBJWT(kbJWT, tokenWithTilde, holderPub, opts)
}
