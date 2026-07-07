package emailtoken

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const TypPolicyEmail = "tamayo-policy-email+jwt"

type PolicyBinding struct {
	TokenFamily             string `json:"token_family"`
	BindingB64              string `json:"binding_b64"`
	BudgetKey               string `json:"budget_key"`
	Origin                  string `json:"origin,omitempty"`
	AuthorizationExpiresAt  int64  `json:"authorization_expires_at"`
	AuthorizationDecisionID string `json:"authorization_decision_id,omitempty"`
}

type PolicyEmailClaims struct {
	Iss           string        `json:"iss"`
	Iat           int64         `json:"iat"`
	Exp           int64         `json:"exp,omitempty"`
	CNF           Confirmation  `json:"cnf"`
	Email         string        `json:"email"`
	EmailVerified bool          `json:"email_verified"`
	Policy        PolicyBinding `json:"policy"`
}

type PolicyEmailIssueOptions struct {
	Email     string
	HolderJWK JWK
	Policy    PolicyBinding
	IssuedAt  time.Time
	TTL       time.Duration
	// Rnd selects hedged ML-DSA signing on the PQ profile (32 fresh CSPRNG
	// bytes); nil means deterministic. Ignored by the Ed25519 signer.
	Rnd []byte
}

type VerifiedPolicyEmailPresentation struct {
	Email         string
	EmailVerified bool
	Token         PolicyEmailClaims
	KB            KBClaims
}

func (s *Signer) IssuePolicyEmail(opts PolicyEmailIssueOptions) (string, error) {
	if opts.Email == "" {
		return "", errors.New("email required")
	}
	if opts.IssuedAt.IsZero() {
		return "", errors.New("issued_at required")
	}
	if _, err := opts.HolderJWK.Ed25519PublicKey(); err != nil {
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
	jws, err := signJWS(Header{Typ: TypPolicyEmail, Kid: s.kid}, claims, s.priv)
	if err != nil {
		return "", err
	}
	return jws + "~", nil
}

func (v *Verifier) VerifyPolicyEmail(token string, opts VerifyOptions) (PolicyEmailClaims, error) {
	token = strings.TrimSpace(token)
	if !strings.HasSuffix(token, "~") {
		return PolicyEmailClaims{}, errors.New("policy email token must include trailing tilde")
	}
	compact := strings.TrimSuffix(token, "~")
	header, payload, err := verifyJWS(compact, v.pub)
	if err != nil {
		return PolicyEmailClaims{}, err
	}
	if header.Typ != TypPolicyEmail {
		return PolicyEmailClaims{}, fmt.Errorf("policy email typ %q unsupported", header.Typ)
	}
	if v.kid != "" && header.Kid != v.kid {
		return PolicyEmailClaims{}, errors.New("policy email kid mismatch")
	}
	return checkPolicyEmailClaims(payload, v.issuer, false, opts)
}

// checkPolicyBinding validates the issuance-side policy binding fields.
func checkPolicyBinding(p PolicyBinding) error {
	if strings.TrimSpace(p.TokenFamily) == "" {
		return errors.New("policy token_family required")
	}
	if p.BindingB64 == "" {
		return errors.New("policy binding_b64 required")
	}
	if p.BudgetKey == "" {
		return errors.New("policy budget_key required")
	}
	return nil
}

// checkPolicyEmailClaims validates the decoded policy email payload; the
// classical profile requires an Ed25519 holder key, the PQ profile also
// accepts AKP/ML-DSA-44 (allowAKP).
func checkPolicyEmailClaims(payload []byte, issuer string, allowAKP bool, opts VerifyOptions) (PolicyEmailClaims, error) {
	var claims PolicyEmailClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return PolicyEmailClaims{}, err
	}
	if claims.Iss != issuer {
		return PolicyEmailClaims{}, errors.New("policy email issuer mismatch")
	}
	if !claims.EmailVerified {
		return PolicyEmailClaims{}, errors.New("policy email email_verified must be true")
	}
	if claims.Email == "" {
		return PolicyEmailClaims{}, errors.New("policy email address required")
	}
	if err := checkHolderJWK(claims.CNF.JWK, allowAKP); err != nil {
		return PolicyEmailClaims{}, fmt.Errorf("policy email cnf.jwk: %w", err)
	}
	if claims.Policy.TokenFamily == "" || claims.Policy.BindingB64 == "" || claims.Policy.BudgetKey == "" {
		return PolicyEmailClaims{}, errors.New("policy email binding is incomplete")
	}
	if err := checkTime("policy email", claims.Iat, claims.Exp, opts.Now, opts.MaxAge); err != nil {
		return PolicyEmailClaims{}, err
	}
	return claims, nil
}

func (v *Verifier) VerifyPolicyEmailPresentation(presentation string, opts PresentationVerifyOptions) (VerifiedPolicyEmailPresentation, error) {
	token, kb, err := splitPresentation(presentation)
	if err != nil {
		return VerifiedPolicyEmailPresentation{}, err
	}
	claims, err := v.VerifyPolicyEmail(token, VerifyOptions{Now: opts.Now, MaxAge: opts.EVTMaxAge})
	if err != nil {
		return VerifiedPolicyEmailPresentation{}, fmt.Errorf("policy email: %w", err)
	}
	holderPub, err := claims.CNF.JWK.Ed25519PublicKey()
	if err != nil {
		return VerifiedPolicyEmailPresentation{}, fmt.Errorf("policy email cnf.jwk: %w", err)
	}
	kbClaims, err := verifyKBJWT(kb, token, holderPub, opts)
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
