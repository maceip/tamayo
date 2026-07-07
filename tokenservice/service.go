package tokenservice

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/maceip/tamayo/emailtoken"
	"github.com/maceip/tamayo/tokenauth"
	"github.com/maceip/tamayo/tokenprofile"
)

type Issuer struct {
	blind   *tokenprofile.Issuer
	email   *emailtoken.Signer
	pqEmail *emailtoken.PQSigner
}

type Verifier struct {
	blind   *tokenprofile.Issuer
	email   *emailtoken.Verifier
	pqEmail *emailtoken.PQVerifier
}

type BlindMintRequest struct {
	Decision tokenauth.MintDecision
	Family   tokenauth.TokenFamily
	Blinded  [][]byte
	Now      time.Time
}

type PolicyEmailIssueRequest struct {
	Decision   tokenauth.MintDecision
	Email      string
	HolderJWK  emailtoken.JWK
	IssuedAt   time.Time
	TTL        time.Duration
	DecisionID string
	// Rnd selects hedged ML-DSA signing on the PQ rail (32 fresh CSPRNG
	// bytes); nil means deterministic. Ignored by the Ed25519 rail.
	Rnd []byte
}

func NewIssuer(blind *tokenprofile.Issuer, email *emailtoken.Signer) (*Issuer, error) {
	if blind == nil && email == nil {
		return nil, errors.New("at least one issuer rail is required")
	}
	return &Issuer{blind: blind, email: email}, nil
}

// NewIssuerWithPQEmail additionally mounts the post-quantum policy-bound
// email rail (ML-DSA-44 JWS; see docs/pq-email-profile.md).
func NewIssuerWithPQEmail(blind *tokenprofile.Issuer, email *emailtoken.Signer, pqEmail *emailtoken.PQSigner) (*Issuer, error) {
	if blind == nil && email == nil && pqEmail == nil {
		return nil, errors.New("at least one issuer rail is required")
	}
	return &Issuer{blind: blind, email: email, pqEmail: pqEmail}, nil
}

func (s *Issuer) Verifier() *Verifier {
	var emailVerifier *emailtoken.Verifier
	if s.email != nil {
		emailVerifier = s.email.Verifier()
	}
	var pqVerifier *emailtoken.PQVerifier
	if s.pqEmail != nil {
		pqVerifier = s.pqEmail.Verifier()
	}
	return &Verifier{
		blind:   s.blind,
		email:   emailVerifier,
		pqEmail: pqVerifier,
	}
}

func (s *Issuer) BlindIssuer() *tokenprofile.Issuer {
	return s.blind
}

func (s *Issuer) EmailSigner() *emailtoken.Signer {
	return s.email
}

func (s *Issuer) SignAuthorizedBlind(req BlindMintRequest) ([][]byte, error) {
	if s.blind == nil {
		return nil, errors.New("blind issuer not configured")
	}
	switch req.Family {
	case tokenauth.TokenBurn, tokenauth.TokenPrivateIdentity:
	default:
		return nil, fmt.Errorf("token family %q is not a blind token family", req.Family)
	}
	if err := validateDecision(req.Decision, req.Family, len(req.Blinded), s.blind.KeyVersion(), req.Now); err != nil {
		return nil, err
	}
	// The authorization must be bound to these exact blinded targets
	// (eat-pass issue_authorized: binding_of(blinded) == auth.binding), so a
	// decision cannot be replayed for a different batch even though the
	// issuer never sees token contents.
	binding := tokenprofile.BindingOf(req.Blinded)
	if base64.RawURLEncoding.EncodeToString(binding[:]) != req.Decision.Constraints.BindingB64 {
		return nil, errors.New("authorization binding does not match blinded targets")
	}
	return s.blind.BlindSign(req.Blinded)
}

func policyEmailOptions(req PolicyEmailIssueRequest) (emailtoken.PolicyEmailIssueOptions, error) {
	if err := validateDecision(req.Decision, tokenauth.TokenPolicyEmail, 1, 0, req.IssuedAt); err != nil {
		return emailtoken.PolicyEmailIssueOptions{}, err
	}
	if req.Email == "" {
		return emailtoken.PolicyEmailIssueOptions{}, errors.New("email required")
	}
	if req.Decision.Constraints.Address != "" && !strings.EqualFold(req.Decision.Constraints.Address, req.Email) {
		return emailtoken.PolicyEmailIssueOptions{}, errors.New("email does not match authorization decision")
	}
	return emailtoken.PolicyEmailIssueOptions{
		Email:     req.Email,
		HolderJWK: req.HolderJWK,
		Policy: emailtoken.PolicyBinding{
			TokenFamily:             string(req.Decision.Constraints.TokenFamily),
			BindingB64:              req.Decision.Constraints.BindingB64,
			BudgetKey:               req.Decision.Constraints.BudgetKey,
			Origin:                  req.Decision.Constraints.Origin,
			AuthorizationExpiresAt:  req.Decision.Constraints.ExpiresAt,
			AuthorizationDecisionID: req.DecisionID,
		},
		IssuedAt: req.IssuedAt,
		TTL:      req.TTL,
		Rnd:      req.Rnd,
	}, nil
}

func (s *Issuer) IssuePolicyEmail(req PolicyEmailIssueRequest) (string, error) {
	if s.email == nil {
		return "", errors.New("email signer not configured")
	}
	opts, err := policyEmailOptions(req)
	if err != nil {
		return "", err
	}
	return s.email.IssuePolicyEmail(opts)
}

// IssuePolicyEmailPQ issues the policy-bound email row under the ML-DSA-44
// profile, with the same authorization gate as the classical rail.
func (s *Issuer) IssuePolicyEmailPQ(req PolicyEmailIssueRequest) (string, error) {
	if s.pqEmail == nil {
		return "", errors.New("pq email signer not configured")
	}
	opts, err := policyEmailOptions(req)
	if err != nil {
		return "", err
	}
	return s.pqEmail.IssuePolicyEmail(opts)
}

func (s *Issuer) IssueGoogleEVT(opts emailtoken.IssueOptions) (string, error) {
	if s.email == nil {
		return "", errors.New("email signer not configured")
	}
	return s.email.IssueEVT(opts)
}

func (v *Verifier) VerifyBurnTokenBytes(tokenBytes []byte, challengeDigest [32]byte) (tokenprofile.BurnToken, error) {
	if v.blind == nil {
		return tokenprofile.BurnToken{}, errors.New("blind verifier not configured")
	}
	token, err := tokenprofile.ParseBurnToken(tokenBytes)
	if err != nil {
		return tokenprofile.BurnToken{}, err
	}
	if err := v.blind.VerifyBurnToken(token, challengeDigest); err != nil {
		return tokenprofile.BurnToken{}, err
	}
	return token, nil
}

func (v *Verifier) VerifyPrivateIdentityPresentation(p tokenprofile.PrivateIdentityPresentation, now time.Time, maxSkew time.Duration) ([32]byte, error) {
	if v.blind == nil {
		return [32]byte{}, errors.New("blind verifier not configured")
	}
	return v.blind.VerifyPrivateIdentityPresentation(p, now, maxSkew)
}

func (v *Verifier) VerifyGoogleEVTPresentation(presentation string, opts emailtoken.PresentationVerifyOptions) (emailtoken.VerifiedPresentation, error) {
	if v.email == nil {
		return emailtoken.VerifiedPresentation{}, errors.New("email verifier not configured")
	}
	return v.email.VerifyPresentation(presentation, opts)
}

func (v *Verifier) VerifyPolicyEmailPresentation(presentation string, opts emailtoken.PresentationVerifyOptions) (emailtoken.VerifiedPolicyEmailPresentation, error) {
	if v.email == nil {
		return emailtoken.VerifiedPolicyEmailPresentation{}, errors.New("email verifier not configured")
	}
	return v.email.VerifyPolicyEmailPresentation(presentation, opts)
}

func (v *Verifier) VerifyPolicyEmailPresentationPQ(presentation string, opts emailtoken.PresentationVerifyOptions) (emailtoken.VerifiedPolicyEmailPresentation, error) {
	if v.pqEmail == nil {
		return emailtoken.VerifiedPolicyEmailPresentation{}, errors.New("pq email verifier not configured")
	}
	return v.pqEmail.VerifyPolicyEmailPresentation(presentation, opts)
}

func validateDecision(decision tokenauth.MintDecision, family tokenauth.TokenFamily, count int, keyVersion uint32, now time.Time) error {
	if !decision.Allow {
		if decision.Reason == "" {
			return errors.New("authorization decision denied")
		}
		return fmt.Errorf("authorization decision denied: %s", decision.Reason)
	}
	if decision.Constraints.TokenFamily != family {
		return fmt.Errorf("authorization decision is for %q, want %q", decision.Constraints.TokenFamily, family)
	}
	if count <= 0 {
		return errors.New("count must be > 0")
	}
	if decision.Constraints.Count != count {
		return fmt.Errorf("authorization decision count is %d, want %d", decision.Constraints.Count, count)
	}
	if keyVersion != 0 && decision.Constraints.KeyVersion != keyVersion {
		return fmt.Errorf("authorization decision key version is %d, want %d", decision.Constraints.KeyVersion, keyVersion)
	}
	if decision.Constraints.BindingB64 == "" {
		return errors.New("authorization decision missing binding")
	}
	if decision.Constraints.ExpiresAt == 0 {
		return errors.New("authorization decision missing expiry")
	}
	if !now.IsZero() && now.Unix() > decision.Constraints.ExpiresAt {
		return errors.New("authorization decision expired")
	}
	return nil
}
