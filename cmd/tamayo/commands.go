package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/maceip/tamayo/mayo"
	"github.com/maceip/tamayo/tokenauth"
	"github.com/maceip/tamayo/tokenprofile"
)

// issuerFile is one issuer key epoch: everything needed to recreate the
// MAYO1/PoMFRIT issuer deterministically. Treat it like a private key.
type issuerFile struct {
	KeyVersion   uint32 `json:"key_version"`
	Mayo1SeedB64 string `json:"mayo1_sk_seed_b64"`
}

func loadIssuer(path string) (*tokenprofile.Issuer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f issuerFile
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("issuer file %s: %w", path, err)
	}
	seed, err := base64.RawURLEncoding.DecodeString(f.Mayo1SeedB64)
	if err != nil {
		return nil, fmt.Errorf("issuer file %s: seed: %w", path, err)
	}
	return tokenprofile.NewIssuer(f.KeyVersion, seed)
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "issuer.json", "path to write the issuer key-epoch file")
	keyVersion := fs.Uint("key-version", 1, "issuer key version (epoch)")
	fs.Parse(args)

	seed := make([]byte, mayo.Mayo1.SKSeedBytes)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	issuer, err := tokenprofile.NewIssuer(uint32(*keyVersion), seed)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(issuerFile{
		KeyVersion:   uint32(*keyVersion),
		Mayo1SeedB64: base64.RawURLEncoding.EncodeToString(seed),
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	id := issuer.TokenKeyID()
	fmt.Printf("wrote %s (secret — 0600)\nkey_version:  %d\ntoken_key_id: %s\nalgorithm:    %s\n",
		*out, *keyVersion, hex.EncodeToString(id[:]), tokenprofile.Algorithm)
	return nil
}

// mintBurn runs the whole blind loop in one process: the "client" half
// (nonce, blinding, finalize) and the issuer half (blind sign). The issuer
// never sees the token contents even here — the halves only exchange the
// blinded target and the blind signature.
func mintBurn(issuer *tokenprofile.Issuer, challenge []byte) (tokenprofile.BurnToken, error) {
	var nonce, additionalR [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return tokenprofile.BurnToken{}, err
	}
	if _, err := rand.Read(additionalR[:]); err != nil {
		return tokenprofile.BurnToken{}, err
	}
	challengeDigest := sha256.Sum256(challenge)

	input := tokenprofile.BurnInput(nonce, challengeDigest, issuer.TokenKeyID())
	target, state := tokenprofile.PrepareBlind(input, additionalR)
	sigs, err := issuer.BlindSign([][]byte{target})
	if err != nil {
		return tokenprofile.BurnToken{}, err
	}
	authenticator, err := tokenprofile.FinalizeBlind(issuer.ExpandedPublicKey(), sigs[0], state)
	if err != nil {
		return tokenprofile.BurnToken{}, err
	}
	return tokenprofile.BurnToken{
		TokenType:       tokenprofile.BurnTokenType,
		Nonce:           nonce,
		ChallengeDigest: challengeDigest,
		TokenKeyID:      issuer.TokenKeyID(),
		Authenticator:   authenticator,
	}, nil
}

func cmdMintBurn(args []string) error {
	fs := flag.NewFlagSet("mint-burn", flag.ExitOnError)
	issuerPath := fs.String("issuer", "issuer.json", "issuer key-epoch file")
	challenge := fs.String("challenge", "", "origin challenge string (digested with sha-256)")
	out := fs.String("out", "", "write the base64 token here (default stdout)")
	fs.Parse(args)
	if *challenge == "" {
		return errors.New("mint-burn: -challenge is required")
	}
	issuer, err := loadIssuer(*issuerPath)
	if err != nil {
		return err
	}
	token, err := mintBurn(issuer, []byte(*challenge))
	if err != nil {
		return err
	}
	enc := base64.RawURLEncoding.EncodeToString(token.Bytes()) + "\n"
	if *out == "" || *out == "-" {
		fmt.Print(enc)
		return nil
	}
	if err := os.WriteFile(*out, []byte(enc), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d token bytes; spend it once)\n", *out, len(token.Bytes()))
	return nil
}

func cmdVerifyBurn(args []string) error {
	fs := flag.NewFlagSet("verify-burn", flag.ExitOnError)
	issuerPath := fs.String("issuer", "issuer.json", "issuer key-epoch file")
	tokenPath := fs.String("token", "-", "base64 token file, or - for stdin")
	challenge := fs.String("challenge", "", "origin challenge string the token must be bound to")
	fs.Parse(args)
	if *challenge == "" {
		return errors.New("verify-burn: -challenge is required")
	}
	issuer, err := loadIssuer(*issuerPath)
	if err != nil {
		return err
	}
	var raw []byte
	if *tokenPath == "-" {
		if raw, err = io.ReadAll(os.Stdin); err != nil {
			return err
		}
	} else if raw, err = os.ReadFile(*tokenPath); err != nil {
		return err
	}
	tokenBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return fmt.Errorf("token is not base64url: %w", err)
	}
	token, err := tokenprofile.ParseBurnToken(tokenBytes)
	if err != nil {
		return err
	}
	if err := issuer.VerifyBurnToken(token, sha256.Sum256([]byte(*challenge))); err != nil {
		return fmt.Errorf("REJECTED: %w", err)
	}
	fmt.Println("OK — signature and challenge binding verified (double-spend accounting is the caller's job)")
	return nil
}

func cmdDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	issuerPath := fs.String("issuer", "", "issuer key-epoch file (default: fresh in-memory issuer)")
	fs.Parse(args)

	var issuer *tokenprofile.Issuer
	var err error
	if *issuerPath != "" {
		issuer, err = loadIssuer(*issuerPath)
	} else {
		issuer, err = tokenprofile.NewIssuer(1, nil)
	}
	if err != nil {
		return err
	}
	id := issuer.TokenKeyID()
	fmt.Printf("issuer: key_version=%d token_key_id=%s\n", issuer.KeyVersion(), hex.EncodeToString(id[:8]))

	// Burn token: blind mint, verify, reject wrong challenge.
	token, err := mintBurn(issuer, []byte("demo origin challenge"))
	if err != nil {
		return err
	}
	if err := issuer.VerifyBurnToken(token, sha256.Sum256([]byte("demo origin challenge"))); err != nil {
		return fmt.Errorf("burn verify: %w", err)
	}
	if err := issuer.VerifyBurnToken(token, sha256.Sum256([]byte("other challenge"))); err == nil {
		return errors.New("burn token verified against the wrong challenge")
	}
	fmt.Printf("burn:   blind mint -> verify OK, wrong challenge rejected (%d bytes)\n", len(token.Bytes()))

	// Private identity token: blind mint, present with an Ed25519 holder
	// proof, check the origin-bound pseudonym.
	holderPub, holderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	input := tokenprofile.NewPrivateIdentityInput(issuer.KeyVersion(), issuer.TokenKeyID(), tokenprofile.HolderAlgEd25519, holderPub)
	var additionalR [32]byte
	if _, err := rand.Read(additionalR[:]); err != nil {
		return err
	}
	target, state := tokenprofile.PrepareBlind(input.Bytes(), additionalR)
	sigs, err := issuer.BlindSign([][]byte{target})
	if err != nil {
		return err
	}
	authenticator, err := tokenprofile.FinalizeBlind(issuer.ExpandedPublicKey(), sigs[0], state)
	if err != nil {
		return err
	}
	pvt := tokenprofile.PrivateIdentityToken{Input: input, Authenticator: authenticator}

	now := time.Now()
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	msg := tokenprofile.PrivateIdentityPresentationMessage("rp.example", nonce, pvt.Digest(), now.Unix())
	pseudonym, err := issuer.VerifyPrivateIdentityPresentation(tokenprofile.PrivateIdentityPresentation{
		Token:     pvt,
		Origin:    "rp.example",
		Nonce:     nonce,
		IssuedAt:  now.Unix(),
		Signature: ed25519.Sign(holderPriv, msg),
	}, now, time.Minute)
	if err != nil {
		return fmt.Errorf("private identity verify: %w", err)
	}
	fmt.Printf("pvt:    blind mint -> present OK, pseudonym@rp.example=%s\n", hex.EncodeToString(pseudonym[:8]))
	fmt.Println("RESULT: PASS")
	return nil
}

// examplePolicy is a development-mode tokenauth policy that the serve
// command can consume as-is: burn and private-identity rows gated on a TEE
// measurement, with small per-bucket budgets.
func examplePolicy() tokenauth.Source {
	return tokenauth.Source{
		Version: 1,
		Mode:    tokenauth.ModeDevelopment,
		Defaults: tokenauth.Defaults{
			AllowSoftwareWitness: true,
			MaxBatch:             8,
			AuthorizationTTL:     120,
		},
		TokenFamilies: map[string]tokenauth.TokenRule{
			string(tokenauth.TokenBurn): {
				Enabled:             true,
				AllowedGates:        []string{string(tokenauth.GateTEE)},
				BudgetGroup:         "burn",
				RequiresAttestation: true,
			},
			string(tokenauth.TokenPrivateIdentity): {
				Enabled:             true,
				AllowedGates:        []string{string(tokenauth.GateTEE)},
				BudgetGroup:         "private",
				RequiresAttestation: true,
			},
		},
		Gates: map[string]tokenauth.GateRule{
			string(tokenauth.GateTEE): {Enabled: true},
		},
		Measurements: []tokenauth.MeasurementRule{{
			ValueX: "dev-measurement",
			Allow:  []string{string(tokenauth.TokenBurn), string(tokenauth.TokenPrivateIdentity)},
		}},
		Budgets: map[string]tokenauth.BudgetRule{
			"burn":    {Limit: 16, WindowSeconds: 3600},
			"private": {Limit: 4, WindowSeconds: 3600},
		},
	}
}

func cmdExamplePolicy(args []string) error {
	fs := flag.NewFlagSet("example-policy", flag.ExitOnError)
	fs.Parse(args)
	raw, err := json.MarshalIndent(examplePolicy(), "", "  ")
	if err != nil {
		return err
	}
	// Prove the printed policy compiles before handing it to the user.
	if _, err := tokenauth.CompileJSON(raw); err != nil {
		return fmt.Errorf("internal: example policy does not compile: %w", err)
	}
	fmt.Println(string(raw))
	return nil
}

// policyKeyFile is an operator's policy-signing key: the 32-byte seed the
// FAEST-128f key pair derives from. Treat it like a private key.
type policyKeyFile struct {
	SeedB64 string `json:"policy_signing_seed_b64"`
}

func loadOrCreatePolicySigner(path string) (*tokenauth.PolicySigner, error) {
	if raw, err := os.ReadFile(path); err == nil {
		var f policyKeyFile
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&f); err != nil {
			return nil, fmt.Errorf("policy key file %s: %w", path, err)
		}
		seed, err := base64.RawURLEncoding.DecodeString(f.SeedB64)
		if err != nil {
			return nil, fmt.Errorf("policy key file %s: %w", path, err)
		}
		return tokenauth.NewPolicySigner(seed)
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	raw, err := json.MarshalIndent(policyKeyFile{SeedB64: base64.RawURLEncoding.EncodeToString(seed)}, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "wrote new policy signing key %s (secret — 0600)\n", path)
	return tokenauth.NewPolicySigner(seed)
}

// cmdSignPolicy writes the FAEST-128f sidecar for a policy file, so a
// runtime configured with the operator's public key refuses any policy
// that was not signed by it.
func cmdSignPolicy(args []string) error {
	fs := flag.NewFlagSet("sign-policy", flag.ExitOnError)
	policyPath := fs.String("policy", "policy.json", "policy JSON to sign")
	keyPath := fs.String("key", "policy-key.json", "operator signing key file (created if absent)")
	fs.Parse(args)

	signer, err := loadOrCreatePolicySigner(*keyPath)
	if err != nil {
		return err
	}
	policyJSON, err := os.ReadFile(*policyPath)
	if err != nil {
		return err
	}
	sidecar, err := signer.SignPolicy(policyJSON, nil)
	if err != nil {
		return err
	}
	sigPath := *policyPath + ".sig"
	if err := os.WriteFile(sigPath, []byte(sidecar+"\n"), 0o644); err != nil {
		return err
	}
	pub := signer.Public()
	fmt.Printf("wrote %s\noperator public key (for serve -policy-pub): %s\n", sigPath, hex.EncodeToString(pub[:]))
	return nil
}
