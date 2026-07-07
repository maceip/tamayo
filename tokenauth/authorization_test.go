package tokenauth

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func testAuthorization(t *testing.T, signer *AttesterSigner) *IssuanceAuthorization {
	t.Helper()
	auth := &IssuanceAuthorization{
		Version:     AuthorizationVersion,
		BindingHex:  hex.EncodeToString(bytes32(0xB1)[:]),
		RateLimitID: []byte("bucket-1"),
		PolicyLabel: "mailbox@v1",
		MaxBatch:    4,
		Iat:         1000,
		Exp:         1000 + DefaultAuthorizationTTLSecs,
	}
	if err := signer.Sign(auth, nil); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return auth
}

// TestIssuanceAuthorizationRoundTrip pins the signed envelope: sign, JSON
// round trip, verify; reject expiry, tamper, wrong key, zero batch, bad
// version.
func TestIssuanceAuthorizationRoundTrip(t *testing.T) {
	signer, err := NewAttesterSigner(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	auth := testAuthorization(t, signer)

	raw, err := json.Marshal(auth)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"policy_label":"mailbox@v1"`) {
		t.Fatalf("wire shape: %s", raw)
	}
	var parsed IssuanceAuthorization
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if err := parsed.Normalize(); err != nil {
		t.Fatal(err)
	}
	if err := parsed.Verify(signer.Public(), 1010); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if err := parsed.Verify(signer.Public(), parsed.Exp+1); err == nil {
		t.Fatal("expired authorization accepted")
	}
	attacker, _ := NewAttesterSigner(append(make([]byte, 31), 1))
	if err := parsed.Verify(attacker.Public(), 1010); err == nil {
		t.Fatal("wrong attester key accepted")
	}
	tampered := parsed
	tampered.MaxBatch = 99
	if err := tampered.Verify(signer.Public(), 1010); err == nil {
		t.Fatal("tampered max_batch accepted")
	}
	zero := parsed
	zero.MaxBatch = 0
	if err := zero.Verify(signer.Public(), 1010); err == nil {
		t.Fatal("zero max_batch accepted")
	}
	wrongVer := parsed
	wrongVer.Version = 2
	if err := wrongVer.Verify(signer.Public(), 1010); err == nil {
		t.Fatal("unknown version accepted")
	}
}

// TestPolicySidecar pins sidecar signing: a compiled policy signs and
// verifies, any trusted key suffices, tampered bytes and untrusted keys are
// rejected, and an empty trusted set disables the check.
func TestPolicySidecar(t *testing.T) {
	policyJSON, err := json.Marshal(Source{
		Version:  1,
		Mode:     ModeDevelopment,
		Defaults: Defaults{AllowSoftwareWitness: true, MaxBatch: 1, AuthorizationTTL: 60},
		TokenFamilies: map[string]TokenRule{
			string(TokenBurn): {Enabled: true, AllowedGates: []string{string(GateTEE)}, BudgetGroup: "b", RequiresAttestation: true},
		},
		Gates:        map[string]GateRule{string(GateTEE): {Enabled: true}},
		Measurements: []MeasurementRule{{ValueX: "m", Allow: []string{string(TokenBurn)}}},
		Budgets:      map[string]BudgetRule{"b": {Limit: 1, WindowSeconds: 60}},
	})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewPolicySigner(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	sidecar, err := signer.SignPolicy(policyJSON, nil)
	if err != nil {
		t.Fatalf("SignPolicy: %v", err)
	}

	other, _ := NewPolicySigner(append(make([]byte, 31), 2))
	if err := VerifyPolicySidecar(policyJSON, sidecar, [][32]byte{other.Public(), signer.Public()}); err != nil {
		t.Fatalf("verify under trusted set: %v", err)
	}
	if err := VerifyPolicySidecar(append(policyJSON, ' '), sidecar, [][32]byte{signer.Public()}); err == nil {
		t.Fatal("tampered policy bytes accepted")
	}
	if err := VerifyPolicySidecar(policyJSON, sidecar, [][32]byte{other.Public()}); err == nil {
		t.Fatal("untrusted key accepted")
	}
	if err := VerifyPolicySidecar(policyJSON, "not-configured", nil); err != nil {
		t.Fatal("empty trusted set must disable the check")
	}
	if _, err := signer.SignPolicy([]byte(`{"not": "a policy"}`), nil); err == nil {
		t.Fatal("non-compiling policy signed")
	}
}
