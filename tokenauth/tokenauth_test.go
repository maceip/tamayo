package tokenauth

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCompileRejectsUnknownFields(t *testing.T) {
	raw := []byte(`{
		"version": 1,
		"mode": "production",
		"defaults": {
			"allow_software_witness": false,
			"max_batch": 1,
			"authorization_ttl_seconds": 60,
			"unexpected": true
		},
		"token_families": {},
		"bridges": {},
		"budgets": {}
	}`)
	_, err := CompileJSON(raw)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("CompileJSON error = %v", err)
	}
}

func TestAuthorizePrivateIdentityWithTEEAndOrigin(t *testing.T) {
	policy := compileTestPolicy(t, Source{
		Version: 1,
		Mode:    ModeProduction,
		Defaults: Defaults{
			MaxBatch:         4,
			AuthorizationTTL: 60,
		},
		TokenFamilies: map[string]TokenRule{
			string(TokenPrivateIdentity): {
				Enabled:             true,
				AllowedBridges:      []string{string(BridgeTEE)},
				AllowedOrigins:      []string{"rp.example"},
				BudgetGroup:         "private",
				RequiresAttestation: true,
				RequiresOrigin:      true,
			},
		},
		Bridges: map[string]BridgeRule{
			string(BridgeTEE): {
				Enabled:     true,
				BucketClaim: "runtime_id",
			},
		},
		Measurements: []MeasurementRule{{
			ValueX: "mayo-faest-runtime-measurement",
			Allow:  []string{string(TokenPrivateIdentity)},
		}},
		Budgets: map[string]BudgetRule{
			"private": {Limit: 8, WindowSeconds: 3600},
		},
	})
	req := MintRequest{
		Subject: Subject{
			ValueX:   "mayo-faest-runtime-measurement",
			Platform: "tamago",
		},
		Eligibility: []Eligibility{{
			BridgeKind: BridgeTEE,
			BucketID:   "runtime-1",
			Assurance:  AssuranceVerified,
			Claims:     map[string]string{"runtime_id": "runtime-1"},
		}},
		TokenFamily: TokenPrivateIdentity,
		Count:       2,
		KeyVersion:  7,
		Origin:      "rp.example",
		Binding:     bytes32(0x11),
	}
	decision := policy.AuthorizeMint(req, nil, time.Unix(1_800_000_000, 0))
	if !decision.Allow {
		t.Fatalf("AuthorizeMint rejected: %s", decision.Reason)
	}
	if decision.Constraints.Origin != "rp.example" {
		t.Fatalf("origin constraint = %q", decision.Constraints.Origin)
	}

	req.Origin = "other.example"
	decision = policy.AuthorizeMint(req, nil, time.Unix(1_800_000_000, 0))
	if decision.Allow || !strings.Contains(decision.Reason, "origin") {
		t.Fatalf("wrong origin decision = %+v", decision)
	}
}

func TestAuthorizePolicyEmailRequiresAddressAndMeasurement(t *testing.T) {
	policy := compileTestPolicy(t, Source{
		Version: 1,
		Mode:    ModeProduction,
		Defaults: Defaults{
			MaxBatch:         1,
			AuthorizationTTL: 60,
		},
		TokenFamilies: map[string]TokenRule{
			string(TokenPolicyEmail): {
				Enabled:              true,
				AllowedBridges:       []string{string(BridgeEmail)},
				BudgetGroup:          "email",
				RequiresAddressClaim: true,
				RequiresAttestation:  true,
			},
		},
		Bridges: map[string]BridgeRule{
			string(BridgeEmail): {
				Enabled:      true,
				BucketClaim:  "email",
				AddressClaim: "email",
			},
		},
		Measurements: []MeasurementRule{{
			ValueX: "accepted-runtime",
			Allow:  []string{string(TokenPolicyEmail)},
		}},
		Budgets: map[string]BudgetRule{
			"email": {Limit: 3, WindowSeconds: 3600},
		},
	})
	req := MintRequest{
		Subject: Subject{
			ValueX:   "accepted-runtime",
			Platform: "tamago",
		},
		Eligibility: []Eligibility{{
			BridgeKind: BridgeEmail,
			BucketID:   "alice@example.com",
			Assurance:  AssuranceVerified,
			Claims:     map[string]string{"email": "alice@example.com"},
		}},
		TokenFamily: TokenPolicyEmail,
		Count:       1,
		KeyVersion:  7,
		Address:     "ALICE@example.com",
		Binding:     bytes32(0x22),
	}
	decision := policy.AuthorizeMint(req, nil, time.Unix(1_800_000_000, 0))
	if !decision.Allow {
		t.Fatalf("AuthorizeMint rejected: %s", decision.Reason)
	}
	req.Subject.ValueX = "unknown-runtime"
	decision = policy.AuthorizeMint(req, nil, time.Unix(1_800_000_000, 0))
	if decision.Allow || !strings.Contains(decision.Reason, "measurement") {
		t.Fatalf("wrong measurement decision = %+v", decision)
	}
}

func TestCompilePolicyEmailMustRequireAddressClaim(t *testing.T) {
	_, err := Compile(Source{
		Version: 1,
		Mode:    ModeProduction,
		Defaults: Defaults{
			MaxBatch:         1,
			AuthorizationTTL: 60,
		},
		TokenFamilies: map[string]TokenRule{
			string(TokenPolicyEmail): {
				Enabled:        true,
				AllowedBridges: []string{string(BridgeEmail)},
				BudgetGroup:    "email",
			},
		},
		Bridges: map[string]BridgeRule{
			string(BridgeEmail): {Enabled: true, AddressClaim: "email"},
		},
		Budgets: map[string]BudgetRule{
			"email": {Limit: 1, WindowSeconds: 60},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "address claim") {
		t.Fatalf("Compile error = %v", err)
	}
}

func TestCompileRejectsProductionSoftwareWitnessDefault(t *testing.T) {
	src := Source{
		Version: 1,
		Mode:    ModeProduction,
		Defaults: Defaults{
			AllowSoftwareWitness: true,
			MaxBatch:             1,
			AuthorizationTTL:     60,
		},
		TokenFamilies: map[string]TokenRule{
			string(TokenBurn): {
				Enabled:        true,
				AllowedBridges: []string{string(BridgeTEE)},
				BudgetGroup:    "burn",
			},
		},
		Bridges: map[string]BridgeRule{
			string(BridgeTEE): {Enabled: true},
		},
		Budgets: map[string]BudgetRule{
			"burn": {Limit: 1, WindowSeconds: 60},
		},
	}
	_, err := Compile(src)
	if err == nil || !strings.Contains(err.Error(), "software witness") {
		t.Fatalf("Compile error = %v", err)
	}
}

func compileTestPolicy(t *testing.T, src Source) *Policy {
	t.Helper()
	raw, err := json.Marshal(src)
	if err != nil {
		t.Fatalf("Marshal policy: %v", err)
	}
	p, err := CompileJSON(raw)
	if err != nil {
		t.Fatalf("CompileJSON: %v", err)
	}
	return p
}

func bytes32(v byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = v
	}
	return out
}
