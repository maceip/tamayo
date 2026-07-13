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
		"gates": {},
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
				AllowedGates:        []string{string(GateTEE)},
				AllowedOrigins:      []string{"rp.example"},
				BudgetGroup:         "private",
				RequiresAttestation: true,
				RequiresOrigin:      true,
			},
		},
		Gates: map[string]GateRule{
			string(GateTEE): {
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
			GateKind:  GateTEE,
			BucketID:  "runtime-1",
			Assurance: AssuranceVerified,
			Claims:    map[string]string{"runtime_id": "runtime-1"},
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
				AllowedGates:         []string{string(GateEmail)},
				BudgetGroup:          "email",
				RequiresAddressClaim: true,
				RequiresAttestation:  true,
			},
		},
		Gates: map[string]GateRule{
			string(GateEmail): {
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
			GateKind:  GateEmail,
			BucketID:  "alice@example.com",
			Assurance: AssuranceVerified,
			Claims:    map[string]string{"email": "alice@example.com"},
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
				Enabled:      true,
				AllowedGates: []string{string(GateEmail)},
				BudgetGroup:  "email",
			},
		},
		Gates: map[string]GateRule{
			string(GateEmail): {Enabled: true, AddressClaim: "email"},
		},
		Budgets: map[string]BudgetRule{
			"email": {Limit: 1, WindowSeconds: 60},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "address claim") {
		t.Fatalf("Compile error = %v", err)
	}
}

// TestCompileProductionRequiresBucketProvenance pins the rule born from the
// SigBird incident: a budget keyed by a bucket the caller names freely is
// decoration, so production policies must state where bucket_id comes from —
// a verified gate claim, or an explicit opt-in that the calling service
// derives it.
func TestCompileProductionRequiresBucketProvenance(t *testing.T) {
	src := func(gate GateRule) Source {
		return Source{
			Version: 1,
			Mode:    ModeProduction,
			Defaults: Defaults{
				MaxBatch:         1,
				AuthorizationTTL: 60,
			},
			TokenFamilies: map[string]TokenRule{
				string(TokenBurn): {
					Enabled:      true,
					AllowedGates: []string{string(GateTEE)},
					BudgetGroup:  "burn",
				},
			},
			Gates: map[string]GateRule{
				string(GateTEE): gate,
			},
			Budgets: map[string]BudgetRule{
				"burn": {Limit: 1, WindowSeconds: 60},
			},
		}
	}

	if _, err := Compile(src(GateRule{Enabled: true})); err == nil || !strings.Contains(err.Error(), "bucket provenance") {
		t.Fatalf("bare gate in production compiled: err = %v", err)
	}
	if _, err := Compile(src(GateRule{Enabled: true, BucketClaim: "runtime_id"})); err != nil {
		t.Fatalf("bucket_claim gate rejected: %v", err)
	}
	if _, err := Compile(src(GateRule{Enabled: true, BucketSource: BucketSourceCaller})); err != nil {
		t.Fatalf("explicit caller opt-in rejected: %v", err)
	}

	dev := src(GateRule{Enabled: true})
	dev.Mode = ModeDevelopment
	dev.Defaults.AllowSoftwareWitness = true
	if _, err := Compile(dev); err != nil {
		t.Fatalf("development mode must stay permissive: %v", err)
	}
}

func TestCompileRejectsBucketSourceMisuse(t *testing.T) {
	base := func(gate GateRule) Source {
		return Source{
			Version: 1,
			Mode:    ModeDevelopment,
			Defaults: Defaults{
				AllowSoftwareWitness: true,
				MaxBatch:             1,
				AuthorizationTTL:     60,
			},
			TokenFamilies: map[string]TokenRule{
				string(TokenBurn): {
					Enabled:      true,
					AllowedGates: []string{string(GateTEE)},
					BudgetGroup:  "burn",
				},
			},
			Gates: map[string]GateRule{
				string(GateTEE): gate,
			},
			Budgets: map[string]BudgetRule{
				"burn": {Limit: 1, WindowSeconds: 60},
			},
		}
	}

	if _, err := Compile(base(GateRule{Enabled: true, BucketSource: "vibes"})); err == nil || !strings.Contains(err.Error(), "bucket_source") {
		t.Fatalf("unknown bucket_source compiled: err = %v", err)
	}
	if _, err := Compile(base(GateRule{Enabled: true, BucketSource: BucketSourceClaim})); err == nil || !strings.Contains(err.Error(), "no bucket_claim") {
		t.Fatalf("bucket_source claim without bucket_claim compiled: err = %v", err)
	}
	if _, err := Compile(base(GateRule{Enabled: true, BucketSource: BucketSourceCaller, BucketClaim: "runtime_id"})); err == nil || !strings.Contains(err.Error(), "pick one") {
		t.Fatalf("conflicting provenance compiled: err = %v", err)
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
				Enabled:      true,
				AllowedGates: []string{string(GateTEE)},
				BudgetGroup:  "burn",
			},
		},
		Gates: map[string]GateRule{
			string(GateTEE): {Enabled: true},
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
