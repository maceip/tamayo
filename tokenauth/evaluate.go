package tokenauth

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

var b64 = base64.RawURLEncoding

func (p *Policy) AuthorizeMint(req MintRequest, budgets BudgetStore, now time.Time) MintDecision {
	var checks []Check
	fail := func(name, detail string) MintDecision {
		checks = append(checks, Check{Name: name, Pass: false, Detail: detail})
		return MintDecision{Allow: false, Reason: detail, Checks: checks}
	}
	pass := func(name, detail string) {
		checks = append(checks, Check{Name: name, Pass: true, Detail: detail})
	}
	if p == nil {
		return fail("policy_present", "policy is nil")
	}
	pass("policy_present", "")
	if now.IsZero() {
		return fail("time_present", "now is required")
	}
	pass("time_present", "")

	tok, ok := p.tokens[req.TokenFamily]
	if !ok {
		return fail("token_family_known", fmt.Sprintf("token family %q is not defined", req.TokenFamily))
	}
	pass("token_family_known", string(req.TokenFamily))
	if !tok.enabled {
		return fail("token_family_enabled", fmt.Sprintf("token family %q is disabled", req.TokenFamily))
	}
	pass("token_family_enabled", "")

	if req.Count <= 0 {
		return fail("count_positive", "count must be > 0")
	}
	pass("count_positive", "")
	if req.Count > tok.maxBatch {
		return fail("count_within_max_batch", fmt.Sprintf("count %d exceeds max_batch %d", req.Count, tok.maxBatch))
	}
	pass("count_within_max_batch", fmt.Sprintf("count=%d max=%d", req.Count, tok.maxBatch))

	if req.KeyVersion == 0 {
		return fail("key_version_present", "key_version must be > 0")
	}
	pass("key_version_present", fmt.Sprintf("v%d", req.KeyVersion))
	if len(req.Binding) != 32 {
		return fail("binding_present", fmt.Sprintf("binding must be 32 bytes, got %d", len(req.Binding)))
	}
	pass("binding_present", "")

	if tok.requiresOrigin {
		if strings.TrimSpace(req.Origin) == "" {
			return fail("origin_present", "origin is required for this token family")
		}
		if len(tok.allowedOrigins) > 0 {
			if _, ok := tok.allowedOrigins[req.Origin]; !ok {
				return fail("origin_allowed", fmt.Sprintf("origin %q is not allowed for token family %q", req.Origin, req.TokenFamily))
			}
		}
		pass("origin_allowed", req.Origin)
	}

	if tok.requiresAttestation {
		if req.Subject.ValueX == "" {
			return fail("attestation_subject_present", "token family requires attestation but subject.value_x is empty")
		}
		allowed, ok := p.measurements[req.Subject.ValueX]
		if !ok {
			return fail("measurement_allowed", "subject measurement is not allowlisted")
		}
		if _, ok := allowed[req.TokenFamily]; !ok {
			return fail("measurement_allows_token_family", "subject measurement does not allow this token family")
		}
		pass("measurement_allows_token_family", short(req.Subject.ValueX))
	}

	if p.mode == ModeProduction && strings.EqualFold(req.Subject.Platform, "software-witness") {
		return fail("software_witness_rejected", "production policy rejects software-witness")
	}
	if strings.EqualFold(req.Subject.Platform, "software-witness") && !p.defaults.AllowSoftwareWitness {
		return fail("software_witness_allowed", "software-witness is not allowed")
	}
	pass("platform_allowed", req.Subject.Platform)

	elig, bridge, ok := p.chooseEligibility(req.Eligibility, tok)
	if !ok {
		return fail("eligible_bridge", "no verified eligibility bridge is allowed for this token family")
	}
	pass("eligible_bridge", string(elig.BridgeKind))
	if bridge.bucketClaim != "" {
		claim := elig.Claims[bridge.bucketClaim]
		if claim == "" {
			return fail("bridge_bucket_claim", fmt.Sprintf("bridge %q requires bucket claim %q", bridge.name, bridge.bucketClaim))
		}
		if claim != elig.BucketID {
			return fail("bridge_bucket_matches", fmt.Sprintf("bridge %q bucket claim does not match bucket_id", bridge.name))
		}
	}
	if tok.requiresAddressClaim {
		claim := elig.Claims[bridge.addressClaim]
		if claim == "" {
			return fail("address_claim_present", fmt.Sprintf("token family %q requires bridge address claim %q", req.TokenFamily, bridge.addressClaim))
		}
		if strings.TrimSpace(req.Address) == "" {
			return fail("address_present", fmt.Sprintf("token family %q requires request address", req.TokenFamily))
		}
		if !strings.EqualFold(claim, req.Address) {
			return fail("address_matches_claim", "request address does not match verified bridge address claim")
		}
	}
	pass("bridge_claims", "")

	if len(bridge.allowedHosts) > 0 {
		host := elig.Claims["host"]
		if host == "" {
			host = elig.Claims["domain"]
		}
		if _, ok := bridge.allowedHosts[host]; !ok {
			return fail("bridge_host_allowed", fmt.Sprintf("host %q not allowed for bridge %q", host, bridge.name))
		}
		pass("bridge_host_allowed", host)
	}

	budget, ok := p.budgets[tok.budgetGroup]
	if !ok {
		return fail("budget_defined", fmt.Sprintf("budget group %q is undefined", tok.budgetGroup))
	}
	budgetKey := string(elig.BridgeKind) + ":" + elig.BucketID + ":" + tok.budgetGroup
	if budgets != nil {
		if err := budgets.Reserve(budgetKey, req.Count, budget.Limit, time.Duration(budget.WindowSeconds)*time.Second, now); err != nil {
			return fail("budget_available", err.Error())
		}
	}
	pass("budget_available", budgetKey)

	expires := now.Add(time.Duration(p.defaults.AuthorizationTTL) * time.Second).Unix()
	return MintDecision{
		Allow:  true,
		Reason: "authorized",
		Checks: checks,
		Constraints: MintConstraints{
			TokenFamily: req.TokenFamily,
			Count:       req.Count,
			KeyVersion:  req.KeyVersion,
			BindingB64:  b64.EncodeToString(req.Binding),
			BudgetKey:   budgetKey,
			Origin:      req.Origin,
			Address:     req.Address,
			ExpiresAt:   expires,
		},
	}
}

func (p *Policy) chooseEligibility(all []Eligibility, tok compiledToken) (Eligibility, compiledBridge, bool) {
	for _, elig := range all {
		if elig.BucketID == "" || !strings.EqualFold(elig.Assurance, AssuranceVerified) {
			continue
		}
		if _, ok := tok.allowedBridges[elig.BridgeKind]; !ok {
			continue
		}
		bridge, ok := p.bridges[elig.BridgeKind]
		if !ok || !bridge.enabled {
			continue
		}
		if elig.Claims == nil {
			elig.Claims = make(map[string]string)
		}
		return elig, bridge, true
	}
	return Eligibility{}, compiledBridge{}, false
}

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}
