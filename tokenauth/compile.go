package tokenauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

func CompileJSON(raw []byte) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var src Source
	if err := dec.Decode(&src); err != nil {
		return nil, err
	}
	return Compile(src)
}

func Compile(src Source) (*Policy, error) {
	if src.Version != 1 {
		return nil, fmt.Errorf("policy version %d unsupported", src.Version)
	}
	if src.Mode == "" {
		src.Mode = ModeProduction
	}
	if src.Mode != ModeDevelopment && src.Mode != ModeProduction {
		return nil, fmt.Errorf("policy mode %q unsupported", src.Mode)
	}
	if src.Mode == ModeProduction && src.Defaults.AllowSoftwareWitness {
		return nil, fmt.Errorf("production policy cannot allow software witness")
	}
	if src.Defaults.MaxBatch <= 0 {
		return nil, fmt.Errorf("defaults.max_batch must be > 0")
	}
	if src.Defaults.AuthorizationTTL <= 0 {
		return nil, fmt.Errorf("defaults.authorization_ttl_seconds must be > 0")
	}
	if len(src.TokenFamilies) == 0 {
		return nil, fmt.Errorf("policy must define token_families")
	}
	if len(src.Gates) == 0 {
		return nil, fmt.Errorf("policy must define gates")
	}
	if len(src.Budgets) == 0 {
		return nil, fmt.Errorf("policy must define budgets")
	}

	p := &Policy{
		mode:         src.Mode,
		defaults:     src.Defaults,
		tokens:       make(map[TokenFamily]compiledToken),
		gates:        make(map[GateKind]compiledGate),
		measurements: make(map[string]map[TokenFamily]struct{}),
		budgets:      make(map[string]BudgetRule),
	}

	for name, b := range src.Budgets {
		if !validName(name) {
			return nil, fmt.Errorf("budget %q has invalid name", name)
		}
		if b.Limit <= 0 {
			return nil, fmt.Errorf("budget %q limit must be > 0", name)
		}
		if b.WindowSeconds <= 0 {
			return nil, fmt.Errorf("budget %q window_seconds must be > 0", name)
		}
		p.budgets[name] = b
	}

	for name, b := range src.Gates {
		if !validName(name) {
			return nil, fmt.Errorf("gate %q has invalid name", name)
		}
		cb := compiledGate{
			name:         GateKind(name),
			enabled:      b.Enabled,
			bucketClaim:  b.BucketClaim,
			addressClaim: b.AddressClaim,
			allowedHosts: make(map[string]struct{}),
		}
		for _, h := range b.AllowedHosts {
			h = strings.TrimSpace(h)
			if h == "" {
				return nil, fmt.Errorf("gate %q has empty allowed host", name)
			}
			cb.allowedHosts[h] = struct{}{}
		}
		p.gates[GateKind(name)] = cb
	}

	for name, t := range src.TokenFamilies {
		if !validTokenFamily(name) {
			return nil, fmt.Errorf("token family %q unsupported", name)
		}
		ct := compiledToken{
			name:                 TokenFamily(name),
			enabled:              t.Enabled,
			allowedGates:         make(map[GateKind]struct{}),
			allowedOrigins:       make(map[string]struct{}),
			budgetGroup:          t.BudgetGroup,
			maxBatch:             t.MaxBatch,
			requiresAddressClaim: t.RequiresAddressClaim,
			requiresAttestation:  t.RequiresAttestation,
			requiresOrigin:       t.RequiresOrigin,
		}
		if ct.maxBatch == 0 {
			ct.maxBatch = src.Defaults.MaxBatch
		}
		if ct.maxBatch <= 0 {
			return nil, fmt.Errorf("token family %q max_batch must be > 0", name)
		}
		if ct.budgetGroup == "" {
			return nil, fmt.Errorf("token family %q missing budget_group", name)
		}
		if _, ok := p.budgets[ct.budgetGroup]; !ok {
			return nil, fmt.Errorf("token family %q references unknown budget %q", name, ct.budgetGroup)
		}
		if ct.enabled && len(t.AllowedGates) == 0 {
			return nil, fmt.Errorf("enabled token family %q must list allowed_gates", name)
		}
		for _, gate := range t.AllowedGates {
			if !validName(gate) {
				return nil, fmt.Errorf("token family %q references invalid gate %q", name, gate)
			}
			cb, ok := p.gates[GateKind(gate)]
			if !ok {
				return nil, fmt.Errorf("token family %q references unknown gate %q", name, gate)
			}
			if ct.enabled && !cb.enabled {
				return nil, fmt.Errorf("enabled token family %q references disabled gate %q", name, gate)
			}
			if ct.requiresAddressClaim && cb.addressClaim == "" {
				return nil, fmt.Errorf("token family %q requires an address claim but gate %q has none", name, gate)
			}
			ct.allowedGates[GateKind(gate)] = struct{}{}
		}
		for _, origin := range t.AllowedOrigins {
			origin = strings.TrimSpace(origin)
			if origin == "" {
				return nil, fmt.Errorf("token family %q has empty allowed origin", name)
			}
			ct.allowedOrigins[origin] = struct{}{}
		}
		if len(ct.allowedOrigins) > 0 {
			ct.requiresOrigin = true
		}
		if TokenFamily(name) == TokenPolicyEmail && !ct.requiresAddressClaim {
			return nil, fmt.Errorf("policy_email policy must require an address claim")
		}
		p.tokens[TokenFamily(name)] = ct
	}

	for _, m := range src.Measurements {
		if strings.TrimSpace(m.ValueX) == "" {
			return nil, fmt.Errorf("measurement with empty value_x")
		}
		if len(m.Allow) == 0 {
			return nil, fmt.Errorf("measurement %q must allow at least one token family", m.ValueX)
		}
		if p.measurements[m.ValueX] == nil {
			p.measurements[m.ValueX] = make(map[TokenFamily]struct{})
		}
		for _, family := range m.Allow {
			if !validTokenFamily(family) {
				return nil, fmt.Errorf("measurement %q allows unsupported token family %q", m.ValueX, family)
			}
			tf := TokenFamily(family)
			if _, ok := p.tokens[tf]; !ok {
				return nil, fmt.Errorf("measurement %q references undefined token family %q", m.ValueX, family)
			}
			p.measurements[m.ValueX][tf] = struct{}{}
		}
	}
	for name, tok := range p.tokens {
		if tok.enabled && tok.requiresAttestation && !p.anyMeasurementAllows(name) {
			return nil, fmt.Errorf("token family %q requires attestation but no measurements allow it", name)
		}
	}

	return p, nil
}

func (p *Policy) anyMeasurementAllows(family TokenFamily) bool {
	for _, allowed := range p.measurements {
		if _, ok := allowed[family]; ok {
			return true
		}
	}
	return false
}

func validName(name string) bool {
	return namePattern.MatchString(name)
}

func validTokenFamily(name string) bool {
	switch TokenFamily(name) {
	case TokenBurn, TokenPrivateIdentity, TokenPolicyEmail:
		return true
	default:
		return false
	}
}
