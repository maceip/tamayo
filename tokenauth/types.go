package tokenauth

import "time"

type TokenFamily string

const (
	TokenBurn            TokenFamily = "burn"
	TokenPrivateIdentity TokenFamily = "private_identity"
	TokenPolicyEmail     TokenFamily = "policy_email"
)

type GateKind string

const (
	GateTEE   GateKind = "tee"
	GateEmail GateKind = "email"
)

const (
	ModeDevelopment = "development"
	ModeProduction  = "production"

	AssuranceVerified = "verified"
)

type Source struct {
	Version       int                   `json:"version"`
	Mode          string                `json:"mode"`
	Defaults      Defaults              `json:"defaults"`
	TokenFamilies map[string]TokenRule  `json:"token_families"`
	Gates         map[string]GateRule   `json:"gates"`
	Measurements  []MeasurementRule     `json:"measurements,omitempty"`
	Budgets       map[string]BudgetRule `json:"budgets"`
}

type Defaults struct {
	AllowSoftwareWitness bool `json:"allow_software_witness"`
	MaxBatch             int  `json:"max_batch"`
	AuthorizationTTL     int  `json:"authorization_ttl_seconds"`
}

type TokenRule struct {
	Enabled              bool     `json:"enabled"`
	AllowedGates         []string `json:"allowed_gates"`
	AllowedOrigins       []string `json:"allowed_origins,omitempty"`
	BudgetGroup          string   `json:"budget_group"`
	MaxBatch             int      `json:"max_batch,omitempty"`
	RequiresAddressClaim bool     `json:"requires_address_claim,omitempty"`
	RequiresAttestation  bool     `json:"requires_attestation,omitempty"`
	RequiresOrigin       bool     `json:"requires_origin,omitempty"`
}

type GateRule struct {
	Enabled      bool     `json:"enabled"`
	BucketClaim  string   `json:"bucket_claim,omitempty"`
	AddressClaim string   `json:"address_claim,omitempty"`
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
}

type MeasurementRule struct {
	ValueX string   `json:"value_x"`
	Allow  []string `json:"allow"`
}

type BudgetRule struct {
	Limit         int `json:"limit"`
	WindowSeconds int `json:"window_seconds"`
}

type Subject struct {
	ValueX   string            `json:"value_x,omitempty"`
	Platform string            `json:"platform,omitempty"`
	Runtime  string            `json:"runtime,omitempty"`
	Claims   map[string]string `json:"claims,omitempty"`
}

type Eligibility struct {
	GateKind  GateKind          `json:"gate_kind"`
	BucketID  string            `json:"bucket_id"`
	Assurance string            `json:"assurance"`
	Claims    map[string]string `json:"claims,omitempty"`
}

type MintRequest struct {
	Subject     Subject       `json:"subject"`
	Eligibility []Eligibility `json:"eligibility"`
	TokenFamily TokenFamily   `json:"token_family"`
	Count       int           `json:"count"`
	KeyVersion  uint32        `json:"key_version"`
	Origin      string        `json:"origin,omitempty"`
	Address     string        `json:"address,omitempty"`
	Binding     []byte        `json:"-"`
}

type MintConstraints struct {
	TokenFamily TokenFamily `json:"token_family"`
	Count       int         `json:"count"`
	KeyVersion  uint32      `json:"key_version"`
	BindingB64  string      `json:"binding_b64"`
	BudgetKey   string      `json:"budget_key"`
	Origin      string      `json:"origin,omitempty"`
	Address     string      `json:"address,omitempty"`
	ExpiresAt   int64       `json:"expires_at"`
}

type Check struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
}

type MintDecision struct {
	Allow       bool            `json:"allow"`
	Reason      string          `json:"reason"`
	Checks      []Check         `json:"checks"`
	Constraints MintConstraints `json:"constraints,omitempty"`
}

type BudgetStore interface {
	Reserve(key string, amount int, limit int, window time.Duration, now time.Time) error
}

type Policy struct {
	mode         string
	defaults     Defaults
	tokens       map[TokenFamily]compiledToken
	gates        map[GateKind]compiledGate
	measurements map[string]map[TokenFamily]struct{}
	budgets      map[string]BudgetRule
}

func (p *Policy) Mode() string {
	if p == nil {
		return ""
	}
	return p.mode
}

type compiledToken struct {
	name                 TokenFamily
	enabled              bool
	allowedGates         map[GateKind]struct{}
	allowedOrigins       map[string]struct{}
	budgetGroup          string
	maxBatch             int
	requiresAddressClaim bool
	requiresAttestation  bool
	requiresOrigin       bool
}

type compiledGate struct {
	name         GateKind
	enabled      bool
	bucketClaim  string
	addressClaim string
	allowedHosts map[string]struct{}
}
