package tokenauth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func budgetTestPolicy(t *testing.T) *Policy {
	t.Helper()
	return compileTestPolicy(t, Source{
		Version: 1,
		Mode:    ModeProduction,
		Defaults: Defaults{
			MaxBatch:         8,
			AuthorizationTTL: 60,
		},
		TokenFamilies: map[string]TokenRule{
			string(TokenBurn): {
				Enabled:             true,
				AllowedGates:        []string{string(GateTEE)},
				BudgetGroup:         "burn",
				RequiresAttestation: true,
			},
		},
		Gates: map[string]GateRule{
			// The test harness derives bucket IDs itself, which production
			// mode only permits by explicit opt-in.
			string(GateTEE): {Enabled: true, BucketSource: BucketSourceCaller},
		},
		Measurements: []MeasurementRule{{
			ValueX: "mayo-faest-runtime-measurement",
			Allow:  []string{string(TokenBurn)},
		}},
		Budgets: map[string]BudgetRule{
			"burn": {Limit: 5, WindowSeconds: 3600},
		},
	})
}

func budgetTestRequest(count int) MintRequest {
	return MintRequest{
		Subject: Subject{
			ValueX:   "mayo-faest-runtime-measurement",
			Platform: "tamago",
		},
		Eligibility: []Eligibility{{
			GateKind:  GateTEE,
			BucketID:  "runtime-1",
			Assurance: AssuranceVerified,
		}},
		TokenFamily: TokenBurn,
		Count:       count,
		KeyVersion:  7,
		Binding:     bytes32(0x11),
	}
}

// TestAuthorizeMintEnforcesBudget exercises the budget path end to end
// through AuthorizeMint: reservations accumulate per bucket per window,
// exceeding the limit denies with the budget_available check, and a new
// window starts a fresh count.
func TestAuthorizeMintEnforcesBudget(t *testing.T) {
	policy := budgetTestPolicy(t)
	budgets := NewMemoryBudgetStore()
	now := time.Unix(1_800_000_000, 0)

	// Limit is 5: 3 + 2 fit, the next single-token mint must be denied.
	for _, count := range []int{3, 2} {
		decision := policy.AuthorizeMint(budgetTestRequest(count), budgets, now)
		if !decision.Allow {
			t.Fatalf("AuthorizeMint(count=%d) rejected: %s", count, decision.Reason)
		}
		if decision.Constraints.BudgetKey != "tee:runtime-1:burn" {
			t.Fatalf("budget key = %q", decision.Constraints.BudgetKey)
		}
	}
	decision := policy.AuthorizeMint(budgetTestRequest(1), budgets, now)
	if decision.Allow {
		t.Fatal("mint beyond budget limit must be denied")
	}
	if !strings.Contains(decision.Reason, "budget") {
		t.Fatalf("denial reason = %q", decision.Reason)
	}
	last := decision.Checks[len(decision.Checks)-1]
	if last.Name != "budget_available" || last.Pass {
		t.Fatalf("failing check = %+v", last)
	}

	// A different bucket is unaffected.
	other := budgetTestRequest(1)
	other.Eligibility[0].BucketID = "runtime-2"
	if d := policy.AuthorizeMint(other, budgets, now); !d.Allow {
		t.Fatalf("independent bucket rejected: %s", d.Reason)
	}

	// The next window starts fresh.
	nextWindow := now.Add(time.Hour)
	if d := policy.AuthorizeMint(budgetTestRequest(5), budgets, nextWindow); !d.Allow {
		t.Fatalf("new window rejected: %s", d.Reason)
	}

	// Prune drops the closed window's counters but keeps the live one.
	budgets.Prune(nextWindow)
	if d := policy.AuthorizeMint(budgetTestRequest(1), budgets, nextWindow); d.Allow {
		t.Fatal("live window must survive pruning")
	}
}

// TestMemoryBudgetStoreSemantics pins the store contract directly: exact
// limit fits, one more is ErrBudgetExceeded, non-positive amounts are
// errors (fail-closed), and window bucketing is epoch-aligned.
func TestMemoryBudgetStoreSemantics(t *testing.T) {
	s := NewMemoryBudgetStore()
	now := time.Unix(1_800_000_000, 0)
	window := time.Hour

	if err := s.Reserve("k", 5, 5, window, now); err != nil {
		t.Fatalf("Reserve to exact limit: %v", err)
	}
	if err := s.Reserve("k", 1, 5, window, now); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("over-limit error = %v", err)
	}
	if err := s.Reserve("k", 0, 5, window, now); err == nil {
		t.Fatal("zero amount must be rejected")
	}
	if err := s.Reserve("k", 1, 5, window, now.Add(window)); err != nil {
		t.Fatalf("fresh window: %v", err)
	}
	// Sub-second windows degenerate to one second instead of dividing by zero.
	if err := s.Reserve("k", 1, 1, time.Millisecond, now); err != nil {
		t.Fatalf("sub-second window: %v", err)
	}
}
