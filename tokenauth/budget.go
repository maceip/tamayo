package tokenauth

import (
	"errors"
	"sync"
	"time"
)

// ErrBudgetExceeded is returned by Reserve when granting the request would
// exceed the budget limit for the current window.
var ErrBudgetExceeded = errors.New("issuance budget exceeded for this bucket in the current window")

// MemoryBudgetStore is the reference BudgetStore: an in-memory,
// window-bucketed counter transpiled from the eat-pass
// InMemoryRateLimiter (core/src/ratelimit.rs). It is process-local — a
// multi-replica issuer must back the interface with a shared store instead —
// and it exists so the budget path has a working, tested implementation and
// so demos and single-process products need not write one.
//
// Failure semantics match the reference: any Reserve error means the caller
// must deny issuance (AuthorizeMint fails the budget_available check), so a
// shared-store implementation that cannot reach its backend must return an
// error, never assume quota is available.
type MemoryBudgetStore struct {
	mu   sync.Mutex
	used map[memoryBudgetKey]int
}

type memoryBudgetKey struct {
	epoch  int64
	window time.Duration
	key    string
}

// NewMemoryBudgetStore returns an empty in-memory budget store.
func NewMemoryBudgetStore() *MemoryBudgetStore {
	return &MemoryBudgetStore{used: make(map[memoryBudgetKey]int)}
}

// Reserve consumes amount permits for key in the window containing now.
// Windows are epoch-aligned (now / window), matching the reference's
// epoch bucketing; a non-positive window degenerates to one second.
func (m *MemoryBudgetStore) Reserve(key string, amount, limit int, window time.Duration, now time.Time) error {
	if amount <= 0 {
		return errors.New("budget reserve amount must be > 0")
	}
	seconds := int64(window / time.Second)
	if seconds <= 0 {
		seconds = 1
		window = time.Second
	}
	k := memoryBudgetKey{epoch: now.Unix() / seconds, window: window, key: key}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.used[k]+amount > limit {
		return ErrBudgetExceeded
	}
	m.used[k] += amount
	return nil
}

// Prune drops counters for windows that ended before now (housekeeping,
// mirrors the reference's prune_before).
func (m *MemoryBudgetStore) Prune(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k := range m.used {
		if (k.epoch+1)*int64(k.window/time.Second) <= now.Unix() {
			delete(m.used, k)
		}
	}
}
