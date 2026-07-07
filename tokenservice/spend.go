package tokenservice

// Double-spend protection, ported from the reference spend module: a burn
// token's nonce is its unique spend identifier, and the spent set is
// partitioned by issuer key epoch so that once a key is retired the whole
// epoch's set can be dropped — that is what keeps the store bounded.
//
// SpentStore is the seam: origin-local for the simple shape, or a shared
// (Redis/DB) implementation behind the same interface for a central
// redeemer. Failure semantics are fail-closed, exactly like BudgetStore: an
// implementation that cannot reach its backend must return an error, and
// the caller must deny the redemption, because it cannot prove the nonce is
// unspent.

import (
	"errors"
	"sync"
)

// ErrDoubleSpend is returned by CheckAndMark when the nonce was already
// spent in the key epoch.
var ErrDoubleSpend = errors.New("token already spent (double-spend)")

// SpentStore records spent token nonces, partitioned by key epoch.
type SpentStore interface {
	// CheckAndMark atomically checks and marks nonce as spent for keyEpoch.
	// It returns ErrDoubleSpend if the nonce was already present, and any
	// other error means the backend failed and the caller must deny.
	CheckAndMark(keyEpoch uint32, nonce [32]byte) error
}

type spentKey struct {
	epoch uint32
	nonce [32]byte
}

// MemorySpentStore is the reference in-memory SpentStore: process-local,
// epoch-partitioned. Multi-replica origins need a shared implementation.
type MemorySpentStore struct {
	mu   sync.Mutex
	seen map[spentKey]struct{}
}

// NewMemorySpentStore returns an empty in-memory spent set.
func NewMemorySpentStore() *MemorySpentStore {
	return &MemorySpentStore{seen: make(map[spentKey]struct{})}
}

// CheckAndMark implements SpentStore.
func (m *MemorySpentStore) CheckAndMark(keyEpoch uint32, nonce [32]byte) error {
	k := spentKey{epoch: keyEpoch, nonce: nonce}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, spent := m.seen[k]; spent {
		return ErrDoubleSpend
	}
	m.seen[k] = struct{}{}
	return nil
}

// PruneEpochsBefore drops spent records for retired key epochs (strictly
// less than keepFrom). Safe once tokens under those keys can no longer
// verify; this is what makes the store bounded.
func (m *MemorySpentStore) PruneEpochsBefore(keepFrom uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k := range m.seen {
		if k.epoch < keepFrom {
			delete(m.seen, k)
		}
	}
}

// Len reports the number of recorded spends (for tests and metrics).
func (m *MemorySpentStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.seen)
}
