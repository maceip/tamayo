package tokenservice

import (
	"errors"
	"testing"
)

// TestSpentStoreSemantics pins the reference contract: first spend marks,
// second is ErrDoubleSpend, epochs are independent, and pruning retired
// epochs keeps live ones.
func TestSpentStoreSemantics(t *testing.T) {
	s := NewMemorySpentStore()
	nonce := [32]byte{0x11}

	if err := s.CheckAndMark(1, nonce); err != nil {
		t.Fatalf("first spend: %v", err)
	}
	if err := s.CheckAndMark(1, nonce); !errors.Is(err, ErrDoubleSpend) {
		t.Fatalf("double spend error = %v", err)
	}
	// The same nonce under another key epoch is a different token.
	if err := s.CheckAndMark(2, nonce); err != nil {
		t.Fatalf("other epoch: %v", err)
	}
	if s.Len() != 2 {
		t.Fatalf("len = %d", s.Len())
	}

	// Retiring epoch 1 drops its records but keeps epoch 2's.
	s.PruneEpochsBefore(2)
	if s.Len() != 1 {
		t.Fatalf("len after prune = %d", s.Len())
	}
	if err := s.CheckAndMark(2, nonce); !errors.Is(err, ErrDoubleSpend) {
		t.Fatal("live epoch record must survive pruning")
	}
	if err := s.CheckAndMark(1, nonce); err != nil {
		t.Fatal("pruned epoch spends again (its tokens can no longer verify)")
	}
}
