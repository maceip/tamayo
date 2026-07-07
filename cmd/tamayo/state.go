package main

// Durable state for the reference runtime — the deliberately boring
// fallback: a single append-only JSON-lines journal that is replayed at
// startup. Every state mutation (burn spend, presentation nonce, budget
// reservation) appends one fsynced line, so a restart no longer opens a
// replay window. This keeps the in-memory stores as the source of truth at
// runtime and adds no dependencies; multi-replica deployments still need a
// shared store behind the library seams (SpentStore/BudgetStore).
//
// Mailbox challenge codes are intentionally NOT journaled: they live
// minutes, are single-use, and re-requesting one after a restart is the
// correct recovery.

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/maceip/tamayo/tokenauth"
	"github.com/maceip/tamayo/tokenservice"
)

type stateRecord struct {
	T string `json:"t"` // "spend" | "pvt" | "budget"

	// spend
	Epoch uint32 `json:"epoch,omitempty"`
	Nonce string `json:"nonce,omitempty"` // base64url

	// pvt
	Key string `json:"key,omitempty"` // base64url(origin \x00 nonce)

	// budget
	BudgetKey string `json:"budget_key,omitempty"`
	Amount    int    `json:"amount,omitempty"`
	Limit     int    `json:"limit,omitempty"`
	WindowS   int64  `json:"window_s,omitempty"`
	Unix      int64  `json:"unix,omitempty"`
}

// journal is the append-only state log. A nil *journal is a no-op, so the
// default in-memory-only behavior is unchanged.
type journal struct {
	mu sync.Mutex
	f  *os.File
}

func (j *journal) append(rec stateRecord) error {
	if j == nil {
		return nil
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, err := j.f.Write(append(raw, '\n')); err != nil {
		return err
	}
	return j.f.Sync()
}

func (j *journal) spend(epoch uint32, nonce [32]byte) error {
	return j.append(stateRecord{T: "spend", Epoch: epoch, Nonce: base64.RawURLEncoding.EncodeToString(nonce[:])})
}

func (j *journal) pvt(key string) error {
	return j.append(stateRecord{T: "pvt", Key: base64.RawURLEncoding.EncodeToString([]byte(key))})
}

// journaledBudgets wraps a BudgetStore so every successful reservation is
// journaled; it is handed to AuthorizeMint and the EVP rail alike.
type journaledBudgets struct {
	inner tokenauth.BudgetStore
	j     *journal
}

func (b *journaledBudgets) Reserve(key string, amount, limit int, window time.Duration, now time.Time) error {
	if err := b.inner.Reserve(key, amount, limit, window, now); err != nil {
		return err
	}
	return b.j.append(stateRecord{
		T: "budget", BudgetKey: key, Amount: amount, Limit: limit,
		WindowS: int64(window / time.Second), Unix: now.Unix(),
	})
}

// openJournal replays <dir>/state.jsonl into the given stores, then opens
// it for appending. Records that no longer apply (duplicate spends from a
// crash between write and ack, reservations in long-closed windows) are
// replayed harmlessly.
func openJournal(dir string, spent *tokenservice.MemorySpentStore, seenPvt map[string]bool, budgets tokenauth.BudgetStore) (*journal, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "state.jsonl")

	if raw, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(raw)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		line := 0
		for sc.Scan() {
			line++
			var rec stateRecord
			if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
				raw.Close()
				return nil, fmt.Errorf("%s:%d: %w", path, line, err)
			}
			switch rec.T {
			case "spend":
				v, err := base64.RawURLEncoding.DecodeString(rec.Nonce)
				if err != nil || len(v) != 32 {
					raw.Close()
					return nil, fmt.Errorf("%s:%d: bad spend nonce", path, line)
				}
				var nonce [32]byte
				copy(nonce[:], v)
				_ = spent.CheckAndMark(rec.Epoch, nonce) // duplicate = already replayed
			case "pvt":
				v, err := base64.RawURLEncoding.DecodeString(rec.Key)
				if err != nil {
					raw.Close()
					return nil, fmt.Errorf("%s:%d: bad pvt key", path, line)
				}
				seenPvt[string(v)] = true
			case "budget":
				// Over-limit or expired-window replays fail harmlessly.
				_ = budgets.Reserve(rec.BudgetKey, rec.Amount, rec.Limit,
					time.Duration(rec.WindowS)*time.Second, time.Unix(rec.Unix, 0))
			default:
				raw.Close()
				return nil, fmt.Errorf("%s:%d: unknown record type %q", path, line, rec.T)
			}
		}
		raw.Close()
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &journal{f: f}, nil
}
