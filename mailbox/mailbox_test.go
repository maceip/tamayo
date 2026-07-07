package mailbox

import (
	"encoding/hex"
	"errors"
	"testing"
)

// TestBucketIDEatPassInterop pins BucketID against values produced by the
// eat-pass reference (core/src/mailbox.rs mailbox_measurement, dumped by
// tools/kt_dump/src/bin/mailbox_dump.rs): the keyed HMAC and its domain
// string must be wire-compatible.
func TestBucketIDEatPassInterop(t *testing.T) {
	key := func(fill byte) [32]byte {
		var k [32]byte
		for i := range k {
			k[i] = fill
		}
		return k
	}
	cases := []struct {
		keyFill byte
		raw     string
		want    string
	}{
		{1, "alice@example.com", "98542dda414c14cab314b2635d8d402614299839990ad1067582255acd9bdcdc"},
		{1, "bob@example.com", "4f67f1c69b8c46960f1311298fbe255f884d8df6423326a1a8343937a0c0e75c"},
		{2, "alice@example.com", "75e35fa50c4f98593ea687f2e3a21b00ae887cbf2961eaf75d8cc2d57b56cdec"},
		{9, "  User@Example.COM ", "29f889851754544e4f5fb0370377003be52bab05d420a22c26fbbcdc8db7aff7"},
	}
	for _, c := range cases {
		canonical, err := CanonicalEmail(c.raw)
		if err != nil {
			t.Fatalf("CanonicalEmail(%q): %v", c.raw, err)
		}
		got := BucketID(key(c.keyFill), canonical)
		if hex.EncodeToString(got[:]) != c.want {
			t.Fatalf("BucketID(key=%d, %q) = %x, want %s", c.keyFill, canonical, got, c.want)
		}
	}
}

func TestCanonicalizationLowercasesAndValidates(t *testing.T) {
	got, err := CanonicalEmail("  Alice@Example.COM ")
	if err != nil || got != "alice@example.com" {
		t.Fatalf("canonical = %q, %v", got, err)
	}
	for _, bad := range []string{"no-at-sign", "@nodomainlocal", "nolocal@", "two@at@signs", "sp ace@example.com"} {
		if _, err := CanonicalEmail(bad); !errors.Is(err, ErrMalformedEmail) {
			t.Fatalf("CanonicalEmail(%q) error = %v", bad, err)
		}
	}
}

func TestBucketIsStablePerAddressAndKeyed(t *testing.T) {
	k1, k2 := [32]byte{}, [32]byte{}
	for i := range k1 {
		k1[i], k2[i] = 1, 2
	}
	a := BucketID(k1, "alice@example.com")
	b := BucketID(k1, "alice@example.com")
	c := BucketID(k1, "bob@example.com")
	d := BucketID(k2, "alice@example.com")
	if a != b {
		t.Fatal("bucket not stable per address")
	}
	if a == c {
		t.Fatal("different addresses share a bucket")
	}
	if a == d {
		t.Fatal("different gate keys share a bucket")
	}
}

func TestChallengeRoundTripSingleUseAndBindingBound(t *testing.T) {
	store := NewChallengeStore(600)
	binding := [32]byte{7}
	code, err := store.Create("Alice@Example.com", binding, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != CodeLen {
		t.Fatalf("code %q length != %d", code, CodeLen)
	}

	// Wrong binding: a code requested for one mint must not authorize another.
	if _, err := store.Verify("alice@example.com", code, [32]byte{8}, 1001); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("wrong binding error = %v", err)
	}
	// Right code, canonicalized address.
	canonical, err := store.Verify(" ALICE@example.COM ", code, binding, 1001)
	if err != nil || canonical != "alice@example.com" {
		t.Fatalf("verify = %q, %v", canonical, err)
	}
	// Single-use.
	if _, err := store.Verify("alice@example.com", code, binding, 1002); !errors.Is(err, ErrNoPending) {
		t.Fatalf("second use error = %v", err)
	}
}

func TestChallengeExpiresAndLocksAfterAttempts(t *testing.T) {
	store := NewChallengeStore(10)
	binding := [32]byte{7}
	code, err := store.Create("a@b.c", binding, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify("a@b.c", code, binding, 1011); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired error = %v", err)
	}

	code, err = store.Create("a@b.c", binding, 2000)
	if err != nil {
		t.Fatal(err)
	}
	wrong := "000000"
	if code == wrong {
		wrong = "000001"
	}
	for i := 0; i < MaxCodeAttempts; i++ {
		if _, err := store.Verify("a@b.c", wrong, binding, 2001); !errors.Is(err, ErrWrongCode) && !errors.Is(err, ErrNoPending) {
			t.Fatalf("attempt %d error = %v", i, err)
		}
	}
	// Consumed by attempts — even the right code is now dead.
	if _, err := store.Verify("a@b.c", code, binding, 2001); !errors.Is(err, ErrNoPending) {
		t.Fatalf("locked-out error = %v", err)
	}
}
