package tokenprofile

import (
	"bytes"
	"strings"
	"testing"
)

// TestPrivateTokenCarriageRoundTrip pins the RFC 9577 header codecs against
// the reference shapes.
func TestPrivateTokenCarriageRoundTrip(t *testing.T) {
	challenge := bytes.Repeat([]byte{0xC1}, 32)
	issuerKey := bytes.Repeat([]byte{0x7E}, 40)

	www := WWWAuthenticate(challenge, issuerKey)
	if !strings.HasPrefix(www, "PrivateToken challenge=") || !strings.Contains(www, ", token-key=") {
		t.Fatalf("www-authenticate shape: %q", www)
	}
	gotChallenge, gotKey, err := ParseWWWAuthenticate(www)
	if err != nil || !bytes.Equal(gotChallenge, challenge) || !bytes.Equal(gotKey, issuerKey) {
		t.Fatalf("parse www-authenticate: %v", err)
	}

	tokenBytes := bytes.Repeat([]byte{0xAB}, 100)
	auth := Authorization(tokenBytes)
	got, err := ParseAuthorization(auth)
	if err != nil || !bytes.Equal(got, tokenBytes) {
		t.Fatalf("parse authorization: %v", err)
	}
	// Quoted and comma-terminated parameter values also parse.
	got, err = ParseAuthorization(`PrivateToken token="` + auth[len("PrivateToken token="):] + `",`)
	if err != nil || !bytes.Equal(got, tokenBytes) {
		t.Fatalf("parse quoted authorization: %v", err)
	}

	for _, bad := range []string{"Bearer abc", "PrivateToken nope=x", "PrivateToken token=!!!"} {
		if _, err := ParseAuthorization(bad); err == nil {
			t.Fatalf("ParseAuthorization(%q) accepted", bad)
		}
	}
	if _, _, err := ParseWWWAuthenticate("PrivateToken challenge=abc"); err == nil {
		t.Fatal("missing token-key accepted")
	}
}
