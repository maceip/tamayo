package tokenprofile

// RFC 9577 PrivateToken HTTP carriage, ported from the reference core http
// module and wire-compatible with it: how an origin challenges for a token
// (WWW-Authenticate) and how a client presents one (Authorization). These
// are pure header codecs — no HTTP types — so they work in any server or
// client.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const privateTokenScheme = "PrivateToken"

var b64url = base64.RawURLEncoding

// WWWAuthenticate builds the challenge header value an origin returns with
// 401: the fresh challenge bytes plus the issuer public key the client
// should expect tokens under.
func WWWAuthenticate(challenge, issuerPublicKey []byte) string {
	return fmt.Sprintf("%s challenge=%s, token-key=%s",
		privateTokenScheme, b64url.EncodeToString(challenge), b64url.EncodeToString(issuerPublicKey))
}

// Authorization builds the presentation header value carrying a serialized
// token (burn or private-identity bytes).
func Authorization(tokenBytes []byte) string {
	return privateTokenScheme + " token=" + b64url.EncodeToString(tokenBytes)
}

// ParseAuthorization extracts the raw token bytes from an Authorization
// header value. The caller decides the token family (ParseBurnToken /
// ParsePrivateIdentityToken).
func ParseAuthorization(header string) ([]byte, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(header), privateTokenScheme)
	if !ok {
		return nil, errors.New("not a PrivateToken authorization header")
	}
	_, v, ok := strings.Cut(rest, "token=")
	if !ok {
		return nil, errors.New("missing token= parameter")
	}
	v = strings.Trim(strings.TrimSuffix(strings.TrimSpace(v), ","), `"`)
	tokenBytes, err := b64url.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("token base64url: %w", err)
	}
	return tokenBytes, nil
}

// ParseWWWAuthenticate extracts the challenge bytes and issuer public key
// from a WWW-Authenticate header value.
func ParseWWWAuthenticate(header string) (challenge, issuerPublicKey []byte, err error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(header), privateTokenScheme)
	if !ok {
		return nil, nil, errors.New("not a PrivateToken challenge header")
	}
	get := func(param string) ([]byte, error) {
		_, v, ok := strings.Cut(rest, param+"=")
		if !ok {
			return nil, fmt.Errorf("missing %s= parameter", param)
		}
		v, _, _ = strings.Cut(v, ",")
		return b64url.DecodeString(strings.Trim(strings.TrimSpace(v), `"`))
	}
	if challenge, err = get("challenge"); err != nil {
		return nil, nil, err
	}
	if issuerPublicKey, err = get("token-key"); err != nil {
		return nil, nil, err
	}
	return challenge, issuerPublicKey, nil
}
