package emailtoken

import "encoding/base64"

var b64 = base64.RawURLEncoding

func encode(b []byte) string {
	return b64.EncodeToString(b)
}

func decode(s string) ([]byte, error) {
	return b64.DecodeString(s)
}
