// Package emailtoken implements the Google EVT-style JOSE profile used by the
// stack for interoperability tests and address-bearing verification.
//
// It owns JWT/JWS formatting, issuer keys, EVT claims, KB-JWT presentation
// verification, and JWKS output. It does not send email, run HTTP routes,
// store nonces, or perform token policy checks.
package emailtoken
