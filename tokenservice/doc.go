// Package tokenservice composes tamayo token profiles into cgo-free issuer and
// verifier service APIs.
//
// The package deliberately stops before transport and persistence. Callers own
// HTTP, nonce storage, spent-token storage, clocks, and measurement collection.
package tokenservice
