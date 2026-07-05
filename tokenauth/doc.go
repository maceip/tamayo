// Package tokenauth contains small, cgo-free authorization data structures for
// token minting.
//
// It is intentionally not a product policy engine. Product runtimes provide
// verified bridge evidence, runtime measurement evidence, and optional budget
// storage. This package compiles a simple JSON policy and turns a mint request
// into an authorization decision that token services can consume.
package tokenauth
