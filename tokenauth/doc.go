// Package tokenauth contains small, cgo-free authorization data structures for
// token minting.
//
// It is intentionally not a product policy engine. Product runtimes provide
// verified gate evidence, runtime measurement evidence, and optional budget
// storage. This package compiles a simple JSON policy and turns a mint request
// into an authorization decision that token services can consume.
//
// Budget semantics: AuthorizeMint enforces the policy's budget rule only
// when the caller supplies a BudgetStore — a nil store means "budget
// enforcement happens elsewhere" and the budget_available check passes
// unconditionally. Deployments that want in-process enforcement use
// MemoryBudgetStore (single process) or implement BudgetStore over shared
// storage; any store error denies issuance (fail-closed).
package tokenauth
