// Package tokenprofile contains cgo-free token profile building blocks on top
// of tamayo's PoMFRIT/MAYO primitives.
//
// This package owns token wire formats and cryptographic verification only. It
// deliberately does not own HTTP, storage, policy files, runtime measurement
// collection, or replay databases.
package tokenprofile
