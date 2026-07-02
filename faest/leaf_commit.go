package faest

import "github.com/maceip/tamayo/field"

// LeafCommit is the BAVC leaf commitment. It expands the leaf seed r under
// (iv, tweak) with the PRG to 4*lambda bytes, then returns sd (the first lambda
// bytes) and com = LeafHash(uhash, the 4*lambda bytes). Transpiled from faest-rs
// src/bavc.rs (LeafCommitment::commit).
//
// ext is the degree-3 extension field for the security level (Big384/576/768);
// lambda = ext.Bytes/3. r is lambda bytes, iv is 16 bytes, uhash is 3*lambda
// bytes; sd is lambda bytes and com is 3*lambda bytes.
func LeafCommit(ext field.Big, r, iv []byte, tweak uint32, uhash []byte) (sd, com []byte) {
	lam := ext.Bytes / 3
	hash := make([]byte, 4*lam)
	NewPRG(r, iv, tweak).Read(hash)
	com = LeafHash(ext, uhash, hash)
	sd = append([]byte(nil), hash[:lam]...)
	return sd, com
}
