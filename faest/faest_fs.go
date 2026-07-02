package faest

import "github.com/maceip/tamayo/field"

// FAEST Fiat-Shamir transcript and VOLE-hash plumbing. Transpiled from faest-rs
// src/faest.rs (the FaestHash impl) and src/parameter.rs (BaseParameters
// hash_u/v/q). The random oracles map to the domain-separated hashers in
// hash.go: H2^0..3 -> H2a..H2d, H3, H4.

// hashMu = H2^0(input || output || msg), 2*lambda bytes.
func hashMu(use256 bool, input, output, msg []byte, lam2 int) []byte {
	h := H2a(use256)
	h.Update(input)
	h.Update(output)
	h.Update(msg)
	mu := make([]byte, lam2)
	h.Finish().Read(mu)
	return mu
}

// hashRIV = H3(key || mu || rho) -> (r [lambda], iv_pre [16]).
func hashRIV(use256 bool, key, mu, rho []byte, lam int) (r, ivPre []byte) {
	h := H3(use256)
	h.Update(key)
	h.Update(mu)
	h.Update(rho)
	rd := h.Finish()
	r = make([]byte, lam)
	rd.Read(r)
	ivPre = make([]byte, 16)
	rd.Read(ivPre)
	return r, ivPre
}

// hashIV = H4(iv_pre) -> iv [16].
func hashIV(use256 bool, ivPre []byte) []byte {
	h := H4(use256)
	h.Update(ivPre)
	iv := make([]byte, 16)
	h.Finish().Read(iv)
	return iv
}

// hashChallenge1 = H2^1(mu || hcom || c || iv), Chall1 = 5*lambda+8 bytes.
func hashChallenge1(use256 bool, mu, hcom, c, iv []byte, challLen int) []byte {
	h := H2b(use256)
	h.Update(mu)
	h.Update(hcom)
	h.Update(c)
	h.Update(iv)
	out := make([]byte, challLen)
	h.Finish().Read(out)
	return out
}

// hashChallenge2Init starts H2^2(chall1 || u_tilde); the caller appends d before
// finalizing.
func hashChallenge2Init(use256 bool, chall1, uTilde []byte) *Hasher {
	h := H2c(use256)
	h.Update(chall1)
	h.Update(uTilde)
	return h
}

// hashChallenge2Finalize appends d and reads chall2 (3*lambda+8 bytes).
func hashChallenge2Finalize(h *Hasher, d []byte, chall2Len int) []byte {
	h.Update(d)
	out := make([]byte, chall2Len)
	h.Finish().Read(out)
	return out
}

// hashChallenge3 = H2^3(chall2 || a0 || a1 || a2 || ctr_le), lambda bytes.
func hashChallenge3(use256 bool, chall2, a0, a1, a2 []byte, ctr uint32, lam int) []byte {
	h := H2d(use256)
	h.Update(chall2)
	h.Update(a0)
	h.Update(a1)
	h.Update(a2)
	h.Update([]byte{byte(ctr), byte(ctr >> 8), byte(ctr >> 16), byte(ctr >> 24)})
	out := make([]byte, lam)
	h.Finish().Read(out)
	return out
}

// checkChallenge3 enforces the WGRIND grinding: the top WGRIND bits of chall3
// must be zero. Transpiled from faest.rs check_challenge_3.
func checkChallenge3(chall3 []byte, lambda, wgrind int) bool {
	startByte := (lambda - wgrind) / 8
	if chall3[startByte]>>((lambda-wgrind)%8) != 0 {
		return false
	}
	for _, b := range chall3[startByte+1:] {
		if b != 0 {
			return false
		}
	}
	return true
}

// hashUVector = VoleHash(u) under seed chall1 (VoleHasherOutputLength bytes).
func hashUVector(f field.Big, u, chall1 []byte) []byte {
	return NewVoleHasher(f, chall1).Process(u)
}

// hashVMatrix absorbs VoleHash(v_row) for each of the lambda rows of v into h2.
func hashVMatrix(f field.Big, h2 *Hasher, v [][]byte, chall1 []byte) {
	vh := NewVoleHasher(f, chall1)
	for _, row := range v {
		h2.Update(vh.Process(row))
	}
}

// hashQMatrix absorbs the corrected VoleHash(q_row) for each row into h2. The
// i-th row is XORed with u_tilde when bit i of the challenge delta (chall3) is
// set (decode_challenge_as_iter, truncated to lambda rows, is the delta bits).
func hashQMatrix(f field.Big, h2 *Hasher, q [][]byte, uTilde, chall1, chall3 []byte) {
	vh := NewVoleHasher(f, chall1)
	for i, row := range q {
		qt := vh.Process(row)
		if (chall3[i/8]>>(i%8))&1 == 1 {
			for k := range qt {
				qt[k] ^= uTilde[k]
			}
		}
		h2.Update(qt)
	}
}
