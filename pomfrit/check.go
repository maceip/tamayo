package pomfrit

import "github.com/maceip/tamayo/field"

// VOLE consistency check (sender side) for the optimized_bs MAYO path.
// Transpiled from pq_blind_signatures vole/faest-cpp-tmp/vole_check.hpp
// (detail::vole_check_both<P>, verifier=false) with the hashers from
// universal_hash.hpp.
//
// For each column (u, then the lambda columns of v) the check computes a 2x2
// linear map of two universal hashes of the column's QUICKSILVER_ROWS bits:
// H_s = Horner_{GF(2^lambda)}(lambda-bit chunks, key_secpar) and
// H_t = Horner_{GF(2^64)}(64-bit words, key_64). The batched delayed-reduction
// hashers of the reference evaluate the same Horner polynomials; since field
// reduction is a ring homomorphism, plain Horner yields byte-identical field
// elements. The lambda+2 output bytes are masked by the column tail.

// voleCheckChallenge is the parsed VOLE-check challenge: the 2x2 matrix, the
// GF(2^lambda) hash key s, and the GF(2^64) hash key t.
type voleCheckChallenge struct {
	matrix [4][]uint64
	s      []uint64
	t      field.GF64
}

func (m MayoForest) parseVoleCheckChallenge(f field.Big, challenge []byte) voleCheckChallenge {
	lb := m.LambdaBytes
	var c voleCheckChallenge
	for i := 0; i < 4; i++ {
		c.matrix[i] = f.FromBytes(challenge[i*lb : (i+1)*lb])
	}
	c.s = f.FromBytes(challenge[4*lb : 5*lb])
	c.t = field.GF64FromBytes(challenge[5*lb : 5*lb+8])
	return c
}

// qsRows = QUICKSILVER_ROWS = WITNESS_BITS + (QS_DEGREE-1=1)*lambda.
func (m MayoForest) qsRows() int { return m.WitnessBits + m.LambdaBytes*8 }

// paddedRows rounds qsRows up to a multiple of lambda (the gfsecpar chunk).
func (m MayoForest) paddedRows() int {
	lam := m.LambdaBytes * 8
	return (m.qsRows() + lam - 1) / lam * lam
}

// hashColumn computes the lambda+2 masked check bytes for one column (to_hash
// laid out as colLen 16-byte blocks). Matches vole_check_both's per-column body.
func (m MayoForest) hashColumn(f field.Big, ch voleCheckChallenge, col []byte) []byte {
	lb := m.LambdaBytes
	lam := lb * 8
	qs := m.qsRows()
	padded := m.paddedRows()

	// Zero-padded copy of the first padded_rows bits of the column.
	pc := make([]byte, padded/8)
	copy(pc, col[:qs/8])
	if qs%8 != 0 {
		// qsRows is a multiple of 8 for all MAYO params, but guard anyway.
		pc[qs/8] = col[qs/8] & byte((1<<(qs%8))-1)
	}

	// H_s: Horner over GF(2^lambda) of the padded_rows/lambda chunks.
	hs := f.Zero()
	for i := 0; i < padded/lam; i++ {
		chunk := f.FromBytes(pc[i*lb : (i+1)*lb])
		hs = f.Add(f.Mul(hs, ch.s), chunk)
	}

	// H_t: Horner in GF(2^64) over the padded_rows/64 64-bit words with key t
	// (hasher_gf64_state; its 2-way delayed reduction evaluates the same
	// polynomial). gf64_combine_hashes keeps the 64-bit result, then
	// poly_secpar::from zero-extends it into GF(2^lambda).
	var ht field.GF64
	for i := 0; i < padded/64; i++ {
		word := field.GF64FromBytes(pc[i*8 : i*8+8])
		ht = ht.Mul(ch.t).Add(word)
	}
	htLow := make([]byte, lb)
	htB := ht.Bytes()
	copy(htLow[:8], htB[:])
	h1 := f.FromBytes(htLow)

	// 2x2 map: mapped[j] = matrix[2j]*H_s + matrix[2j+1]*H_t.
	mapped0 := f.Add(f.Mul(ch.matrix[0], hs), f.Mul(ch.matrix[1], h1))
	mapped1 := f.Add(f.Mul(ch.matrix[2], hs), f.Mul(ch.matrix[3], h1))
	m0b, m1b := f.ToBytes(mapped0), f.ToBytes(mapped1)

	// Output = [mapped0 (lambda)] ++ [mapped1[:2]], XOR the column tail.
	out := make([]byte, lb+2)
	copy(out, m0b)
	out[lb] = m1b[0]
	out[lb+1] = m1b[1]
	tail := col[qs/8 : qs/8+lb+2]
	for i := range out {
		out[i] ^= tail[i]
	}
	return out
}

// VoleCheckSenderBlocks runs the sender vole_check over (u, v) and returns the
// ordered blocks it absorbs into the transcript hasher: the u_tilde proof
// (HASH_BYTES = lambda+2) followed by the lambda v-column hashes. Transpiled
// from vole_check_both (verifier=false): col=-1 (u) yields u_tilde and is
// absorbed first, then each v column.
func (m MayoForest) VoleCheckSenderBlocks(u, v, challenge []byte) (proof []byte, colHashes [][]byte) {
	f := m.field()
	ch := m.parseVoleCheckChallenge(f, challenge)
	colBytes := m.colLenBytes()
	lam := m.LambdaBytes * 8

	proof = m.hashColumn(f, ch, u)
	colHashes = make([][]byte, lam)
	for c := 0; c < lam; c++ {
		colHashes[c] = m.hashColumn(f, ch, v[c*colBytes:(c+1)*colBytes])
	}
	return proof, colHashes
}

// VoleCheckSender is VoleCheckSenderBlocks plus the fresh-hasher finalization
// (u_tilde ++ v-col hashes -> 2*lambda), used by the isolated vole_check KAT.
func (m MayoForest) VoleCheckSender(u, v, challenge []byte) (proof, transcriptHash []byte) {
	proof, colHashes := m.VoleCheckSenderBlocks(u, v, challenge)
	x := m.newXOF()
	x.Write(proof)
	for _, ch := range colHashes {
		x.Write(ch)
	}
	transcriptHash = make([]byte, 2*m.LambdaBytes)
	x.Read(transcriptHash)
	return proof, transcriptHash
}

// field returns the GF(2^lambda) descriptor for this parameter set.
func (m MayoForest) field() field.Big {
	switch m.LambdaBytes {
	case 16:
		return field.Big128
	case 24:
		return field.Big192
	case 32:
		return field.Big256
	}
	panic("faest: bad MAYO lambda")
}

// TransposeToMacs converts the column-major VOLE matrix (lambda columns, each
// colLen 16-byte blocks) into row-major field elements: macs[row] is the
// lambda-bit value whose bit c is column c's bit `row`. Matches transpose_secpar
// truncated to the given number of rows. Returns rows field elements as bytes.
func (m MayoForest) TransposeToMacs(v []byte, rows int) [][]byte {
	lb := m.LambdaBytes
	colBytes := m.colLenBytes()
	macs := make([][]byte, rows)
	for r := range macs {
		macs[r] = make([]byte, lb)
	}
	for c := 0; c < lb*8; c++ {
		col := v[c*colBytes : (c+1)*colBytes]
		for r := 0; r < rows; r++ {
			bit := (col[r/8] >> (r % 8)) & 1
			macs[r][c/8] |= bit << (c % 8)
		}
	}
	return macs
}
