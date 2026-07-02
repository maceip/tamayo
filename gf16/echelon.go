package gf16

// Constant-time row echelon form over GF(16), the core of MAYO's preimage
// solver. The algorithm is a direct port of the MAYO reference EF
// (MAYO-C, src/generic/echelon_form.h; cross-checked against pq-mayo
// src/echelon.rs): the pivot column is public but the pivot row is treated as
// secret, so row selection and elimination use branch-free masks.
//
// This implementation operates on the element-per-byte layout used elsewhere in
// this package. The nibble-packed (SIMD-friendly) representation used by the
// reference is a throughput optimization that can be added later without
// changing this API or its results.

// ctNeqMask returns ^0 if a != b and 0 if a == b, for non-negative ints.
func ctNeqMask(a, b int) uint64 {
	d := uint64(a) ^ uint64(b)
	return uint64(int64(d|(^d+1)) >> 63) // (d | -d) has bit 63 set iff d != 0
}

// ctEqMask returns ^0 if a == b, else 0.
func ctEqMask(a, b int) uint64 { return ^ctNeqMask(a, b) }

// ctGtMask returns ^0 if a > b, else 0, for non-negative ints in range.
func ctGtMask(a, b int) uint64 {
	return uint64(int64(uint64(b)-uint64(a)) >> 63) // b-a is negative iff a > b
}

// EF reduces the nrows x ncols matrix A (row-major, one GF(16) element per
// byte) to row echelon form with leading ones, in place and in constant time
// with respect to the matrix entries.
func EF(a []byte, nrows, ncols int) {
	pivotRow := make([]byte, ncols)
	pivotRow2 := make([]byte, ncols)
	pr := 0

	for pivotCol := 0; pivotCol < ncols; pivotCol++ {
		lo := pivotCol + nrows - ncols
		if lo < 0 {
			lo = 0
		}
		hi := pivotCol
		if hi > nrows-1 {
			hi = nrows - 1
		}

		for i := range pivotRow {
			pivotRow[i] = 0
		}

		// Assemble the pivot row in constant time: take the row at index pr,
		// or the first nonzero row below it if pr's candidate is still zero.
		pivotIsZero := ^uint64(0)
		searchHi := hi + 32
		if searchHi > nrows-1 {
			searchHi = nrows - 1
		}
		for row := lo; row <= searchHi; row++ {
			sel := ctEqMask(row, pr) | (ctGtMask(row, pr) & pivotIsZero)
			m := byte(sel)
			base := row * ncols
			for j := 0; j < ncols; j++ {
				pivotRow[j] ^= m & a[base+j]
			}
			pivotIsZero = ctEqMask(int(pivotRow[pivotCol]), 0)
		}

		// Normalize: pivotRow2 = inverse(pivot) * pivotRow (Inv(0)=0 is safe).
		inv := Inv(pivotRow[pivotCol])
		for j := 0; j < ncols; j++ {
			pivotRow2[j] = Mul(inv, pivotRow[j])
		}

		// Write the normalized pivot row back to row pr iff the pivot is nonzero.
		for row := lo; row <= hi; row++ {
			doCopy := byte(ctEqMask(row, pr) &^ pivotIsZero)
			keep := ^doCopy
			base := row * ncols
			for j := 0; j < ncols; j++ {
				a[base+j] = (keep & a[base+j]) | (doCopy & pivotRow2[j])
			}
		}

		// Eliminate the pivot column in all rows strictly below the pivot.
		for row := lo; row < nrows; row++ {
			below := byte(ctGtMask(row, pr))
			elt := a[row*ncols+pivotCol] & below
			base := row * ncols
			for j := 0; j < ncols; j++ {
				a[base+j] ^= Mul(elt, pivotRow2[j])
			}
		}

		pr += int(^pivotIsZero & 1) // advance only when a nonzero pivot was found
	}
}
