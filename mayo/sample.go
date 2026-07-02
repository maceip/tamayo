package mayo

import "github.com/maceip/tamayo/gf16"

// ctCompare8 returns 0xff if a != b and 0 if a == b, in constant time.
// Transpiled from pq-mayo src/echelon.rs: ct_compare_8.
func ctCompare8(a, b byte) byte {
	diff := a ^ b
	nonzero := ((diff | (^diff + 1)) >> 7) & 1
	return -nonzero
}

// sampleSolution solves the linearized MAYO system A·x = y in constant time,
// with x prefilled with the random vinegar-derived r. It returns false if the
// system is singular (caller retries). Transpiled from pq-mayo
// src/sample.rs: sample_solution.
//
// a is m×ACols (last column is workspace), y has m elements, x has ACols bytes.
func sampleSolution(p *Params, a, y, x []byte) bool {
	k := p.K
	o := p.O
	m := p.M
	aCols := p.ACols()
	ko := k * o

	// Ar = A · x (last column of A cleared first)
	ar := make([]byte, m)
	for i := 0; i < m; i++ {
		a[ko+i*aCols] = 0
	}
	gf16.MatMul(ar, a, x, m, aCols, 1)

	// last column of A <- y - Ar
	for i := 0; i < m; i++ {
		a[ko+i*aCols] = y[i] ^ ar[i]
	}

	gf16.EF(a, m, aCols)

	// rank indicator (computed before back-substitution; returned after)
	var fullRank byte
	for i := 0; i < aCols-1; i++ {
		fullRank |= a[(m-1)*aCols+i]
	}

	// back substitution — runs unconditionally to avoid secret-dependent timing
	for row := m - 1; row >= 0; row-- {
		var finished byte
		colUpperBound := row + 32/(m-row)
		if colUpperBound > ko {
			colUpperBound = ko
		}
		for col := row; col <= colUpperBound; col++ {
			correctColumn := ctCompare8(a[row*aCols+col], 0) &^ finished
			u := correctColumn & a[row*aCols+aCols-1]
			x[col] ^= u

			for i := 0; i < row; i += 8 {
				end := i + 8
				if end > row {
					end = row
				}
				var tmp uint64
				for ii := i; ii < end; ii++ {
					tmp ^= uint64(a[ii*aCols+col]) << uint((ii-i)*8)
				}
				tmp = gf16.MulFx8(u, tmp)
				for ii := i; ii < end; ii++ {
					a[ii*aCols+aCols-1] ^= byte((tmp >> uint((ii-i)*8)) & 0xf)
				}
			}

			finished |= correctColumn
		}
	}

	return fullRank != 0
}
