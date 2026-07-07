package faest

// Tau holds one FAEST GGM-tree / small-VOLE parameter set, the "TauParameters"
// of faest-rs src/parameter.rs. Every derived quantity below is a pure integer
// function of these fields.
//
// The forest is a single GGM tree with L leaves (2*L-1 nodes total); it is
// partitioned into Tau small-VOLE instances, Tau1 of depth K and Tau0 of depth
// K-1, so that Tau0+Tau1 == Tau and Tau1*2^K + Tau0*2^(K-1) == L.
type Tau struct {
	Name  string
	Tau   int // number of small-VOLE instances
	K     int // bit-length (depth) of the larger instances
	L     int // number of GGM-tree leaves
	Tau0  int // number of smaller instances (depth K-1)
	Tau1  int // number of larger instances (depth K)
	Topen int // maximum GGM opening-size threshold
}

// The standard (non-EM) FAEST parameter sets, transpiled verbatim from
// faest-rs src/parameter.rs. Small trades speed for smaller proofs; Fast the
// reverse. Security levels 128/192/256 line up with MAYO 1/3/5.
var (
	Tau128Small = Tau{"128s", 11, 12, 22528, 11, 0, 102}
	Tau128Fast  = Tau{"128f", 16, 8, 3072, 8, 8, 110}
	Tau192Small = Tau{"192s", 16, 12, 40960, 12, 4, 162}
	Tau192Fast  = Tau{"192f", 24, 8, 5120, 8, 16, 163}
	Tau256Small = Tau{"256s", 22, 12, 61440, 14, 8, 245}
	Tau256Fast  = Tau{"256f", 32, 8, 7168, 8, 24, 246}

	// Even-Mansour Tau sets: same tau/k split as their AES counterparts but
	// distinct leaf counts (L) and opening thresholds (Topen). Transpiled
	// from faest-rs src/parameter.rs Tau*EM.
	Tau128SmallEM = Tau{"em128s", 11, 12, 22528, 11, 0, 103}
	Tau128FastEM  = Tau{"em128f", 16, 8, 3072, 8, 8, 112}
	Tau192SmallEM = Tau{"em192s", 16, 12, 49152, 8, 8, 162}
	Tau192FastEM  = Tau{"em192f", 24, 8, 5120, 8, 16, 176}
	Tau256SmallEM = Tau{"em256s", 22, 12, 61440, 14, 8, 218}
	Tau256FastEM  = Tau{"em256f", 32, 8, 7168, 8, 24, 234}
)

// Tau1Offset returns the flat offset of the i-th (larger) instance's bits.
func (t Tau) Tau1Offset(i int) int { return t.K * i }

// Tau0Offset returns the flat offset of the i-th (smaller) instance's bits.
func (t Tau) Tau0Offset(i int) int { return t.Tau1*t.K + (t.K-1)*(i-t.Tau1) }

// BavcIndexOffset returns the leaf offset of the i-th small-VOLE instance
// within the GGM tree.
func (t Tau) BavcIndexOffset(i int) int {
	if i < t.Tau1 {
		return (1 << t.K) * i
	}
	return t.Tau1*(1<<t.K) + (1<<(t.K-1))*(i-t.Tau1)
}

// BavcMaxNodeDepth returns the maximum depth of the i-th small-VOLE instance.
func (t Tau) BavcMaxNodeDepth(i int) int {
	if i < t.Tau1 {
		return t.K
	}
	return t.K - 1
}

// BavcMaxNodeIndex returns the number of leaves of the i-th small-VOLE instance.
func (t Tau) BavcMaxNodeIndex(i int) int { return 1 << t.BavcMaxNodeDepth(i) }

// PosInTree maps the j-th entry of the i-th small-VOLE instance to its leaf
// index in the GGM tree.
func (t Tau) PosInTree(i, j int) int {
	tmp := 1 << (t.K - 1)
	if j < tmp {
		return t.L - 1 + t.Tau*j + i
	}
	// mod 2^(k-1) is the k-2 LSBs.
	mask := tmp - 1
	return t.L - 1 + t.Tau*tmp + t.Tau1*(j&mask) + i
}

// VoleArrayLength returns the array length required to generate the VOLE
// correlations of the i-th instance in ConvertToVOLE.
func (t Tau) VoleArrayLength(i int) int {
	n := t.BavcMaxNodeIndex(i)
	sum := 0
	for d := 2; d < t.BavcMaxNodeDepth(i); d++ {
		sum += n/(1<<d) - 1
	}
	return n/2 - sum
}

// challToU16 extracts k (< 16) bits from chall starting at bit index startBit,
// least-significant bit first. Transpiled from faest-rs src/utils.rs
// (chall_to_u16 + extract_k_bits_*).
func challToU16(chall []byte, startBit, k int) uint16 {
	byteIdx := startBit / 8
	bitOff := startBit % 8
	nbitsFirst := 8 - bitOff

	if k <= nbitsFirst {
		mask := uint16((1 << k) - 1)
		return (uint16(chall[byteIdx]) >> bitOff) & mask
	}

	firstMask := uint16((1 << nbitsFirst) - 1)
	res := (uint16(chall[byteIdx]) >> bitOff) & firstMask

	if k <= 8+nbitsFirst {
		nextMask := uint16((1 << (k - nbitsFirst)) - 1)
		res |= (uint16(chall[byteIdx+1]) & nextMask) << nbitsFirst
		return res
	}

	res |= uint16(chall[byteIdx+1]) << nbitsFirst
	thirdMask := uint16((1 << (k - nbitsFirst - 8)) - 1)
	res |= (uint16(chall[byteIdx+2]) & thirdMask) << (nbitsFirst + 8)
	return res
}

// DecodeChallenge decodes a lambda-bit challenge into the Tau hidden-leaf
// indices i_delta (each in [0, 2^k_i)). Transpiled from faest-rs src/utils.rs
// (decode_all_chall_3).
func (t Tau) DecodeChallenge(chall []byte) []uint16 {
	out := make([]uint16, t.Tau)
	for i := 0; i < t.Tau1; i++ {
		out[i] = challToU16(chall, t.Tau1Offset(i), t.K)
	}
	for i := t.Tau1; i < t.Tau; i++ {
		out[i] = challToU16(chall, t.Tau0Offset(i), t.K-1)
	}
	return out
}
