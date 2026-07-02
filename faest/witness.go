package faest

import "github.com/maceip/tamayo/field"

// OWFParams holds the constants of one FAEST one-way-function parameter set (the
// standard AES sets and the Even-Mansour Rijndael sets). Transpiled from the
// OWFParameters impls in faest-rs src/parameter.rs.
type OWFParams struct {
	Name        string
	LambdaBytes int // security level in bytes (also the Rijndael key length)
	InputSize   int // OWF input length in bytes
	LBytes      int // extended-witness length in bytes
	NK          int // key columns
	R           int // rounds
	SKe         int // key-schedule S-box count
	Beta        int // number of OWF blocks
	NSt         int // state (block) columns
	LKe         int // key-schedule witness bits
	LEnc        int // per-block encryption witness bits
	IsEM        bool
}

// Lambda returns the security level in bits.
func (o OWFParams) Lambda() int { return o.LambdaBytes * 8 }

// L returns the extended-witness length in bits.
func (o OWFParams) L() int { return o.LBytes * 8 }

// NStBits is the state size in bits (one commitment per bit).
func (o OWFParams) NStBits() int { return o.NSt * 32 }

// NStBytes is the state size in bytes.
func (o OWFParams) NStBytes() int { return o.NSt * 4 }

// R1Times128 is the key-schedule forward-expansion size in bits, 128*(R+1).
func (o OWFParams) R1Times128() int { return (o.R + 1) * 128 }

// LKeMinusLambda is LKe - Lambda.
func (o OWFParams) LKeMinusLambda() int { return o.LKe - o.Lambda() }

// The standard AES and Even-Mansour Rijndael FAEST parameter sets.
var (
	OWF128 = OWFParams{Name: "128", LambdaBytes: 16, InputSize: 16, LBytes: 160, NK: 4, R: 10, SKe: 40, Beta: 1, NSt: 4, LKe: 448, LEnc: 832}
	OWF192 = OWFParams{Name: "192", LambdaBytes: 24, InputSize: 16, LBytes: 312, NK: 6, R: 12, SKe: 32, Beta: 2, NSt: 4, LKe: 448, LEnc: 1024}
	OWF256 = OWFParams{Name: "256", LambdaBytes: 32, InputSize: 16, LBytes: 388, NK: 8, R: 14, SKe: 52, Beta: 2, NSt: 4, LKe: 672, LEnc: 1216}

	OWF128EM = OWFParams{Name: "128em", LambdaBytes: 16, InputSize: 16, LBytes: 120, NK: 4, R: 10, SKe: 40, Beta: 1, NSt: 4, LKe: 128, LEnc: 832, IsEM: true}
	OWF192EM = OWFParams{Name: "192em", LambdaBytes: 24, InputSize: 24, LBytes: 216, NK: 6, R: 12, SKe: 52, Beta: 1, NSt: 6, LKe: 192, LEnc: 1536, IsEM: true}
	OWF256EM = OWFParams{Name: "256em", LambdaBytes: 32, InputSize: 32, LBytes: 336, NK: 8, R: 14, SKe: 60, Beta: 1, NSt: 8, LKe: 256, LEnc: 2432, IsEM: true}
)

// gf8Exp238 raises x to the 238th power in GF(2^8) via the reference addition
// chain (238 = 0b11101110). Transpiled from witness.rs gf8_exp_238.
func gf8Exp238(x field.GF8) field.GF8 {
	y := x.Square()
	x = y.Square()
	y = x.Mul(y)
	x = x.Square()
	y = x.Mul(y)
	x = x.Square()
	x = x.Square()
	y = x.Mul(y)
	x = x.Square()
	y = x.Mul(y)
	x = x.Square()
	return x.Mul(y)
}

func invnorm(x byte) byte {
	v := byte(gf8Exp238(field.GF8(x)))
	return (v & 1) ^ ((v >> 5) & 6) ^ ((v << 1) & 8)
}

func storeInvnormState(lo, hi byte) byte {
	return invnorm(lo) | (invnorm(hi) << 4)
}

// batchWord returns the w-th 4-byte word of a two-block batch (w in 0..8).
func batchWord(bb [2][16]byte, w int) [4]byte {
	var out [4]byte
	copy(out[:], bb[w/4][(w%4)*4:(w%4)*4+4])
	return out
}

func saveKeyBits(o OWFParams, witness, key []byte, index *int) {
	copy(witness[:o.LambdaBytes], key[:o.LambdaBytes])
	*index += o.LambdaBytes
}

func saveNonLinBits(o OWFParams, witness []byte, kb []uint32, index *int) {
	startOff := 1 + o.NK/8

	var nonLin int
	if o.NK%4 == 0 {
		nonLin = o.SKe / 4
	} else {
		nonLin = o.SKe * 3 / 8
	}

	for j := startOff; j < startOff+nonLin; j++ {
		res := invBitslice(kb[8*j : 8*(j+1)])
		if o.NK != 6 || j%3 == 0 {
			w := batchWord(res, 0)
			copy(witness[*index:*index+4], w[:])
			*index += 4
		} else if j%3 == 1 {
			w := batchWord(res, 2)
			copy(witness[*index:*index+4], w[:])
			*index += 4
		}
	}
}

func roundWithSave(o OWFParams, input []byte, kb []uint32, witness []byte, index *int) {
	state := make([]uint32, 8)
	var in1 []byte
	if len(input) > 16 {
		in1 = input[16:]
	}
	bitslice(state, input[:16], in1)
	rijndaelAddRoundKey(state, kb[:8])

	for j := 0; j < o.R-1; j++ {
		even := j%2 == 0

		if even {
			toTake := 4
			if o.IsEM {
				toTake = o.NK
			}
			res := invBitslice(state)
			for i := 0; i < toTake; i++ {
				w := batchWord(res, i)
				witness[*index] = storeInvnormState(w[0], w[1])
				*index++
				witness[*index] = storeInvnormState(w[2], w[3])
				*index++
			}
		}

		subBytes(state)
		subBytesNots(state)
		rijndaelShiftRows1(state, o.NSt)

		if !even {
			res := invBitslice(state)
			for i := 0; i < o.NSt; i++ {
				w := batchWord(res, i)
				copy(witness[*index:*index+4], w[:])
				*index += 4
			}
		}

		mixColumns0(state)
		rijndaelAddRoundKey(state, kb[8*(j+1):8*(j+2)])
	}
}

// aesExtendedWitness derives the FAEST extended witness. Transpiled from
// witness.rs aes_extendedwitness; owfSecret keys the Rijndael, owfInput is the
// block(s) it encrypts.
func aesExtendedWitness(o OWFParams, owfSecret, owfInput []byte) []byte {
	input := append([]byte(nil), owfInput...)
	witness := make([]byte, o.LBytes)
	kb := rijndaelKeySchedule(owfSecret, o.NSt, o.NK, o.R, o.SKe)

	index := 0
	if !o.IsEM {
		saveKeyBits(o, witness, owfSecret, &index)
		saveNonLinBits(o, witness, kb, &index)
	} else {
		saveKeyBits(o, witness, owfInput, &index)
	}

	for b := 0; b < o.Beta; b++ {
		roundWithSave(o, input, kb, witness, &index)
		input[0] ^= 1
	}

	return witness
}

// ExtendWitness computes the FAEST extended witness for (key, input), applying
// the Even-Mansour key/input swap so callers always pass (key, input).
func ExtendWitness(o OWFParams, key, input []byte) []byte {
	if o.IsEM {
		return aesExtendedWitness(o, input, key)
	}
	return aesExtendedWitness(o, key, input)
}
