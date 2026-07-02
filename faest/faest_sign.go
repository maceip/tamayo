package faest

import (
	"encoding/binary"
	"io"

	"github.com/maceip/tamayo/field"
)

// FaestParams binds an OWF, Tau/BAVC, and grinding parameter into a FAEST
// signature scheme instance. Transpiled from faest-rs src/parameter.rs
// (FAESTParameters) and src/faest.rs (sign/verify).
type FaestParams struct {
	Name    string
	OWF     OWFParams
	Tau     Tau
	Ext     field.Big // degree-3 extension field for BAVC leaf commitments
	Field   field.Big // OWF field (GF128/192/256)
	WGrind  int
	SigSize int
}

// The six standard (non-EM) FAEST parameter sets.
var (
	FAEST128s = FaestParams{"128s", OWF128, Tau128Small, field.Big384, field.Big128, 7, 4506}
	FAEST128f = FaestParams{"128f", OWF128, Tau128Fast, field.Big384, field.Big128, 8, 5924}
	FAEST192s = FaestParams{"192s", OWF192, Tau192Small, field.Big576, field.Big192, 12, 11260}
	FAEST192f = FaestParams{"192f", OWF192, Tau192Fast, field.Big576, field.Big192, 8, 14948}
	FAEST256s = FaestParams{"256s", OWF256, Tau256Small, field.Big768, field.Big256, 6, 20696}
	FAEST256f = FaestParams{"256f", OWF256, Tau256Fast, field.Big768, field.Big256, 8, 26548}
)

func (p FaestParams) use256() bool { return p.OWF.LambdaBytes != 16 }
func (p FaestParams) lHat() int    { return p.OWF.LBytes + 3*p.OWF.LambdaBytes + 2 }

func flatten(parts [][]byte) []byte {
	var out []byte
	for _, x := range parts {
		out = append(out, x...)
	}
	return out
}

// evaluateOWF computes the OWF output y = AES_key(input) for each of Beta blocks
// (byte 0 of the input flipped per block). Transpiled from parameter.rs
// evaluate_owf (non-EM).
func evaluateOWF(o OWFParams, key, input []byte) []byte {
	out := make([]byte, 0, o.Beta*16)
	inp := append([]byte(nil), input...)
	rkeys := rijndaelKeySchedule(key, o.NSt, o.NK, o.R, o.SKe)
	for b := 0; b < o.Beta; b++ {
		padded := make([]byte, 32)
		copy(padded, inp)
		res := rijndaelEncrypt(rkeys, padded, o.NSt, o.R)
		out = append(out, res[0][:16]...)
		inp[0] ^= 1
	}
	return out
}

// KeyGen samples a FAEST secret key (owf_input || owf_key) from rand and derives
// the public key. It applies the reference rejection rule: owf_key is resampled
// while the low two bits of its first byte are both set (owf_key[0]&3 == 3),
// which the first QuickSilver constraint (k0*k1 = 0) requires. The draw order
// matches faest-rs keygen_with_rng: owf_key first, then owf_input.
func (p FaestParams) KeyGen(rand io.Reader) (sk []byte, pk *PublicKey, err error) {
	o := p.OWF
	owfKey := make([]byte, o.LambdaBytes)
	for {
		if _, err = io.ReadFull(rand, owfKey); err != nil {
			return nil, nil, err
		}
		if owfKey[0]&0b11 != 0b11 {
			break
		}
	}
	owfInput := make([]byte, o.InputSize)
	if _, err = io.ReadFull(rand, owfInput); err != nil {
		return nil, nil, err
	}
	sk = append(append([]byte(nil), owfInput...), owfKey...)
	_, _, pk = p.PublicKeyFromSecret(sk)
	return sk, pk, nil
}

// PublicKeyFromSecret parses a FAEST secret key (owf_input || owf_key) and
// derives the public key.
func (p FaestParams) PublicKeyFromSecret(sk []byte) (owfKey, owfInput []byte, pk *PublicKey) {
	o := p.OWF
	owfInput = sk[:o.InputSize]
	owfKey = sk[o.InputSize : o.InputSize+o.LambdaBytes]
	pk = &PublicKey{OwfInput: owfInput, OwfOutput: evaluateOWF(o, owfKey, owfInput)}
	return owfKey, owfInput, pk
}

// Sign produces a FAEST signature. Transpiled from faest.rs faest_sign/sign.
func (p FaestParams) Sign(msg, sk, rho []byte) []byte {
	o := p.OWF
	f := p.Field
	u256 := p.use256()
	lam := o.LambdaBytes
	lHat := p.lHat()

	owfKey, owfInput, pk := p.PublicKeyFromSecret(sk)
	witness := ExtendWitness(o, owfKey, owfInput)

	mu := hashMu(u256, pk.OwfInput, pk.OwfOutput, msg, 2*lam)
	r, ivPre := hashRIV(u256, owfKey, mu, rho, lam)
	iv := hashIV(u256, ivPre)

	bavc := NewBavc(p.Tau, p.Ext)
	vc := bavc.VoleCommit(r, iv, lHat)

	cs := flatten(vc.C)
	chall1 := hashChallenge1(u256, mu, vc.Com, cs, iv, 5*lam+8)
	uTilde := hashUVector(f, vc.U, chall1)

	h2 := hashChallenge2Init(u256, chall1, uTilde)
	hashVMatrix(f, h2, vc.V, chall1)

	d := make([]byte, o.LBytes)
	for i := range d {
		d[i] = witness[i] ^ vc.U[i]
	}
	chall2 := hashChallenge2Finalize(h2, d, 3*lam+8)

	a0, a1, a2 := o.AesProve(f, witness, vc.U[o.LBytes:o.LBytes+2*lam], vc.V, pk, chall2)
	a0b, a1b, a2b := f.ToBytes(a0), f.ToBytes(a1), f.ToBytes(a2)

	decomSize := p.Tau.Tau*3*lam + p.Tau.Topen*lam
	for ctr := uint32(0); ; ctr++ {
		chall3 := hashChallenge3(u256, chall2, a0b, a1b, a2b, ctr, lam)
		if !checkChallenge3(chall3, o.Lambda(), p.WGrind) {
			continue
		}
		iDelta := p.Tau.DecodeChallenge(chall3)
		op, ok := bavc.Open(vc.Keys, vc.Coms, iDelta)
		if !ok {
			continue
		}

		decom := make([]byte, 0, decomSize)
		for _, c := range op.Coms {
			decom = append(decom, c...)
		}
		for _, n := range op.Nodes {
			decom = append(decom, n...)
		}
		for len(decom) < decomSize {
			decom = append(decom, 0)
		}

		ctrLE := make([]byte, 4)
		binary.LittleEndian.PutUint32(ctrLE, ctr)

		sig := make([]byte, 0, p.SigSize)
		sig = append(sig, cs...)
		sig = append(sig, uTilde...)
		sig = append(sig, d...)
		sig = append(sig, a1b...)
		sig = append(sig, a2b...)
		sig = append(sig, decom...)
		sig = append(sig, chall3...)
		sig = append(sig, ivPre...)
		sig = append(sig, ctrLE...)
		return sig
	}
}

// Verify checks a FAEST signature. Transpiled from faest.rs faest_verify/verify.
func (p FaestParams) Verify(msg []byte, pk *PublicKey, sig []byte) bool {
	o := p.OWF
	f := p.Field
	u256 := p.use256()
	lam := o.LambdaBytes
	lHat := p.lHat()

	csLen := lHat * (p.Tau.Tau - 1)
	uTildeLen := lam + 2
	decomSize := p.Tau.Tau*3*lam + p.Tau.Topen*lam

	off := 0
	take := func(n int) []byte { s := sig[off : off+n]; off += n; return s }
	cs := take(csLen)
	uTilde := take(uTildeLen)
	d := take(o.LBytes)
	a1b := take(lam)
	a2b := take(lam)
	decomI := take(decomSize)
	chall3 := take(lam)
	ivPre := take(16)
	ctrB := take(4)

	if !checkChallenge3(chall3, o.Lambda(), p.WGrind) {
		return false
	}
	ctr := binary.LittleEndian.Uint32(ctrB)

	mu := hashMu(u256, pk.OwfInput, pk.OwfOutput, msg, 2*lam)
	iv := hashIV(u256, ivPre)

	// parse decommitment
	comSize := 3 * lam
	op := &BavcOpening{}
	for i := 0; i < p.Tau.Tau; i++ {
		op.Coms = append(op.Coms, decomI[i*comSize:(i+1)*comSize])
	}
	nodes := decomI[p.Tau.Tau*comSize:]
	for i := 0; i+lam <= len(nodes); i += lam {
		op.Nodes = append(op.Nodes, nodes[i:i+lam])
	}

	// reshape cs into Tau-1 rows of lHat
	cRows := make([][]byte, p.Tau.Tau-1)
	for i := range cRows {
		cRows[i] = cs[i*lHat : (i+1)*lHat]
	}

	bavc := NewBavc(p.Tau, p.Ext)
	rec, ok := bavc.VoleReconstruct(chall3, op, cRows, iv, lHat)
	if !ok {
		return false
	}

	chall1 := hashChallenge1(u256, mu, rec.Com, cs, iv, 5*lam+8)
	h2 := hashChallenge2Init(u256, chall1, uTilde)
	hashQMatrix(f, h2, rec.Q, uTilde, chall1, chall3)
	chall2 := hashChallenge2Finalize(h2, d, 3*lam+8)

	a0 := o.AesVerify(f, rec.Q, d, pk, chall2, chall3, a1b, a2b)
	chall3p := hashChallenge3(u256, chall2, f.ToBytes(a0), a1b, a2b, ctr, lam)

	if len(chall3) != len(chall3p) {
		return false
	}
	for i := range chall3 {
		if chall3[i] != chall3p[i] {
			return false
		}
	}
	return true
}
