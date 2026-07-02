// Command qemudemo runs the full One-More-MAYO blind signature on a bare
// TamaGo target (QEMU sifive_u, riscv64) as an on-device end-to-end check,
// covering all three security levels (L1/128, L3/192, L5/256).
//
// It embeds the reference vectors produced by tools/blind_loop_dump.cpp
// (the real blind_sig_optimized loop compiled against the C++/C reference),
// runs sign_1 -> sign_2 -> sign_3 -> verify on device for each level, and
// confirms that the device reproduces the reference blinded message,
// preimage and proof byte-for-byte and that the on-device verifier accepts
// good proofs and rejects tampered ones.
//
// Build/run: TARGET=sifive_u ... (see cmd/qemudemo/Makefile), which boots this
// under qemu-system-riscv64 -machine sifive_u and reads the UART console.
//
//go:build tamago

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"runtime"

	_ "github.com/usbarmory/tamago/board/qemu/sifive_u"

	"github.com/maceip/tamayo/faest"
	"github.com/maceip/tamayo/mayo"
)

//go:embed data/l1_epk.bin
var l1EPK []byte

//go:embed data/l1_csk.bin
var l1CSK []byte

//go:embed data/l1_m.bin
var l1Msg []byte

//go:embed data/l1_radd.bin
var l1RAdd []byte

//go:embed data/l1_proof.bin
var l1Proof []byte

//go:embed data/l1_t.bin
var l1T []byte

//go:embed data/l1_bsig.bin
var l1BSig []byte

//go:embed data/l3_epk.bin
var l3EPK []byte

//go:embed data/l3_csk.bin
var l3CSK []byte

//go:embed data/l3_m.bin
var l3Msg []byte

//go:embed data/l3_radd.bin
var l3RAdd []byte

//go:embed data/l3_proof.bin
var l3Proof []byte

//go:embed data/l3_t.bin
var l3T []byte

//go:embed data/l3_bsig.bin
var l3BSig []byte

//go:embed data/l5_epk.bin
var l5EPK []byte

//go:embed data/l5_csk.bin
var l5CSK []byte

//go:embed data/l5_m.bin
var l5Msg []byte

//go:embed data/l5_radd.bin
var l5RAdd []byte

//go:embed data/l5_proof.bin
var l5Proof []byte

//go:embed data/l5_t.bin
var l5T []byte

//go:embed data/l5_bsig.bin
var l5BSig []byte

type level struct {
	name  string
	owf   faest.MayoOWF
	mp    *mayo.Params
	epk   []byte
	csk   []byte
	msg   []byte
	rAdd  []byte
	proof []byte
	t     []byte
	bsig  []byte
}

func runLevel(l *level) bool {
	fmt.Printf("\n--- %s ---\n", l.name)

	// r_additional is consumed read-only here; keep a private copy.
	rAdd := append([]byte(nil), l.rAdd...)

	fmt.Print("[sign_1] blinding message ... ")
	t, st, h := l.owf.Sign1(l.msg, rAdd)
	okT := bytes.Equal(t, l.t)
	fmt.Printf("t byte-exact vs reference: %v\n", okT)

	fmt.Print("[sign_2] MAYO preimage ... ")
	bsig := l.mp.SignWithoutHashing(t, l.csk)
	okBSig := bytes.Equal(bsig, l.bsig)
	fmt.Printf("bsig byte-exact vs reference: %v\n", okBSig)

	fmt.Print("[sign_3] VOLE-in-the-Head proof ... ")
	sig := l.owf.Sign3(l.epk, h, bsig, st, rAdd)
	okProof := bytes.Equal(sig.Bytes, l.proof)
	fmt.Printf("proof byte-exact vs reference (%d bytes): %v\n", len(sig.Bytes), okProof)

	fmt.Print("[verify] on-device blind verify (Go proof) ... ")
	okVerifyGo := l.owf.BlindVerify(l.epk, l.msg, sig.Bytes, rAdd)
	fmt.Printf("verify=%v\n", okVerifyGo)

	fmt.Print("[verify] on-device blind verify (reference proof) ... ")
	okVerifyRef := l.owf.BlindVerify(l.epk, l.msg, l.proof, rAdd)
	fmt.Printf("verify=%v\n", okVerifyRef)

	bad := append([]byte(nil), sig.Bytes...)
	bad[0] ^= 1
	fmt.Print("[verify] tampered proof rejected ... ")
	rejected := !l.owf.BlindVerify(l.epk, l.msg, bad, rAdd)
	fmt.Printf("rejected=%v\n", rejected)

	pass := okT && okBSig && okProof && okVerifyGo && okVerifyRef && rejected
	if pass {
		fmt.Printf("%s: PASS\n", l.name)
	} else {
		fmt.Printf("%s: FAIL\n", l.name)
	}
	return pass
}

func main() {
	fmt.Print("\n=== One-More-MAYO blind signature on TamaGo (sifive_u/riscv64), L1+L3+L5 ===\n")

	levels := []*level{
		{"L1 (mayo_128_s)", faest.MayoOWFL1, &mayo.Mayo1, l1EPK, l1CSK, l1Msg, l1RAdd, l1Proof, l1T, l1BSig},
		{"L3 (mayo_192_s)", faest.MayoOWFL3, &mayo.Mayo3, l3EPK, l3CSK, l3Msg, l3RAdd, l3Proof, l3T, l3BSig},
		{"L5 (mayo_256_s)", faest.MayoOWFL5, &mayo.Mayo5, l5EPK, l5CSK, l5Msg, l5RAdd, l5Proof, l5T, l5BSig},
	}

	pass := true
	for _, l := range levels {
		pass = runLevel(l) && pass
		runtime.GC()
	}

	if pass {
		fmt.Print("\nRESULT: PASS — One-More-MAYO blind sign+verify byte-exact on device (L1+L3+L5).\n")
	} else {
		fmt.Print("\nRESULT: FAIL\n")
	}
	fmt.Print("DONE\n")
	for {
	}
}
