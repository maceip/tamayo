// Command qemudemo runs the full One-More-MAYO blind signature (L1) on a bare
// TamaGo target (QEMU sifive_u, riscv64) as an on-device end-to-end check.
//
// It embeds the L1 reference vector produced by tools/blind_loop_dump.cpp
// (the real blind_sig_optimized loop compiled against the C++/C reference),
// runs sign_1 -> sign_2 -> sign_3 -> verify on device, and confirms that the
// device reproduces the reference blinded message, preimage and proof
// byte-for-byte and that the on-device verifier accepts.
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

	_ "github.com/usbarmory/tamago/board/qemu/sifive_u"

	"github.com/maceip/tamayo/faest"
	"github.com/maceip/tamayo/mayo"
)

//go:embed data/epk.bin
var epk []byte

//go:embed data/csk.bin
var csk []byte

//go:embed data/m.bin
var msg []byte

//go:embed data/radd.bin
var rAdditional []byte

//go:embed data/proof.bin
var refProof []byte

//go:embed data/t.bin
var refT []byte

//go:embed data/bsig.bin
var refBSig []byte

func main() {
	fmt.Print("\n=== One-More-MAYO blind signature on TamaGo (sifive_u/riscv64), L1 ===\n")

	o := faest.MayoOWFL1
	mp := &mayo.Mayo1

	// r_additional is consumed read-only here; keep a private copy.
	rAdd := append([]byte(nil), rAdditional...)

	fmt.Print("[sign_1] blinding message ... ")
	t, st, h := o.Sign1(msg, rAdd)
	okT := bytes.Equal(t, refT)
	fmt.Printf("t byte-exact vs reference: %v\n", okT)

	fmt.Print("[sign_2] MAYO preimage ... ")
	bsig := mp.SignWithoutHashing(t, csk)
	okBSig := bytes.Equal(bsig, refBSig)
	fmt.Printf("bsig byte-exact vs reference: %v\n", okBSig)

	fmt.Print("[sign_3] VOLE-in-the-Head proof ... ")
	sig := o.Sign3(epk, h, bsig, st, rAdd)
	okProof := bytes.Equal(sig.Bytes, refProof)
	fmt.Printf("proof byte-exact vs reference (%d bytes): %v\n", len(sig.Bytes), okProof)

	fmt.Print("[verify] on-device blind verify (Go proof) ... ")
	okVerifyGo := o.BlindVerify(epk, msg, sig.Bytes, rAdd)
	fmt.Printf("verify=%v\n", okVerifyGo)

	fmt.Print("[verify] on-device blind verify (reference proof) ... ")
	okVerifyRef := o.BlindVerify(epk, msg, refProof, rAdd)
	fmt.Printf("verify=%v\n", okVerifyRef)

	bad := append([]byte(nil), sig.Bytes...)
	bad[0] ^= 1
	fmt.Print("[verify] tampered proof rejected ... ")
	rejected := !o.BlindVerify(epk, msg, bad, rAdd)
	fmt.Printf("rejected=%v\n", rejected)

	pass := okT && okBSig && okProof && okVerifyGo && okVerifyRef && rejected
	if pass {
		fmt.Print("\nRESULT: PASS — One-More-MAYO blind sign+verify byte-exact on device.\n")
	} else {
		fmt.Print("\nRESULT: FAIL\n")
	}
	fmt.Print("DONE\n")
	for {
	}
}
