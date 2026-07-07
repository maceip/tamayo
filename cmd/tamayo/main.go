// Command tamayo is the reference token issuer/verifier runtime: a thin,
// in-memory wiring of the library packages (tokenprofile blind issuance,
// tokenauth policy + budgets, tokenservice composition).
//
// It exists so the repo ships a runnable binary (go install
// github.com/maceip/tamayo/cmd/tamayo@latest) and so the full mint→verify
// flow can be exercised without writing a product runtime. Per
// docs/implementation-inventory.md the durable pieces — persistent spent-token
// storage, real transport, operator policy, measurement collection — belong
// to product repos; everything stateful here is in-memory and dies with the
// process.
//
// Subcommands:
//
//	keygen         write a new issuer key-epoch file
//	demo           run the burn and private-identity blind loops end to end
//	mint-burn      client+issuer blind mint of one burn token (in-process)
//	verify-burn    verify a burn token against a challenge
//	example-policy print a tokenauth policy JSON to adapt for serve
//	serve          reference HTTP issuer/verifier (policy-gated blind-sign,
//	               burn + private-identity verification, in-memory state)
package main

import (
	"fmt"
	"os"
)

const usage = `usage: tamayo <command> [flags]

commands:
  keygen         -out issuer.json [-key-version N]
  demo           -issuer issuer.json
  mint-burn      -issuer issuer.json -challenge <string> [-out token.b64]
  verify-burn    -issuer issuer.json -token <file|-> -challenge <string>
  example-policy
  sign-policy     -policy policy.json [-key policy-key.json]
  serve          -issuer issuer.json -policy policy.json [-addr 127.0.0.1:8787]

run 'tamayo <command> -h' for the flags of one command.`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "demo":
		err = cmdDemo(os.Args[2:])
	case "mint-burn":
		err = cmdMintBurn(os.Args[2:])
	case "verify-burn":
		err = cmdVerifyBurn(os.Args[2:])
	case "example-policy":
		err = cmdExamplePolicy(os.Args[2:])
	case "sign-policy":
		err = cmdSignPolicy(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Println(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "tamayo: unknown command %q\n%s\n", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tamayo:", err)
		os.Exit(1)
	}
}
