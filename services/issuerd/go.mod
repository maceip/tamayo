module github.com/maceip/tamayo/services/issuerd

go 1.26.4

require (
	github.com/emersion/go-msgauth v0.7.0
	github.com/emersion/go-smtp v0.24.0
	github.com/maceip/tamayo v0.0.0
)

require (
	github.com/emersion/go-sasl v0.0.0-20241020182733-b788ff22d5a6
	golang.org/x/crypto v0.31.0 // indirect
)

replace github.com/maceip/tamayo => ../..
