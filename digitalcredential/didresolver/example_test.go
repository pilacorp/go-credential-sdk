package didresolver_test

import (
	"github.com/pilacorp/go-credential-sdk/digitalcredential/didresolver"
)

// Applies the rule of W3C CID with no exception: a key revoked for any reason
// stops verifying at its revoked time.
func ExampleNew_acceptKey() {
	_, _ = didresolver.New(didresolver.Config{
		URL: "https://resolver.example/1.0/identifiers/",
		AcceptKey: func(k didresolver.KeyInfo) bool {
			k.RevocationReason = ""
			return didresolver.DefaultAcceptKey(k)
		},
	})
}
