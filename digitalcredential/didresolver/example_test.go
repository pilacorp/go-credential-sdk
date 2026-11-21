package didresolver_test

import (
	"github.com/pilacorp/go-credential-sdk/digitalcredential/didresolver"
)

// Applies the rule of W3C CID with no exception: a key is refused at or after
// its revoked time, regardless of the reason (CID §2.2). DefaultAcceptKey is
// more lenient: it accepts a key revoked for a reason other than keyCompromise,
// so that credentials signed before the revocation stay valid.
func ExampleNew_acceptKey() {
	cidStrict := func(k didresolver.KeyInfo) bool {
		if !k.Expires.IsZero() && !k.At.Before(k.Expires) {
			return false
		}
		return k.Revoked.IsZero() || k.At.Before(k.Revoked)
	}
	_, _ = didresolver.New(didresolver.Config{
		URL:       "https://resolver.example/1.0/identifiers/",
		AcceptKey: cidStrict,
	})
}
