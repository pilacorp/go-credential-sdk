// Package jwttest builds and checks signatures without the code under test,
// so a test can tell whether the SDK was right to accept or refuse one.
package jwttest

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/jwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// SignExternally signs data the way a caller outside the SDK does: SHA-256,
// then the raw signer output (65 bytes for secp256k1).
func SignExternally(t *testing.T, s signer.SignerProvider, data string) []byte {
	t.Helper()
	digest := sha256.Sum256([]byte(data))
	sig, err := s.Sign(digest[:])
	if err != nil {
		t.Fatalf("external sign: %v", err)
	}
	return sig
}

// VerifyByHand builds signingInput.signature (r||s) and runs it through the
// SDK's JWT verifier.
func VerifyByHand(resolver verificationmethod.ResolverProvider, signingInput string, sig []byte) error {
	if len(sig) == 65 {
		sig = sig[:64]
	}
	return jwt.NewJWTVerifier(resolver).VerifyJWT(signingInput + "." + base64.RawURLEncoding.EncodeToString(sig))
}

// Counting wraps a signer and records how many digests reach it.
type Counting struct {
	signer.SignerProvider
	Calls int
}

// Sign counts the call and signs with the wrapped signer.
func (c *Counting) Sign(digest []byte) ([]byte, error) {
	c.Calls++
	return c.SignerProvider.Sign(digest)
}
