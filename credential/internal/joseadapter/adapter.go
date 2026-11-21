// Package joseadapter adapts types from the credential module to the jose
// module's interfaces and back.
package joseadapter

import (
	"context"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	"github.com/pilacorp/go-credential-sdk/credential/internal/jwtutil"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
)

// NewSigner wraps a SignerProvider as a jws.Signer. The SignerProvider
// receives a SHA-256 digest and returns 64 or 65 bytes (r||s with an optional
// trailing recovery id); the jws.Signer receives the JWS Signing Input and
// returns 64-byte r||s.
//
// alg names the algorithm (jws.AlgES256 or jws.AlgES256K). The alg must
// match the curve of the public key the signer operates on; jws.Sign and
// jws.Verify check that.
func NewSigner(alg string, sp signer.SignerProvider) (jws.Signer, error) {
	if sp == nil {
		return nil, fmt.Errorf("signer provider cannot be nil")
	}
	return jws.DigestSigner(alg, func(_ context.Context, digest []byte) ([]byte, error) {
		raw, err := sp.Sign(digest)
		if err != nil {
			return nil, err
		}
		return jwtutil.TrimRecoveryByte(raw), nil
	})
}
