// Package joseadapter adapts types from the credential module to the jose
// module's interfaces and back.
package joseadapter

import (
	"context"
	"crypto/ecdsa"
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

// VerifyCompact checks a compact JWS with jws.Verify and returns the
// jws.Header and the original payload bytes. It is the single point where the
// credential and presentation paths call into the jose module for
// cryptographic verification, so every stricter check the jose module
// performs (crit, strict base64url, UTF-8) is applied here.
func VerifyCompact(compact string, pub *ecdsa.PublicKey, allowed []string) (jws.Header, []byte, error) {
	return jws.Verify(compact, pub, allowed)
}
