package jwt

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// SigningKey is the verification method a JWT is issued under: the kid and alg
// its header carries, and the public key a fresh signature must verify against.
// The zero value is a token that was parsed rather than built.
type SigningKey struct {
	ID        string
	Alg       string
	PublicKey *ecdsa.PublicKey
}

// ResolveSigningKey resolves the verification method to sign with — the pinned
// one, or by default the latest active one for purpose — and derives the JOSE
// alg from the key it holds.
func ResolveSigningKey(ctx context.Context, did, purpose, pinnedKey string, resolver verificationmethod.ResolverProvider) (SigningKey, error) {
	vm, kid, err := verificationmethod.ResolveSigningVM(ctx, did, purpose, pinnedKey, resolver)
	if err != nil {
		return SigningKey{}, fmt.Errorf("resolve verification method: %w", err)
	}
	kind, ok := verificationmethod.VMKeyKind(vm)
	if !ok {
		return SigningKey{}, fmt.Errorf("verification method %q has an unrecognized key type", kid)
	}
	alg, err := AlgForKeyKind(kind)
	if err != nil {
		return SigningKey{}, fmt.Errorf("verification method %q: %w", kid, err)
	}
	pub, err := verificationmethod.ECPubFromVM(vm)
	if err != nil {
		return SigningKey{}, fmt.Errorf("verification method %q: %w", kid, err)
	}
	return SigningKey{ID: kid, Alg: alg, PublicKey: pub}, nil
}

// Sign signs signingInput (header.payload) with provider and returns the
// base64url signature, checked by Accept.
func (k SigningKey) Sign(provider signer.SignerProvider, signingInput string) (string, error) {
	signature, err := NewJWTSigner(provider).SignString(signingInput)
	if err != nil {
		return "", fmt.Errorf("failed to sign signing input: %w", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return "", fmt.Errorf("invalid signature encoding: %w", err)
	}
	return k.Accept(signingInput, raw)
}

// Accept checks a raw signature over signingInput against the key and returns
// it base64url-encoded for the token. A signer that does not hold the key still
// produces a well-formed signature, which would otherwise fail only at the
// verifier. A zero SigningKey (a parsed token) skips the check.
func (k SigningKey) Accept(signingInput string, signature []byte) (string, error) {
	signature = trimRecoveryID(signature)
	if k.PublicKey != nil {
		if err := VerifyECDSA(signingInput, signature, k.PublicKey); err != nil {
			return "", fmt.Errorf("the signature does not verify against verification method %q: it was made by another key or over data other than the signing input — to sign with another key, pass WithVerificationMethodKey to NewJWTCredential / NewJWTPresentation: %w", k.ID, err)
		}
	}
	return base64.RawURLEncoding.EncodeToString(signature), nil
}
