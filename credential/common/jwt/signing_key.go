package jwt

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/internal/jwtutil"
	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
)

// SigningKey is the verification method a JWT is issued under: the kid and alg
// its header carries, and the public key a fresh signature must verify against.
// The zero value is a token that was parsed rather than built; Accept refuses
// it, because there is no key to check the signature against.
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

// RequireBound refuses a key with no verification method: a parsed token has
// none to hold a new signature to, so it cannot be signed again.
func (k SigningKey) RequireBound() error {
	if k.PublicKey == nil {
		return fmt.Errorf("no verification method is bound to check this signature: the token was parsed, not built — build it with New* to sign it")
	}
	return nil
}

// Accept checks a raw signature over signingInput against the key and returns
// it base64url-encoded for the token. A signer that does not hold the key still
// produces a well-formed signature, which would otherwise fail only at the
// verifier.
//
// A zero SigningKey (a parsed token) refuses: without a key the check cannot
// run, and skipping it would accept any signature silently. Build the token
// with New* to sign it.
func (k SigningKey) Accept(signingInput string, signature []byte) (string, error) {
	signature = jwtutil.TrimRecoveryByte(signature)
	if n := len(signature); n != 64 {
		return "", fmt.Errorf("signature must be 64-byte r||s (65 with a trailing recovery id is trimmed), got %d bytes: the signer returned another format, not a JWS signature", n)
	}
	if err := k.RequireBound(); err != nil {
		return "", err
	}
	encoded := jose.EncodeSegment(signature)
	compact := signingInput + "." + encoded
	if _, _, err := jws.Verify(compact, k.PublicKey, []string{k.Alg}); err != nil {
		return "", fmt.Errorf("the signature does not verify against verification method %q: it was made by another key or over data other than the signing input — to sign with another key, pass WithVerificationMethodKey to NewJWTCredential / NewJWTPresentation: %w", k.ID, err)
	}
	return encoded, nil
}
