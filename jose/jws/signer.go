// RFC 7515 §5.1 step 5: the party that holds the private key computes the
// JWS Signature over the JWS Signing Input; RFC 7518 §3.4 and RFC 8812 §3.2
// define it for ES256 and ES256K.

package jws

import (
	"context"
	"crypto"
	"crypto/sha256"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/internal/ec"
	"github.com/pilacorp/go-credential-sdk/jose/internal/errtext"
)

// Signer computes JWS Signatures with a private key it keeps to itself, in
// memory, in a key management service or in an HSM. Sign checks what a
// Signer returns by verifying the token with the public key it was given, so
// a Signer that answers DER or r||s||v fails with ErrSelfCheck rather than
// producing a token no one can verify.
//
// Sign takes the caller's context, since a Signer that calls a key store
// does network I/O: it passes ctx on, so the caller's deadline and cancel
// reach that call. A Signer that signs in memory may ignore ctx.
type Signer interface {
	// Alg returns the alg the Signer signs with (RFC 7515 §4.1.1); Sign
	// writes it into the header.
	Alg() string
	// Sign returns the JWS Signature for Alg over signingInput, which is
	// base64url(header) "." base64url(payload) (RFC 7515 §5.1). For ES256
	// and ES256K that is SHA-256 of signingInput signed with ECDSA, as 64-byte
	// r||s (RFC 7518 §3.4, RFC 8812 §3.2).
	Sign(ctx context.Context, signingInput []byte) ([]byte, error)
}

// PrivateKeySigner returns a Signer that signs with priv, held in memory: a
// Signer to use as is, or to follow when writing one for a key store. priv
// must be an *ecdsa.PrivateKey on P-256 (alg ES256) or secp256k1 (ES256K),
// else jose.ErrUnsupportedKey. A nil key, a d outside [1, n-1], or a
// PublicKey that is not d·G is ErrBadKey. The Signer keeps a copy of the key,
// so later changes to priv do not reach it, and is safe for concurrent use.
// Its signatures are r||s with each number left-padded to 32 bytes. Its Sign
// does no I/O and does not read ctx.
func PrivateKeySigner(priv crypto.PrivateKey) (Signer, error) {
	k, err := ec.FromPrivateKey(priv)
	if err != nil {
		return nil, keyError("private key", err)
	}
	return privateKeySigner{key: k, alg: algOf(k.Point.Kind)}, nil
}

type privateKeySigner struct {
	key ec.PrivateKey
	alg string
}

func (s privateKeySigner) Alg() string { return s.alg }

func (s privateKeySigner) Sign(_ context.Context, signingInput []byte) ([]byte, error) {
	digest := sha256.Sum256(signingInput)
	return s.key.SignRS(digest[:])
}

// DigestSigner returns a Signer for a key store that signs a digest it is
// given, as most HSM and KMS APIs do. Its Sign hashes the JWS Signing Input
// with the hash of alg, SHA-256 for ES256 and ES256K (RFC 7518 §3.4, RFC 8812
// §3.2), passes the 32 bytes and the caller's ctx unchanged to sign, and
// returns what sign returns unchanged, so sign must answer 64-byte r||s. An
// alg other than ES256 and ES256K is jose.ErrUnsupportedAlg; a nil sign is
// jose.ErrInvalidArgument.
func DigestSigner(alg string, sign func(ctx context.Context, digest []byte) ([]byte, error)) (Signer, error) {
	if !isSupportedAlg(alg) {
		return nil, fmt.Errorf("%w: %s; %s", jose.ErrUnsupportedAlg, errtext.Quote(alg), supportedAlgs)
	}
	if sign == nil {
		return nil, fmt.Errorf("%w: nil sign function", jose.ErrInvalidArgument)
	}
	// A pointer, so Signers compare with == without a panic: a struct with
	// a func field is not comparable.
	return &digestSigner{alg: alg, sign: sign}, nil
}

type digestSigner struct {
	alg  string
	sign func(ctx context.Context, digest []byte) ([]byte, error)
}

func (s *digestSigner) Alg() string { return s.alg }

func (s *digestSigner) Sign(ctx context.Context, signingInput []byte) ([]byte, error) {
	digest := sha256.Sum256(signingInput)
	return s.sign(ctx, digest[:])
}
