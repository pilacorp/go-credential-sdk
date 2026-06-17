package ecdsasd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// ephemeralKey is the proof-scoped P-256 key pair; its public half is embedded
// in the proof so verifiers can check the per-statement signatures.
type ephemeralKey struct {
	priv *ecdsa.PrivateKey
}

func newEphemeralKey() (*ephemeralKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	return &ephemeralKey{priv: priv}, nil
}

// publicKeyCompressed returns the 33-byte compressed SEC1 encoding of the
// P-256 public key.
func (e *ephemeralKey) publicKeyCompressed() []byte {
	return elliptic.MarshalCompressed(elliptic.P256(), e.priv.PublicKey.X, e.priv.PublicKey.Y)
}

// signStatement signs SHA-256(statement) and returns the 64-byte R||S signature.
func (e *ephemeralKey) signStatement(statement string) ([]byte, error) {
	digest := sha256.Sum256([]byte(statement))
	r, s, err := ecdsa.Sign(rand.Reader, e.priv, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign statement: %w", err)
	}
	return encodeRS(r, s), nil
}

func encodeRS(r, s *big.Int) []byte {
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}
