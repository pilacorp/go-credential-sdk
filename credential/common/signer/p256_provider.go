package signer

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

var _ SignerProvider = (*P256Provider)(nil)

// P256Provider signs a 32-byte digest with a P-256 key (ecdsa-sd-2023),
// producing a 64-byte R||S signature, using either an in-memory key or a
// caller-supplied callback (HSM/KMS).
type P256Provider struct {
	sign func([]byte) ([]byte, error)
	pub  *ecdsa.PublicKey // nil for callback-based providers
}

// NewP256Provider creates a P-256 signer from an in-memory key.
func NewP256Provider(priv *ecdsa.PrivateKey) (*P256Provider, error) {
	if priv == nil {
		return nil, fmt.Errorf("p256 private key is nil")
	}
	if priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("private key is not P-256")
	}
	return &P256Provider{sign: p256SignFunc(priv), pub: &priv.PublicKey}, nil
}

// NewP256ProviderFromHex creates a P-256 signer from a hex-encoded scalar (the
// 32-byte private exponent). The hex may include or omit the "0x" prefix.
func NewP256ProviderFromHex(privHex string) (*P256Provider, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(privHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("decode p256 private key hex: %w", err)
	}
	// Left-pad scalars whose hex omits leading zero bytes; NewPrivateKey wants 32.
	if len(b) > 0 && len(b) < 32 {
		b = append(make([]byte, 32-len(b)), b...)
	}
	ecdhPriv, err := ecdh.P256().NewPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("invalid p256 private key: %w", err)
	}
	pubBytes := ecdhPriv.PublicKey().Bytes() // 0x04 || X(32) || Y(32)
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(pubBytes[1:33]),
			Y:     new(big.Int).SetBytes(pubBytes[33:65]),
		},
		D: new(big.Int).SetBytes(b),
	}
	return &P256Provider{sign: p256SignFunc(priv), pub: &priv.PublicKey}, nil
}

// NewP256Func creates a P-256 signer that delegates to signFn. signFn receives
// the 32-byte digest and must return a 64-byte R||S signature.
func NewP256Func(signFn func([]byte) ([]byte, error)) (*P256Provider, error) {
	if signFn == nil {
		return nil, fmt.Errorf("sign function is nil")
	}
	return &P256Provider{sign: signFn}, nil
}

// Public returns the P-256 public key, or nil for callback-based providers.
func (p *P256Provider) Public() *ecdsa.PublicKey {
	return p.pub
}

func (p *P256Provider) Sign(hashPayload []byte) ([]byte, error) {
	if len(hashPayload) != 32 {
		return nil, fmt.Errorf("hash payload must be 32 bytes, got %d", len(hashPayload))
	}
	return p.sign(hashPayload)
}

// Algorithm reports the JOSE algorithm for P-256 JsonWebSignature2020 (ES256).
func (p *P256Provider) Algorithm() string { return "ES256" }

func p256SignFunc(priv *ecdsa.PrivateKey) func([]byte) ([]byte, error) {
	return func(hashPayload []byte) ([]byte, error) {
		r, s, err := ecdsa.Sign(rand.Reader, priv, hashPayload)
		if err != nil {
			return nil, fmt.Errorf("p256 sign: %w", err)
		}
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out, nil
	}
}
