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

var (
	_ SignerProvider = (*P256Provider)(nil)
	_ SignerProvider = (*P256FuncProvider)(nil)
)

// P256Provider signs a 32-byte digest with an in-memory P-256 (secp256r1) key,
// producing a 64-byte R||S signature. It is the issuer signer for ecdsa-sd-2023.
type P256Provider struct {
	priv *ecdsa.PrivateKey
}

// NewP256Provider creates a P-256 signer from an in-memory key.
func NewP256Provider(priv *ecdsa.PrivateKey) (*P256Provider, error) {
	if priv == nil {
		return nil, fmt.Errorf("p256 private key is nil")
	}
	if priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("private key is not P-256")
	}
	return &P256Provider{priv: priv}, nil
}

// NewP256ProviderFromHex creates a P-256 signer from a hex-encoded scalar (the
// 32-byte private exponent). The hex may include or omit the "0x" prefix.
func NewP256ProviderFromHex(privHex string) (*P256Provider, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(privHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("decode p256 private key hex: %w", err)
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
	return &P256Provider{priv: priv}, nil
}

// Public returns the issuer's P-256 public key.
func (p *P256Provider) Public() *ecdsa.PublicKey {
	return &p.priv.PublicKey
}

func (p *P256Provider) Sign(hashPayload []byte) ([]byte, error) {
	if p == nil || p.priv == nil {
		return nil, fmt.Errorf("p256 signer private key is nil")
	}
	if len(hashPayload) != 32 {
		return nil, fmt.Errorf("hash payload must be 32 bytes, got %d", len(hashPayload))
	}
	r, s, err := ecdsa.Sign(rand.Reader, p.priv, hashPayload)
	if err != nil {
		return nil, fmt.Errorf("p256 sign: %w", err)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// P256FuncProvider delegates P-256 signing to a caller-supplied callback (e.g.
// HSM, KMS, remote RPC). signFn receives the 32-byte digest and must return a
// 64-byte R||S signature.
type P256FuncProvider struct {
	sign func([]byte) ([]byte, error)
}

// NewP256Func creates a P-256 signer that delegates to signFn.
func NewP256Func(signFn func([]byte) ([]byte, error)) (*P256FuncProvider, error) {
	if signFn == nil {
		return nil, fmt.Errorf("sign function is nil")
	}
	return &P256FuncProvider{sign: signFn}, nil
}

func (p *P256FuncProvider) Sign(hashPayload []byte) ([]byte, error) {
	if len(hashPayload) != 32 {
		return nil, fmt.Errorf("hash payload must be 32 bytes, got %d", len(hashPayload))
	}
	return p.sign(hashPayload)
}
