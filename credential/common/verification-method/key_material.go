package verificationmethod

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mr-tron/base58"
)

var bls12381G2PublicKeyMulticodec = []byte{0xeb, 0x01}

// PublicKeyHexFromVM returns the public key hex material for the given VM.
// It supports both `publicKeyHex` and `publicKeyJwk` encodings.
//
// The returned value may include or omit the 0x prefix depending on source;
// callers that decode should accept either (most helpers in this repo trim it).
func PublicKeyHexFromVM(vm *VerificationMethodEntry) (string, error) {
	if vm == nil {
		return "", fmt.Errorf("verification method is nil")
	}
	if vm.PublicKeyHex != "" {
		return strings.TrimPrefix(vm.PublicKeyHex, "0x"), nil
	}
	if vm.PublicKeyJwk != nil {
		return JWKToHex(vm.PublicKeyJwk)
	}
	return "", fmt.Errorf("verification method '%s' has no public key material", vm.ID)
}

// PublicKeyMultibaseBytesFromVM decodes publicKeyMultibase verification material.
func PublicKeyMultibaseBytesFromVM(vm *VerificationMethodEntry) ([]byte, error) {
	if vm == nil {
		return nil, fmt.Errorf("verification method is nil")
	}
	if vm.PublicKeyMultibase == "" {
		return nil, fmt.Errorf("verification method '%s' has no publicKeyMultibase", vm.ID)
	}
	if vm.PublicKeyMultibase[0] != 'z' {
		return nil, fmt.Errorf("unsupported multibase prefix in verification method '%s'", vm.ID)
	}
	raw, err := base58.Decode(vm.PublicKeyMultibase[1:])
	if err != nil {
		return nil, fmt.Errorf("decode publicKeyMultibase: %w", err)
	}
	if bytes.HasPrefix(raw, bls12381G2PublicKeyMulticodec) {
		return raw[len(bls12381G2PublicKeyMulticodec):], nil
	}
	return raw, nil
}

// JWKToHex converts a secp256k1 JWK to its uncompressed hex representation
// (0x04 || X || Y). Useful when callers already have a JWK in hand and want
// to produce a hex public key without going through any DID resolver.
func JWKToHex(jwk *JWK) (string, error) {
	if jwk == nil {
		return "", fmt.Errorf("jwk is nil")
	}
	if jwk.Kty != "EC" {
		return "", fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
	if jwk.Crv != "secp256k1" {
		return "", fmt.Errorf("unsupported curve: %s", jwk.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return "", fmt.Errorf("failed to decode X coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return "", fmt.Errorf("failed to decode Y coordinate: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	publicKey := &ecdsa.PublicKey{
		Curve: crypto.S256(),
		X:     x,
		Y:     y,
	}

	uncompressed := crypto.FromECDSAPub(publicKey)
	return hex.EncodeToString(uncompressed), nil
}

// P256PubKeyFromJWK builds an *ecdsa.PublicKey on the P-256 curve from a JWK
// with kty=EC and crv=P-256. Used by the ecdsa-sd-2023 verifier.
func P256PubKeyFromJWK(jwk *JWK) (*ecdsa.PublicKey, error) {
	if jwk == nil {
		return nil, fmt.Errorf("jwk is nil")
	}
	if jwk.Kty != "EC" {
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
	if jwk.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported curve: %s (want P-256)", jwk.Crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}
	// ecdsa.Verify rejects an off-curve point, so no explicit IsOnCurve check
	// (deprecated since Go 1.21) is needed here.
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

// RSAPubKeyFromJWK builds an *rsa.PublicKey from a JWK with kty=RSA.
func RSAPubKeyFromJWK(jwk *JWK) (*rsa.PublicKey, error) {
	if jwk == nil {
		return nil, fmt.Errorf("jwk is nil")
	}
	if jwk.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
	if jwk.N == "" || jwk.E == "" {
		return nil, fmt.Errorf("RSA jwk missing n or e")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}
