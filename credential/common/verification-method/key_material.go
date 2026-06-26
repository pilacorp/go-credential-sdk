package verificationmethod

import (
	"bytes"
	"crypto/ecdh"
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

// Multicodec varint prefixes for P-256 Multikeys:
//
//	p256-pub  0x1200 -> varint 0x80 0x24
//	p256-priv 0x1306 -> varint 0x86 0x26
var (
	p256PubMulticodec  = []byte{0x80, 0x24}
	p256PrivMulticodec = []byte{0x86, 0x26}
)

// P256PubFromVM extracts the P-256 public key from a verification method,
// accepting either `publicKeyJwk` (JsonWebKey2020) or the W3C
// `publicKeyMultibase` (Multikey) form.
func P256PubFromVM(vm *VerificationMethodEntry) (*ecdsa.PublicKey, error) {
	switch {
	case vm.PublicKeyJwk != nil:
		return P256PubKeyFromJWK(vm.PublicKeyJwk)
	case vm.PublicKeyMultibase != "":
		_, pub, err := DecodeP256PubMultibase(vm.PublicKeyMultibase)
		return pub, err
	}
	return nil, fmt.Errorf("ecdsa-sd-2023 verification method '%s' must publish a P-256 publicKeyJwk or publicKeyMultibase", vm.ID)
}

// Secp256k1PubFromHex parses an uncompressed (0x04||X||Y) hex public key into an
// *ecdsa.PublicKey on the secp256k1 curve. The 0x prefix is optional. Pair it
// with PublicKeyHexFromVM to resolve a secp256k1 key from a verification method.
func Secp256k1PubFromHex(h string) (*ecdsa.PublicKey, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(h, "0x"))
	if err != nil {
		return nil, fmt.Errorf("decode secp256k1 public key hex: %w", err)
	}
	pub, err := crypto.UnmarshalPubkey(b)
	if err != nil {
		return nil, fmt.Errorf("invalid secp256k1 public key: %w", err)
	}
	return pub, nil
}

// DecodeMultibaseKey decodes a base58btc ('z') multibase string into its raw
// bytes (including any multicodec prefix).
func DecodeMultibaseKey(s string) ([]byte, error) {
	if len(s) == 0 || s[0] != 'z' {
		return nil, fmt.Errorf("multikey: expected base58btc 'z' multibase")
	}
	b, err := base58.Decode(s[1:])
	if err != nil {
		return nil, fmt.Errorf("multikey: base58 decode: %w", err)
	}
	return b, nil
}

// EncodeMultibaseKey encodes raw bytes as a base58btc ('z') multibase string.
func EncodeMultibaseKey(raw []byte) string {
	return "z" + base58.Encode(raw)
}

// DecodeP256PubMultibase decodes a P-256 public-key Multikey ("zDnae...") into
// its raw form (prefix + 33-byte compressed point) and an *ecdsa.PublicKey.
func DecodeP256PubMultibase(s string) ([]byte, *ecdsa.PublicKey, error) {
	raw, err := DecodeMultibaseKey(s)
	if err != nil {
		return nil, nil, err
	}
	pub, err := P256PubFromMultikeyBytes(raw)
	if err != nil {
		return nil, nil, err
	}
	return raw, pub, nil
}

// EncodeP256PubMultibase encodes a P-256 public key as a Multikey string.
func EncodeP256PubMultibase(pub *ecdsa.PublicKey) string {
	compressed := elliptic.MarshalCompressed(elliptic.P256(), pub.X, pub.Y)
	return EncodeMultibaseKey(P256PubToMultikeyBytes(compressed))
}

// P256PubToMultikeyBytes prepends the p256-pub multicodec prefix to a 33-byte
// compressed SEC1 point, producing the raw Multikey byte form.
func P256PubToMultikeyBytes(compressed []byte) []byte {
	return append(append([]byte{}, p256PubMulticodec...), compressed...)
}

// P256PubFromMultikeyBytes decodes raw Multikey bytes (prefix + compressed
// point) of a P-256 public key into an *ecdsa.PublicKey.
func P256PubFromMultikeyBytes(raw []byte) (*ecdsa.PublicKey, error) {
	if !bytes.HasPrefix(raw, p256PubMulticodec) {
		return nil, fmt.Errorf("multikey: not a p256-pub multikey")
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), raw[len(p256PubMulticodec):])
	if x == nil {
		return nil, fmt.Errorf("multikey: invalid p256 compressed point")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// DecodeP256PrivMultibase decodes a P-256 secret-key Multikey ("z42t...").
func DecodeP256PrivMultibase(s string) (*ecdsa.PrivateKey, error) {
	raw, err := DecodeMultibaseKey(s)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(raw, p256PrivMulticodec) {
		return nil, fmt.Errorf("multikey: not a p256-priv multikey")
	}
	d := raw[len(p256PrivMulticodec):]
	if len(d) != 32 {
		return nil, fmt.Errorf("multikey: p256 secret key must be 32 bytes, got %d", len(d))
	}
	ecdhPriv, err := ecdh.P256().NewPrivateKey(d)
	if err != nil {
		return nil, fmt.Errorf("multikey: invalid p256 secret key: %w", err)
	}
	pubBytes := ecdhPriv.PublicKey().Bytes() // 0x04 || X(32) || Y(32)
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(pubBytes[1:33]),
			Y:     new(big.Int).SetBytes(pubBytes[33:65]),
		},
		D: new(big.Int).SetBytes(d),
	}, nil
}
