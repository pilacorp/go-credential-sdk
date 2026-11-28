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

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mr-tron/base58"

	"github.com/pilacorp/go-credential-sdk/credential/internal/eckey"
)

// stripHexPrefix drops a leading "0x" or "0X"; hex.DecodeString accepts neither.
func stripHexPrefix(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}

// ecCurveForJWK maps a JWK crv to its curve and coordinate size in bytes.
func ecCurveForJWK(crv string) (elliptic.Curve, int, error) {
	switch crv {
	case "secp256k1":
		return crypto.S256(), 32, nil
	case "P-256":
		return elliptic.P256(), 32, nil
	case "P-384":
		return elliptic.P384(), 48, nil
	default:
		return nil, 0, fmt.Errorf("unsupported curve: %.64q (want secp256k1, P-256 or P-384)", crv)
	}
}

// ECPubFromJWK builds an *ecdsa.PublicKey from an EC JWK on secp256k1, P-256 or
// P-384, rejecting off-curve points. A short coordinate is left-padded (some DID
// documents strip leading zeros); a coordinate longer than the field is refused.
func ECPubFromJWK(jwk *JWK) (*ecdsa.PublicKey, error) {
	if jwk == nil {
		return nil, fmt.Errorf("jwk is nil")
	}
	if jwk.Kty != "EC" {
		return nil, fmt.Errorf("unsupported key type: %.64q", jwk.Kty)
	}
	if jwk.hasPrivate {
		return nil, errPrivateJWK
	}
	curve, size, err := ecCurveForJWK(jwk.Crv)
	if err != nil {
		return nil, err
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode X coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Y coordinate: %w", err)
	}
	if len(xBytes) > size || len(yBytes) > size {
		return nil, fmt.Errorf("jwk %s: coordinates must be at most %d bytes, got x=%d y=%d",
			jwk.Crv, size, len(xBytes), len(yBytes))
	}

	point := make([]byte, 1+2*size)
	point[0] = 4
	copy(point[1+size-len(xBytes):1+size], xBytes)
	copy(point[1+2*size-len(yBytes):], yBytes)
	pub, err := eckey.ParseUncompressed(curve, point)
	if err != nil {
		return nil, fmt.Errorf("jwk %s: invalid public key point: %w", jwk.Crv, err)
	}
	return pub, nil
}

// P256PubKeyFromJWK builds an *ecdsa.PublicKey from a crv=P-256 JWK, refusing
// any other curve. Used by the ecdsa-sd-2023 and JWS ES256 verifiers.
func P256PubKeyFromJWK(jwk *JWK) (*ecdsa.PublicKey, error) {
	if jwk == nil {
		return nil, fmt.Errorf("jwk is nil")
	}
	if jwk.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported curve: %.64q (want P-256)", jwk.Crv)
	}
	return ECPubFromJWK(jwk)
}

// RSAPubKeyFromJWK builds an *rsa.PublicKey from a JWK with kty=RSA.
func RSAPubKeyFromJWK(jwk *JWK) (*rsa.PublicKey, error) {
	if jwk == nil {
		return nil, fmt.Errorf("jwk is nil")
	}
	if jwk.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %.64q", jwk.Kty)
	}
	if jwk.hasPrivate {
		return nil, errPrivateJWK
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
	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}
	// JsonWebSignature2020 §3.1 lists RSA keys as "RSA 2048+".
	if pub.N.BitLen() < minRSABits {
		return nil, fmt.Errorf("RSA jwk modulus is %d bits; at least %d are required", pub.N.BitLen(), minRSABits)
	}
	return pub, nil
}

// minRSABits is the smallest RSA modulus accepted.
const minRSABits = 2048

// errPrivateJWK refuses a verification method JWK that carries the private key.
var errPrivateJWK = fmt.Errorf("publicKeyJwk must not contain the private key member d")

// Multicodec varint prefixes for P-256 Multikeys:
//
//	p256-pub  0x1200 -> varint 0x80 0x24
//	p256-priv 0x1306 -> varint 0x86 0x26
var (
	p256PubMulticodec  = []byte{0x80, 0x24}
	p256PrivMulticodec = []byte{0x86, 0x26}
	p384PubMulticodec  = []byte{0x81, 0x24}
)

// ECPubFromVM extracts a public key from a VM's publicKeyHex, publicKeyJwk or
// publicKeyMultibase, on whichever curve it names. publicKeyHex names none, so
// it is read as secp256k1 — the only curve this repo publishes that way.
func ECPubFromVM(vm *VerificationMethodEntry) (*ecdsa.PublicKey, error) {
	if vm == nil {
		return nil, fmt.Errorf("verification method is nil")
	}
	switch {
	case vm.PublicKeyHex != "":
		return Secp256k1PubFromHex(vm.PublicKeyHex)
	case vm.PublicKeyJwk != nil:
		return ECPubFromJWK(vm.PublicKeyJwk)
	case vm.PublicKeyMultibase != "":
		return ECPubFromMultibase(vm.PublicKeyMultibase)
	}
	return nil, fmt.Errorf("verification method '%s' has no public key material", vm.ID)
}

// Secp256k1PubFromHex parses a secp256k1 public key from hex, compressed
// (02/03 || X) or uncompressed (04 || X || Y). The 0x prefix is optional.
func Secp256k1PubFromHex(h string) (*ecdsa.PublicKey, error) {
	b, err := hex.DecodeString(stripHexPrefix(h))
	if err != nil {
		return nil, fmt.Errorf("decode secp256k1 public key hex: %w", err)
	}
	var pub *ecdsa.PublicKey
	switch {
	case len(b) == 33 && (b[0] == 0x02 || b[0] == 0x03):
		pub, err = crypto.DecompressPubkey(b)
	case len(b) == 65 && b[0] == 0x04:
		pub, err = crypto.UnmarshalPubkey(b)
	default:
		return nil, fmt.Errorf("secp256k1 public key: want 33 compressed or 65 uncompressed bytes, got %d", len(b))
	}
	if err != nil {
		return nil, fmt.Errorf("invalid secp256k1 public key: %w", err)
	}
	return pub, nil
}

// ECPubFromMultikeyBytes decodes raw Multikey bytes (2-byte multicodec prefix +
// compressed point), taking the curve from the prefix. Only the curves CID 1.0
// defines for ECDSA are accepted — secp256k1 is not one of them.
func ECPubFromMultikeyBytes(raw []byte) (*ecdsa.PublicKey, error) {
	if len(raw) < 2 {
		return nil, fmt.Errorf("multikey: value too short")
	}
	var curve elliptic.Curve
	switch {
	case bytes.HasPrefix(raw, p256PubMulticodec):
		curve = elliptic.P256()
	case bytes.HasPrefix(raw, p384PubMulticodec):
		curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("multikey: unsupported multicodec prefix %#x", raw[:2])
	}
	x, y := elliptic.UnmarshalCompressed(curve, raw[2:])
	if x == nil {
		return nil, fmt.Errorf("multikey: invalid %s compressed point", curve.Params().Name)
	}
	size := (curve.Params().BitSize + 7) / 8
	point := make([]byte, 1+2*size)
	point[0] = 4
	x.FillBytes(point[1 : 1+size])
	y.FillBytes(point[1+size:])
	pub, err := eckey.ParseUncompressed(curve, point)
	if err != nil {
		return nil, fmt.Errorf("multikey: invalid %s compressed point: %w", curve.Params().Name, err)
	}
	return pub, nil
}

// ECPubFromMultibase decodes a Multikey string, curve taken from its prefix.
func ECPubFromMultibase(s string) (*ecdsa.PublicKey, error) {
	raw, err := DecodeMultibaseKey(s)
	if err != nil {
		return nil, err
	}
	return ECPubFromMultikeyBytes(raw)
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

// pubMulticodecFor maps a curve to its public-key multicodec prefix.
func pubMulticodecFor(c elliptic.Curve) ([]byte, error) {
	switch c {
	case elliptic.P256():
		return p256PubMulticodec, nil
	case elliptic.P384():
		return p384PubMulticodec, nil
	}
	return nil, fmt.Errorf("multikey: unsupported curve %s", c.Params().Name)
}

// PubToMultikeyBytes renders a public key as raw Multikey bytes (multicodec
// prefix + compressed point).
func PubToMultikeyBytes(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("public key is nil")
	}

	prefix, err := pubMulticodecFor(pub.Curve)
	if err != nil {
		return nil, err
	}
	point, err := eckey.UncompressedBytes(pub)
	if err != nil {
		return nil, fmt.Errorf("multikey: %w", err)
	}
	// SEC 1 §2.3.3 compressed form: 0x02 or 0x03 by the parity of Y, then X.
	size := (len(point) - 1) / 2
	compressed := make([]byte, 1+size)
	compressed[0] = 2 | point[len(point)-1]&1
	copy(compressed[1:], point[1:1+size])
	return append(append([]byte{}, prefix...), compressed...), nil
}

// EncodePubMultibase encodes a public key as a Multikey string ("zDn...").
func EncodePubMultibase(pub *ecdsa.PublicKey) (string, error) {
	raw, err := PubToMultikeyBytes(pub)
	if err != nil {
		return "", err
	}
	return EncodeMultibaseKey(raw), nil
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
	priv, err := eckey.ParseP256PrivateKey(raw[len(p256PrivMulticodec):])
	if err != nil {
		return nil, fmt.Errorf("multikey: invalid p256 secret key: %w", err)
	}
	return priv, nil
}
