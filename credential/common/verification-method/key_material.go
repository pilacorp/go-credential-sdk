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

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mr-tron/base58"
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
		return nil, 0, fmt.Errorf("unsupported curve: %s (want secp256k1, P-256 or P-384)", crv)
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
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
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

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	if err := checkOnCurve(jwk.Crv, pub); err != nil {
		return nil, err
	}
	return pub, nil
}

// checkOnCurve rejects an off-curve point, via each curve's own parser
// (elliptic.Curve.IsOnCurve is deprecated as of Go 1.21).
func checkOnCurve(crv string, pub *ecdsa.PublicKey) error {
	uncompressed := marshalUncompressed(pub)
	var err error
	switch crv {
	case "secp256k1":
		_, err = crypto.UnmarshalPubkey(uncompressed)
	case "P-256":
		_, err = ecdh.P256().NewPublicKey(uncompressed)
	case "P-384":
		_, err = ecdh.P384().NewPublicKey(uncompressed)
	default:
		return fmt.Errorf("unsupported curve: %s", crv)
	}
	if err != nil {
		return fmt.Errorf("jwk %s: invalid public key point: %w", crv, err)
	}
	return nil
}

// curveSize is the coordinate size in bytes for a curve.
func curveSize(c elliptic.Curve) int {
	return (c.Params().BitSize + 7) / 8
}

// marshalUncompressed renders a public key as SEC1 uncompressed bytes
// (0x04 || X || Y), coordinates left-padded to the field size.
func marshalUncompressed(pub *ecdsa.PublicKey) []byte {
	size := curveSize(pub.Curve)
	buf := make([]byte, 1+2*size)
	buf[0] = 4
	pub.X.FillBytes(buf[1 : 1+size])
	pub.Y.FillBytes(buf[1+size:])
	return buf
}

// P256PubKeyFromJWK builds an *ecdsa.PublicKey from a crv=P-256 JWK, refusing
// any other curve. Used by the ecdsa-sd-2023 and JWS ES256 verifiers.
func P256PubKeyFromJWK(jwk *JWK) (*ecdsa.PublicKey, error) {
	if jwk == nil {
		return nil, fmt.Errorf("jwk is nil")
	}
	if jwk.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported curve: %s (want P-256)", jwk.Crv)
	}
	return ECPubFromJWK(jwk)
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
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
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
	prefix, err := pubMulticodecFor(pub.Curve)
	if err != nil {
		return nil, err
	}
	compressed := elliptic.MarshalCompressed(pub.Curve, pub.X, pub.Y)
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
