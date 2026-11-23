// Package eckey reads and writes EC keys as SEC 1 bytes, without the big.Int
// coordinates of crypto/ecdsa that Go 1.26 deprecated. crypto/ecdsa handles
// only the NIST curves, so secp256k1 goes through go-ethereum. Every key whose
// curve is chosen at run time passes here, so the choice between the two
// libraries and the validity rules live in one place.
package eckey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
)

// isNIST reports whether crypto/ecdsa encodes and parses keys on curve.
func isNIST(curve elliptic.Curve) bool {
	switch curve {
	case elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521():
		return true
	}
	return false
}

// UncompressedBytes returns pub as a SEC 1 uncompressed point
// (0x04 || X || Y). It refuses a point that is not on the key's curve, or on
// secp256k1 when the curve is not a NIST one.
func UncompressedBytes(pub *ecdsa.PublicKey) ([]byte, error) {
	// PublicKey.Bytes dereferences a nil coordinate instead of returning an
	// error, and no accessor that is not deprecated can tell nil apart.
	if pub == nil || pub.X == nil || pub.Y == nil { //nolint:staticcheck // see above
		return nil, errors.New("public key has no point")
	}
	if isNIST(pub.Curve) {
		return pub.Bytes()
	}
	// go-ethereum truncates or panics on a coordinate outside [0, 2^256)
	// before it checks the point, so such a value is refused here.
	if !fitsSecp256k1(pub.X) || !fitsSecp256k1(pub.Y) { //nolint:staticcheck // see above
		return nil, errors.New("secp256k1 public key coordinate out of range")
	}
	// secp256k1 keys come from go-ethereum and btcec, whose Curve values differ.
	point := crypto.FromECDSAPub(pub)
	if _, err := crypto.UnmarshalPubkey(point); err != nil {
		return nil, err
	}
	return point, nil
}

func fitsSecp256k1(c *big.Int) bool {
	return c.Sign() >= 0 && c.BitLen() <= 256
}

// ParseUncompressed reads a SEC 1 uncompressed point (0x04 || X || Y) on
// curve and refuses one that is not on it. The curve is a NIST one or
// go-ethereum's secp256k1; any other is refused.
func ParseUncompressed(curve elliptic.Curve, point []byte) (*ecdsa.PublicKey, error) {
	if isNIST(curve) {
		return ecdsa.ParseUncompressedPublicKey(curve, point)
	}
	if curve != crypto.S256() {
		return nil, errors.New("unsupported curve")
	}
	return crypto.UnmarshalPubkey(point)
}

// ParseP256PrivateKey reads a P-256 private key from its 32-byte scalar.
func ParseP256PrivateKey(d []byte) (*ecdsa.PrivateKey, error) {
	if len(d) != 32 {
		return nil, fmt.Errorf("a P-256 private key is 32 bytes, got %d", len(d))
	}
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		// The only refusal left for 32 bytes is a scalar out of range, and
		// crypto/ecdsa words it as a public key encoding error.
		return nil, errors.New("a P-256 private key must be from 1 to n-1")
	}
	return priv, nil
}
