package did

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mr-tron/base58"
)

// Multicodec varint prefixes for the Multikeys this package writes:
//
//	p256-pub       0x1200 -> varint 0x80 0x24
//	secp256k1-pub  0x00e7 -> varint 0xe7 0x01
var (
	p256PubMulticodec      = []byte{0x80, 0x24}
	secp256k1PubMulticodec = []byte{0xe7, 0x01}
)

// curveIsSecp256k1 reports whether c is secp256k1, compared by the curve's
// order rather than by the Curve value: elliptic.Curve is an interface, so ==
// compares the dynamic type and pointer, and go-ethereum hands back
// *secp256k1.BitCurve where btcec/decred hand back *secp256k1.KoblitzCurve —
// two objects describing one curve. BitCurve also leaves Params().Name empty,
// so the name identifies nothing either.
func curveIsSecp256k1(c elliptic.Curve) bool {
	return c != nil && c.Params().N.Cmp(crypto.S256().Params().N) == 0
}

// encodePubMultibase renders a public key as a Multikey string: multicodec prefix
// + compressed point, base58btc behind a 'z'.
//
// TODO: duplicates verificationmethod.EncodePubMultibase; fold into one package.
func encodePubMultibase(pub *ecdsa.PublicKey) (string, error) {
	if pub == nil {
		return "", fmt.Errorf("multikey: public key is nil")
	}

	prefix, err := pubMulticodecFor(pub.Curve)
	if err != nil {
		return "", err
	}

	compressed := elliptic.MarshalCompressed(pub.Curve, pub.X, pub.Y)
	raw := append(append([]byte{}, prefix...), compressed...)

	return "z" + base58.Encode(raw), nil
}

// pubMulticodecFor maps a curve to its multicodec prefix.
func pubMulticodecFor(c elliptic.Curve) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("multikey: curve is nil")
	}
	// Before the == case, and by order: see curveIsSecp256k1.
	if curveIsSecp256k1(c) {
		return secp256k1PubMulticodec, nil
	}
	if c == elliptic.P256() {
		return p256PubMulticodec, nil
	}

	name := c.Params().Name
	if name == "" {
		name = "unknown"
	}

	return nil, fmt.Errorf("multikey: unsupported curve %s", name)
}
