package did

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"

	"github.com/mr-tron/base58"
)

// p256PubMulticodec is varint(0x1200) — the multicodec prefix for a p256-pub key.
var p256PubMulticodec = []byte{0x80, 0x24}

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

// pubMulticodecFor maps a curve to its multicodec prefix; secp256k1 uses publicKeyHex.
func pubMulticodecFor(c elliptic.Curve) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("multikey: curve is nil")
	}
	if c == elliptic.P256() {
		return p256PubMulticodec, nil
	}

	return nil, fmt.Errorf("multikey: unsupported curve %s", c.Params().Name)
}
