package ecdsasd

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/mr-tron/base58"
)

// Multicodec varint prefixes for P-256 Multikeys (per the multicodec table):
//   p256-pub  0x1200 -> varint 0x80 0x24
//   p256-priv 0x1306 -> varint 0x86 0x26
var (
	p256PubPrefix  = []byte{0x80, 0x24}
	p256PrivPrefix = []byte{0x86, 0x26}
)

// decodeMultibaseKey decodes a base58btc ('z') multibase string into its raw
// bytes (including any multicodec prefix).
func decodeMultibaseKey(s string) ([]byte, error) {
	if len(s) == 0 || s[0] != 'z' {
		return nil, fmt.Errorf("multikey: expected base58btc 'z' multibase")
	}
	b, err := base58.Decode(s[1:])
	if err != nil {
		return nil, fmt.Errorf("multikey: base58 decode: %w", err)
	}
	return b, nil
}

// encodeMultibaseKey encodes raw bytes as a base58btc ('z') multibase string.
func encodeMultibaseKey(raw []byte) string {
	return "z" + base58.Encode(raw)
}

// decodeP256PubMultibase decodes a P-256 public-key Multikey ("zDnae...") into
// its raw form (prefix + 33-byte compressed point) and an *ecdsa.PublicKey.
func decodeP256PubMultibase(s string) ([]byte, *ecdsa.PublicKey, error) {
	raw, err := decodeMultibaseKey(s)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.HasPrefix(raw, p256PubPrefix) {
		return nil, nil, fmt.Errorf("multikey: not a p256-pub multikey")
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), raw[len(p256PubPrefix):])
	if x == nil {
		return nil, nil, fmt.Errorf("multikey: invalid p256 compressed point")
	}
	return raw, &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// encodeP256PubMultibase encodes a P-256 public key as a Multikey string.
func encodeP256PubMultibase(pub *ecdsa.PublicKey) string {
	compressed := elliptic.MarshalCompressed(elliptic.P256(), pub.X, pub.Y)
	return encodeMultibaseKey(append(append([]byte{}, p256PubPrefix...), compressed...))
}

// p256PubFromMultikeyBytes decodes the raw Multikey bytes (prefix + compressed
// point) of a P-256 public key into an *ecdsa.PublicKey.
func p256PubFromMultikeyBytes(raw []byte) (*ecdsa.PublicKey, error) {
	if !bytes.HasPrefix(raw, p256PubPrefix) {
		return nil, fmt.Errorf("multikey: not a p256-pub multikey")
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), raw[len(p256PubPrefix):])
	if x == nil {
		return nil, fmt.Errorf("multikey: invalid p256 compressed point")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// decodeP256PrivMultibase decodes a P-256 secret-key Multikey ("z42t...").
func decodeP256PrivMultibase(s string) (*ecdsa.PrivateKey, error) {
	raw, err := decodeMultibaseKey(s)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(raw, p256PrivPrefix) {
		return nil, fmt.Errorf("multikey: not a p256-priv multikey")
	}
	d := raw[len(p256PrivPrefix):]
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
