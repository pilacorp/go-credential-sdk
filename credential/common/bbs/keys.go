package bbs

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/mr-tron/base58"
)

var bls12381G2PublicKeyMulticodec = []byte{0xeb, 0x01}

// DecodePublicKeyHex parses a compressed BLS12-381 G2 public key from hex.
func DecodePublicKeyHex(publicKeyHex string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(publicKeyHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("bbs: decode public key hex: %w", err)
	}
	return raw, nil
}

// DecodePrivateKeyHex parses a compressed BLS12-381 private key from hex.
func DecodePrivateKeyHex(privateKeyHex string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(privateKeyHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("bbs: decode private key hex: %w", err)
	}
	return raw, nil
}

// DecodePublicKeyMultibase parses a BLS12-381 G2 public key from a base58btc
// multikey string and strips the multicodec prefix.
func DecodePublicKeyMultibase(multibase string) ([]byte, error) {
	if multibase == "" {
		return nil, fmt.Errorf("bbs: publicKeyMultibase is empty")
	}
	if multibase[0] != 'z' {
		return nil, fmt.Errorf("bbs: unsupported multibase prefix %q", multibase[:1])
	}
	raw, err := base58.Decode(multibase[1:])
	if err != nil {
		return nil, fmt.Errorf("bbs: decode publicKeyMultibase: %w", err)
	}
	if bytes.HasPrefix(raw, bls12381G2PublicKeyMulticodec) {
		return append([]byte{}, raw[len(bls12381G2PublicKeyMulticodec):]...), nil
	}
	return raw, nil
}

// EncodePublicKeyMultibase encodes a compressed BLS12-381 G2 public key as a
// base58btc multikey string.
func EncodePublicKeyMultibase(publicKey []byte) string {
	buf := append(append([]byte{}, bls12381G2PublicKeyMulticodec...), publicKey...)
	return "z" + base58.Encode(buf)
}

