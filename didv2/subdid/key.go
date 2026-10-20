package subdid

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/pilacorp/go-credential-sdk/didv2/did"
)

const (
	kdfSalt       = "subdid-keygen-v1"
	kdfInfoPrefix = "subdid-key-v1"
	kdfLength     = 48
)

// DeriveSubDIDKey derives the key of the Sub-DID subID under the root DID whose
// primary private key is rootPrivateKeyHex, with nda-subdid-hkdf-sha256-v1: the
// derivation Vault uses for CreateSubDID. The scalar is valid on secp256k1 and P-256.
func DeriveSubDIDKey(rootPrivateKeyHex, subID string) (*did.KeyPair, error) {
	root, err := hex.DecodeString(strings.TrimPrefix(rootPrivateKeyHex, "0x"))
	if err != nil || len(root) != 32 {
		return nil, errors.New("subdid: root private key must be 32 bytes of hex")
	}
	rootScalar := new(big.Int).SetBytes(root)
	if rootScalar.Sign() == 0 || rootScalar.Cmp(crypto.S256().Params().N) >= 0 {
		return nil, errors.New("subdid: root private key is out of range")
	}

	id, err := ParseSubID(subID)
	if err != nil {
		return nil, err
	}

	prk, err := hkdf.Extract(sha256.New, root, []byte(kdfSalt))
	if err != nil {
		return nil, fmt.Errorf("subdid: derive key: %w", err)
	}
	okm, err := hkdf.Expand(sha256.New, prk, kdfInfoPrefix+string(id), kdfLength)
	if err != nil {
		return nil, fmt.Errorf("subdid: derive key: %w", err)
	}

	child := make([]byte, 32)
	reduceToP256Scalar(okm).FillBytes(child)

	secpPriv, err := crypto.ToECDSA(child)
	if err != nil {
		return nil, fmt.Errorf("subdid: derive key: %w", err)
	}
	p256Priv, err := ecdh.P256().NewPrivateKey(child)
	if err != nil {
		return nil, fmt.Errorf("subdid: derive key: %w", err)
	}
	p256Pub := p256Priv.PublicKey().Bytes()

	return &did.KeyPair{
		PublicKey:  &secpPriv.PublicKey,
		PrivateKey: secpPriv,
		P256PublicKey: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(p256Pub[1:33]),
			Y:     new(big.Int).SetBytes(p256Pub[33:65]),
		},
	}, nil
}

func reduceToP256Scalar(okm []byte) *big.Int {
	nMinusOne := new(big.Int).Sub(elliptic.P256().Params().N, big.NewInt(1))
	k := new(big.Int).Mod(new(big.Int).SetBytes(okm), nMinusOne)

	return k.Add(k, big.NewInt(1))
}
