package crypto

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/crypto"
)

// Sign signs a message using ECDSA with secp256k1, producing a 65-byte [r, s, v] signature.
func ECDSASign(msg []byte, hexPrivateKey string) ([]byte, error) {
	privKey, err := crypto.HexToECDSA(hexPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("ecdsa: invalid private key: %w", err)
	}

	signature, err := crypto.Sign(msg, privKey)
	if err != nil {
		return nil, fmt.Errorf("ecdsa: sign error: %w", err)
	}

	// Validate signature length
	if len(signature) != 65 {
		return nil, fmt.Errorf("ecdsa: invalid signature length, expected 65 bytes")
	}

	return signature, nil
}

func ECDSAVerifySignature(publicKey, signature string, msg []byte) (bool, error) {
	// Decode hex-encoded public key
	pubKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return false, fmt.Errorf("failed to decode public key: %v", err)
	}

	if pubKeyBytes[0] == 0x02 || pubKeyBytes[0] == 0x03 {
		pubKeyParsed, err := btcec.ParsePubKey(pubKeyBytes)
		if err != nil {
			return false, fmt.Errorf("failed to parse compressed public key: %v", err)
		}
		pubKeyBytes = pubKeyParsed.SerializeUncompressed()
	}

	// Parse public key
	pubKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %v", err)
	}

	// Decode hex-encoded signature
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %v", err)
	}

	// Handle signature length (64 bytes for r,s or 65 bytes for r,s,v)
	var rsBytes []byte
	if len(sigBytes) == 65 {
		rsBytes = sigBytes[:64]
	} else if len(sigBytes) == 64 {
		rsBytes = sigBytes
	} else {
		return false, fmt.Errorf("invalid signature length: got %d, want 64 or 65 bytes", len(sigBytes))
	}

	// Use messageBytes directly (no hashing, assuming signRaw signs raw bytes)
	r := new(big.Int).SetBytes(rsBytes[:32])
	s := new(big.Int).SetBytes(rsBytes[32:])

	// Verify the signature
	verified := ecdsa.Verify(pubKey, msg, r, s)
	if !verified {
		return false, nil
	}

	return true, nil
}

// VerifyKeyPair verifies if a private key and public key match
func VerifyKeyPair(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) bool {
	// Get the public key from the private key
	derivedPublicKey := &privateKey.PublicKey

	// Compare the X and Y coordinates of both public keys
	return derivedPublicKey.X.Cmp(publicKey.X) == 0 &&
		derivedPublicKey.Y.Cmp(publicKey.Y) == 0
}

// VerifyKeyPairFromHex verifies if a private key (hex) and public key (hex) match.
func VerifyKeyPairFromHex(privateKeyHex, publicKeyHex string) (bool, error) {
	// Convert hex-encoded private key to ECDSA private key
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return false, fmt.Errorf("failed to convert private key hex: %w", err)
	}

	// Decode hex-encoded public key
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return false, fmt.Errorf("failed to decode public key hex: %w", err)
	}

	// Handle compressed public key (33 bytes) by converting to uncompressed (65 bytes)
	if len(publicKeyBytes) == 33 && (publicKeyBytes[0] == 0x02 || publicKeyBytes[0] == 0x03) {
		pubKeyParsed, err := btcec.ParsePubKey(publicKeyBytes)
		if err != nil {
			return false, fmt.Errorf("failed to parse compressed public key: %w", err)
		}
		publicKeyBytes = pubKeyParsed.SerializeUncompressed()
	}

	// Unmarshal public key bytes to ECDSA public key
	publicKey, err := crypto.UnmarshalPubkey(publicKeyBytes)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	// Verify if the private key's derived public key matches the provided public key
	return VerifyKeyPair(privateKey, publicKey), nil
}
