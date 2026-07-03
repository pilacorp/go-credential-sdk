package crypto

import (
	"crypto/ecdsa"
	"math/big"
)

// VerifyP256 verifies a 64-byte R||S signature over a 32-byte digest with a
// P-256 public key. Used for the ecdsa-sd-2023 issuer base signature.
func VerifyP256(pub *ecdsa.PublicKey, digest, sig []byte) bool {
	if pub == nil || len(sig) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	return ecdsa.Verify(pub, digest, r, s)
}

// VerifyECDSA verifies an ecdsa-sd-2023 issuer base signature over a 32-byte
// digest using the issuer key's own curve. Standard P-256 keys produce a 64-byte
// R||S signature; as a non-standard extension this SDK also accepts a secp256k1
// issuer key whose go-ethereum signature is 65 bytes (R||S||V) — the trailing
// recovery byte is dropped before verification.
func VerifyECDSA(pub *ecdsa.PublicKey, digest, sig []byte) bool {
	if pub == nil {
		return false
	}
	if len(sig) == 65 {
		sig = sig[:64]
	}
	if len(sig) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	return ecdsa.Verify(pub, digest, r, s)
}
