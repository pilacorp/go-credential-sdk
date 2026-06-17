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
