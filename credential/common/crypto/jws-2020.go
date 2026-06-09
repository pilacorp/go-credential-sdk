package crypto

import (
	stdcrypto "crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

// VerifyRSAJWS verifies a JWS signature for the JsonWebSignature2020 suite
// (RSA family). Supported algs: RS256, PS256, RS384, PS384, RS512, PS512.
func VerifyRSAJWS(alg string, pub *rsa.PublicKey, signingInput, sig []byte) error {
	if pub == nil {
		return fmt.Errorf("nil RSA public key")
	}
	switch alg {
	case "RS256":
		h := sha256.Sum256(signingInput)
		return rsa.VerifyPKCS1v15(pub, stdcrypto.SHA256, h[:], sig)
	case "PS256":
		h := sha256.Sum256(signingInput)
		return rsa.VerifyPSS(pub, stdcrypto.SHA256, h[:], sig, nil)
	case "RS384":
		h := sha512.Sum384(signingInput)
		return rsa.VerifyPKCS1v15(pub, stdcrypto.SHA384, h[:], sig)
	case "PS384":
		h := sha512.Sum384(signingInput)
		return rsa.VerifyPSS(pub, stdcrypto.SHA384, h[:], sig, nil)
	case "RS512":
		h := sha512.Sum512(signingInput)
		return rsa.VerifyPKCS1v15(pub, stdcrypto.SHA512, h[:], sig)
	case "PS512":
		h := sha512.Sum512(signingInput)
		return rsa.VerifyPSS(pub, stdcrypto.SHA512, h[:], sig, nil)
	default:
		return fmt.Errorf("unsupported JWS alg: %s", alg)
	}
}
