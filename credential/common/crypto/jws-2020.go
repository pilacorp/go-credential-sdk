package crypto

import (
	stdcrypto "crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

// VerifyRSAJWS verifies an RSA JWS signature (RFC 7518 §3.3, §3.5):
// RS256/384/512 and PS256/384/512, PSS with a salt as long as the hash.
// JsonWebSignature2020 admits only PS256 of these; jsonmap enforces that.
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
		return rsa.VerifyPSS(pub, stdcrypto.SHA256, h[:], sig, PSSOptions())
	case "RS384":
		h := sha512.Sum384(signingInput)
		return rsa.VerifyPKCS1v15(pub, stdcrypto.SHA384, h[:], sig)
	case "PS384":
		h := sha512.Sum384(signingInput)
		return rsa.VerifyPSS(pub, stdcrypto.SHA384, h[:], sig, PSSOptions())
	case "RS512":
		h := sha512.Sum512(signingInput)
		return rsa.VerifyPKCS1v15(pub, stdcrypto.SHA512, h[:], sig)
	case "PS512":
		h := sha512.Sum512(signingInput)
		return rsa.VerifyPSS(pub, stdcrypto.SHA512, h[:], sig, PSSOptions())
	default:
		return fmt.Errorf("unsupported JWS alg: %s", alg)
	}
}

// PSSOptions fixes the PSS salt to the hash length, as RFC 7518 §3.5 defines
// PS256/384/512 ("The size of the salt value is the same size as the hash
// function output"). nil options would sign with the largest salt the key
// allows and verify any salt length. The signer and the verifier both use it,
// so they cannot drift apart.
func PSSOptions() *rsa.PSSOptions {
	return &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
}
