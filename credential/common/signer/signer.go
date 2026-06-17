package signer

import "fmt"

// SignerProvider signs digests produced by the SDK.
//
// Contract:
// - hashPayload MUST be a 32-byte digest computed by the SDK.
// - Implementations may return:
//   - 64 bytes: R(32) || S(32)
//   - 65 bytes: R(32) || S(32) || V(1)
type SignerProvider interface {
	// Sign signs a 32-byte digest produced by the SDK.
	//
	// The SDK always passes a 32-byte digest; implementations should return an
	// error if the input is not 32 bytes to avoid accidentally signing raw data.
	Sign(hashPayload []byte) ([]byte, error)
}

// ECDSASignerProvider is an alias for SignerProvider, named to mirror
// JWSSignerProvider and the future BBSSignerProvider. Prefer this name.
type ECDSASignerProvider = SignerProvider

// JWSSignerProvider signs the JWS signing input (encodedHeader + "." + payload)
// and reports its JOSE algorithm (e.g. "RS256"). It maps to the
// JsonWebSignature2020 cryptosuite.
type JWSSignerProvider interface {
	SignJWS(signingInput []byte) ([]byte, error)
	Algorithm() string
}

func ValidateSignatureLength(signature []byte) error {
	switch len(signature) {
	case 64, 65:
		return nil
	default:
		return fmt.Errorf("invalid signature length: got %d, want 64 or 65", len(signature))
	}
}
