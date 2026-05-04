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
	Sign(hashPayload []byte) ([]byte, error)
}

func ValidateSignatureLength(signature []byte) error {
	switch len(signature) {
	case 64, 65:
		return nil
	default:
		return fmt.Errorf("invalid signature length: got %d, want 64 or 65", len(signature))
	}
}

