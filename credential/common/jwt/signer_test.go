package jwt

import (
	"encoding/base64"
	"fmt"
	"testing"
)

type testSigner struct {
	sig []byte
	err error
}

func (s *testSigner) Sign(hashPayload []byte) ([]byte, error) {
	if len(hashPayload) != 32 {
		return nil, fmt.Errorf("hash payload must be 32 bytes, got %d", len(hashPayload))
	}
	if s.err != nil {
		return nil, s.err
	}
	return s.sig, nil
}

func TestJWTSigner_SignString_Returns64BytesSignature(t *testing.T) {
	signingString := "header.payload"

	// 65-byte signature: should be normalized to 64 bytes for JWT.
	sig65 := make([]byte, 65)
	for i := range sig65 {
		sig65[i] = byte(i)
	}

	j := NewJWTSigner(&testSigner{sig: sig65})
	out, err := j.SignString(signingString)
	if err != nil {
		t.Fatalf("SignString error: %v", err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(out)
	if err != nil {
		t.Fatalf("DecodeString error: %v", err)
	}
	if len(raw) != 64 {
		t.Fatalf("expected 64-byte JWT signature, got %d", len(raw))
	}
	for i := 0; i < 64; i++ {
		if raw[i] != sig65[i] {
			t.Fatalf("signature mismatch at %d", i)
		}
	}
}

func TestJWTSigner_SignString_InvalidSignatureLength(t *testing.T) {
	j := NewJWTSigner(&testSigner{sig: make([]byte, 63)})
	if _, err := j.SignString("header.payload"); err == nil {
		t.Fatalf("expected error for invalid signature length")
	}
}
