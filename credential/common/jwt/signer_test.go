package jwt

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
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

func TestJWTSigner_SignString_Provider64ByteSignatureVerifies(t *testing.T) {
	privHex := "e5c9a597b20e13627a3850d38439b61ec9ee7aefd77c7cb6c01dc3866e1db19a"
	priv, err := crypto.HexToECDSA(privHex)
	if err != nil {
		t.Fatalf("HexToECDSA: %v", err)
	}

	signingString := "header.payload"
	hash := sha256.Sum256([]byte(signingString))

	// go-ethereum returns R||S||V (65 bytes); a provider may return only R||S (64 bytes).
	sig65, err := crypto.Sign(hash[:], priv)
	if err != nil {
		t.Fatalf("crypto.Sign: %v", err)
	}
	sig64 := sig65[:64]

	j := NewJWTSigner(&testSigner{sig: sig64})
	out, err := j.SignString(signingString)
	if err != nil {
		t.Fatalf("SignString error: %v", err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(out)
	if err != nil {
		t.Fatalf("DecodeString error: %v", err)
	}
	if len(raw) != 64 {
		t.Fatalf("expected 64-byte signature, got %d", len(raw))
	}

	if err := ES256K.Verify(signingString, raw, &priv.PublicKey); err != nil {
		t.Fatalf("Verify failed: %v (sig=%s)", err, hex.EncodeToString(raw))
	}
}
