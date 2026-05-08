package jsonmap

import (
	"encoding/hex"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
)

type testSigner struct {
	sig []byte
}

func (s *testSigner) Sign(hashPayload []byte) ([]byte, error) {
	if len(hashPayload) != 32 {
		return nil, signer.ValidateSignatureLength(hashPayload)
	}
	return s.sig, nil
}

func TestJSONMap_AddECDSAProof_Accepts64ByteSignature(t *testing.T) {
	m := JSONMap{
		"issuer": "did:example:issuer",
		"type":   "VerifiableCredential",
	}

	sig64 := make([]byte, 64)
	for i := range sig64 {
		sig64[i] = 0xAB
	}

	err := (&m).AddECDSAProof(&testSigner{sig: sig64}, "did:example:issuer#key-1", "assertionMethod", "https://example.invalid")
	if err != nil {
		t.Fatalf("AddECDSAProof error: %v", err)
	}

	proofObj, ok := m["proof"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected proof to be a map, got %T", m["proof"])
	}
	pv, _ := proofObj["proofValue"].(string)
	if len(pv) != hex.EncodedLen(64) {
		t.Fatalf("expected proofValue hex length %d, got %d", hex.EncodedLen(64), len(pv))
	}
}

func TestJSONMap_AddECDSAProof_Accepts65ByteSignature(t *testing.T) {
	m := JSONMap{
		"issuer": "did:example:issuer",
		"type":   "VerifiableCredential",
	}

	sig65 := make([]byte, 65)
	for i := range sig65 {
		sig65[i] = 0xCD
	}

	err := (&m).AddECDSAProof(&testSigner{sig: sig65}, "did:example:issuer#key-1", "assertionMethod", "https://example.invalid")
	if err != nil {
		t.Fatalf("AddECDSAProof error: %v", err)
	}

	proofObj, ok := m["proof"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected proof to be a map, got %T", m["proof"])
	}
	pv, _ := proofObj["proofValue"].(string)
	if len(pv) != hex.EncodedLen(65) {
		t.Fatalf("expected proofValue hex length %d, got %d", hex.EncodedLen(65), len(pv))
	}
}

func TestJSONMap_AddECDSAProof_RejectsInvalidSignatureLength(t *testing.T) {
	m := JSONMap{
		"issuer": "did:example:issuer",
		"type":   "VerifiableCredential",
	}

	err := (&m).AddECDSAProof(&testSigner{sig: make([]byte, 66)}, "did:example:issuer#key-1", "assertionMethod", "https://example.invalid")
	if err == nil {
		t.Fatalf("expected error for invalid signature length")
	}
}

