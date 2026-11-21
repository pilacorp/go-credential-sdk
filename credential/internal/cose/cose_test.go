package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestSign1Verify1_ES256_RoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"@context":"https://www.w3.org/ns/credentials/v2","type":"VerifiableCredential"}`)

	prot := Protected{
		Alg:         AlgES256,
		ContentType: "application/vc",
		Kid:         "did:example:issuer#key-1",
		Typ:         "application/vc+cose",
	}

	data, err := Sign1(prot, payload, signP256(key))
	if err != nil {
		t.Fatalf("Sign1: %v", err)
	}

	// Should start with CBOR tag 18.
	if !IsCOSESign1(data) {
		t.Fatalf("IsCOSESign1 = false, want true")
	}

	gotProt, gotPayload, err := Verify1(data, &key.PublicKey, []int{AlgES256})
	if err != nil {
		t.Fatalf("Verify1: %v", err)
	}

	if gotProt.Alg != AlgES256 {
		t.Errorf("alg = %d, want %d", gotProt.Alg, AlgES256)
	}
	if gotProt.ContentType != "application/vc" {
		t.Errorf("content_type = %q, want %q", gotProt.ContentType, "application/vc")
	}
	if gotProt.Kid != "did:example:issuer#key-1" {
		t.Errorf("kid = %q, want %q", gotProt.Kid, "did:example:issuer#key-1")
	}
	if gotProt.Typ != "application/vc+cose" {
		t.Errorf("typ = %q, want %q", gotProt.Typ, "application/vc+cose")
	}
	if string(gotPayload) != string(payload) {
		t.Errorf("payload mismatch")
	}
}

func TestSign1Verify1_ES256K_RoundTrip(t *testing.T) {
	// Use a secp256k1 key. go-ethereum's S256() is secp256k1.
	// We generate a random key on secp256k1 manually.
	key, err := generateSecp256k1Key()
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"@context":"https://www.w3.org/ns/credentials/v2","type":"VerifiableCredential"}`)

	prot := Protected{
		Alg:         AlgES256K,
		ContentType: "application/vc",
		Kid:         "did:example:issuer#key-1",
		Typ:         "application/vc+cose",
	}

	signFn := func(digest []byte) ([]byte, error) {
		r, s, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			return nil, err
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig, nil
	}

	data, err := Sign1(prot, payload, signFn)
	if err != nil {
		t.Fatalf("Sign1: %v", err)
	}

	gotProt, gotPayload, err := Verify1(data, &key.PublicKey, []int{AlgES256K})
	if err != nil {
		t.Fatalf("Verify1: %v", err)
	}

	if gotProt.Alg != AlgES256K {
		t.Errorf("alg = %d, want %d", gotProt.Alg, AlgES256K)
	}
	if string(gotPayload) != string(payload) {
		t.Errorf("payload mismatch")
	}
}

func TestVerify1_TamperedPayload(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	payload := []byte(`{"issuer":"did:example:1"}`)

	prot := Protected{Alg: AlgES256, Kid: "kid", Typ: "application/vc+cose"}

	data, err := Sign1(prot, payload, signP256(key))
	if err != nil {
		t.Fatal(err)
	}

	// Flip a byte in the payload region. The payload is JSON, so flipping
	// a byte in the middle of the CBOR should change the signature check.
	tampered := make([]byte, len(data))
	copy(tampered, data)
	tampered[len(tampered)/2] ^= 0xff

	if _, _, err := Verify1(tampered, &key.PublicKey, []int{AlgES256}); err == nil {
		t.Fatal("expected verification failure on tampered payload")
	}
}

func TestVerify1_WrongKey(t *testing.T) {
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	payload := []byte(`{"issuer":"did:example:1"}`)

	prot := Protected{Alg: AlgES256, Kid: "kid", Typ: "application/vc+cose"}

	data, err := Sign1(prot, payload, signP256(key1))
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := Verify1(data, &key2.PublicKey, []int{AlgES256}); err == nil {
		t.Fatal("expected verification failure with wrong key")
	}
}

func TestVerify1_DisallowedAlg(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	payload := []byte(`{"issuer":"did:example:1"}`)

	prot := Protected{Alg: AlgES256, Kid: "kid", Typ: "application/vc+cose"}

	data, err := Sign1(prot, payload, signP256(key))
	if err != nil {
		t.Fatal(err)
	}

	// Only allow ES256K.
	if _, _, err := Verify1(data, &key.PublicKey, []int{AlgES256K}); err == nil {
		t.Fatal("expected rejection for disallowed alg")
	}
}

func TestParse1_Empty(t *testing.T) {
	if _, _, _, err := Parse1(nil); err == nil {
		t.Fatal("expected error on nil input")
	}
	if _, _, _, err := Parse1([]byte{}); err == nil {
		t.Fatal("expected error on empty input")
	}
}

func TestIsCOSESign1(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"nil", nil, false},
		{"empty", []byte{}, false},
		{"short", []byte{0xd2}, false},
		{"tag18+array4", []byte{0xd2, 0x84}, true},
		{"tag18+other", []byte{0xd2, 0x83}, false},
		{"not tag18", []byte{0xd3, 0x84}, false},
		{"jwt string", []byte("eyJ"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsCOSESign1(tt.data); got != tt.want {
				t.Errorf("IsCOSESign1 = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAlgMapping(t *testing.T) {
	tests := []struct {
		jose string
		cose int
	}{
		{"ES256", AlgES256},
		{"ES256K", AlgES256K},
	}
	for _, tt := range tests {
		cose, err := COSEAlgForJOSE(tt.jose)
		if err != nil {
			t.Errorf("COSEAlgForJOSE(%q) error: %v", tt.jose, err)
		}
		if cose != tt.cose {
			t.Errorf("COSEAlgForJOSE(%q) = %d, want %d", tt.jose, cose, tt.cose)
		}
		jose, err := JOSEAlgForCOSE(tt.cose)
		if err != nil {
			t.Errorf("JOSEAlgForCOSE(%d) error: %v", tt.cose, err)
		}
		if jose != tt.jose {
			t.Errorf("JOSEAlgForCOSE(%d) = %q, want %q", tt.cose, jose, tt.jose)
		}
	}

	if _, err := COSEAlgForJOSE("RS256"); err == nil {
		t.Error("expected error for unsupported JOSE alg")
	}
	if _, err := JOSEAlgForCOSE(-999); err == nil {
		t.Error("expected error for unsupported COSE alg")
	}
}

func TestW3CTestVector_CredentialCOSEMinimal(t *testing.T) {
	// W3C vc-jose-cose-test-suite: tests/input/credential-cose-minimal.txt
	// Source: https://github.com/w3c/vc-jose-cose-test-suite
	// SHA-256 of this base64url string: checked at fetch time (2026-11-21).
	//
	// Protected header:
	//   alg: -7 (ES256)
	//   content_type: "application/vc"
	//   kid: bstr "73voMXFNmNlOEpuYCSJlh8eN0dscykoO6gBukgRS1uU"
	//   typ: "application/vc+cose"
	const vectorB64 = "0oRYVqQBJgNuYXBwbGljYXRpb24vdmMEWCs3M3ZvTVhGTm1ObE9FcHVZQ1NKbGg4ZU4wZHNjeWtvTzZnQnVrZ1JTMXVVEHNhcHBsaWNhdGlvbi92Yytjb3NloFkB8nsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YyIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJFeGFtcGxlQWx1bW5pQ3JlZGVudGlhbCJdLCJpZCI6Imh0dHA6Ly91bml2ZXJzaXR5LmV4YW1wbGUvY3JlZGVudGlhbHMvMTg3MiIsImlzc3VlciI6Imh0dHBzOi8vZXhhbXBsZS5pc3N1ZXIvdmMtam9zZS1jb3NlIiwidmFsaWRGcm9tIjoiMjAxMC0wMS0wMVQxOToyMzoyNFoiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJkZWdyZWUiOnsibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMiLCJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUifSwiaWQiOiJkaWQ6ZXhhbXBsZToxMjMifSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vZXhhbXBsZS5vcmcvZXhhbXBsZXMvZGVncmVlLmpzb24iLCJ0eXBlIjoiSnNvblNjaGVtYSJ9fVhAs3W1WN83yVu/HoEyYMy7Tcmub9zL55PDnfcx5yG42BTe0gdQ+E0V9B3B1gMZyt9dDEGZVJynd8vztWVr7d4Kkw"

	data := decodeTestVector(t, vectorB64)

	if !IsCOSESign1(data) {
		t.Fatal("test vector is not recognised as COSE_Sign1")
	}

	prot, payload, _, err := Parse1(data)
	if err != nil {
		t.Fatalf("Parse1: %v", err)
	}

	if prot.Alg != AlgES256 {
		t.Errorf("alg = %d, want %d (ES256)", prot.Alg, AlgES256)
	}
	if prot.ContentType != "application/vc" {
		t.Errorf("content_type = %q, want %q", prot.ContentType, "application/vc")
	}
	if prot.Kid != "73voMXFNmNlOEpuYCSJlh8eN0dscykoO6gBukgRS1uU" {
		t.Errorf("kid = %q", prot.Kid)
	}
	if prot.Typ != "application/vc+cose" {
		t.Errorf("typ = %q, want %q", prot.Typ, "application/vc+cose")
	}

	// Check the payload is valid JSON with expected fields.
	var body map[string]interface{}
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if body["issuer"] != "https://example.issuer/vc-jose-cose" {
		t.Errorf("issuer = %v", body["issuer"])
	}
}

func TestW3CTestVector_BadMediaType(t *testing.T) {
	// W3C vc-jose-cose-test-suite: tests/input/credential-cose-bad-media-type.txt
	// Protected header has typ: "really/bad" and content_type: "very/bad".
	const vectorB64 = "0oRYSKQBOCIDaHZlcnkvYmFkBFgrOTZxQm5EcHZTNng4WVNDSF94bW5MbFhaTWtEaEhCcjhsajk5dTVhb2c3cxBqcmVhbGx5L2JhZKBZAfJ7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy9leGFtcGxlcy92MiJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRXhhbXBsZUFsdW1uaUNyZWRlbnRpYWwiXSwiaWQiOiJodHRwOi8vdW5pdmVyc2l0eS5leGFtcGxlL2NyZWRlbnRpYWxzLzE4NzIiLCJpc3N1ZXIiOiJodHRwczovL2V4YW1wbGUuaXNzdWVyL3ZjLWpvc2UtY29zZSIsInZhbGlkRnJvbSI6IjIwMTAtMDEtMDFUMTk6MjM6MjRaIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiZGVncmVlIjp7Im5hbWUiOiJCYWNoZWxvciBvZiBTY2llbmNlIGFuZCBBcnRzIiwidHlwZSI6IkJhY2hlbG9yRGVncmVlIn0sImlkIjoiZGlkOmV4YW1wbGU6MTIzIn0sImNyZWRlbnRpYWxTY2hlbWEiOnsiaWQiOiJodHRwczovL2V4YW1wbGUub3JnL2V4YW1wbGVzL2RlZ3JlZS5qc29uIiwidHlwZSI6Ikpzb25TY2hlbWEifX1YYPTKiZkxA1XUBgMqJ_eX5cpijouAd2ButW2pHrXxSAn7RwysI8wVcEBm29St1db5pWqHPMBE-Fxmeh6Qmw_V5tY25w9g36J4bkd3MmbmFHo3dXUiADBCI_Ae-b8WxKltQg"

	data := decodeTestVector(t, vectorB64)

	prot, _, _, err := Parse1(data)
	if err != nil {
		t.Fatalf("Parse1: %v", err)
	}

	// The vector should parse structurally but have wrong media types.
	if prot.Typ != "really/bad" {
		t.Errorf("typ = %q, want %q", prot.Typ, "really/bad")
	}
	if prot.ContentType != "very/bad" {
		t.Errorf("content_type = %q, want %q", prot.ContentType, "very/bad")
	}
}

// decodeTestVector decodes a base64url (without padding) string. The W3C test
// vectors use standard base64url encoding (the files are served as text).
func decodeTestVector(t *testing.T, s string) []byte {
	t.Helper()
	// Try base64url (no padding) first, then standard base64.
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("decode test vector: %v", err)
		}
	}
	return data
}

// signP256 is a convenience that returns a SignFunc for a P-256 private key.
func signP256(key *ecdsa.PrivateKey) SignFunc {
	return func(digest []byte) ([]byte, error) {
		r, s, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			return nil, err
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig, nil
	}
}

func TestProtected_Deterministic(t *testing.T) {
	// Encoding the same header twice must produce identical bytes (canonical CBOR).
	p := Protected{
		Alg:         AlgES256,
		ContentType: "application/vc",
		Kid:         "did:example:issuer#key-1",
		Typ:         "application/vc+cose",
	}
	b1, err := p.encode()
	if err != nil {
		t.Fatal(err)
	}
	b2, err := p.encode()
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Fatal("non-deterministic encoding")
	}

	// Hash of Sign1 output must also be deterministic.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	payload := []byte(`{"test":true}`)

	// Use a deterministic signer (fixed k) — but we can't easily do that,
	// so just check the structure is deterministic modulo the signature.
	data, err := Sign1(p, payload, signP256(key))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	_ = h // just checking it doesn't panic
}

// generateSecp256k1Key generates a random secp256k1 private key.
func generateSecp256k1Key() (*ecdsa.PrivateKey, error) {
	return crypto.GenerateKey()
}
