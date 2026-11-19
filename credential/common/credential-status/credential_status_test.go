package credentialstatus

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	"github.com/pilacorp/go-credential-sdk/credential/common/util"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const testIssuerDID = "did:example:issuer"
const testVMFragment = "key-1"
const testVMID = testIssuerDID + "#" + testVMFragment

// buildW3CEncodedList creates a W3C-conformant encodedList (u prefix, gzip,
// MSB-first, 16 KB padded). revoked lists the bit positions to set.
func buildW3CEncodedList(t *testing.T, revoked []int) string {
	t.Helper()
	const minBytes = 16384 // 16 KB

	bs := make([]byte, minBytes)
	for _, pos := range revoked {
		byteIdx := pos / 8
		bitIdx := 7 - (pos % 8) // MSB-first
		if byteIdx >= len(bs) {
			t.Fatalf("position %d exceeds 16 KB bitstring", pos)
		}
		bs[byteIdx] |= 1 << uint(bitIdx)
	}

	encoded, err := util.CompressToBase64URL(bs)
	require.NoError(t, err)
	return "u" + encoded // multibase prefix
}

// buildLegacyEncodedList creates a legacy (authen-service) encodedList: gzip,
// base64url-no-pad, LSB-first, no prefix, no minimum size.
func buildLegacyEncodedList(t *testing.T, size int, revoked []int) string {
	t.Helper()
	bs := make([]byte, size)
	for _, pos := range revoked {
		byteIdx := pos / 8
		bitIdx := pos % 8 // LSB-first
		if byteIdx >= len(bs) {
			t.Fatalf("position %d exceeds bitstring of size %d", pos, size)
		}
		bs[byteIdx] |= 1 << uint(bitIdx)
	}

	encoded, err := util.CompressToBase64URL(bs)
	require.NoError(t, err)
	return encoded
}

// testKeyPair generates a fresh P-256 key and builds a resolver, signer, and
// DID document.
func testKeyPair(t *testing.T) (*ecdsa.PrivateKey, verificationmethod.ResolverProvider) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	vm, err := verificationmethod.NewP256VM(testIssuerDID, testVMFragment, &priv.PublicKey)
	require.NoError(t, err)
	doc := verificationmethod.NewDIDDocument(testIssuerDID, vm)
	resolver := verificationmethod.NewStaticResolver(doc)
	return priv, resolver
}

// signStatusListCredential builds and signs a status list credential as a
// JSONMap, the same way authen-service does (ecdsa-rdfc-2019 proof).
func signStatusListCredential(t *testing.T, priv *ecdsa.PrivateKey, issuer, purpose, encodedList string) map[string]interface{} {
	t.Helper()
	now := time.Now().UTC()
	vc := jsonmap.JSONMap{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
		},
		"type":       []interface{}{"VerifiableCredential", "BitstringStatusListCredential"},
		"id":         issuer + "/status/0",
		"issuer":     issuer,
		"validFrom":  now.Add(-1 * time.Hour).Format(time.RFC3339),
		"validUntil": now.Add(24 * time.Hour).Format(time.RFC3339),
		"credentialSubject": map[string]interface{}{
			"id":            issuer + "/status/0#list",
			"type":          "BitstringStatusList",
			"statusPurpose": purpose,
			"encodedList":   encodedList,
		},
	}

	sp, err := signer.NewP256Provider(priv)
	require.NoError(t, err)
	err = vc.AddECDSAProof(sp, testVMID, "assertionMethod")
	require.NoError(t, err)

	return map[string]interface{}(vc)
}

// serveStatusList starts an httptest server that returns the given VC wrapped
// in {"data": <vc>}.
func serveStatusList(t *testing.T, vc map[string]interface{}) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{"data": vc}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(server.Close)
	return server
}

// ---------------------------------------------------------------------------
// CheckBitStatus tests
// ---------------------------------------------------------------------------

func TestCheckBitStatus_W3C_Index0Revoked(t *testing.T) {
	encoded := buildW3CEncodedList(t, []int{0})
	subject := StatusListCredentialSubject{
		EncodedList:   encoded,
		StatusPurpose: "revocation",
	}

	isSet, err := CheckBitStatus(0, subject, "revocation")
	require.NoError(t, err)
	assert.True(t, isSet, "position 0 should be set (revoked)")

	isSet, err = CheckBitStatus(7, subject, "revocation")
	require.NoError(t, err)
	assert.False(t, isSet, "position 7 should not be set")
}

func TestCheckBitStatus_W3C_MultiplePositions(t *testing.T) {
	encoded := buildW3CEncodedList(t, []int{0, 7, 100})
	subject := StatusListCredentialSubject{
		EncodedList:   encoded,
		StatusPurpose: "revocation",
	}

	for _, pos := range []int{0, 7, 100} {
		isSet, err := CheckBitStatus(pos, subject, "revocation")
		require.NoError(t, err)
		assert.True(t, isSet, "position %d should be set", pos)
	}
	for _, pos := range []int{1, 6, 8, 99, 101} {
		isSet, err := CheckBitStatus(pos, subject, "revocation")
		require.NoError(t, err)
		assert.False(t, isSet, "position %d should not be set", pos)
	}
}

func TestCheckBitStatus_W3C_Under16KB_Refused(t *testing.T) {
	// Build a small bitstring (128 bytes), gzip it, prepend 'u'.
	small := make([]byte, 128)
	small[0] = 0x80 // MSB of byte 0 set
	encoded, err := util.CompressToBase64URL(small)
	require.NoError(t, err)
	encoded = "u" + encoded

	subject := StatusListCredentialSubject{
		EncodedList:   encoded,
		StatusPurpose: "revocation",
	}

	_, err = CheckBitStatus(0, subject, "revocation")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "16 KB")
}

func TestCheckBitStatus_Legacy_Unchanged(t *testing.T) {
	// Legacy authen-style: 128 bytes (1024 bits), LSB-first, position 0 set.
	encoded := buildLegacyEncodedList(t, 128, []int{0})
	subject := StatusListCredentialSubject{
		EncodedList:   encoded,
		StatusPurpose: "revocation",
	}

	isSet, err := CheckBitStatus(0, subject, "revocation")
	require.NoError(t, err)
	assert.True(t, isSet, "legacy position 0 should be set")

	isSet, err = CheckBitStatus(1, subject, "revocation")
	require.NoError(t, err)
	assert.False(t, isSet, "legacy position 1 should not be set")
}

func TestCheckBitStatus_Legacy_StartsWithH_NeverW3C(t *testing.T) {
	// A legacy list's base64url always starts with 'H' (gzip magic bytes
	// 0x1f 0x8b encode to "H4sI..."). Verify it is never mistaken for W3C.
	encoded := buildLegacyEncodedList(t, 128, []int{0})
	assert.True(t, len(encoded) > 0 && encoded[0] == 'H',
		"legacy encodedList should start with 'H', got %q", string(encoded[0]))

	subject := StatusListCredentialSubject{
		EncodedList:   encoded,
		StatusPurpose: "revocation",
	}

	// Should succeed as legacy (not fail with 16KB check).
	isSet, err := CheckBitStatus(0, subject, "revocation")
	require.NoError(t, err)
	assert.True(t, isSet)
}

func TestCheckBitStatus_PurposeMismatch(t *testing.T) {
	encoded := buildLegacyEncodedList(t, 128, []int{0})
	subject := StatusListCredentialSubject{
		EncodedList:   encoded,
		StatusPurpose: "revocation",
	}

	_, err := CheckBitStatus(0, subject, "suspension")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "statusPurpose mismatch")
}

func TestCheckBitStatus_W3C_MSBFirst_BitOrdering(t *testing.T) {
	// Set only position 7 in a W3C list. In MSB-first, position 7 is bit 0
	// (LSB) of byte 0. Byte 0 should be 0x01.
	encoded := buildW3CEncodedList(t, []int{7})
	subject := StatusListCredentialSubject{
		EncodedList:   encoded,
		StatusPurpose: "revocation",
	}

	isSet, err := CheckBitStatus(7, subject, "revocation")
	require.NoError(t, err)
	assert.True(t, isSet, "W3C position 7 should be set")

	isSet, err = CheckBitStatus(0, subject, "revocation")
	require.NoError(t, err)
	assert.False(t, isSet, "W3C position 0 should not be set")
}

// ---------------------------------------------------------------------------
// IsRevoked backward-compatibility tests
// ---------------------------------------------------------------------------

func TestIsRevoked(t *testing.T) {
	// Legacy LSB-first: 0x01 -> bit 0 set.
	raw := []byte{0x01}
	encoded, err := util.CompressToBase64URL(raw)
	assert.NoError(t, err)

	subject := StatusListCredentialSubject{
		EncodedList:   encoded,
		StatusPurpose: "revocation",
	}

	revoked, err := IsRevoked(0, subject)
	assert.NoError(t, err)
	assert.True(t, revoked, "position 0 should be revoked")

	notRevoked, err := IsRevoked(1, subject)
	assert.NoError(t, err)
	assert.False(t, notRevoked, "position 1 should not be revoked")
}

func TestIsRevoked_NonRevocationPurpose(t *testing.T) {
	raw := []byte{0x01}
	encoded, err := util.CompressToBase64URL(raw)
	assert.NoError(t, err)

	subject := StatusListCredentialSubject{
		EncodedList:   encoded,
		StatusPurpose: "suspension",
	}

	revoked, err := IsRevoked(0, subject)
	assert.NoError(t, err)
	assert.False(t, revoked, "non-revocation purpose should always be not revoked")
}

// ---------------------------------------------------------------------------
// VerifyAndCheckStatus tests (integration with httptest + proof)
// ---------------------------------------------------------------------------

func TestVerifyAndCheckStatus_Signed_W3C(t *testing.T) {
	priv, resolver := testKeyPair(t)
	encoded := buildW3CEncodedList(t, []int{0})

	vc := signStatusListCredential(t, priv, testIssuerDID, "revocation", encoded)
	server := serveStatusList(t, vc)

	client := NewClient(WithResolver(resolver))

	// Position 0 is set -> status is set for purpose "revocation".
	err := client.VerifyAndCheckStatus(server.URL, 0, "revocation", testIssuerDID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credential status is set for purpose")
	assert.Contains(t, err.Error(), "revocation")

	// Position 7 is not set -> not revoked.
	err = client.VerifyAndCheckStatus(server.URL, 7, "revocation", testIssuerDID)
	assert.NoError(t, err)
}

func TestVerifyAndCheckStatus_Signed_Legacy(t *testing.T) {
	priv, resolver := testKeyPair(t)
	encoded := buildLegacyEncodedList(t, 128, []int{0})

	vc := signStatusListCredential(t, priv, testIssuerDID, "revocation", encoded)
	server := serveStatusList(t, vc)

	client := NewClient(WithResolver(resolver))

	// Position 0 is set -> status is set for purpose "revocation".
	err := client.VerifyAndCheckStatus(server.URL, 0, "revocation", testIssuerDID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credential status is set for purpose")

	// Position 1 is not set -> not revoked.
	err = client.VerifyAndCheckStatus(server.URL, 1, "revocation", testIssuerDID)
	assert.NoError(t, err)
}

func TestVerifyAndCheckStatus_UnsignedCredential_Refused(t *testing.T) {
	_, resolver := testKeyPair(t)
	encoded := buildLegacyEncodedList(t, 128, []int{})

	// Build an unsigned status list credential (no proof).
	vc := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential", "BitstringStatusListCredential"},
		"id":       testIssuerDID + "/status/0",
		"issuer":   testIssuerDID,
		"credentialSubject": map[string]interface{}{
			"type":          "BitstringStatusList",
			"statusPurpose": "revocation",
			"encodedList":   encoded,
		},
	}
	server := serveStatusList(t, vc)

	client := NewClient(WithResolver(resolver))
	err := client.VerifyAndCheckStatus(server.URL, 0, "revocation", testIssuerDID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "proof")
}

func TestVerifyAndCheckStatus_TamperedCredential_Refused(t *testing.T) {
	priv, resolver := testKeyPair(t)
	encoded := buildLegacyEncodedList(t, 128, []int{0})

	vc := signStatusListCredential(t, priv, testIssuerDID, "revocation", encoded)
	// Tamper: change the issuer after signing.
	vc["issuer"] = "did:example:tampered"

	server := serveStatusList(t, vc)

	client := NewClient(WithResolver(resolver))
	err := client.VerifyAndCheckStatus(server.URL, 0, "revocation", "did:example:tampered")
	assert.Error(t, err)
	// The proof should fail because the document was tampered.
	assert.Contains(t, err.Error(), "proof")
}

func TestVerifyAndCheckStatus_IssuerMismatch_Refused(t *testing.T) {
	priv, resolver := testKeyPair(t)
	encoded := buildLegacyEncodedList(t, 128, []int{})

	// Status list credential issued by testIssuerDID.
	vc := signStatusListCredential(t, priv, testIssuerDID, "revocation", encoded)
	server := serveStatusList(t, vc)

	client := NewClient(WithResolver(resolver))
	// But the VC being checked has a different issuer.
	err := client.VerifyAndCheckStatus(server.URL, 0, "revocation", "did:example:other-issuer")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")
}

func TestVerifyAndCheckStatus_PurposeMismatch_Refused(t *testing.T) {
	priv, resolver := testKeyPair(t)
	encoded := buildLegacyEncodedList(t, 128, []int{})

	// Status list credential with purpose "revocation".
	vc := signStatusListCredential(t, priv, testIssuerDID, "revocation", encoded)
	server := serveStatusList(t, vc)

	client := NewClient(WithResolver(resolver))
	// But the VC entry claims purpose "suspension".
	err := client.VerifyAndCheckStatus(server.URL, 0, "suspension", testIssuerDID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "statusPurpose mismatch")
}

func TestVerifyAndCheckStatus_ExpiredCredential_Refused(t *testing.T) {
	priv, resolver := testKeyPair(t)
	encoded := buildLegacyEncodedList(t, 128, []int{})

	// Build a manually expired status list credential.
	now := time.Now().UTC()
	vc := jsonmap.JSONMap{
		"@context":   []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":       []interface{}{"VerifiableCredential", "BitstringStatusListCredential"},
		"id":         testIssuerDID + "/status/0",
		"issuer":     testIssuerDID,
		"validFrom":  now.Add(-48 * time.Hour).Format(time.RFC3339),
		"validUntil": now.Add(-1 * time.Hour).Format(time.RFC3339), // expired
		"credentialSubject": map[string]interface{}{
			"type":          "BitstringStatusList",
			"statusPurpose": "revocation",
			"encodedList":   encoded,
		},
	}
	sp, err := signer.NewP256Provider(priv)
	require.NoError(t, err)
	err = vc.AddECDSAProof(sp, testVMID, "assertionMethod")
	require.NoError(t, err)

	server := serveStatusList(t, map[string]interface{}(vc))

	client := NewClient(WithResolver(resolver))
	err = client.VerifyAndCheckStatus(server.URL, 0, "revocation", testIssuerDID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

// ---------------------------------------------------------------------------
// Legacy FetchAndCheckRevocation test (unchanged)
// ---------------------------------------------------------------------------

func TestFetchAndCheckRevocation(t *testing.T) {
	// Prepare encoded list where position 0 is revoked (bit 1).
	raw := []byte{0x01}
	encoded, err := util.CompressToBase64URL(raw)
	assert.NoError(t, err)

	// Build a fake status list credential response.
	respBody := StatusListCredentialResponse{
		Data: StatusListCredential{
			CredentialSubject: StatusListCredentialSubject{
				EncodedList:   encoded,
				StatusPurpose: "revocation",
				ID:            "did:example:status/0#list",
				Type:          "BitstringStatusList",
			},
			ID:         "did:example:status/0",
			Issuer:     IssuerField{DID: "did:example:issuer"},
			Proof:      map[string]interface{}{},
			Type:       []string{"VerifiableCredential", "BitstringStatusListCredential"},
			ValidFrom:  "2025-01-01T00:00:00Z",
			ValidUntil: "2025-01-02T00:00:00Z",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(respBody)
	}))
	defer server.Close()

	url := server.URL

	revoked, err := FetchAndCheckRevocation(url, 0)
	assert.NoError(t, err)
	assert.True(t, revoked, "credential at position 0 should be revoked")
}

// ---------------------------------------------------------------------------
// Client option tests
// ---------------------------------------------------------------------------

func TestNewClient_UsesDefaultHTTPClient(t *testing.T) {
	client := NewClient()
	assert.Equal(t, defaultHTTPClient, client.client)
}

func TestWithHTTPClient_OverridesClient(t *testing.T) {
	custom := &http.Client{Timeout: 5 * time.Second}

	client := NewClient(WithHTTPClient(custom))
	assert.Equal(t, custom, client.client)
}

func TestWithHTTPClient_NilDoesNotOverride(t *testing.T) {
	client := NewClient(WithHTTPClient(nil))
	assert.Equal(t, defaultHTTPClient, client.client)
}

// ---------------------------------------------------------------------------
// W3C vs Legacy detection edge case
// ---------------------------------------------------------------------------

func TestCheckBitStatus_W3C_Exactly16KB(t *testing.T) {
	// 16384 bytes is exactly the minimum. Should be accepted.
	encoded := buildW3CEncodedList(t, []int{0})
	subject := StatusListCredentialSubject{
		EncodedList:   encoded,
		StatusPurpose: "revocation",
	}

	isSet, err := CheckBitStatus(0, subject, "revocation")
	require.NoError(t, err)
	assert.True(t, isSet)
}

func TestCheckBitStatus_OutOfBounds(t *testing.T) {
	encoded := buildLegacyEncodedList(t, 1, []int{}) // 1 byte = 8 bits
	subject := StatusListCredentialSubject{
		EncodedList:   encoded,
		StatusPurpose: "revocation",
	}

	_, err := CheckBitStatus(8, subject, "revocation")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")
}

func TestCheckBitStatus_NegativePosition(t *testing.T) {
	encoded := buildLegacyEncodedList(t, 1, []int{})
	subject := StatusListCredentialSubject{
		EncodedList:   encoded,
		StatusPurpose: "revocation",
	}

	_, err := CheckBitStatus(-1, subject, "revocation")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")
}

func TestCheckBitStatus_EmptyEncodedList(t *testing.T) {
	subject := StatusListCredentialSubject{
		EncodedList:   "",
		StatusPurpose: "revocation",
	}

	_, err := CheckBitStatus(0, subject, "revocation")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

// ---------------------------------------------------------------------------
// Mock resolver for negative cases
// ---------------------------------------------------------------------------

type failResolver struct{}

func (failResolver) ResolveDocument(_ context.Context, _ string) (*verificationmethod.DIDDocument, error) {
	return nil, fmt.Errorf("resolver: DID not found")
}

func TestVerifyAndCheckStatus_UnresolvableIssuer_Refused(t *testing.T) {
	priv, _ := testKeyPair(t)
	encoded := buildLegacyEncodedList(t, 128, []int{})

	vc := signStatusListCredential(t, priv, testIssuerDID, "revocation", encoded)
	server := serveStatusList(t, vc)

	client := NewClient(WithResolver(failResolver{}))
	err := client.VerifyAndCheckStatus(server.URL, 0, "revocation", testIssuerDID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "proof")
}

// ---------------------------------------------------------------------------
// Object-form issuer (item 1)
// ---------------------------------------------------------------------------

func TestVerifyAndCheckStatus_ObjectFormIssuer(t *testing.T) {
	priv, resolver := testKeyPair(t)
	encoded := buildLegacyEncodedList(t, 128, []int{})

	// Build a status list credential with object-form issuer.
	now := time.Now().UTC()
	vc := jsonmap.JSONMap{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential", "BitstringStatusListCredential"},
		"id":       testIssuerDID + "/status/0",
		"issuer": map[string]interface{}{
			"id":   testIssuerDID,
			"name": "Test Issuer Organization",
		},
		"validFrom":  now.Add(-1 * time.Hour).Format(time.RFC3339),
		"validUntil": now.Add(24 * time.Hour).Format(time.RFC3339),
		"credentialSubject": map[string]interface{}{
			"type":          "BitstringStatusList",
			"statusPurpose": "revocation",
			"encodedList":   encoded,
		},
	}

	sp, err := signer.NewP256Provider(priv)
	require.NoError(t, err)
	err = vc.AddECDSAProof(sp, testVMID, "assertionMethod")
	require.NoError(t, err)

	server := serveStatusList(t, map[string]interface{}(vc))

	client := NewClient(WithResolver(resolver))
	err = client.VerifyAndCheckStatus(server.URL, 0, "revocation", testIssuerDID)
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Nil resolver error (item 2)
// ---------------------------------------------------------------------------

func TestVerifyAndCheckStatus_NilResolver_Error(t *testing.T) {
	// Create a client without a resolver.
	client := NewClient()
	err := client.VerifyAndCheckStatus("http://example.com/status", 0, "revocation", testIssuerDID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "resolver is required")
}

// ---------------------------------------------------------------------------
// Purpose-aware error message (item 4)
// ---------------------------------------------------------------------------

func TestVerifyAndCheckStatus_PurposeAwareMessage_Suspension(t *testing.T) {
	priv, resolver := testKeyPair(t)
	encoded := buildW3CEncodedList(t, []int{0})

	vc := signStatusListCredential(t, priv, testIssuerDID, "suspension", encoded)
	server := serveStatusList(t, vc)

	client := NewClient(WithResolver(resolver))
	err := client.VerifyAndCheckStatus(server.URL, 0, "suspension", testIssuerDID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credential status is set for purpose")
	assert.Contains(t, err.Error(), "suspension")
	// Must NOT say "revoked" for a suspension purpose.
	assert.NotContains(t, err.Error(), "revoked")
}

// ---------------------------------------------------------------------------
// Size limits (item 5)
// ---------------------------------------------------------------------------

func TestDecompressFromBase64URLWithLimit(t *testing.T) {
	// A normal small payload should decompress fine.
	small := make([]byte, 100)
	small[0] = 0x42
	encoded, err := util.CompressToBase64URL(small)
	require.NoError(t, err)

	out, err := decompressFromBase64URLWithLimit(encoded, 1024)
	require.NoError(t, err)
	assert.Equal(t, small, out)

	// A payload that decompresses beyond the limit should fail.
	big := make([]byte, 2048)
	encoded, err = util.CompressToBase64URL(big)
	require.NoError(t, err)

	_, err = decompressFromBase64URLWithLimit(encoded, 1024)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}

func TestVerifyAndCheckStatus_ResponseBodyLimit(t *testing.T) {
	// Serve a response larger than maxResponseBodySize. The explicit size
	// check should reject it before JSON parsing.
	_, resolver := testKeyPair(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write a valid JSON prefix followed by padding that exceeds 16 MiB.
		_, _ = w.Write([]byte(`{"data":`))
		padding := make([]byte, 1024)
		for i := range padding {
			padding[i] = ' '
		}
		// Write ~17 MiB of spaces.
		for i := 0; i < 17*1024; i++ {
			_, _ = w.Write(padding)
		}
		_, _ = w.Write([]byte(`{}}`))
	}))
	t.Cleanup(server.Close)

	client := NewClient(WithResolver(resolver))
	err := client.VerifyAndCheckStatus(server.URL, 0, "revocation", testIssuerDID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status list response exceeds")
}
