package credentialstatus

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/util"
	"github.com/stretchr/testify/assert"
)

func TestIsRevoked(t *testing.T) {
	// Bit pattern: 0x01 -> [1,0,0,0,0,0,0,0] (LSB-first)
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
			Issuer:     "did:example:issuer",
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
