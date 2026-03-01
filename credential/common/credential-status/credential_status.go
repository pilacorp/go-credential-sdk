package credentialstatus

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/util"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

var defaultHTTPClient = &http.Client{
	Timeout:   10 * time.Second,
	Transport: otelhttp.NewTransport(http.DefaultTransport),
}

// FetchAndCheckRevocation fetches the status list credential from the given
// statusListCredential URL and checks whether the credential at the given
// position is revoked.
func FetchAndCheckRevocation(statusListCredentialURL string, position int) (bool, error) {
	resp, err := FetchStatusListCredential(statusListCredentialURL)
	if err != nil {
		return false, err
	}

	return IsRevoked(position, resp.Data.CredentialSubject)
}

// FetchStatusListCredential fetches and parses the status list credential
// located at the given statusListCredential URL.
func FetchStatusListCredential(statusListCredentialURL string) (*StatusListCredentialResponse, error) {
	if statusListCredentialURL == "" {
		return nil, fmt.Errorf("statusListCredential URL is empty")
	}

	resp, err := defaultHTTPClient.Get(statusListCredentialURL)
	if err != nil {
		return nil, fmt.Errorf("failed to call status list credential endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status list credential API returned non-200 status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read status list credential response body: %w", err)
	}

	var result StatusListCredentialResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal status list credential JSON: %w", err)
	}

	return &result, nil
}

// IsRevoked checks whether a credential is revoked based on the encoded list
// and a given status position (index in the bitstring).
func IsRevoked(position int, subject StatusListCredentialSubject) (bool, error) {
	// Only handle revocation lists here.
	if subject.StatusPurpose != "revocation" {
		return false, nil
	}

	// Decode bitstring from encodedList.
	byteString, err := util.DecompressFromBase64URL(subject.EncodedList)
	if err != nil {
		return false, err
	}

	byteIndex := position / 8
	bitIndex := position % 8
	isRevoked := (byteString[byteIndex]>>bitIndex)&1 == 1

	return isRevoked, nil
}
