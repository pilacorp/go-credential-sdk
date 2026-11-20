package credentialstatus

import (
	"encoding/json"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
)

// StatusListCredentialResponse represents the top-level response wrapper:
type StatusListCredentialResponse struct {
	Data StatusListCredential `json:"data"`
}

// StatusListCredential models the Verifiable Credential returned by the
// status list endpoint. Only fields that are clearly needed are typed;
// the rest can be extended later as required.
type StatusListCredential struct {
	Context           []string                    `json:"@context"`
	CredentialSubject StatusListCredentialSubject `json:"credentialSubject"`
	ID                string                      `json:"id"`
	Issuer            IssuerField                 `json:"issuer"`
	Proof             map[string]interface{}      `json:"proof"`
	Type              []string                    `json:"type"`
	ValidFrom         string                      `json:"validFrom"`
	ValidUntil        string                      `json:"validUntil"`
}

// IssuerField represents the issuer of a Verifiable Credential. Per the VC
// Data Model it may be a plain DID string ("did:example:issuer") or an object
// with an id field ({"id": "did:example:issuer", "name": "..."}).
type IssuerField struct {
	DID string
}

// UnmarshalJSON accepts both a plain string and an object with an id field.
func (f *IssuerField) UnmarshalJSON(data []byte) error {
	// Try string first.
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		f.DID = s
		return nil
	}
	// Fall back to object form via DIDFromField.
	var raw interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	did, _ := jsonmap.DIDFromField(raw)
	f.DID = did
	return nil
}

// MarshalJSON writes the issuer as a plain string when non-empty.
func (f IssuerField) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.DID)
}

// StatusListCredentialSubject represents the credentialSubject of the
// status list credential, including the encoded bitstring list.
type StatusListCredentialSubject struct {
	EncodedList   string `json:"encodedList"`
	ID            string `json:"id"`
	StatusPurpose string `json:"statusPurpose"`
	Type          string `json:"type"`
}
