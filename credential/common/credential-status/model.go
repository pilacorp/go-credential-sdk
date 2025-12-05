package credentialstatus

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
	Issuer            string                      `json:"issuer"`
	Proof             map[string]interface{}      `json:"proof"`
	Type              []string                    `json:"type"`
	ValidFrom         string                      `json:"validFrom"`
	ValidUntil        string                      `json:"validUntil"`
}

// StatusListCredentialSubject represents the credentialSubject of the
// status list credential, including the encoded bitstring list.
type StatusListCredentialSubject struct {
	EncodedList   string `json:"encodedList"`
	ID            string `json:"id"`
	StatusPurpose string `json:"statusPurpose"`
	Type          string `json:"type"`
}
