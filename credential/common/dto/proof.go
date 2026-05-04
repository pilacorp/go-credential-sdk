package dto

// Proof represents a Linked Data Proof for a Verifiable Credential.
type Proof struct {
	Type               string   `json:"type"`
	Created            string   `json:"created"`
	VerificationMethod string   `json:"verificationMethod"`
	ProofPurpose       string   `json:"proofPurpose"`
	ProofValue         string   `json:"proofValue,omitempty"`
	JWS                string   `json:"jws,omitempty"`
	Disclosures        []string `json:"disclosures,omitempty"`
	Cryptosuite        string   `json:"cryptosuite,omitempty"`
	Challenge          string   `json:"challenge,omitempty"`
	Domain             string   `json:"domain,omitempty"`
}
