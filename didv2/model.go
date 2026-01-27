package didv2

import (
	"github.com/pilacorp/go-credential-sdk/didv2/did"
	"github.com/pilacorp/go-credential-sdk/didv2/didcontract"
)

// DIDTxResult represents the complete result of a DID generation operation.
//
// It contains all the necessary information for DID issuance:
//   - The DID identifier (e.g., "did:nda:0x...")
//   - The DID Document (W3C compliant)
//   - The raw transaction ready for blockchain submission
//   - The secret (private key) if a new key pair was generated
type DIDTxResult struct {
	// DID is the full DID identifier string (e.g., "did:nda:0x1234...").
	DID string `json:"did"`
	// Secret contains the private key if a new key pair was generated.
	// This is only populated when using GenerateDID().
	Secret *Secret `json:"secret"`
	// Document is the W3C-compliant DID Document containing verification methods
	// and metadata.
	Document *did.DIDDocument `json:"document"`
	// Transaction is the signed raw transaction ready for blockchain submission.
	// The SDK does not submit this transaction; it must be submitted separately.
	Transaction *didcontract.Transaction `json:"transaction"`
}

// Secret represents the private key of a DID.
//
// This is only included in DIDTxResult when a new key pair is automatically
// generated (e.g., via GenerateDID()). Store this securely as it proves
// ownership of the DID.
type Secret struct {
	// PrivateKeyHex is the private key in hexadecimal format (with "0x" prefix).
	PrivateKeyHex string `json:"privateKeyHex"`
}
