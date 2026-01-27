package didv2

import (
	"github.com/pilacorp/go-credential-sdk/didv2/did"
	"github.com/pilacorp/go-credential-sdk/didv2/didcontract"
)

// DIDTxResult represents a DIDTxResult and its associated data.
type DIDTxResult struct {
	DID         string                   `json:"did"`
	Secret      *Secret                  `json:"secret"`
	Document    *did.DIDDocument         `json:"document"`
	Transaction *didcontract.Transaction `json:"transaction"`
}

// Secret represents the secret of a DID.
type Secret struct {
	PrivateKeyHex string `json:"privateKeyHex"`
}
