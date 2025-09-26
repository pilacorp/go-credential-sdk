package provider

import (
	"github.com/pilacorp/go-credential-sdk/credential/common/model"
)

// Provider defines the interface for external services like DID resolution,
// schema fetching, and cryptographic operations. This allows for custom
// implementations to be injected into the credential logic.
type Provider interface {
	// DIDResolver resolves a DID string into a DID Document.
	// The result is returned as an interface{} to remain flexible.
	DIDResolver(did string) (*model.DIDDocument, error)

	// SchemaResolver fetches a schema from a given URL.
	// The result is returned as an interface{} to accommodate different schema formats.
	SchemaResolver(url string) (*model.SchemaDocument, error)

	// SignProof creates a cryptographic signature for the given input data.
	// It takes the signing input, a private key, and the verification method URI.
	SignProof(signingInput []byte, signer string) (*model.Proof, error)
}
