// Package subdid creates Sub-DIDs for a client: GenerateSubDID builds and signs
// the document, and DeriveSubDIDKey derives the Sub-DID key from the root key
// as Vault does. It also holds the rules and Merkle tree the platform checks
// them with.
package subdid

import (
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/pilacorp/go-credential-sdk/didv2/did"
	"github.com/pilacorp/go-credential-sdk/didv2/signer"
)

// SubDIDResult is what RegisterSubDID takes: Document, Type and Signature.
type SubDIDResult struct {
	DID       string
	Document  *did.DIDDocument
	Type      string
	Signature string
}

// SubDIDOption configures GenerateSubDID.
type SubDIDOption func(*subDIDConfig)

type subDIDConfig struct {
	extraVMs []did.VerificationMethodSpec
}

// WithSubDIDVerificationMethods adds secondary verification methods.
func WithSubDIDVerificationMethods(specs ...did.VerificationMethodSpec) SubDIDOption {
	return func(c *subDIDConfig) { c.extraVMs = append(c.extraVMs, specs...) }
}

// GenerateSubDID builds the document of the Sub-DID whose #key-1 is
// subPublicKeyHex, under rootDID. rootSigner, the root DID's primary key, signs
// the root consent; subSigner, the Sub-DID key, signs the docHash. subID, type
// and rootConsent in metadata are always set by GenerateSubDID.
func GenerateSubDID(
	rootDID string,
	subID string,
	subPublicKeyHex string,
	didType did.DIDType,
	metadata map[string]any,
	rootSigner signer.SignerProvider,
	subSigner signer.SignerProvider,
	options ...SubDIDOption,
) (*SubDIDResult, error) {
	if rootSigner == nil || subSigner == nil {
		return nil, errors.New("subdid: root signer and Sub-DID signer are required")
	}
	if didType.String() == "unknown" {
		return nil, fmt.Errorf("subdid: unknown DID type %d", didType)
	}

	var cfg subDIDConfig
	for _, opt := range options {
		opt(&cfg)
	}

	if _, err := ParseSubID(subID); err != nil {
		return nil, err
	}

	pubBytes, err := hex.DecodeString(strings.TrimPrefix(subPublicKeyHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("subdid: Sub-DID public key: %w", err)
	}
	pub, err := crypto.DecompressPubkey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("subdid: Sub-DID public key: %w", err)
	}
	subDID, err := SubDIDFor(rootDID, pub)
	if err != nil {
		return nil, err
	}

	consent, err := signRootConsent(subDID, rootSigner)
	if err != nil {
		return nil, err
	}

	docMetadata := maps.Clone(metadata)
	if docMetadata == nil {
		docMetadata = make(map[string]any)
	}
	docMetadata[subIDKey] = subID

	doc := did.GenerateDIDDocument(subPublicKeyHex, subDID, "", rootDID, didType, docMetadata, cfg.extraVMs...)
	if doc == nil {
		return nil, errors.New("subdid: build document: invalid verification methods")
	}
	if err := setRootConsent(doc, consent); err != nil {
		return nil, err
	}
	if err := ValidateSubDID(doc, rootDID); err != nil {
		return nil, err
	}
	if err := VerifyRootConsent(doc, rootDID); err != nil {
		return nil, fmt.Errorf("subdid: the root signer does not hold the primary key of %s: %w", rootDID, err)
	}

	sig, err := signDocument(doc, subSigner)
	if err != nil {
		return nil, err
	}
	if err := VerifyDocumentSignature(doc, sig); err != nil {
		return nil, fmt.Errorf("subdid: the Sub-DID signer does not hold the key of %s: %w", subDID, err)
	}

	return &SubDIDResult{
		DID:       subDID,
		Document:  doc,
		Type:      didType.String(),
		Signature: "0x" + hex.EncodeToString(sig),
	}, nil
}
