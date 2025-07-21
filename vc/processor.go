package vc

import (
	"crypto/sha256"
	"fmt"

	"github.com/piprate/json-gold/ld"
)

// ProcessorOpt represents an option for JSON-LD processing.
type ProcessorOpt func(*ProcessorOptions)

// ProcessorOptions holds configuration for JSON-LD processing.
type ProcessorOptions struct {
	documentLoader   ld.DocumentLoader
	algorithm        string
	removeInvalidRDF bool
	schemaLoader     *CredentialSchemaLoader
}

// WithDocumentLoader sets the document loader for JSON-LD processing.
func WithDocumentLoader(loader ld.DocumentLoader) ProcessorOpt {
	return func(p *ProcessorOptions) {
		p.documentLoader = loader
	}
}

// WithAlgorithm sets the canonicalization algorithm.
func WithAlgorithm(alg string) ProcessorOpt {
	return func(p *ProcessorOptions) {
		p.algorithm = alg
	}
}

// WithRemoveAllInvalidRDF enables removal of invalid RDF during processing.
func WithRemoveAllInvalidRDF() ProcessorOpt {
	return func(p *ProcessorOptions) {
		p.removeInvalidRDF = true
	}
}

// CanonicalizeDocument canonicalizes a document using JSON-LD processing.
func CanonicalizeDocument(doc interface{}, opts ...ProcessorOpt) ([]byte, error) {
	processor := &ld.JsonLdProcessor{}
	options := &ProcessorOptions{
		algorithm: "URDNA2015",
	}
	for _, opt := range opts {
		opt(options)
	}

	jsonldOptions := &ld.JsonLdOptions{
		Format:                "application/n-quads",
		Algorithm:             options.algorithm,
		DocumentLoader:        options.documentLoader,
		UseNativeTypes:        true,
		ProduceGeneralizedRdf: !options.removeInvalidRDF,
	}

	canonicalized, err := processor.Normalize(doc, jsonldOptions)
	if err != nil {
		return nil, fmt.Errorf("normalize document: %w", err)
	}

	return []byte(canonicalized.(string)), nil
}

// ComputeDigest computes the SHA-256 digest of the input data.
func ComputeDigest(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	return hash[:], nil
}
