package schema

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
	SchemaLoader     *CredentialSchemaLoader
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

// defaultDocumentLoader is a shared caching loader to prevent repeated fetches across function calls.
var defaultDocumentLoader ld.DocumentLoader

func init() {
	innerLoader := ld.NewDefaultDocumentLoader(nil) // HTTP client
	defaultDocumentLoader = ld.NewCachingDocumentLoader(innerLoader)

}

// CanonicalizeDocument canonicalizes a document using JSON-LD processing.
func CanonicalizeDocument(doc map[string]interface{}) ([]byte, error) {
	if doc == nil {
		return nil, fmt.Errorf("failed to canonicalize document: document is nil")
	}
	processor := ld.NewJsonLdProcessor()
	jsonldOptions := ld.NewJsonLdOptions("")
	jsonldOptions.Format = "application/n-quads"
	jsonldOptions.Algorithm = ld.AlgorithmURDNA2015
	// Use CachingDocumentLoader to cache remote contexts
	jsonldOptions.DocumentLoader = defaultDocumentLoader

	standardizedDoc, err := standardizeToJSONLD(doc)
	if err != nil {
		return nil, fmt.Errorf("failed to standardize to JSON-LD: %w", err)
	}

	canonicalized, err := processor.Normalize(standardizedDoc, jsonldOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to normalize document: %w", err)
	}

	return []byte(canonicalized.(string)), nil
}

// ComputeDigest computes the SHA-256 digest of the input data.
func ComputeDigest(data []byte) ([]byte, error) {
	if data == nil {
		return nil, fmt.Errorf("failed to compute digest: input data is nil")
	}
	hash := sha256.Sum256(data)
	return hash[:], nil
}

// standardizeToJSONLD converts a map to a JSON-LD-compatible format.
func standardizeToJSONLD(input map[string]interface{}) (map[string]interface{}, error) {
	if input == nil {
		return nil, fmt.Errorf("failed to standardize to JSON-LD: input is nil")
	}
	result := make(map[string]interface{})
	for key, value := range input {
		result[key] = convertToJSONLDCompatible(value)
	}
	return result, nil
}

// convertToJSONLDCompatible converts a value to a JSON-LD-compatible format, forcing numeric values to strings.
func convertToJSONLDCompatible(value interface{}) interface{} {
	switch v := value.(type) {
	case string:
		return v // Strings are returned as-is
	case map[string]interface{}:
		result := make(map[string]interface{})
		for key, val := range v {
			result[key] = convertToJSONLDCompatible(val)
		}
		return result
	case []string:
		result := make([]interface{}, len(v))
		for i, val := range v {
			result[i] = convertToJSONLDCompatible(val)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, val := range v {
			result[i] = convertToJSONLDCompatible(val)
		}
		return result
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return map[string]interface{}{
			"@value": fmt.Sprintf("%v", v),
			"@type":  "http://www.w3.org/2001/XMLSchema#string",
		}
	case bool:
		return map[string]interface{}{
			"@value": fmt.Sprintf("%v", v),
			"@type":  "http://www.w3.org/2001/XMLSchema#boolean",
		}
	case nil:
		return nil
	default:
		// Fallback to string for any other types
		return map[string]interface{}{
			"@value": fmt.Sprintf("%v", v),
			"@type":  "http://www.w3.org/2001/XMLSchema#string",
		}
	}
}
