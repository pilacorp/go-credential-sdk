package processor

import (
	"crypto/sha256"
	_ "embed"
	"encoding/json"
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

//go:embed w3c.credential.v2.json
var w3cCredentialV2Context []byte

//go:embed w3c.credential.examples.v2.json
var w3cCredentialExamplesV2Context []byte

//go:embed w3c.credential.v1.json
var w3cCredentialV1Context []byte

//go:embed w3c.security.data-integrity.v2.json
var w3cSecurityDataIntegrityV2Context []byte

// Well-known W3C context URLs mapped to their embedded JSON bytes. These are
// frozen, immutable published contexts, so serving them from embedded copies is
// byte-for-byte equivalent to fetching them — it only removes the network
// dependency (and avoids w3.org rate-limiting / 403s).
var wellKnownContexts = map[string][]byte{
	"https://www.w3.org/2018/credentials/v1":               w3cCredentialV1Context,
	"https://www.w3.org/2018/credentials/v1.jsonld":        w3cCredentialV1Context,
	"https://www.w3.org/ns/credentials/v2":                 w3cCredentialV2Context,
	"https://www.w3.org/ns/credentials/v2.jsonld":          w3cCredentialV2Context,
	"https://www.w3.org/ns/credentials/examples/v2":        w3cCredentialExamplesV2Context,
	"https://www.w3.org/ns/credentials/examples/v2.jsonld": w3cCredentialExamplesV2Context,
	"https://w3id.org/security/data-integrity/v2":          w3cSecurityDataIntegrityV2Context,
}

// localContextDocumentLoader wraps a default loader and checks for local context files first
type localContextDocumentLoader struct {
	fallback ld.DocumentLoader
}

// LoadDocument implements ld.DocumentLoader interface
func (l *localContextDocumentLoader) LoadDocument(url string) (*ld.RemoteDocument, error) {
	// Check if this is a well-known context that should be loaded locally
	if doc := loadLocalContext(url); doc != nil {
		return doc, nil
	}

	// Fallback to default loader (network)
	return l.fallback.LoadDocument(url)
}

// loadLocalContext attempts to load a context from embedded data.
func loadLocalContext(url string) *ld.RemoteDocument {
	data, ok := wellKnownContexts[url]
	if !ok || len(data) == 0 {
		return nil
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}

	return &ld.RemoteDocument{
		DocumentURL: url,
		Document:    doc,
	}
}

// defaultDocumentLoader is a shared caching loader to prevent repeated fetches across function calls.
var defaultDocumentLoader ld.DocumentLoader

func init() {
	innerLoader := ld.NewDefaultDocumentLoader(nil) // HTTP client
	// Cache only network fetches. Bundled local contexts are re-parsed fresh on
	// every call (loadLocalContext json-unmarshals a new object each time) so
	// json-gold can never mutate a shared cached context — that sharing caused
	// intermittent "@protected ... not bool" panics once concurrency increased.
	cachedNetwork := ld.NewCachingDocumentLoader(innerLoader)
	defaultDocumentLoader = &localContextDocumentLoader{fallback: cachedNetwork}
}

// recoverJSONLD converts a panic from the json-gold library (e.g. its unchecked
// `@protected.(bool)` assertion on a malformed @context) into an error, so
// adversarial input cannot crash the process. A well-formed document never
// panics here, so this is a pure safety net: it does not change the result for
// any valid document.
func recoverJSONLD(err *error, op string) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("%s: malformed JSON-LD input: %v", op, r)
	}
}

// CanonicalizeDocument canonicalizes a document using JSON-LD processing.
func CanonicalizeDocument(doc map[string]interface{}) (out []byte, err error) {
	if doc == nil {
		return nil, fmt.Errorf("failed to canonicalize document: document is nil")
	}
	defer recoverJSONLD(&err, "canonicalize document")
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

// standardizeForCanonicalization deep-copies a JSON document while preserving
// native JSON types (numbers stay numeric, booleans stay boolean). It lets
// json-gold assign the correct XSD datatypes per the JSON-LD 1.1 number rules
// (no fractional part -> xsd:integer, otherwise xsd:double) so canonical
// N-Quads match other conformant processors (e.g. digitalbazaar/rdf-canonize).
//
// The W3C-conformant ecdsa-sd-2023 path uses this. The legacy
// CanonicalizeDocument keeps standardizeToJSONLD (which coerces numbers to
// xsd:string) unchanged, so already-issued ecdsa-rdfc-2019 / secp256k1
// credentials verify exactly as before.
func standardizeForCanonicalization(input map[string]interface{}) (map[string]interface{}, error) {
	if input == nil {
		return nil, fmt.Errorf("failed to standardize to JSON-LD: input is nil")
	}
	out, _ := preserveNativeTypes(input).(map[string]interface{})
	return out, nil
}

func preserveNativeTypes(value interface{}) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for k, val := range v {
			out[k] = preserveNativeTypes(val)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(v))
		for i, val := range v {
			out[i] = preserveNativeTypes(val)
		}
		return out
	default:
		// numbers (float64/json.Number), bool, string, nil pass through as-is
		return v
	}
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
