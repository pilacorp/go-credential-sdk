package internal

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/piprate/json-gold/ld"

	"credential-sdk/vc/options"
)

const (
	format             = "application/n-quads"
	defaultAlgorithm   = "URDNA2015"
	handleNormalizeErr = "error while parsing N-Quads; invalid quad. line:"
)

// ErrInvalidRDFFound is returned when normalized view contains invalid RDF.
var ErrInvalidRDFFound = errors.New("invalid JSON-LD context")

// Processor is JSON-LD processor for Verifiable Credentials.
type Processor struct {
	algorithm string
}

// NewProcessor returns new JSON-LD processor.
func NewProcessor(algorithm string) *Processor {
	if algorithm == "" {
		return Default()
	}
	return &Processor{algorithm}
}

// Default returns new JSON-LD processor with default RDF dataset algorithm.
func Default() *Processor {
	return &Processor{defaultAlgorithm}
}

// prepareProcessorOpts prepares processor options from given ProcessorOpt arguments.
func prepareProcessorOpts(opts []options.ProcessorOpt) *options.ProcessorOptions {
	procOpts := &options.ProcessorOptions{
		DocumentLoader: ld.NewDefaultDocumentLoader(nil),
		Algorithm:      defaultAlgorithm,
	}
	for _, opt := range opts {
		opt(procOpts)
	}
	return procOpts
}

// CanonicalizeDocument canonicalizes a JSON-LD document.
func CanonicalizeDocument(doc map[string]interface{}, opts ...options.ProcessorOpt) ([]byte, error) {
	procOptions := prepareProcessorOpts(opts)

	processor := NewProcessor(procOptions.Algorithm)
	return processor.GetCanonicalDocument(doc, opts...)
}

// GetCanonicalDocument returns canonized document of given JSON-LD.
func (p *Processor) GetCanonicalDocument(doc map[string]interface{}, opts ...options.ProcessorOpt) ([]byte, error) {
	procOptions := prepareProcessorOpts(opts)

	ldOptions := ld.NewJsonLdOptions("")
	ldOptions.ProcessingMode = ld.JsonLd_1_1
	ldOptions.Algorithm = p.algorithm
	ldOptions.Format = format
	ldOptions.ProduceGeneralizedRdf = true
	ldOptions.DocumentLoader = procOptions.DocumentLoader

	if len(procOptions.ExternalContexts) > 0 {
		doc["@context"] = AppendExternalContexts(doc["@context"], procOptions.ExternalContexts...)
	}

	proc := ld.NewJsonLdProcessor()

	view, err := proc.Normalize(doc, ldOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to normalize JSON-LD document: %w", err)
	}

	result, ok := view.(string)
	if !ok {
		return nil, errors.New("failed to normalize JSON-LD document, invalid view")
	}

	result, err = p.removeMatchingInvalidRDFs(result, procOptions)
	if err != nil {
		return nil, err
	}

	return []byte(result), nil
}

// AppendExternalContexts appends external context(s) to the JSON-LD context.
func AppendExternalContexts(context interface{}, extraContexts ...string) []interface{} {
	var contexts []interface{}
	switch c := context.(type) {
	case string:
		contexts = append(contexts, c)
	case []interface{}:
		contexts = append(contexts, c...)
	}
	for i := range extraContexts {
		contexts = append(contexts, extraContexts[i])
	}
	return contexts
}

// removeMatchingInvalidRDFs validates normalized view to find any invalid RDF and
// returns filtered view after removing all invalid data.
func (p *Processor) removeMatchingInvalidRDFs(view string, opts *options.ProcessorOptions) (string, error) {
	if !opts.RemoveInvalidRDF && !opts.ValidateRDF {
		return view, nil
	}

	views := strings.Split(view, "\n")
	var filteredViews []string
	var foundInvalid bool

	for _, v := range views {
		_, err := ld.ParseNQuads(v)
		if err != nil {
			if !strings.Contains(err.Error(), handleNormalizeErr) {
				return "", err
			}
			foundInvalid = true
			continue
		}
		filteredViews = append(filteredViews, v)
	}

	if !foundInvalid {
		return view, nil
	} else if opts.ValidateRDF {
		return "", ErrInvalidRDFFound
	}

	filteredView := strings.Join(filteredViews, "\n")
	return p.normalizeFilteredDataset(filteredView)
}

// normalizeFilteredDataset recreates JSON-LD from RDF view and
// returns normalized RDF dataset from recreated JSON-LD.
func (p *Processor) normalizeFilteredDataset(view string) (string, error) {
	ldOptions := ld.NewJsonLdOptions("")
	ldOptions.ProcessingMode = ld.JsonLd_1_1
	ldOptions.Algorithm = p.algorithm
	ldOptions.Format = format

	proc := ld.NewJsonLdProcessor()
	filteredJSONLd, err := proc.FromRDF(view, ldOptions)
	if err != nil {
		return "", err
	}

	result, err := proc.Normalize(filteredJSONLd, ldOptions)
	if err != nil {
		return "", err
	}

	return result.(string), nil
}

// ComputeDigest computes the SHA-256 digest of the given data.
func ComputeDigest(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	return hash[:], nil
}
