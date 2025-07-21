package options

import "github.com/piprate/json-gold/ld"

// ProcessorOptions holds options for canonicalization of JSON-LD docs.
type ProcessorOptions struct {
	RemoveInvalidRDF bool
	ValidateRDF      bool
	DocumentLoader   ld.DocumentLoader
	ExternalContexts []string
	Algorithm        string
}

// ProcessorOpt are the options for JSON-LD operations.
type ProcessorOpt func(opts *ProcessorOptions)

// WithRemoveAllInvalidRDF option for removing all invalid RDF dataset from normalized document.
func WithRemoveAllInvalidRDF() ProcessorOpt {
	return func(opts *ProcessorOptions) {
		opts.RemoveInvalidRDF = true
	}
}

// WithValidateRDF option validates result view and fails if any invalid RDF dataset found.
func WithValidateRDF() ProcessorOpt {
	return func(opts *ProcessorOptions) {
		opts.ValidateRDF = true
	}
}

// WithDocumentLoader option is for passing custom JSON-LD document loader.
func WithDocumentLoader(loader ld.DocumentLoader) ProcessorOpt {
	return func(opts *ProcessorOptions) {
		opts.DocumentLoader = loader
	}
}

// WithExternalContext option is for definition of external context when doing JSON-LD operations.
func WithExternalContext(context ...string) ProcessorOpt {
	return func(opts *ProcessorOptions) {
		opts.ExternalContexts = context
	}
}

// WithAlgorithm option specifies the JSON-LD normalization algorithm.
func WithAlgorithm(algorithm string) ProcessorOpt {
	return func(opts *ProcessorOptions) {
		opts.Algorithm = algorithm
	}
}
