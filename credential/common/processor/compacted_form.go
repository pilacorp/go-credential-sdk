package processor

import (
	"errors"
	"fmt"

	"github.com/pilacorp/json-gold/ld"
)

// ErrNotCompactedForm signals that a verified document's JSON does not say, for
// a property the SDK reads by name, what its signed JSON-LD meaning says. A
// holder rewrote it into an equivalent form (an alias, a full IRI, @nest) that
// the proof still accepts but that hides or changes the property.
var ErrNotCompactedForm = errors.New("document is not in compacted form")

// CompactedForms expands body (a document without its proof) once and compacts
// it against its own @context and against the known context: the entries of
// its @context that are contexts this SDK bundles.
//
// The known form is the recompaction of VC Data Integrity 1.0 §4.6 step 3.1;
// §4.6 leaves the set of known contexts to the application, and this SDK takes
// its bundled contexts that the document names. The holder writes the
// document's @context, so a compaction against it says whatever an alias in it
// makes it say. An inline context or one this SDK does not bundle is left
// out, so terms it defines come out of the known form as full or compact IRIs,
// and a bundled term an alias renamed comes back under its name.
//
// Expansion drops terms no context defines (JSON-LD 1.1 API §5.1.2 step 13.3):
// a raw value under such a term then has nothing to match and the document is
// refused. It applies the same inline-context limit as ExpandJSONLD.
func CompactedForms(body map[string]interface{}) (own, known map[string]interface{}, err error) {
	ctx, ok := body["@context"]
	if !ok || ctx == nil {
		return nil, nil, fmt.Errorf("%w: no @context", ErrNotCompactedForm)
	}
	knownCtx := knownContext(ctx)
	if len(knownCtx) == 0 {
		return nil, nil, fmt.Errorf("%w: @context names no context this SDK knows", ErrNotCompactedForm)
	}
	expanded, err := expandPermissive(body)
	if err != nil {
		return nil, nil, fmt.Errorf("compact document form: %w", err)
	}
	if known, err = compactFrom(expanded, knownCtx); err != nil {
		return nil, nil, err
	}
	// A @context of bundled contexts only is its own known context: the two
	// compactions would be the same.
	if len(knownCtx) == len(contextEntries(ctx)) {
		return known, known, nil
	}
	if own, err = compactFrom(expanded, ctx); err != nil {
		return nil, nil, err
	}
	return own, known, nil
}

func compactFrom(expanded []interface{}, ctx interface{}) (map[string]interface{}, error) {
	out, err := CompactJSONLD(expanded, ctx)
	if err != nil {
		return nil, fmt.Errorf("compact document form: %w", err)
	}
	return out, nil
}

// contextEntries returns the entries of a @context value.
func contextEntries(ctx interface{}) []interface{} {
	switch c := ctx.(type) {
	case []interface{}:
		return c
	case nil:
		return nil
	default:
		return []interface{}{c}
	}
}

// knownContext returns the string entries of ctx that are bundled contexts, in
// their order. The examples context is among them: it maps every term through
// @vocab to https://www.w3.org/ns/credentials/examples#, and issuers write
// their claims under it.
func knownContext(ctx interface{}) []interface{} {
	var out []interface{}
	for _, e := range contextEntries(ctx) {
		if url, ok := e.(string); ok {
			if _, bundled := wellKnownContexts[url]; bundled {
				out = append(out, url)
			}
		}
	}
	return out
}

// expandPermissive expands a JSON-LD document without SafeMode, under the
// same inline-context limit ExpandJSONLD applies, since this runs on every
// verified document whatever proof suite verified it.
func expandPermissive(doc map[string]interface{}) (result []interface{}, err error) {
	defer finishJSONLD(&err, "expand")
	std, err := standardizeForCanonicalization(doc)
	if err != nil {
		return nil, fmt.Errorf("expand: standardize: %w", err)
	}
	opts := ld.NewJsonLdOptions("")
	opts.Algorithm = ld.AlgorithmURDNA2015
	opts.DocumentLoader = newContextBudget()
	if err := limitInlineContexts(opts, std); err != nil {
		return nil, fmt.Errorf("expand: %w", err)
	}
	out, err := ld.NewJsonLdProcessor().Expand(std, opts)
	if err != nil {
		return nil, fmt.Errorf("expand: %w", err)
	}
	return out, nil
}
