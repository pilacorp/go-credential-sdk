package processor

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// JSONLDLimits configures pre-verification limits on the JSON-LD processing
// work a document can cause. Setting a field to zero (the default) means no
// limit for that dimension. The zero value of the struct imposes no limit and
// gives exactly today's behavior.
//
// Limits are opt-in: a consumer that exposes verify to untrusted callers sets
// them from the largest credential it issues. No existing API is changed.
type JSONLDLimits struct {
	// MaxValues is the total number of JSON values the document may contain,
	// excluding the @context subtree. Every array element and every object
	// member (key-value pair) at any depth counts as one value.
	//
	// This bound is sound by construction: any merge json-gold performs
	// during expansion (IRI aliases, @nest, same-@id, scoped-context
	// remapping, container maps) can only put at most MaxValues values on a
	// single expanded property, so the quadratic cost of blank-node linking
	// in ToRDF is bounded by MaxValues².
	//
	// Set this to the total value count of the largest credential the
	// consumer issues, with headroom.
	MaxValues int

	// MaxScopedContextUses is the maximum total number of times terms that
	// carry a scoped @context may appear as property names or @type / type
	// values in the document. json-gold re-parses a term's scoped context
	// on every use, so processing time is roughly proportional to this count
	// times the size of the scoped context.
	//
	// What is counted: the document's top-level @context chain is loaded
	// through the caching document loader (the same cache verification itself
	// uses) to learn which terms have a scoped @context in their definition.
	// All reachable contexts are walked: scoped contexts, nested scoped
	// contexts, and contexts introduced via @import. The document body
	// (everything except @context) is then scanned, and every use of such a
	// term as a property name and every use as a @type / type value is
	// counted once.
	//
	// If any context URL cannot be loaded (or exceeds the remote-load
	// budget), the document is refused with ErrUnresolvedContext.
	MaxScopedContextUses int
}

// IsSet reports whether any limit is configured.
func (l JSONLDLimits) IsSet() bool {
	return l.MaxValues > 0 || l.MaxScopedContextUses > 0
}

// ErrTooManyValues is returned when the document's total value count exceeds
// JSONLDLimits.MaxValues.
var ErrTooManyValues = errors.New("document exceeds the total values limit")

// ErrTooManyScopedContextUses is returned when scoped-context terms appear
// more times in the document than JSONLDLimits.MaxScopedContextUses allows.
var ErrTooManyScopedContextUses = errors.New("document exceeds the scoped-context-uses limit")

// ErrUnresolvedContext is returned when limits are set but the pre-scan cannot
// resolve one or more context URLs. Without a fully resolved context chain the
// scoped-context scan cannot reliably discover all scoped terms. Refusing is
// sound: json-gold needs the context too, so a truly unavailable context would
// fail verification anyway.
var ErrUnresolvedContext = errors.New("cannot verify limits: a context URL could not be resolved")

// CheckJSONLDLimits pre-scans doc and returns an error if it exceeds any
// configured limit. It runs before json-gold processes the document, so an
// over-limit document is refused without the expensive work.
func CheckJSONLDLimits(doc map[string]interface{}, limits JSONLDLimits) error {
	if limits.MaxValues > 0 {
		if err := checkTotalValues(doc, limits.MaxValues); err != nil {
			return err
		}
	}
	if limits.MaxScopedContextUses > 0 {
		if err := checkScopedContextUses(doc, limits.MaxScopedContextUses); err != nil {
			return err
		}
	}
	return nil
}

// ===== (a) total value count =====

// checkTotalValues counts all JSON values in the document body (excluding
// @context subtrees) and returns ErrTooManyValues if the count exceeds limit.
func checkTotalValues(doc map[string]interface{}, limit int) error {
	count := countValues(doc)
	if count > limit {
		return fmt.Errorf("%w: %d values, limit is %d",
			ErrTooManyValues, count, limit)
	}
	return nil
}

// countValues recursively counts JSON values in v, excluding @context
// subtrees. Each object member (key-value pair) counts as 1, and each array
// element counts as 1, at every depth. The count is O(document size).
func countValues(v interface{}) int {
	switch t := v.(type) {
	case map[string]interface{}:
		total := 0
		for key, val := range t {
			if key == "@context" {
				continue
			}
			total++ // count this member
			total += countValues(val)
		}
		return total
	case []interface{}:
		total := 0
		for _, item := range t {
			total++ // count this element
			total += countValues(item)
		}
		return total
	}
	return 0
}

// ===== (b) scoped context uses =====

// maxResolverRemoteLoads bounds the remote context URLs the scoped-term
// collector tries to load. A document that references more non-bundled URLs
// than this triggers ErrUnresolvedContext. Real credentials reference 1-5
// context URLs; this limit protects the pre-scan from pathological documents
// with hundreds of context URLs that would each cause a network round-trip.
const maxResolverRemoteLoads = 32

// checkScopedContextUses identifies terms with scoped @context from the
// document's top-level @context chain (and all reachable scoped, nested, and
// @import'ed contexts), then counts how many times those terms appear as
// property names or @type / type values in the document body.
func checkScopedContextUses(doc map[string]interface{}, limit int) error {
	scoped, hasUnresolved := collectScopedTerms(doc["@context"])

	// Refuse when any context is unresolved. An unresolvable context could
	// define scoped terms the scan cannot see, causing an under-count.
	if hasUnresolved {
		return fmt.Errorf("%w", ErrUnresolvedContext)
	}

	if len(scoped) == 0 {
		return nil
	}
	count := countScopedUses(doc, scoped)
	if count > limit {
		return fmt.Errorf("%w: %d uses, limit is %d",
			ErrTooManyScopedContextUses, count, limit)
	}
	return nil
}

// collectScopedTerms returns the set of term names that carry a scoped
// @context anywhere in the given context chain, and whether any context URL
// could not be resolved. It loads remote contexts through the caching
// document loader (same cache verification itself uses), with a remote-load
// budget of maxResolverRemoteLoads. It recurses into scoped contexts and
// handles @import so that terms defined only inside a scoped or imported
// context are found too.
func collectScopedTerms(ctx interface{}) (map[string]bool, bool) {
	c := &scopedTermCollector{
		result: make(map[string]bool),
		seen:   make(map[string]bool),
	}
	c.walk(ctx)
	return c.result, c.hasUnresolved
}

type scopedTermCollector struct {
	result        map[string]bool
	seen          map[string]bool
	hasUnresolved bool
	remoteLoads   int
}

func (c *scopedTermCollector) walk(ctx interface{}) {
	switch v := ctx.(type) {
	case string:
		if c.seen[v] {
			return
		}
		c.seen[v] = true
		if _, bundled := wellKnownContexts[v]; !bundled {
			c.remoteLoads++
			if c.remoteLoads > maxResolverRemoteLoads {
				c.hasUnresolved = true
				return
			}
		}
		doc := loadContextForScan(v)
		if doc == nil {
			c.hasUnresolved = true
			return
		}
		c.walk(doc)
	case []interface{}:
		for _, item := range v {
			c.walk(item)
		}
	case map[string]interface{}:
		// Handle @import: load the imported context and merge its terms.
		if importURL, ok := v["@import"]; ok {
			if s, ok := importURL.(string); ok {
				c.walk(s)
			}
		}
		for key, def := range v {
			if strings.HasPrefix(key, "@") {
				continue
			}
			defMap, ok := def.(map[string]interface{})
			if !ok {
				continue
			}
			if scoped, ok := defMap["@context"]; ok && scoped != nil {
				c.result[key] = true
				// Recursively find scoped terms inside this scoped context.
				c.walk(scoped)
			}
		}
	}
}

// loadContextForScan loads a context URL for the pre-scan. Bundled contexts
// are loaded from embedded bytes; remote contexts go through the caching
// document loader.
func loadContextForScan(url string) interface{} {
	// Bundled context: parse from embedded bytes.
	if data, ok := wellKnownContexts[url]; ok {
		var doc map[string]interface{}
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil
		}
		return doc["@context"]
	}
	// Remote context: use the caching loader.
	doc, err := defaultDocumentLoader.fallback.Load().LoadDocument(url)
	if err != nil {
		return nil
	}
	if m, ok := doc.Document.(map[string]interface{}); ok {
		return m["@context"]
	}
	return nil
}

// countScopedUses counts uses of scoped terms as property names and as
// @type / type values in v, excluding @context keys.
func countScopedUses(v interface{}, scoped map[string]bool) int {
	total := 0
	switch t := v.(type) {
	case map[string]interface{}:
		for key, val := range t {
			if key == "@context" {
				continue
			}
			// Property name that is a scoped term.
			if scoped[key] {
				total++
			}
			// Type values that are scoped terms (type-scoped contexts).
			if key == "@type" || key == "type" {
				total += countTypeValues(val, scoped)
			}
			total += countScopedUses(val, scoped)
		}
	case []interface{}:
		for _, item := range t {
			total += countScopedUses(item, scoped)
		}
	}
	return total
}

// countTypeValues counts how many values in a type field match scoped terms.
func countTypeValues(v interface{}, scoped map[string]bool) int {
	count := 0
	switch t := v.(type) {
	case string:
		if scoped[t] {
			count++
		}
	case []interface{}:
		for _, item := range t {
			if s, ok := item.(string); ok && scoped[s] {
				count++
			}
		}
	}
	return count
}
