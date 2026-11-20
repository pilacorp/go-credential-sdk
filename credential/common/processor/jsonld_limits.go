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
	// including inline @context subtrees. Every array element and every
	// object member (key-value pair) at any depth counts as one value.
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
	// What is counted: every @context in the document (at any depth, not
	// just the top-level one) is loaded through the caching document loader
	// (the same cache verification itself uses) to learn which terms have a
	// scoped @context in their definition. All reachable contexts are
	// walked: scoped contexts, nested scoped contexts, and contexts
	// introduced via @import. The document body (everything except @context)
	// is then scanned, and every use of such a term as a property name and
	// every use as a type value is counted once. Type aliases — context
	// terms that expand to @type (e.g. "kieu": "@type") — are recognised:
	// values under an alias key count the same as under @type / type.
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

// countValues recursively counts JSON values in v. Every object member
// (key-value pair) counts as 1, and every array element counts as 1, at any
// depth. Inline @context subtrees are counted because json-gold processes them
// (they define terms, trigger @import loads, and scoped-context re-parsing).
// The count is O(document size).
func countValues(v interface{}) int {
	switch t := v.(type) {
	case map[string]interface{}:
		total := 0
		for _, val := range t {
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

// collectScopedTerms returns the set of term names that carry a scoped
// @context anywhere in the given context chain, and whether any context URL
// could not be resolved. Used directly by unit tests.
func collectScopedTerms(ctx interface{}) (map[string]bool, bool) {
	c := &scopedTermCollector{
		result:      make(map[string]bool),
		typeAliases: make(map[string]bool),
		seen:        make(map[string]bool),
		budget:      newContextBudget(),
	}
	c.walk(ctx)
	return c.result, c.hasUnresolved
}

// checkScopedContextUses identifies terms with scoped @context from every
// @context in the document (not just the top-level one — credentialSubject,
// holder, and embedded VCs may carry inline contexts that define additional
// scoped terms). It then counts how many times those terms appear as property
// names or as type values in the document body. Type aliases (context terms
// that expand to @type) are recognised too: a key that is an alias is treated
// the same as @type / type.
//
// Context URLs are loaded through a contextBudget, which shares the same
// per-operation limits (30 s deadline, 4 MB bytes, 1024 loads) as the
// verification loader.
func checkScopedContextUses(doc map[string]interface{}, limit int) error {
	c := &scopedTermCollector{
		result:      make(map[string]bool),
		typeAliases: make(map[string]bool),
		seen:        make(map[string]bool),
		budget:      newContextBudget(),
	}

	// Walk every @context in the document, at any depth.
	walkDocContexts(doc, func(ctx interface{}) {
		c.walk(ctx)
	})

	if c.hasUnresolved {
		return fmt.Errorf("%w", ErrUnresolvedContext)
	}

	if len(c.result) == 0 {
		return nil
	}
	count := countScopedUses(doc, c.result, c.typeAliases)
	if count > limit {
		return fmt.Errorf("%w: %d uses, limit is %d",
			ErrTooManyScopedContextUses, count, limit)
	}
	return nil
}

// walkDocContexts visits every @context value at any depth in the document
// tree and calls fn for each. It does not recurse into the @context values
// themselves (those are context definitions, not document nodes).
func walkDocContexts(v interface{}, fn func(ctx interface{})) {
	switch t := v.(type) {
	case map[string]interface{}:
		if ctx, ok := t["@context"]; ok {
			fn(ctx)
		}
		for key, val := range t {
			if key == "@context" {
				continue
			}
			walkDocContexts(val, fn)
		}
	case []interface{}:
		for _, item := range t {
			walkDocContexts(item, fn)
		}
	}
}

type scopedTermCollector struct {
	result        map[string]bool // terms that carry a scoped @context
	typeAliases   map[string]bool // terms that expand to @type
	seen          map[string]bool // context URLs already visited
	hasUnresolved bool
	budget        *contextBudget
}

func (c *scopedTermCollector) walk(ctx interface{}) {
	switch v := ctx.(type) {
	case string:
		if c.seen[v] {
			return
		}
		c.seen[v] = true
		parsed := c.loadContext(v)
		if parsed == nil {
			c.hasUnresolved = true
			return
		}
		c.walk(parsed)
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
			switch d := def.(type) {
			case string:
				// A term defined as the string "@type" is a type alias.
				if d == "@type" {
					c.typeAliases[key] = true
				}
			case map[string]interface{}:
				// {"@id": "@type"} is also a type alias.
				if id, ok := d["@id"]; ok {
					if idStr, ok := id.(string); ok && idStr == "@type" {
						c.typeAliases[key] = true
					}
				}
				if scoped, ok := d["@context"]; ok && scoped != nil {
					c.result[key] = true
					c.walk(scoped)
				}
			}
		}
	}
}

// loadContext loads a context URL through the contextBudget, which enforces
// the same per-operation limits as the verification loader (30 s deadline,
// 4 MB bytes, 1024 loads). Bundled contexts are served from embedded bytes.
func (c *scopedTermCollector) loadContext(url string) interface{} {
	// Bundled context: parse from embedded bytes.
	if data, ok := wellKnownContexts[url]; ok {
		var doc map[string]interface{}
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil
		}
		return doc["@context"]
	}
	// Remote context: use the budgeted loader.
	doc, err := c.budget.LoadDocument(url)
	if err != nil {
		return nil
	}
	if m, ok := doc.Document.(map[string]interface{}); ok {
		return m["@context"]
	}
	return nil
}

// countScopedUses counts uses of scoped terms as property names and as type
// values in v, excluding @context keys. typeAliases are keys that expand to
// @type in the active context, so their values are type values too.
func countScopedUses(v interface{}, scoped, typeAliases map[string]bool) int {
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
			if key == "@type" || key == "type" || typeAliases[key] {
				total += countTypeValues(val, scoped)
			}
			total += countScopedUses(val, scoped, typeAliases)
		}
	case []interface{}:
		for _, item := range t {
			total += countScopedUses(item, scoped, typeAliases)
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
