package processor

import (
	"errors"
	"fmt"

	"github.com/pilacorp/json-gold/ld"
)

// JSONLDLimits bounds the JSON-LD work a document can cause when it is
// verified. A zero or negative field sets no limit, and the zero value
// changes nothing. The processor functions that take it enforce both fields,
// MaxValues on their input before json-gold runs and MaxScopedContextUses
// through json-gold, except CompactJSONLD, whose expanded input MaxValues
// does not measure.
//
// The SDK sets no default: only a consumer knows the largest credential it
// issues, and a limit below that would stop its own credentials verifying. A
// consumer that verifies documents from untrusted callers sets both fields
// from that credential, with headroom.
type JSONLDLimits struct {
	// MaxValues is the number of JSON values the document may hold: every
	// object member and every array element at any depth, inline @context
	// bodies included. Nothing json-gold merges onto one property can give it
	// more values than the document holds, so this bounds the per-property
	// comparison of Node Map Generation (JSON-LD 1.1 Processing Algorithms and
	// API, W3C REC 2020-07-16, §7.2.2 steps 4.1.2, 6.5.2, 6.6.2.2 and 6.7), which is
	// quadratic in the values of one property. It is checked on the JSON
	// before json-gold runs.
	MaxValues int

	// MaxScopedContextUses is how many times one json-gold operation may
	// apply a term's scoped context or a node's own @context: §5.1.2 steps 8,
	// 9, 11.2 and 13.8.3.2 and §6.1.2 steps 6.1 and 11.1, and @nest as the
	// JSON-LD 1.2 draft's §5.1.2 step 14.2.2 does, which json-gold follows.
	// json-gold runs the Context Processing algorithm on that context each
	// time: at least once per object under a
	// property-scoped term and once per node of a type-scoped type, so the
	// work is about this count times the size of the context. json-gold
	// counts as it goes and stops at the limit. One verification runs a few
	// operations: the proof's canonicalization and the compacted-form check.
	MaxScopedContextUses int
}

// ErrTooManyValues is returned when the document holds more values than
// JSONLDLimits.MaxValues.
var ErrTooManyValues = errors.New("document exceeds the total values limit")

// ErrTooManyScopedContextUses is returned when a JSON-LD operation would apply
// scoped contexts more times than JSONLDLimits.MaxScopedContextUses.
var ErrTooManyScopedContextUses = errors.New("document exceeds the scoped-context-uses limit")

// CheckJSONLDLimits refuses doc when it holds more values than
// limits.MaxValues. It walks the JSON only, so a caller can run it before any
// other work; MaxScopedContextUses needs json-gold and is not checked here.
func CheckJSONLDLimits(doc map[string]interface{}, limits JSONLDLimits) error {
	return checkValues(doc, limits)
}

func checkValues(doc interface{}, limits JSONLDLimits) error {
	if limits.MaxValues <= 0 {
		return nil
	}
	if count := countValues(doc); count > limits.MaxValues {
		return fmt.Errorf("%w: %d values, limit is %d", ErrTooManyValues, count, limits.MaxValues)
	}
	return nil
}

// countValues counts every object member and every array element in v, at
// any depth.
func countValues(v interface{}) int {
	total := 0
	switch t := v.(type) {
	case map[string]interface{}:
		for _, val := range t {
			total += 1 + countValues(val)
		}
	case []interface{}:
		for _, item := range t {
			total += 1 + countValues(item)
		}
	}
	return total
}

// apply passes the limits json-gold enforces to opts.
func (l JSONLDLimits) apply(opts *ld.JsonLdOptions) {
	if l.MaxScopedContextUses > 0 {
		opts.MaxScopedContexts = l.MaxScopedContextUses
	}
}

// limitsFor returns the optional limits argument of an entry point after
// checking input against MaxValues. More than one limits value is refused
// rather than dropped.
func limitsFor(input interface{}, limits []JSONLDLimits) (JSONLDLimits, error) {
	switch len(limits) {
	case 0:
		return JSONLDLimits{}, nil
	case 1:
		return limits[0], checkValues(input, limits[0])
	}
	return JSONLDLimits{}, fmt.Errorf("processor: pass at most one JSONLDLimits, got %d", len(limits))
}

// markScopedContextOverflow makes json-gold's ScopedContextOverflow match
// ErrTooManyScopedContextUses.
func markScopedContextOverflow(err error) error {
	var ldErr *ld.JsonLdError
	if err == nil || errors.Is(err, ErrTooManyScopedContextUses) ||
		!errors.As(err, &ldErr) || ldErr.Code != ld.ScopedContextOverflow {
		return err
	}
	return fmt.Errorf("%w: %w", ErrTooManyScopedContextUses, err)
}
