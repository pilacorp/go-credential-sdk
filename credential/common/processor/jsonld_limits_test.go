package processor

import (
	"errors"
	"testing"
)

func TestCheckJSONLDLimits_MaxValues(t *testing.T) {
	// 3 members, one of them an array of 2: 5 values.
	doc := map[string]interface{}{"@context": "https://www.w3.org/ns/credentials/v2", "a": "x", "b": []interface{}{"y", "z"}}
	if err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 5}); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	if err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 4}); !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("over the limit: err = %v, want ErrTooManyValues", err)
	}
}

// scopedDoc uses the property-scoped term p on n objects. json-gold applies
// the document's context once, p's once for the key and once per object.
func scopedDoc(n int, key string) map[string]interface{} {
	items := make([]interface{}, n)
	for i := range items {
		items[i] = map[string]interface{}{"q": "v"}
	}
	return map[string]interface{}{
		"@context": map[string]interface{}{
			"@vocab": "https://ex.org/",
			"p":      map[string]interface{}{"@id": "https://ex.org/p", "@context": map[string]interface{}{"q": "https://ex.org/q"}},
		},
		key: items,
	}
}

// The limit counts every application of a scoped context, not every key: one
// key over many objects is refused.
func TestMaxScopedContextUses_ObjectsUnderOneKey(t *testing.T) {
	limits := JSONLDLimits{MaxScopedContextUses: 10}
	if _, err := CanonicalizeNQuads(scopedDoc(8, "p"), limits); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	if _, err := CanonicalizeNQuads(scopedDoc(9, "p"), limits); !errors.Is(err, ErrTooManyScopedContextUses) {
		t.Fatalf("over the limit: err = %v, want ErrTooManyScopedContextUses", err)
	}
	if _, err := CanonicalizeNQuads(scopedDoc(10, "p")); err != nil {
		t.Fatalf("no limit: %v", err)
	}
}

// Compaction selects the scoped term for a key written as its IRI, and
// applies its context too.
func TestMaxScopedContextUses_CompactionOfFullIRIKey(t *testing.T) {
	doc := scopedDoc(20, "https://ex.org/p")
	doc["@context"] = []interface{}{"https://www.w3.org/ns/credentials/v2", doc["@context"]}
	_, _, err := CompactedForms(doc, JSONLDLimits{MaxScopedContextUses: 10})
	if !errors.Is(err, ErrTooManyScopedContextUses) {
		t.Fatalf("err = %v, want ErrTooManyScopedContextUses", err)
	}
}

// Every entry point that takes the limits enforces MaxValues on its input,
// and refuses a second limits value rather than dropping it.
func TestEntryPointLimits(t *testing.T) {
	doc := scopedDoc(10, "p")
	if _, err := CanonicalizeNQuads(doc, JSONLDLimits{MaxValues: 5}); !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("MaxValues: err = %v, want ErrTooManyValues", err)
	}
	if _, err := ExpandJSONLD(doc, JSONLDLimits{}, JSONLDLimits{MaxValues: 5}); err == nil {
		t.Fatal("two limits values were accepted")
	}
}
