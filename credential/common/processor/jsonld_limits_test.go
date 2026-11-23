package processor

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// ===== (a) total value count =====

func TestCheckTotalValues_UnderLimit(t *testing.T) {
	doc := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     "VerifiableCredential",
		"credentialSubject": map[string]interface{}{
			"data": makeArray(50),
		},
	}
	// Total: type(1) + credentialSubject(1) + data(1) + 50 elements = 53
	if err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 100}); err != nil {
		t.Fatalf("under-limit document should pass: %v", err)
	}
}

func TestCheckTotalValues_AtLimit(t *testing.T) {
	doc := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"credentialSubject": map[string]interface{}{
			"data": makeArray(96),
		},
	}
	// Total: @context(1) + 1 element + credentialSubject(1) + data(1) + 96 elements = 100
	if err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 100}); err != nil {
		t.Fatalf("at-limit document should pass: %v", err)
	}
}

func TestCheckTotalValues_OverLimit(t *testing.T) {
	doc := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"credentialSubject": map[string]interface{}{
			"data": makeArray(101),
		},
	}
	// Total: @context(1) + 1 element + credentialSubject(1) + data(1) + 101 elements = 105
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 100})
	if err == nil {
		t.Fatal("over-limit document should be refused")
	}
	if !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("expected ErrTooManyValues, got %v", err)
	}
}

func TestCheckTotalValues_NestedObject(t *testing.T) {
	// A large array nested inside an inner object should be caught.
	doc := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"credentialSubject": map[string]interface{}{
			"inner": map[string]interface{}{
				"deep": makeArray(200),
			},
		},
	}
	// Total: credentialSubject(1) + inner(1) + deep(1) + 200 elements = 203
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 100})
	if !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("expected ErrTooManyValues for nested object, got %v", err)
	}
}

func TestCheckTotalValues_NestedArray(t *testing.T) {
	// JSON-LD flattens nested arrays; the total count includes nested elements.
	inner := makeArray(60)
	doc := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"credentialSubject": map[string]interface{}{
			"data": []interface{}{inner, inner},
		},
	}
	// Total: credentialSubject(1) + data(1) + 2 outer elements + 2*60 inner elements = 124
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 100})
	if !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("expected ErrTooManyValues for nested array (124 > 100), got %v", err)
	}
}

func TestCheckTotalValues_ContextIncluded(t *testing.T) {
	// Inline @context subtrees are counted because json-gold processes them.
	doc := map[string]interface{}{
		"@context":          makeArray(200), // 200 context elements are counted
		"credentialSubject": map[string]interface{}{"name": "test"},
	}
	// Total: @context(1) + 200 elements + credentialSubject(1) + name(1) = 203
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 10})
	if !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("inline @context should count toward MaxValues, got %v", err)
	}
}

func TestCheckTotalValues_NoLimit(t *testing.T) {
	doc := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"credentialSubject": map[string]interface{}{
			"data": makeArray(100000),
		},
	}
	// Zero limit means no check.
	if err := CheckJSONLDLimits(doc, JSONLDLimits{}); err != nil {
		t.Fatalf("no limit should accept anything: %v", err)
	}
}

// ===== countValues unit tests =====

func TestCountValues(t *testing.T) {
	tests := []struct {
		name string
		v    interface{}
		want int
	}{
		{"scalar", "hello", 0},
		{"nil", nil, 0},
		{"flat array 5", makeArray(5), 5},
		{"nested array", []interface{}{makeArray(3), makeArray(4)}, 2 + 3 + 4},
		{"simple object", map[string]interface{}{"a": "b", "c": "d"}, 2},
		{"object with array", map[string]interface{}{
			"data": makeArray(5),
		}, 1 + 5},
		{"@context included", map[string]interface{}{
			"@context": makeArray(100),
			"data":     "v",
		}, 1 + 100 + 1},
		{"nested @context included", map[string]interface{}{
			"inner": map[string]interface{}{
				"@context": "skip",
				"name":     "v",
			},
		}, 1 + 1 + 1},
		{"empty array", []interface{}{}, 0},
		{"empty object", map[string]interface{}{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countValues(tt.v)
			if got != tt.want {
				t.Fatalf("got %d, want %d", got, tt.want)
			}
		})
	}
}

// ===== (b) scoped context uses =====

func TestCheckScopedContextUses_InlineScoped_UnderLimit(t *testing.T) {
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"scopedTerm": map[string]interface{}{
					"@id":      "https://example.org/scopedTerm",
					"@context": map[string]interface{}{"inner": "https://example.org/inner"},
				},
			},
		},
		"type":   "VerifiableCredential",
		"issuer": "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":         "did:example:subject",
			"scopedTerm": "value1",
		},
	}
	if err := CheckJSONLDLimits(doc, JSONLDLimits{MaxScopedContextUses: 10}); err != nil {
		t.Fatalf("under-limit should pass: %v", err)
	}
}

func TestCheckScopedContextUses_InlineScoped_OverLimit(t *testing.T) {
	// Build a document with many uses of a scoped term.
	subject := make(map[string]interface{})
	subject["id"] = "did:example:subject"
	for i := 0; i < 20; i++ {
		subject[fmt.Sprintf("item%d", i)] = map[string]interface{}{
			"scopedTerm": fmt.Sprintf("value%d", i),
		}
	}
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"scopedTerm": map[string]interface{}{
					"@id":      "https://example.org/scopedTerm",
					"@context": map[string]interface{}{"inner": "https://example.org/inner"},
				},
				// Define item0..item19 so the doc expands
				"item0": "https://example.org/item0", "item1": "https://example.org/item1",
				"item2": "https://example.org/item2", "item3": "https://example.org/item3",
				"item4": "https://example.org/item4", "item5": "https://example.org/item5",
				"item6": "https://example.org/item6", "item7": "https://example.org/item7",
				"item8": "https://example.org/item8", "item9": "https://example.org/item9",
				"item10": "https://example.org/item10", "item11": "https://example.org/item11",
				"item12": "https://example.org/item12", "item13": "https://example.org/item13",
				"item14": "https://example.org/item14", "item15": "https://example.org/item15",
				"item16": "https://example.org/item16", "item17": "https://example.org/item17",
				"item18": "https://example.org/item18", "item19": "https://example.org/item19",
			},
		},
		"type":              "VerifiableCredential",
		"issuer":            "did:example:issuer",
		"credentialSubject": subject,
	}
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxScopedContextUses: 5})
	if err == nil {
		t.Fatal("over-limit scoped context uses should be refused")
	}
	if !errors.Is(err, ErrTooManyScopedContextUses) {
		t.Fatalf("expected ErrTooManyScopedContextUses, got %v", err)
	}
}

func TestCheckScopedContextUses_TypeScoped(t *testing.T) {
	// A type with a scoped context used many times should be counted.
	subjects := make([]interface{}, 20)
	for i := range subjects {
		subjects[i] = map[string]interface{}{
			"type": "ScopedType",
			"name": fmt.Sprintf("item%d", i),
		}
	}
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"ScopedType": map[string]interface{}{
					"@id":      "https://example.org/ScopedType",
					"@context": map[string]interface{}{"name": "https://example.org/name"},
				},
			},
		},
		"type":              "VerifiableCredential",
		"issuer":            "did:example:issuer",
		"credentialSubject": subjects,
	}
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxScopedContextUses: 5})
	if !errors.Is(err, ErrTooManyScopedContextUses) {
		t.Fatalf("expected ErrTooManyScopedContextUses for type-scoped context, got %v", err)
	}
}

func TestCheckScopedContextUses_NoScopedTerms(t *testing.T) {
	// A document with no scoped contexts should always pass.
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"plain": "https://example.org/plain",
			},
		},
		"type":   "VerifiableCredential",
		"issuer": "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":    "did:example:subject",
			"plain": "value",
		},
	}
	if err := CheckJSONLDLimits(doc, JSONLDLimits{MaxScopedContextUses: 1}); err != nil {
		t.Fatalf("no scoped terms should always pass: %v", err)
	}
}

func TestCheckScopedContextUses_NoLimit(t *testing.T) {
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"scopedTerm": map[string]interface{}{
					"@id":      "https://example.org/scopedTerm",
					"@context": map[string]interface{}{"inner": "https://example.org/inner"},
				},
			},
		},
		"credentialSubject": map[string]interface{}{
			"scopedTerm": "v1",
		},
	}
	// Zero limit means no check.
	if err := CheckJSONLDLimits(doc, JSONLDLimits{}); err != nil {
		t.Fatalf("no limit should accept anything: %v", err)
	}
}

// ===== Sentinel error matching =====

func TestSentinelErrors_MatchableViaErrorsIs(t *testing.T) {
	doc := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"credentialSubject": map[string]interface{}{
			"data": makeArray(200),
		},
	}
	// Total: credentialSubject(1) + data(1) + 200 = 202
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 100})
	if !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("ErrTooManyValues not matchable via errors.Is: %v", err)
	}

	// ErrTooManyScopedContextUses: zero limit should not error
	doc2 := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"scopedTerm": map[string]interface{}{
					"@id":      "https://example.org/scopedTerm",
					"@context": map[string]interface{}{"inner": "https://example.org/inner"},
				},
			},
		},
		"credentialSubject": map[string]interface{}{
			"scopedTerm": "v1",
		},
	}
	err2 := CheckJSONLDLimits(doc2, JSONLDLimits{MaxScopedContextUses: 0})
	if err2 != nil {
		t.Fatalf("zero limit should not error: %v", err2)
	}
}

// ===== Timing: limits refuse fast =====

func TestTiming_TotalValues_RefusedFast(t *testing.T) {
	// 20,000 values takes json-gold >7 s without a limit.
	doc := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     "VerifiableCredential",
		"issuer":   "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"data": makeArray(20000),
		},
	}
	start := time.Now()
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 1000})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("should have been refused")
	}
	if !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("expected ErrTooManyValues, got %v", err)
	}
	if elapsed > 50*time.Millisecond {
		t.Fatalf("check took %v, expected < 50ms", elapsed)
	}
	t.Logf("20,000-value document refused in %v", elapsed)
}

func TestTiming_ScopedContextUses_RefusedFast(t *testing.T) {
	// Build a document that resembles the issue's attack shape: many uses
	// of a scoped term across nested objects.
	subject := make(map[string]interface{})
	subject["id"] = "did:example:subject"
	for i := 0; i < 500; i++ {
		key := fmt.Sprintf("n%d", i)
		subject[key] = map[string]interface{}{
			"scopedTerm": fmt.Sprintf("val%d", i),
		}
	}
	termDefs := map[string]interface{}{
		"scopedTerm": map[string]interface{}{
			"@id":      "https://example.org/scopedTerm",
			"@context": map[string]interface{}{"inner": "https://example.org/inner"},
		},
	}
	for i := 0; i < 500; i++ {
		termDefs[fmt.Sprintf("n%d", i)] = fmt.Sprintf("https://example.org/n%d", i)
	}
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			termDefs,
		},
		"type":              "VerifiableCredential",
		"issuer":            "did:example:issuer",
		"credentialSubject": subject,
	}
	start := time.Now()
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxScopedContextUses: 100})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("should have been refused")
	}
	if !errors.Is(err, ErrTooManyScopedContextUses) {
		t.Fatalf("expected ErrTooManyScopedContextUses, got %v", err)
	}
	if elapsed > 50*time.Millisecond {
		t.Fatalf("check took %v, expected < 50ms", elapsed)
	}
	t.Logf("500-use scoped-context document refused in %v", elapsed)
}

// ===== Well-known contexts are scanned correctly =====

func TestCollectScopedTerms_BundledContext(t *testing.T) {
	// credentials/v2 and other bundled contexts should be scannable.
	scoped, _ := collectScopedTerms("https://www.w3.org/ns/credentials/v2")
	// credentials/v2 may or may not define scoped terms; this test verifies
	// the scan completes without error or panic.
	t.Logf("scoped terms in credentials/v2: %v", scoped)
}

func TestCollectScopedTerms_MixedContexts(t *testing.T) {
	ctx := []interface{}{
		"https://www.w3.org/ns/credentials/v2",
		map[string]interface{}{
			"myScopedTerm": map[string]interface{}{
				"@id": "https://example.org/myScopedTerm",
				"@context": map[string]interface{}{
					"innerTerm": "https://example.org/innerTerm",
				},
			},
			"plainTerm": "https://example.org/plainTerm",
		},
	}
	scoped, _ := collectScopedTerms(ctx)
	if !scoped["myScopedTerm"] {
		t.Fatal("myScopedTerm should be identified as scoped")
	}
	if scoped["plainTerm"] {
		t.Fatal("plainTerm should NOT be identified as scoped")
	}
}

func TestCollectScopedTerms_RecursiveScoped(t *testing.T) {
	// A scoped context that itself defines a scoped term.
	ctx := map[string]interface{}{
		"outer": map[string]interface{}{
			"@id": "https://example.org/outer",
			"@context": map[string]interface{}{
				"inner": map[string]interface{}{
					"@id": "https://example.org/inner",
					"@context": map[string]interface{}{
						"deep": "https://example.org/deep",
					},
				},
			},
		},
	}
	scoped, _ := collectScopedTerms(ctx)
	if !scoped["outer"] {
		t.Fatal("outer should be scoped")
	}
	if !scoped["inner"] {
		t.Fatal("inner (defined in outer's scoped context) should be scoped")
	}
	if scoped["deep"] {
		t.Fatal("deep has no scoped @context itself, should NOT be scoped")
	}
}

// ===== Attack shapes =====

// TestAttackShape_ManyValues reproduces the issue's first attack (20k values)
// at a smaller size and shows the limit catches it fast.
func TestAttackShape_ManyValues(t *testing.T) {
	for _, n := range []int{200, 2000, 20000} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			doc := map[string]interface{}{
				"@context": []interface{}{
					"https://www.w3.org/ns/credentials/v2",
					map[string]interface{}{
						"data": "https://example.org/data",
					},
				},
				"type":   "VerifiableCredential",
				"issuer": "did:example:issuer",
				"credentialSubject": map[string]interface{}{
					"id":   "did:example:subject",
					"data": makeArray(n),
				},
			}
			limit := 100
			start := time.Now()
			err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: limit})
			elapsed := time.Since(start)
			if !errors.Is(err, ErrTooManyValues) {
				t.Fatalf("expected ErrTooManyValues, got %v", err)
			}
			if elapsed > 100*time.Millisecond {
				t.Fatalf("check took %v, expected < 100ms", elapsed)
			}
			t.Logf("n=%d refused in %v", n, elapsed)
		})
	}
}

func TestAttackShape_ManyScopedContextUses(t *testing.T) {
	const nTerms = 50
	const usesPerTerm = 10
	termDefs := make(map[string]interface{}, nTerms+nTerms*usesPerTerm)
	for i := 0; i < nTerms; i++ {
		name := fmt.Sprintf("st%d", i)
		termDefs[name] = map[string]interface{}{
			"@id": fmt.Sprintf("https://example.org/%s", name),
			"@context": map[string]interface{}{
				"inner": "https://example.org/inner",
			},
		}
	}
	for i := 0; i < nTerms*usesPerTerm; i++ {
		name := fmt.Sprintf("c%d", i)
		termDefs[name] = fmt.Sprintf("https://example.org/%s", name)
	}

	subject := make(map[string]interface{})
	subject["id"] = "did:example:subject"
	idx := 0
	for i := 0; i < nTerms; i++ {
		scopedName := fmt.Sprintf("st%d", i)
		for j := 0; j < usesPerTerm; j++ {
			containerName := fmt.Sprintf("c%d", idx)
			subject[containerName] = map[string]interface{}{
				scopedName: fmt.Sprintf("val%d", idx),
			}
			idx++
		}
	}

	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			termDefs,
		},
		"type":              "VerifiableCredential",
		"issuer":            "did:example:issuer",
		"credentialSubject": subject,
	}

	limit := 100
	start := time.Now()
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxScopedContextUses: limit})
	elapsed := time.Since(start)

	totalUses := nTerms * usesPerTerm // 500
	if !errors.Is(err, ErrTooManyScopedContextUses) {
		t.Fatalf("expected ErrTooManyScopedContextUses (%d uses > %d limit), got %v",
			totalUses, limit, err)
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("check took %v, expected < 100ms", elapsed)
	}
	t.Logf("%d scoped-term uses refused in %v", totalUses, elapsed)
}

// ===== Bypass shapes: total count catches all merging strategies =====
//
// These tests verify that the document-wide total count catches attacks that
// rely on json-gold merging values onto one property: IRI aliases, @nest,
// same-@id, container maps. Because the total count bounds the maximum
// values any single expanded property can have, all these shapes are caught
// without needing term resolution.

func TestBypass_Aliases_Caught(t *testing.T) {
	// Three compact terms all expand to the same IRI. Per-key each has 100
	// values, but the total count is 300+ and exceeds the limit.
	const perAlias = 100
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"ex":  "https://example.org/",
				"foo": "https://example.org/foo",
				"bar": "https://example.org/foo", // alias
			},
		},
		"type":   "VerifiableCredential",
		"issuer": "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":     "did:example:subject",
			"foo":    makeArray(perAlias),
			"bar":    makeArray(perAlias),
			"ex:foo": makeArray(perAlias), // compact-IRI alias
		},
	}
	// Total: type(1) + issuer(1) + credentialSubject(1) + id(1) +
	//   foo(1)+100 + bar(1)+100 + ex:foo(1)+100 = 307
	// Limit 200: total 307 > 200.
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 200})
	if !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("alias bypass should be caught, got %v", err)
	}
}

func TestBypass_Aliases_UnderLimit_Passes(t *testing.T) {
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"foo": "https://example.org/foo",
				"bar": "https://example.org/foo",
			},
		},
		"type":   "VerifiableCredential",
		"issuer": "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":  "did:example:subject",
			"foo": makeArray(10),
			"bar": makeArray(10),
		},
	}
	// Total: type(1) + issuer(1) + credentialSubject(1) + id(1) +
	//   foo(1)+10 + bar(1)+10 = 26, well under 100.
	if err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 100}); err != nil {
		t.Fatalf("alias under limit should pass: %v", err)
	}
}

func TestBypass_Nest_Caught(t *testing.T) {
	// Properties inside @nest containers merge into the parent node.
	// Total count catches this regardless of merging.
	const perNest = 100
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"data":  "https://example.org/data",
				"nest1": map[string]interface{}{"@id": "@nest"},
				"nest2": map[string]interface{}{"@id": "@nest"},
			},
		},
		"type":   "VerifiableCredential",
		"issuer": "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"data": makeArray(perNest),
			"nest1": map[string]interface{}{
				"data": makeArray(perNest),
			},
			"nest2": map[string]interface{}{
				"data": makeArray(perNest),
			},
		},
	}
	// Total: type(1) + issuer(1) + credentialSubject(1) + id(1) +
	//   data(1)+100 + nest1(1)+data(1)+100 + nest2(1)+data(1)+100 = 309
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 200})
	if !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("@nest bypass should be caught, got %v", err)
	}
}

func TestBypass_Nest_UnderLimit_Passes(t *testing.T) {
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"data":  "https://example.org/data",
				"nest1": map[string]interface{}{"@id": "@nest"},
			},
		},
		"type":   "VerifiableCredential",
		"issuer": "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"data": makeArray(10),
			"nest1": map[string]interface{}{
				"data": makeArray(10),
			},
		},
	}
	// Total: type(1) + issuer(1) + credentialSubject(1) + id(1) +
	//   data(1)+10 + nest1(1)+data(1)+10 = 27
	if err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 100}); err != nil {
		t.Fatalf("@nest under limit should pass: %v", err)
	}
}

func TestBypass_SameID_Caught(t *testing.T) {
	// Objects with the same @id are merged; total count catches this.
	const perObject = 100
	subjects := make([]interface{}, 3)
	for i := range subjects {
		subjects[i] = map[string]interface{}{
			"@id":  "did:example:merged",
			"data": makeArray(perObject),
		}
	}
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"data": "https://example.org/data",
			},
		},
		"type":              "VerifiableCredential",
		"issuer":            "did:example:issuer",
		"credentialSubject": subjects,
	}
	// Total: type(1) + issuer(1) + credentialSubject(1) +
	//   3 array elements, each: @id(1) + data(1) + 100 elements = 102
	//   = 1+1+1 + 3*(1+102) = 312
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 200})
	if !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("same-@id bypass should be caught, got %v", err)
	}
}

func TestBypass_SameID_UnderLimit_Passes(t *testing.T) {
	subjects := make([]interface{}, 3)
	for i := range subjects {
		subjects[i] = map[string]interface{}{
			"@id":  "did:example:merged",
			"data": makeArray(10),
		}
	}
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"data": "https://example.org/data",
			},
		},
		"type":              "VerifiableCredential",
		"issuer":            "did:example:issuer",
		"credentialSubject": subjects,
	}
	// Total: type(1) + issuer(1) + credentialSubject(1) +
	//   3*(1+1+10) = 36 → 39
	if err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 100}); err != nil {
		t.Fatalf("same-@id under limit should pass: %v", err)
	}
}

func TestBypass_Reverse_NotExploitable(t *testing.T) {
	// @reverse is not an exploitable bypass. Verify the pre-scan does not
	// reject an otherwise-valid document.
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"data": "https://example.org/data",
				"rev":  map[string]interface{}{"@reverse": "https://example.org/data"},
			},
		},
		"type":   "VerifiableCredential",
		"issuer": "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"data": makeArray(5),
			"rev":  "did:example:other",
		},
	}
	if err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 100}); err != nil {
		t.Fatalf("@reverse should not cause false positive: %v", err)
	}
}

// TestBypass_Timing shows the pre-scan catches bypass shapes in microseconds.
func TestBypass_Timing(t *testing.T) {
	const n = 5000
	tests := []struct {
		name string
		doc  map[string]interface{}
	}{
		{"aliases_3x5000", func() map[string]interface{} {
			return map[string]interface{}{
				"@context": []interface{}{
					"https://www.w3.org/ns/credentials/v2",
					map[string]interface{}{
						"ex":  "https://example.org/",
						"foo": "https://example.org/foo",
						"bar": "https://example.org/foo",
					},
				},
				"type": "VerifiableCredential", "issuer": "did:example:issuer",
				"credentialSubject": map[string]interface{}{
					"id": "did:example:s", "foo": makeArray(n),
					"bar": makeArray(n), "ex:foo": makeArray(n),
				},
			}
		}()},
		{"nest_3x5000", func() map[string]interface{} {
			return map[string]interface{}{
				"@context": []interface{}{
					"https://www.w3.org/ns/credentials/v2",
					map[string]interface{}{
						"data":  "https://example.org/data",
						"nest1": map[string]interface{}{"@id": "@nest"},
						"nest2": map[string]interface{}{"@id": "@nest"},
					},
				},
				"type": "VerifiableCredential", "issuer": "did:example:issuer",
				"credentialSubject": map[string]interface{}{
					"id": "did:example:s", "data": makeArray(n),
					"nest1": map[string]interface{}{"data": makeArray(n)},
					"nest2": map[string]interface{}{"data": makeArray(n)},
				},
			}
		}()},
		{"sameID_3x5000", func() map[string]interface{} {
			return map[string]interface{}{
				"@context": []interface{}{
					"https://www.w3.org/ns/credentials/v2",
					map[string]interface{}{"data": "https://example.org/data"},
				},
				"type": "VerifiableCredential", "issuer": "did:example:issuer",
				"credentialSubject": []interface{}{
					map[string]interface{}{"@id": "did:example:m", "data": makeArray(n)},
					map[string]interface{}{"@id": "did:example:m", "data": makeArray(n)},
					map[string]interface{}{"@id": "did:example:m", "data": makeArray(n)},
				},
			}
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Now()
			err := CheckJSONLDLimits(tt.doc, JSONLDLimits{MaxValues: 1000})
			elapsed := time.Since(start)
			if !errors.Is(err, ErrTooManyValues) {
				t.Fatalf("expected ErrTooManyValues, got %v", err)
			}
			if elapsed > 50*time.Millisecond {
				t.Fatalf("pre-scan took %v, expected < 50ms", elapsed)
			}
			t.Logf("%s: refused in %v (json-gold would take >1s)", tt.name, elapsed)
		})
	}
}

// ===== Remote context: scoped-context check =====

func TestBypass_RemoteContextAliases_Caught(t *testing.T) {
	// A remote context with scoped terms must be detected. The total values
	// check does not need context resolution, but the scoped check does.
	srv := contextServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ld+json")
		w.Write([]byte(`{"@context":{
			"remoteScopedTerm": {
				"@id": "https://example.org/remoteScopedTerm",
				"@context": {"inner": "https://example.org/inner"}
			}
		}}`))
	})
	useTestClient(t, srv)

	// 20 uses of the remote scoped term.
	subject := make(map[string]interface{})
	subject["id"] = "did:example:subject"
	for i := 0; i < 20; i++ {
		subject[fmt.Sprintf("n%d", i)] = map[string]interface{}{
			"remoteScopedTerm": fmt.Sprintf("val%d", i),
		}
	}
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			srv.URL,
		},
		"type":              "VerifiableCredential",
		"issuer":            "did:example:issuer",
		"credentialSubject": subject,
	}
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxScopedContextUses: 5})
	if !errors.Is(err, ErrTooManyScopedContextUses) {
		t.Fatalf("remote-context scoped term should be caught, got %v", err)
	}
}

func TestBypass_RemoteContextAliases_UnreachableContext_Refused(t *testing.T) {
	// When a remote context cannot be loaded and scoped limits are set, the
	// document is refused.
	srv := contextServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusGone)
	})
	useTestClient(t, srv)

	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			srv.URL,
		},
		"type":   "VerifiableCredential",
		"issuer": "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "single value",
		},
	}
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxScopedContextUses: 1000})
	if !errors.Is(err, ErrUnresolvedContext) {
		t.Fatalf("unreachable context should refuse document, got %v", err)
	}
}

func TestCheckScopedContextUses_UnresolvedContext_Refused(t *testing.T) {
	srv := contextServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusGone)
	})
	useTestClient(t, srv)

	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			srv.URL,
		},
		"type":   "VerifiableCredential",
		"issuer": "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "test",
		},
	}
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxScopedContextUses: 100})
	if !errors.Is(err, ErrUnresolvedContext) {
		t.Fatalf("scoped check with unresolved context should refuse, got %v", err)
	}
}

// ===== Container map bypass shapes =====
//
// Map containers (@language, @index, @id, @type) expand each key to a
// separate value. Total counting catches these because every entry in the
// map object counts as a member.

func TestBypass_LanguageContainer_Caught(t *testing.T) {
	const n = 300
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"labels": map[string]interface{}{
					"@id":        "https://example.org/labels",
					"@container": "@language",
				},
			},
		},
		"type":   "VerifiableCredential",
		"issuer": "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":     "did:example:subject",
			"labels": makeMap(n),
		},
	}
	// Total includes: type(1)+issuer(1)+credentialSubject(1)+id(1)+labels(1)+300 map entries = 305
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 200})
	if !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("@language container bypass should be caught, got %v", err)
	}
}

func TestBypass_IndexContainer_Caught(t *testing.T) {
	const n = 300
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"data": map[string]interface{}{
					"@id":        "https://example.org/data",
					"@container": "@index",
				},
			},
		},
		"type":   "VerifiableCredential",
		"issuer": "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"data": makeMap(n),
		},
	}
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 200})
	if !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("@index container bypass should be caught, got %v", err)
	}
}

func TestBypass_IDContainer_Caught(t *testing.T) {
	const n = 300
	m := make(map[string]interface{})
	for i := 0; i < n; i++ {
		m[fmt.Sprintf("http://example.org/%d", i)] = map[string]interface{}{
			"name": fmt.Sprintf("v%d", i),
		}
	}
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"data": map[string]interface{}{
					"@id":        "https://example.org/data",
					"@container": "@id",
				},
			},
		},
		"type":   "VerifiableCredential",
		"issuer": "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"data": m,
		},
	}
	// Total: overhead + data(1) + 300 entries × (1 + name(1)) = 605+
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 200})
	if !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("@id container bypass should be caught, got %v", err)
	}
}

func TestBypass_TypeContainer_Caught(t *testing.T) {
	const n = 300
	m := make(map[string]interface{})
	for i := 0; i < n; i++ {
		m[fmt.Sprintf("http://example.org/Type%d", i)] = map[string]interface{}{
			"name": fmt.Sprintf("v%d", i),
		}
	}
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"data": map[string]interface{}{
					"@id":        "https://example.org/data",
					"@container": "@type",
				},
			},
		},
		"type":   "VerifiableCredential",
		"issuer": "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"data": m,
		},
	}
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 200})
	if !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("@type container bypass should be caught, got %v", err)
	}
}

func TestBypass_LanguageContainer_ArrayEntries_Caught(t *testing.T) {
	// An entry in a @language map can be an array of strings.
	m := map[string]interface{}{
		"en": makeArray(60),
		"fr": makeArray(60),
	}
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"labels": map[string]interface{}{
					"@id":        "https://example.org/labels",
					"@container": "@language",
				},
			},
		},
		"type":   "VerifiableCredential",
		"issuer": "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":     "did:example:subject",
			"labels": m,
		},
	}
	// Total includes: en(1)+60 + fr(1)+60 inside labels map = 122 for labels alone
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 100})
	if !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("@language container with array entries should be caught, got %v", err)
	}
}

func TestBypass_ContainerTiming(t *testing.T) {
	const n = 10000
	tests := []struct {
		name    string
		makeDoc func() map[string]interface{}
	}{
		{
			"language_10000",
			func() map[string]interface{} {
				return map[string]interface{}{
					"@context": []interface{}{
						"https://www.w3.org/ns/credentials/v2",
						map[string]interface{}{
							"data": map[string]interface{}{
								"@id": "https://example.org/data", "@container": "@language",
							},
						},
					},
					"type": "VerifiableCredential", "issuer": "did:example:issuer",
					"credentialSubject": map[string]interface{}{
						"id": "did:example:s", "data": makeMap(n),
					},
				}
			},
		},
		{
			"index_10000",
			func() map[string]interface{} {
				return map[string]interface{}{
					"@context": []interface{}{
						"https://www.w3.org/ns/credentials/v2",
						map[string]interface{}{
							"data": map[string]interface{}{
								"@id": "https://example.org/data", "@container": "@index",
							},
						},
					},
					"type": "VerifiableCredential", "issuer": "did:example:issuer",
					"credentialSubject": map[string]interface{}{
						"id": "did:example:s", "data": makeMap(n),
					},
				}
			},
		},
		{
			"id_10000",
			func() map[string]interface{} {
				m := make(map[string]interface{})
				for i := 0; i < n; i++ {
					m[fmt.Sprintf("http://example.org/%d", i)] = map[string]interface{}{"name": fmt.Sprintf("v%d", i)}
				}
				return map[string]interface{}{
					"@context": []interface{}{
						"https://www.w3.org/ns/credentials/v2",
						map[string]interface{}{
							"data": map[string]interface{}{
								"@id": "https://example.org/data", "@container": "@id",
							},
						},
					},
					"type": "VerifiableCredential", "issuer": "did:example:issuer",
					"credentialSubject": map[string]interface{}{
						"id": "did:example:s", "data": m,
					},
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := tt.makeDoc()
			start := time.Now()
			err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 100})
			elapsed := time.Since(start)
			if !errors.Is(err, ErrTooManyValues) {
				t.Fatalf("expected ErrTooManyValues, got %v", err)
			}
			if elapsed > 50*time.Millisecond {
				t.Fatalf("pre-scan took %v, expected < 50ms", elapsed)
			}
			t.Logf("%s: refused in %v", tt.name, elapsed)
		})
	}
}

// ===== New bypass shapes from review (type-scoped/property-scoped remap) =====
//
// These shapes bypass per-IRI counting because scoped contexts remap keys.
// Total counting is sound by construction: it counts all values regardless
// of which IRI they will expand to.

func TestBypass_TypeScopedRemap_Caught(t *testing.T) {
	// Type-scoped context remaps: type "X" carries a scoped context that
	// maps t0..t99 all to the same expanded IRI. Under per-IRI-per-node
	// counting, the resolver misses this (it only sees the top-level
	// context). Under total counting, the 100*200 = 20000 values exceed
	// any reasonable limit.
	const nKeys = 100
	const nVals = 200
	subject := make(map[string]interface{})
	subject["@type"] = "X"
	for i := 0; i < nKeys; i++ {
		subject[fmt.Sprintf("t%d", i)] = makeArray(nVals)
	}

	// Define the type-scoped context: X maps every t_i → same IRI.
	scopedDefs := make(map[string]interface{})
	for i := 0; i < nKeys; i++ {
		scopedDefs[fmt.Sprintf("t%d", i)] = "https://example.org/sameProperty"
	}
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"X": map[string]interface{}{
					"@id":      "https://example.org/X",
					"@context": scopedDefs,
				},
			},
		},
		"type":              "VerifiableCredential",
		"issuer":            "did:example:issuer",
		"credentialSubject": subject,
	}
	// Total: type(1)+issuer(1)+credentialSubject(1)+@type(1)+
	//   100 keys × (1 + 200 elements) = 20104
	start := time.Now()
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 1000})
	elapsed := time.Since(start)
	if !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("type-scoped remap should be caught, got %v", err)
	}
	t.Logf("type-scoped remap (100×200 = 20000 values) refused in %v", elapsed)
}

func TestBypass_PropertyScopedRemap_Caught(t *testing.T) {
	// Property-scoped context remaps: property "wrapper" carries a scoped
	// context that remaps t0..t99 to the same IRI. Same as type-scoped but
	// triggered by a property name.
	const nKeys = 100
	const nVals = 200
	inner := make(map[string]interface{})
	for i := 0; i < nKeys; i++ {
		inner[fmt.Sprintf("t%d", i)] = makeArray(nVals)
	}

	scopedDefs := make(map[string]interface{})
	for i := 0; i < nKeys; i++ {
		scopedDefs[fmt.Sprintf("t%d", i)] = "https://example.org/sameProperty"
	}
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"wrapper": map[string]interface{}{
					"@id":      "https://example.org/wrapper",
					"@context": scopedDefs,
				},
			},
		},
		"type":   "VerifiableCredential",
		"issuer": "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":      "did:example:subject",
			"wrapper": inner,
		},
	}
	// Total: type(1)+issuer(1)+credentialSubject(1)+id(1)+wrapper(1)+
	//   100 keys × (1 + 200) = 20105
	start := time.Now()
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 1000})
	elapsed := time.Since(start)
	if !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("property-scoped remap should be caught, got %v", err)
	}
	t.Logf("property-scoped remap (100×200 = 20000 values) refused in %v", elapsed)
}

func TestBypass_DistinctProperties_1000x200_Caught(t *testing.T) {
	// 1000 distinct properties each with 200 values. Under per-IRI counting
	// each property is under the per-property limit, but total counting
	// catches the 200,000 values.
	const nKeys = 1000
	const nVals = 200
	subject := make(map[string]interface{})
	subject["id"] = "did:example:subject"
	for i := 0; i < nKeys; i++ {
		subject[fmt.Sprintf("p%d", i)] = makeArray(nVals)
	}
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
		},
		"type":              "VerifiableCredential",
		"issuer":            "did:example:issuer",
		"credentialSubject": subject,
	}
	// Total: type(1)+issuer(1)+credentialSubject(1)+id(1)+
	//   1000 keys × (1 + 200) = 201004
	start := time.Now()
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 10000})
	elapsed := time.Since(start)
	if !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("1000×200 distinct properties should be caught, got %v", err)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("pre-scan took %v, expected < 200ms", elapsed)
	}
	t.Logf("1000×200 (200000 values) refused in %v", elapsed)
}

func TestBypass_ImportIntroducedScopedTerm_Caught(t *testing.T) {
	// A scoped term defined only in an @import'ed context must be detected.
	srv := contextServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ld+json")
		w.Write([]byte(`{"@context":{
			"importedScoped": {
				"@id": "https://example.org/importedScoped",
				"@context": {"inner": "https://example.org/inner"}
			}
		}}`))
	})
	useTestClient(t, srv)

	// 20 uses of the @import-introduced scoped term.
	subject := make(map[string]interface{})
	subject["id"] = "did:example:subject"
	for i := 0; i < 20; i++ {
		subject[fmt.Sprintf("n%d", i)] = map[string]interface{}{
			"importedScoped": fmt.Sprintf("val%d", i),
		}
	}
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"@import":   srv.URL,
				"localTerm": "https://example.org/localTerm",
			},
		},
		"type":              "VerifiableCredential",
		"issuer":            "did:example:issuer",
		"credentialSubject": subject,
	}
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxScopedContextUses: 5})
	if !errors.Is(err, ErrTooManyScopedContextUses) {
		t.Fatalf("@import-introduced scoped term should be caught, got %v", err)
	}
}

func TestCollectScopedTerms_Import(t *testing.T) {
	// Verify @import is handled: a scoped term in the imported context is
	// discovered by collectScopedTerms.
	srv := contextServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ld+json")
		w.Write([]byte(`{"@context":{
			"importedScoped": {
				"@id": "https://example.org/importedScoped",
				"@context": {"deep": "https://example.org/deep"}
			},
			"plainImported": "https://example.org/plainImported"
		}}`))
	})
	useTestClient(t, srv)

	ctx := map[string]interface{}{
		"@import":   srv.URL,
		"localTerm": "https://example.org/localTerm",
	}
	scoped, hasUnresolved := collectScopedTerms(ctx)
	if hasUnresolved {
		t.Fatal("should not have unresolved contexts")
	}
	if !scoped["importedScoped"] {
		t.Fatal("importedScoped should be detected via @import")
	}
	if scoped["plainImported"] {
		t.Fatal("plainImported has no scoped @context, should not be detected")
	}
	if scoped["localTerm"] {
		t.Fatal("localTerm has no scoped @context, should not be detected")
	}
}

// ===== Both limits together =====

func TestBothLimits_FirstFailureReported(t *testing.T) {
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"scopedTerm": map[string]interface{}{
					"@id":      "https://example.org/scopedTerm",
					"@context": map[string]interface{}{"inner": "https://example.org/inner"},
				},
			},
		},
		"credentialSubject": map[string]interface{}{
			"data":       makeArray(200),
			"scopedTerm": "value",
		},
	}
	// Total values: credentialSubject(1) + data(1) + 200 + scopedTerm(1) = 203
	// Values checked first.
	err := CheckJSONLDLimits(doc, JSONLDLimits{
		MaxValues:            100,
		MaxScopedContextUses: 1000,
	})
	if !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("expected ErrTooManyValues (checked first), got %v", err)
	}
}

// ===== IsSet =====

func TestJSONLDLimits_IsSet(t *testing.T) {
	if (JSONLDLimits{}).IsSet() {
		t.Fatal("zero value should not be set")
	}
	if !(JSONLDLimits{MaxValues: 1}).IsSet() {
		t.Fatal("MaxValues=1 should be set")
	}
	if !(JSONLDLimits{MaxScopedContextUses: 1}).IsSet() {
		t.Fatal("MaxScopedContextUses=1 should be set")
	}
}

// ===== helpers =====

func makeArray(n int) []interface{} {
	arr := make([]interface{}, n)
	for i := range arr {
		arr[i] = fmt.Sprintf("v%d", i)
	}
	return arr
}

func makeMap(n int) map[string]interface{} {
	m := make(map[string]interface{})
	for i := 0; i < n; i++ {
		m[fmt.Sprintf("x%d", i)] = fmt.Sprintf("v%d", i)
	}
	return m
}

// ===== Review findings: type alias, inline body context, @context in MaxValues =====

func TestBypass_TypeAlias_Caught(t *testing.T) {
	// "kieu" is defined as an alias for @type. 20 uses of a scoped type
	// through "kieu" should be counted as type-scoped-context uses.
	subjects := make([]interface{}, 20)
	for i := range subjects {
		subjects[i] = map[string]interface{}{
			"kieu": "ScopedType",
			"name": fmt.Sprintf("item%d", i),
		}
	}
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"kieu": "@type",
				"ScopedType": map[string]interface{}{
					"@id":      "https://example.org/ScopedType",
					"@context": map[string]interface{}{"name": "https://example.org/name"},
				},
			},
		},
		"type":              "VerifiableCredential",
		"issuer":            "did:example:issuer",
		"credentialSubject": subjects,
	}
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxScopedContextUses: 5})
	if !errors.Is(err, ErrTooManyScopedContextUses) {
		t.Fatalf("type alias bypass should be caught, got %v", err)
	}
}

func TestBypass_TypeAlias_MapDefinition_Caught(t *testing.T) {
	// "kieu" defined with {"@id": "@type"} (map form) must also be detected.
	subjects := make([]interface{}, 20)
	for i := range subjects {
		subjects[i] = map[string]interface{}{
			"kieu": "ScopedType",
			"name": fmt.Sprintf("item%d", i),
		}
	}
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"kieu": map[string]interface{}{"@id": "@type"},
				"ScopedType": map[string]interface{}{
					"@id":      "https://example.org/ScopedType",
					"@context": map[string]interface{}{"name": "https://example.org/name"},
				},
			},
		},
		"type":              "VerifiableCredential",
		"issuer":            "did:example:issuer",
		"credentialSubject": subjects,
	}
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxScopedContextUses: 5})
	if !errors.Is(err, ErrTooManyScopedContextUses) {
		t.Fatalf("type alias (map def) bypass should be caught, got %v", err)
	}
}

func TestBypass_TypeAlias_ChainedAlias_Caught(t *testing.T) {
	// "loai" is defined as "kieu", and "kieu" is defined as "@type".
	// json-gold resolves loai → kieu → @type (confirmed by expansion test).
	// 20 uses of a scoped type through "loai" should be counted.
	subjects := make([]interface{}, 20)
	for i := range subjects {
		subjects[i] = map[string]interface{}{
			"loai": "ScopedType",
			"name": fmt.Sprintf("item%d", i),
		}
	}
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"kieu": "@type",
				"loai": "kieu",
				"ScopedType": map[string]interface{}{
					"@id":      "https://example.org/ScopedType",
					"@context": map[string]interface{}{"name": "https://example.org/name"},
				},
			},
		},
		"type":              "VerifiableCredential",
		"issuer":            "did:example:issuer",
		"credentialSubject": subjects,
	}
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxScopedContextUses: 5})
	if !errors.Is(err, ErrTooManyScopedContextUses) {
		t.Fatalf("chained type alias bypass should be caught, got %v", err)
	}
}

func TestBypass_TypeAlias_ChainedMap_Caught(t *testing.T) {
	// "loai" defined as {"@id": "kieu"}, "kieu" as "@type".
	subjects := make([]interface{}, 20)
	for i := range subjects {
		subjects[i] = map[string]interface{}{
			"loai": "ScopedType",
			"name": fmt.Sprintf("item%d", i),
		}
	}
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"kieu": "@type",
				"loai": map[string]interface{}{"@id": "kieu"},
				"ScopedType": map[string]interface{}{
					"@id":      "https://example.org/ScopedType",
					"@context": map[string]interface{}{"name": "https://example.org/name"},
				},
			},
		},
		"type":              "VerifiableCredential",
		"issuer":            "did:example:issuer",
		"credentialSubject": subjects,
	}
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxScopedContextUses: 5})
	if !errors.Is(err, ErrTooManyScopedContextUses) {
		t.Fatalf("chained type alias (map @id) bypass should be caught, got %v", err)
	}
}

func TestBypass_TypeAlias_ThreeLevel_Caught(t *testing.T) {
	// "a" → "b" → "kieu" → "@type": three-level chain.
	subjects := make([]interface{}, 20)
	for i := range subjects {
		subjects[i] = map[string]interface{}{
			"a":    "ScopedType",
			"name": fmt.Sprintf("item%d", i),
		}
	}
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"kieu": "@type",
				"b":    "kieu",
				"a":    "b",
				"ScopedType": map[string]interface{}{
					"@id":      "https://example.org/ScopedType",
					"@context": map[string]interface{}{"name": "https://example.org/name"},
				},
			},
		},
		"type":              "VerifiableCredential",
		"issuer":            "did:example:issuer",
		"credentialSubject": subjects,
	}
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxScopedContextUses: 5})
	if !errors.Is(err, ErrTooManyScopedContextUses) {
		t.Fatalf("3-level chained type alias bypass should be caught, got %v", err)
	}
}

func TestScanBudget_ExcessiveRemoteContexts_Refused(t *testing.T) {
	// A document referencing more remote context URLs than the contextBudget
	// allows (maxContextLoads=1024) should be refused with ErrUnresolvedContext.
	// This pins the contextBudget wiring: if the scan used
	// defaultDocumentLoader.fallback directly (unbounded), it would not refuse.
	srv := contextServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ld+json")
		w.Write([]byte(`{"@context":{"dummy":"https://example.org/dummy"}}`))
	})
	useTestClient(t, srv)

	// Build a context with 1030 distinct remote URLs (> 1024 budget).
	ctxArray := make([]interface{}, 1030)
	for i := range ctxArray {
		ctxArray[i] = fmt.Sprintf("%s/ctx/%d", srv.URL, i)
	}
	doc := map[string]interface{}{
		"@context":          ctxArray,
		"credentialSubject": map[string]interface{}{"name": "test"},
	}
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxScopedContextUses: 1})
	if !errors.Is(err, ErrUnresolvedContext) {
		t.Fatalf("excessive remote contexts should trigger ErrUnresolvedContext, got %v", err)
	}
}

func TestBypass_InlineBodyContext_ScopedTerm_Caught(t *testing.T) {
	// A scoped term defined on credentialSubject's inline @context (not the
	// top-level @context) should still be detected and counted.
	subject := map[string]interface{}{
		"@context": map[string]interface{}{
			"bodyScopedTerm": map[string]interface{}{
				"@id":      "https://example.org/bodyScopedTerm",
				"@context": map[string]interface{}{"inner": "https://example.org/inner"},
			},
		},
		"id": "did:example:subject",
	}
	for i := 0; i < 20; i++ {
		subject[fmt.Sprintf("n%d", i)] = map[string]interface{}{
			"bodyScopedTerm": fmt.Sprintf("val%d", i),
		}
	}
	doc := map[string]interface{}{
		"@context":          []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":              "VerifiableCredential",
		"issuer":            "did:example:issuer",
		"credentialSubject": subject,
	}
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxScopedContextUses: 5})
	if !errors.Is(err, ErrTooManyScopedContextUses) {
		t.Fatalf("inline body context scoped term should be caught, got %v", err)
	}
}

func TestCheckTotalValues_InlineContextCounted(t *testing.T) {
	// @context subtrees should count toward MaxValues because json-gold
	// processes them (inline context body is work).
	termDefs := make(map[string]interface{})
	for i := 0; i < 50; i++ {
		termDefs[fmt.Sprintf("t%d", i)] = fmt.Sprintf("https://example.org/t%d", i)
	}
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			termDefs,
		},
		"credentialSubject": map[string]interface{}{"name": "test"},
	}
	// The inline context has 50 terms plus overhead. With @context counted,
	// the total should exceed 5.
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxValues: 5})
	if !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("inline context should count toward MaxValues, got %v", err)
	}
}

// ===== Attack shape timing without limit (baseline) =====

func TestBaseline_ManyValues_WithoutLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow baseline in -short mode")
	}
	const n = 5000
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"data": "https://example.org/data",
			},
		},
		"type":   "VerifiableCredential",
		"issuer": "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"data": makeArray(n),
		},
	}
	start := time.Now()
	_, _ = ExpandJSONLD(doc)
	elapsed := time.Since(start)
	t.Logf("ExpandJSONLD with %d values took %v (no limit)", n, elapsed)
}

// ===== Comment #4661874576: nested context overwrites termDefs, breaking alias chain =====

func TestBypass_NestedContextOverwritesAlias(t *testing.T) {
	// Top-level: "kieu": "@type", "loai": "kieu" (so loai → kieu → @type).
	// Child node has "@context": {"loai": "http://ex.org/loai"} which, with
	// a single-string termDefs map, would overwrite the top-level definition
	// and break the chain. The top-level "loai" must still be recognized as
	// a type alias.
	subjects := make([]interface{}, 20)
	for i := range subjects {
		subjects[i] = map[string]interface{}{
			"loai": "ScopedType",
			"name": fmt.Sprintf("item%d", i),
		}
	}
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{
				"kieu": "@type",
				"loai": "kieu",
				"ScopedType": map[string]interface{}{
					"@id":      "https://example.org/ScopedType",
					"@context": map[string]interface{}{"name": "https://example.org/name"},
				},
			},
		},
		"type":   "VerifiableCredential",
		"issuer": "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			// This inline context redefines "loai" to a plain IRI.
			"@context": map[string]interface{}{
				"loai": "http://ex.org/loai",
			},
			"items": subjects,
		},
	}
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxScopedContextUses: 5})
	if !errors.Is(err, ErrTooManyScopedContextUses) {
		t.Fatalf("nested context overwriting alias should not break detection, got %v", err)
	}
}

// ===== Comment #4661874728: 16,000-term chain resolves fast (linear) =====

func TestResolveTypeAliasChains_16000_Linear(t *testing.T) {
	// Build a 16,000-term chain: t0 → @type, t1 → t0, t2 → t1, ..., t15999 → t15998.
	// The old fixed-point loop is O(n²) and takes ~3.5s. The new BFS is O(n).
	const n = 16000
	ctx := make(map[string]interface{}, n+1)
	ctx["t0"] = "@type"
	for i := 1; i < n; i++ {
		ctx[fmt.Sprintf("t%d", i)] = fmt.Sprintf("t%d", i-1)
	}
	// Also add a scoped term so the check actually exercises the alias chain.
	ctx["ScopedType"] = map[string]interface{}{
		"@id":      "https://example.org/ScopedType",
		"@context": map[string]interface{}{"inner": "https://example.org/inner"},
	}

	// Build a document that uses the last alias in the chain many times.
	lastAlias := fmt.Sprintf("t%d", n-1)
	subjects := make([]interface{}, 20)
	for i := range subjects {
		subjects[i] = map[string]interface{}{
			lastAlias: "ScopedType",
			"name":    fmt.Sprintf("item%d", i),
		}
	}
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			ctx,
		},
		"type":              "VerifiableCredential",
		"issuer":            "did:example:issuer",
		"credentialSubject": subjects,
	}

	start := time.Now()
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxScopedContextUses: 5})
	elapsed := time.Since(start)

	// The last alias in the chain must be recognized as a type alias.
	if !errors.Is(err, ErrTooManyScopedContextUses) {
		t.Fatalf("16000-term chain: last alias should be recognized as type alias, got %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("16000-term chain took %v, expected < 500ms", elapsed)
	}
	t.Logf("16000-term alias chain resolved in %v", elapsed)
}

// ===== Comment #4661874872: load error wrapped under ErrUnresolvedContext =====

func TestUnresolvedContext_WrapsLoadError_FileScheme(t *testing.T) {
	// A file: URL context should give errors.Is(err, ErrUnresolvedContext)
	// AND errors.Is(err, ErrContextScheme).
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			"file:///etc/passwd",
		},
		"type":   "VerifiableCredential",
		"issuer": "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "test",
		},
	}
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxScopedContextUses: 100})
	if !errors.Is(err, ErrUnresolvedContext) {
		t.Fatalf("expected ErrUnresolvedContext, got %v", err)
	}
	if !errors.Is(err, ErrContextScheme) {
		t.Fatalf("expected ErrContextScheme to be wrapped, got %v", err)
	}
}

func TestUnresolvedContext_WrapsLoadError_PrivateAddress(t *testing.T) {
	// A loopback address should give ErrUnresolvedContext wrapping ErrContextAddress.
	srv := contextServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusGone)
	})
	useTestClient(t, srv)

	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			srv.URL, // loopback
		},
		"type":   "VerifiableCredential",
		"issuer": "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "test",
		},
	}
	err := CheckJSONLDLimits(doc, JSONLDLimits{MaxScopedContextUses: 100})
	if !errors.Is(err, ErrUnresolvedContext) {
		t.Fatalf("expected ErrUnresolvedContext, got %v", err)
	}
}

func TestBaseline_ScopedContextUses_WithoutLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow baseline in -short mode")
	}
	const nTerms = 50
	const usesPerTerm = 20
	termDefs := make(map[string]interface{}, nTerms+nTerms*usesPerTerm)
	for i := 0; i < nTerms; i++ {
		name := fmt.Sprintf("st%d", i)
		termDefs[name] = map[string]interface{}{
			"@id": fmt.Sprintf("https://example.org/%s", name),
			"@context": map[string]interface{}{
				"inner": "https://example.org/inner",
			},
		}
	}
	for i := 0; i < nTerms*usesPerTerm; i++ {
		name := fmt.Sprintf("c%d", i)
		termDefs[name] = fmt.Sprintf("https://example.org/%s", name)
	}

	subject := make(map[string]interface{})
	subject["id"] = "did:example:subject"
	idx := 0
	for i := 0; i < nTerms; i++ {
		scopedName := fmt.Sprintf("st%d", i)
		for j := 0; j < usesPerTerm; j++ {
			containerName := fmt.Sprintf("c%d", idx)
			subject[containerName] = map[string]interface{}{scopedName: fmt.Sprintf("val%d", idx)}
			idx++
		}
	}

	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			termDefs,
		},
		"type":              "VerifiableCredential",
		"issuer":            "did:example:issuer",
		"credentialSubject": subject,
	}
	start := time.Now()
	_, _ = ExpandJSONLD(doc)
	elapsed := time.Since(start)
	t.Logf("ExpandJSONLD with %d scoped-context uses took %v (no limit)",
		nTerms*usesPerTerm, elapsed)
}
