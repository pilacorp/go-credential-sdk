package ecdsasd

import (
	"reflect"
	"testing"
)

// #176: ecdsasd's old parsePointer converted all-digit tokens to int, which
// (a) lost numeric object keys (/3 on {"3":"val"} → not found) and
// (b) accepted non-canonical array indexes (/01 → index 1). The shared
// jsonpointer package fixes both: a token is an array index only when the
// parent is an array, and array indexes follow RFC 6901 §4 (0 | [1-9][0-9]*).
func TestSelectJsonLdRFC6901Compliance(t *testing.T) {
	type testCase struct {
		name     string
		document map[string]interface{}
		pointers []string
		wantErr  bool
		check    func(t *testing.T, got map[string]interface{})
	}

	cases := []testCase{
		{
			name: "numeric token on object is a key lookup",
			document: map[string]interface{}{
				"credentialSubject": map[string]interface{}{"3": "numeric-key-value"},
			},
			pointers: []string{"/credentialSubject/3"},
			check: func(t *testing.T, got map[string]interface{}) {
				cs := got["credentialSubject"].(map[string]interface{})
				if cs["3"] != "numeric-key-value" {
					t.Errorf("credentialSubject[\"3\"] = %v, want \"numeric-key-value\"", cs["3"])
				}
			},
		},
		{
			name:     "valid array index 0",
			document: map[string]interface{}{"list": []interface{}{"first", "second"}},
			pointers: []string{"/list/0"},
			check: func(t *testing.T, got map[string]interface{}) {
				list := got["list"].([]interface{})
				if len(list) != 1 || list[0] != "first" {
					t.Errorf("list = %v, want [first]", list)
				}
			},
		},
		{
			name:     "leading-zero array index 01 rejected",
			document: map[string]interface{}{"list": []interface{}{"a", "b"}},
			pointers: []string{"/list/01"},
			wantErr:  true,
		},
		{
			name:     "signed array index +1 rejected",
			document: map[string]interface{}{"list": []interface{}{"a", "b"}},
			pointers: []string{"/list/+1"},
			wantErr:  true,
		},
		{
			name:     "signed array index -1 rejected",
			document: map[string]interface{}{"list": []interface{}{"a", "b"}},
			pointers: []string{"/list/-1"},
			wantErr:  true,
		},
		{
			name:     "tilde escape ~0 and slash escape ~1",
			document: map[string]interface{}{"a/b": map[string]interface{}{"~key": "escaped"}},
			pointers: []string{"/a~1b/~0key"},
			check: func(t *testing.T, got map[string]interface{}) {
				ab := got["a/b"].(map[string]interface{})
				if ab["~key"] != "escaped" {
					t.Errorf("a/b[~key] = %v, want \"escaped\"", ab["~key"])
				}
			},
		},
		// selectJsonLd does not reject a pointer without a leading slash: it
		// reads mandatory pointers stored in base proofs issued before the check
		// was added. checkPointers tests that rejection separately.
		{
			name:     "root pointer returns whole document",
			document: map[string]interface{}{"name": "Alice", "age": 30.0},
			pointers: []string{""},
			check: func(t *testing.T, got map[string]interface{}) {
				if got["name"] != "Alice" || got["age"] != 30.0 {
					t.Errorf("root selection = %v, want whole document", got)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectJsonLd(tc.document, tc.pointers)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("selectJsonLd(%v) = %v, want error", tc.pointers, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("selectJsonLd(%v) error = %v", tc.pointers, err)
			}
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}
}

// checkPointers must reject /01 and accept /3 on an object (the pointer
// matches because "3" is a valid key).
func TestCheckPointersRFC6901Compliance(t *testing.T) {
	doc := map[string]interface{}{
		"credentialSubject": map[string]interface{}{"3": "value"},
		"list":              []interface{}{"a", "b"},
	}

	// /credentialSubject/3 matches: "3" is an object key.
	if err := checkPointers(doc, []string{"/credentialSubject/3"}); err != nil {
		t.Errorf("checkPointers(/credentialSubject/3) = %v, want nil", err)
	}

	// /list/01 does not match: leading-zero index is invalid.
	if err := checkPointers(doc, []string{"/list/01"}); err == nil {
		t.Error("checkPointers(/list/01) = nil, want error for leading-zero index")
	}
}

// A "~" not followed by 0 or 1 is refused (RFC 6901 §3); main read "~2"
// literally as part of the key.
func TestSelectJsonLdRejectsBadTildeEscape(t *testing.T) {
	doc := map[string]interface{}{
		"foo~2bar": "oops",
		"name":     "Alice",
	}
	_, err := selectJsonLd(doc, []string{"/foo~2bar"})
	if err == nil {
		t.Fatal(`selectJsonLd("/foo~2bar") = nil error; want bad-escape error`)
	}
}

func TestCheckPointersRejectsBadTildeEscape(t *testing.T) {
	doc := map[string]interface{}{"foo~2bar": "oops"}
	if err := checkPointers(doc, []string{"/foo~2bar"}); err == nil {
		t.Fatal(`checkPointers("/foo~2bar") = nil; want bad-escape error`)
	}
}

// A mandatory pointer stored in an issued base proof is read the way the
// reference di-sd-primitives reads it: the first token is dropped. On main,
// "x/validFrom" selects /validFrom and "credentialSubject" selects the whole
// document; both must keep doing so, or base proofs issued with such pointers
// stop verifying.
func TestSelectJsonLdStoredPointerWithoutLeadingSlash(t *testing.T) {
	doc := map[string]interface{}{
		"validFrom":         "2026-01-01T00:00:00Z",
		"credentialSubject": map[string]interface{}{"name": "A"},
	}

	got, err := selectJsonLd(doc, []string{"x/validFrom"})
	if err != nil {
		t.Fatalf("selectJsonLd(x/validFrom): %v", err)
	}
	if got["validFrom"] != "2026-01-01T00:00:00Z" {
		t.Errorf("x/validFrom selected %v, want validFrom", got)
	}
	if _, ok := got["credentialSubject"]; ok {
		t.Errorf("x/validFrom also selected credentialSubject: %v", got)
	}

	got, err = selectJsonLd(doc, []string{"credentialSubject"})
	if err != nil {
		t.Fatalf("selectJsonLd(credentialSubject): %v", err)
	}
	if !reflect.DeepEqual(got, doc) {
		t.Errorf("credentialSubject selected %v, want the whole document", got)
	}
}
