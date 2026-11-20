package jsonmap

import (
	"reflect"
	"testing"
)

// #176: shared RFC 6901 compliance test for SelectJSONLD. These cases must
// produce the same results as the ecdsasd and vc/render call sites.
func TestSelectJSONLDRFC6901SharedCases(t *testing.T) {
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
		{
			name:     "pointer without leading slash rejected",
			document: map[string]interface{}{"name": "Alice"},
			pointers: []string{"name"},
			wantErr:  true,
		},
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
			got, err := SelectJSONLD(tc.document, tc.pointers)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("SelectJSONLD(%v) = %v, want error", tc.pointers, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("SelectJSONLD(%v) error = %v", tc.pointers, err)
			}
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}
}

// #176 review item 2: SelectJSONLD silently ignores ParseTokens errors. With
// a bad ~escape, ParseTokens returns nil, nil tokens make Matches return true,
// and SelectJSONLD treats it as the root pointer.
func TestSelectJSONLDRejectsBadTildeEscape(t *testing.T) {
	doc := map[string]interface{}{
		"foo~2bar": "oops",
		"name":     "Alice",
	}
	_, err := SelectJSONLD(doc, []string{"/foo~2bar"})
	if err == nil {
		t.Fatal(`SelectJSONLD("/foo~2bar") = nil error; want bad-escape error`)
	}
}

// Cross-check: jsonmap and ecdsasd produce the same selection for a document
// with numeric object keys and array indexes.
func TestSelectJSONLDMatchesEcdsasdOnNumericKeys(t *testing.T) {
	document := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     "VerifiableCredential",
		"credentialSubject": map[string]interface{}{
			"id":    "did:example:subject",
			"type":  "Person",
			"3":     "numeric-key-value",
			"items": []interface{}{"zero", "one", "two"},
		},
	}

	// /credentialSubject/3 selects the object key "3".
	got, err := SelectJSONLD(document, []string{"/credentialSubject/3"})
	if err != nil {
		t.Fatalf("SelectJSONLD(/credentialSubject/3) error = %v", err)
	}
	cs := got["credentialSubject"].(map[string]interface{})
	if cs["3"] != "numeric-key-value" {
		t.Fatalf("credentialSubject[\"3\"] = %v, want \"numeric-key-value\"", cs["3"])
	}

	// /credentialSubject/items/1 selects array index 1 = "one".
	got, err = SelectJSONLD(document, []string{"/credentialSubject/items/1"})
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	items := got["credentialSubject"].(map[string]interface{})["items"].([]interface{})
	if !reflect.DeepEqual(items, []interface{}{"one"}) {
		t.Fatalf("items = %v, want [one]", items)
	}
}
