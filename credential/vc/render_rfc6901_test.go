package vc

import (
	"testing"
)

// #176: shared RFC 6901 compliance test for resolveJSONPointer. These cases
// must produce the same results as the ecdsasd and jsonmap call sites.
func TestResolveJSONPointerRFC6901SharedCases(t *testing.T) {
	type testCase struct {
		name    string
		doc     any
		pointer string
		wantErr bool
		want    any
	}

	doc := map[string]any{
		"credentialSubject": map[string]any{
			"3":     "numeric-key-value",
			"items": []any{"zero", "one", "two"},
		},
		"a/b":  map[string]any{"~key": "escaped"},
		"name": "Alice",
		"age":  30.0,
	}

	cases := []testCase{
		{
			name:    "numeric token on object is a key lookup",
			doc:     doc,
			pointer: "/credentialSubject/3",
			want:    "numeric-key-value",
		},
		{
			name:    "valid array index 0",
			doc:     doc,
			pointer: "/credentialSubject/items/0",
			want:    "zero",
		},
		{
			name:    "leading-zero array index 01 rejected",
			doc:     doc,
			pointer: "/credentialSubject/items/01",
			wantErr: true,
		},
		{
			name:    "signed array index +1 rejected",
			doc:     doc,
			pointer: "/credentialSubject/items/+1",
			wantErr: true,
		},
		{
			name:    "signed array index -1 rejected",
			doc:     doc,
			pointer: "/credentialSubject/items/-1",
			wantErr: true,
		},
		{
			name:    "tilde escape ~0 and slash escape ~1",
			doc:     doc,
			pointer: "/a~1b/~0key",
			want:    "escaped",
		},
		{
			name:    "pointer without leading slash rejected",
			doc:     doc,
			pointer: "name",
			wantErr: true,
		},
		{
			name:    "root pointer returns whole document",
			doc:     doc,
			pointer: "",
			want:    doc,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveJSONPointer(tc.doc, tc.pointer)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolveJSONPointer(%q) = %v, want error", tc.pointer, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveJSONPointer(%q) error = %v", tc.pointer, err)
			}
			if string(mustJSON(got)) != string(mustJSON(tc.want)) {
				t.Errorf("resolveJSONPointer(%q) = %v, want %v", tc.pointer, got, tc.want)
			}
		})
	}
}
