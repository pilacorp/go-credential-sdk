package vc

import (
	"reflect"
	"testing"
)

func TestDotPathsToPointers(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		// Dot paths: "." separates levels, everything else is a name.
		{"dot path", []string{"credentialSubject.name"}, []string{"/credentialSubject/name"}},
		{"single segment", []string{"issuer"}, []string{"/issuer"}},
		{"array index", []string{"credentialSubject.0.name"}, []string{"/credentialSubject/0/name"}},
		{"deep nesting", []string{"a.b.c.d"}, []string{"/a/b/c/d"}},
		{"name containing / is escaped", []string{"meta.a/b"}, []string{"/meta/a~1b"}},
		{"name containing ~ is escaped", []string{"meta.a~b"}, []string{"/meta/a~0b"}},
		{"name containing ~1 literal is escaped again", []string{"meta.a~1b"}, []string{"/meta/a~01b"}},
		{"both escapes in one path", []string{"a~b.c/d"}, []string{"/a~0b/c~1d"}},
		{"space and unicode kept", []string{"họ tên.số nhà"}, []string{"/họ tên/số nhà"}},

		// JSON Pointers: "/" separates levels, caller has already escaped names.
		{"pointer passes through", []string{"/credentialSubject/name"}, []string{"/credentialSubject/name"}},
		{"pointer single segment", []string{"/issuer"}, []string{"/issuer"}},
		{"pointer with array index", []string{"/credentialSubject/0/name"}, []string{"/credentialSubject/0/name"}},
		{"pointer keeps its escapes", []string{"/a~0b/c~1d"}, []string{"/a~0b/c~1d"}},
		{"pointer is not re-escaped", []string{"/meta/a~1b"}, []string{"/meta/a~1b"}},
		{"pointer with dot in name stays one level", []string{"/meta/a.b"}, []string{"/meta/a.b"}},
		{"root pointer", []string{"/"}, []string{"/"}},

		// Same field, both spellings, same pointer.
		{"dot and pointer agree", []string{"credentialSubject.name", "/credentialSubject/name"},
			[]string{"/credentialSubject/name", "/credentialSubject/name"}},
		{"dot and pointer agree with escapes", []string{"meta.a/b", "/meta/a~1b"},
			[]string{"/meta/a~1b", "/meta/a~1b"}},

		// List handling.
		{"mixed list keeps order", []string{"/issuer", "credentialSubject.name", "/validFrom"},
			[]string{"/issuer", "/credentialSubject/name", "/validFrom"}},
		{"empty entries dropped", []string{"", "/issuer", ""}, []string{"/issuer"}},
		{"all empty", []string{"", ""}, []string{}},
		{"nil", nil, []string{}},
		{"empty slice", []string{}, []string{}},

		// Edge shapes pass through the dot converter verbatim; validity is the
		// pointer library's concern.
		{"leading dot yields empty first segment", []string{".a"}, []string{"//a"}},
		{"trailing dot yields empty last segment", []string{"a."}, []string{"/a/"}},
		{"consecutive dots yield empty segment", []string{"a..b"}, []string{"/a//b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dotPathsToPointers(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("dotPathsToPointers(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// The converter must not mutate its input.
func TestDotPathsToPointers_DoesNotMutateInput(t *testing.T) {
	in := []string{"credentialSubject.name", "/issuer"}
	orig := append([]string(nil), in...)
	_ = dotPathsToPointers(in)
	if !reflect.DeepEqual(in, orig) {
		t.Errorf("input mutated: %q, want %q", in, orig)
	}
}
