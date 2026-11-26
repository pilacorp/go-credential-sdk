package jsonpointer

import (
	"math"
	"reflect"
	"strconv"
	"testing"
)

// RFC 6901 §5 example document.
var rfc6901Document = map[string]interface{}{
	"foo":  []interface{}{"bar", "baz"},
	"":     0.0,
	"a/b":  1.0,
	"c%d":  2.0,
	"e^f":  3.0,
	"g|h":  4.0,
	"i\\j": 5.0,
	"k\"l": 6.0,
	" ":    7.0,
	"m~n":  8.0,
}

// TestRFC6901ExampleDocument exercises the table from RFC 6901 §5.
func TestRFC6901ExampleDocument(t *testing.T) {
	tests := []struct {
		pointer string
		want    interface{}
	}{
		{"", rfc6901Document}, // whole document
		{"/foo", []interface{}{"bar", "baz"}},
		{"/foo/0", "bar"},
		{"/", 0.0},
		{"/a~1b", 1.0},
		{"/c%d", 2.0},
		{"/e^f", 3.0},
		{"/g|h", 4.0},
		{"/i\\j", 5.0},
		{"/k\"l", 6.0},
		{"/ ", 7.0},
		{"/m~0n", 8.0},
	}
	for _, tt := range tests {
		got, err := Resolve(rfc6901Document, tt.pointer)
		if err != nil {
			t.Errorf("Resolve(%q) error = %v", tt.pointer, err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("Resolve(%q) = %v, want %v", tt.pointer, got, tt.want)
		}
	}
}

// TestResolveRejectsPointerWithoutLeadingSlash ensures that a non-empty
// pointer without "/" is an error (RFC 6901 §3).
func TestResolveRejectsPointerWithoutLeadingSlash(t *testing.T) {
	for _, pointer := range []string{"foo", "credentialSubject", "x/y"} {
		if _, err := Resolve(rfc6901Document, pointer); err == nil {
			t.Errorf("Resolve(%q) = nil error, want leading-slash error", pointer)
		}
	}
}

// TestResolveRejectsMissingMember checks that a pointer to a non-existent
// member returns an error.
func TestResolveRejectsMissingMember(t *testing.T) {
	for _, pointer := range []string{"/missing", "/foo/2", "/foo/missing"} {
		if _, err := Resolve(rfc6901Document, pointer); err == nil {
			t.Errorf("Resolve(%q) = nil error, want missing member error", pointer)
		}
	}
}

// TestResolveArrayIndexOnlyWhenParentIsArray ensures that a numeric token is
// an array index only when the parent is an array.
func TestResolveArrayIndexOnlyWhenParentIsArray(t *testing.T) {
	doc := map[string]interface{}{
		"obj":   map[string]interface{}{"3": "object-value"},
		"array": []interface{}{"first", "second", "third", "fourth"},
	}
	// Numeric token on an object is a key lookup.
	got, err := Resolve(doc, "/obj/3")
	if err != nil || got != "object-value" {
		t.Errorf("Resolve(/obj/3) = %v, %v; want object-value", got, err)
	}
	// Numeric token on an array is an index.
	got, err = Resolve(doc, "/array/3")
	if err != nil || got != "fourth" {
		t.Errorf("Resolve(/array/3) = %v, %v; want fourth", got, err)
	}
}

// TestResolveRejectsNonCanonicalArrayIndexes checks leading zeros, signs, etc.
func TestResolveRejectsNonCanonicalArrayIndexes(t *testing.T) {
	doc := map[string]interface{}{"list": []interface{}{"a", "b", "c"}}
	for _, pointer := range []string{
		"/list/01",
		"/list/+1",
		"/list/-1",
		"/list/-",
		"/list/ 1",
		"/list/1a",
	} {
		if _, err := Resolve(doc, pointer); err == nil {
			t.Errorf("Resolve(%q) = nil error, want invalid array index error", pointer)
		}
	}
}

// TestResolveAcceptsZeroArrayIndex checks "0" is a valid index.
func TestResolveAcceptsZeroArrayIndex(t *testing.T) {
	doc := map[string]interface{}{"list": []interface{}{"first"}}
	got, err := Resolve(doc, "/list/0")
	if err != nil || got != "first" {
		t.Errorf("Resolve(/list/0) = %v, %v; want first", got, err)
	}
}

// TestResolveRejectsOverflowArrayIndex ensures huge numbers don't wrap.
func TestResolveRejectsOverflowArrayIndex(t *testing.T) {
	doc := map[string]interface{}{"list": []interface{}{"a"}}
	overflow := strconv.FormatUint(uint64(math.MaxInt)+1, 10)
	for _, pointer := range []string{
		"/list/" + overflow,
		"/list/9223372036854775808",
		"/list/99999999999999999999999",
	} {
		if _, err := Resolve(doc, pointer); err == nil {
			t.Errorf("Resolve(%q) = nil error, want overflow error", pointer)
		}
	}
}

// TestResolveHandlesEscaping tests ~0 and ~1.
func TestResolveHandlesEscaping(t *testing.T) {
	doc := map[string]interface{}{
		"a/b":  "slash",
		"c~d":  "tilde",
		"e~/f": "both",
	}
	tests := []struct {
		pointer string
		want    string
	}{
		{"/a~1b", "slash"},
		{"/c~0d", "tilde"},
		{"/e~0~1f", "both"},
	}
	for _, tt := range tests {
		got, err := Resolve(doc, tt.pointer)
		if err != nil || got != tt.want {
			t.Errorf("Resolve(%q) = %v, %v; want %v", tt.pointer, got, err, tt.want)
		}
	}
}

// TestResolveRootPointerReturnsWholeDocument ensures "" returns the document.
func TestResolveRootPointerReturnsWholeDocument(t *testing.T) {
	doc := map[string]interface{}{"name": "Alice"}
	got, err := Resolve(doc, "")
	if err != nil {
		t.Fatalf("Resolve(\"\") error = %v", err)
	}
	if !reflect.DeepEqual(got, doc) {
		t.Errorf("Resolve(\"\") = %v, want %v", got, doc)
	}
}

// TestResolveNullValue ensures null values are returned, not treated as missing.
func TestResolveNullValue(t *testing.T) {
	doc := map[string]interface{}{"field": nil}
	got, err := Resolve(doc, "/field")
	if err != nil {
		t.Fatalf("Resolve(/field) error = %v", err)
	}
	if got != nil {
		t.Errorf("Resolve(/field) = %v, want nil", got)
	}
}

// TestParseTokens checks ParseTokens for various inputs.
func TestParseTokens(t *testing.T) {
	tests := []struct {
		pointer string
		want    []string
		err     bool
	}{
		{"", nil, false},
		{"/", []string{""}, false},
		{"/foo", []string{"foo"}, false},
		{"/foo/0", []string{"foo", "0"}, false},
		{"/a~1b/c~0d", []string{"a/b", "c~d"}, false},
		{"foo", nil, true},
		{"foo/bar", nil, true},
	}
	for _, tt := range tests {
		got, err := ParseTokens(tt.pointer)
		if (err != nil) != tt.err {
			t.Errorf("ParseTokens(%q) error = %v, want error=%v", tt.pointer, err, tt.err)
			continue
		}
		if !tt.err && !reflect.DeepEqual(got, tt.want) {
			t.Errorf("ParseTokens(%q) = %v, want %v", tt.pointer, got, tt.want)
		}
	}
}

// TestValidate checks syntax-only validation.
func TestValidate(t *testing.T) {
	valid := []string{"", "/", "/foo", "/foo/bar", "/a~0b", "/a~1b", "/~0~1"}
	for _, p := range valid {
		if err := Validate(p); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", p, err)
		}
	}
	invalid := []string{"foo", "foo/bar", "/~", "/~2", "/bad~", "/a~2b", "/\xff"}
	for _, p := range invalid {
		if err := Validate(p); err == nil {
			t.Errorf("Validate(%q) = nil, want error", p)
		}
	}
}

// TestArrayIndexFunc tests the ArrayIndex function directly.
func TestArrayIndexFunc(t *testing.T) {
	cases := []struct {
		token string
		want  int
		ok    bool
	}{
		{"0", 0, true},
		{"7", 7, true},
		{"42", 42, true},
		{"", 0, false},
		{"01", 0, false},
		{"-1", 0, false},
		{"+1", 0, false},
		{"1a", 0, false},
		{strconv.Itoa(math.MaxInt), math.MaxInt, true},
		{strconv.FormatUint(uint64(math.MaxInt)+1, 10), 0, false},
		{"9223372036854775808", 0, false},
		{"99999999999999999999999", 0, false},
	}
	for _, tc := range cases {
		got, ok := ArrayIndex(tc.token)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("ArrayIndex(%q) = (%d, %v), want (%d, %v)", tc.token, got, ok, tc.want, tc.ok)
		}
	}
}

// TestResolveCannotTraversePrimitive ensures resolving past a primitive fails.
func TestResolveCannotTraversePrimitive(t *testing.T) {
	doc := map[string]interface{}{"name": "Alice"}
	if _, err := Resolve(doc, "/name/child"); err == nil {
		t.Error("Resolve(/name/child) = nil error, want cannot-traverse error")
	}
}

// TestParseTokensRejectsBadTildeEscapes ensures ParseTokens refuses ~ followed
// by anything other than 0 or 1 (RFC 6901 §4). Without this, Resolve silently
// returns the wrong key: "/foo~2bar" unescapes to "foo~2bar" and looks up that
// literal, which is not what the pointer means.
func TestParseTokensRejectsBadTildeEscapes(t *testing.T) {
	bad := []string{"/~2", "/foo~2bar", "/~", "/bad~", "/a~3", "/~9x"}
	for _, p := range bad {
		tokens, err := ParseTokens(p)
		if err == nil {
			t.Errorf("ParseTokens(%q) = %v, nil; want error for bad ~ escape", p, tokens)
		}
	}
}

// TestResolveRejectsBadTildeEscapes ensures Resolve surfaces the same error.
func TestResolveRejectsBadTildeEscapes(t *testing.T) {
	doc := map[string]interface{}{"foo~2bar": "oops"}
	_, err := Resolve(doc, "/foo~2bar")
	if err == nil {
		t.Error(`Resolve(doc, "/foo~2bar") = nil error; want bad-escape error`)
	}
}

// TestParseTokensRejectsFooTilde2 is the Matches case from the spec. A token
// that parsed would be an ordinary object key, so Matches cannot reject it.
// The refusal belongs to ParseTokens.
func TestParseTokensRejectsFooTilde2(t *testing.T) {
	if _, err := ParseTokens("/foo~2bar"); err == nil {
		t.Fatal(`ParseTokens("/foo~2bar") = nil, want an error`)
	}
}
