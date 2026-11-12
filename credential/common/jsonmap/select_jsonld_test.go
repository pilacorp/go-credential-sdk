package jsonmap

import (
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestSelectJSONLDPreservesContextAndNodeMetadata(t *testing.T) {
	document := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialSubject": map[string]interface{}{
			"id":     "did:example:subject",
			"type":   []interface{}{"Person"},
			"name":   "Alice",
			"secret": "hidden",
		},
	}

	got, err := SelectJSONLD(document, []string{"/credentialSubject/name"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"type": []interface{}{"Person"},
			"name": "Alice",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selection = %#v, want %#v", got, want)
	}
}

func TestSelectJSONLDMergesPointersAndHandlesArrays(t *testing.T) {
	document := map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"items": []interface{}{
				map[string]interface{}{"name": "first", "secret": "one"},
				map[string]interface{}{"name": "second", "secret": "two"},
			},
		},
	}

	got, err := SelectJSONLD(document, []string{
		"/credentialSubject/items/0/name",
		"/credentialSubject/items/1/name",
	})
	if err != nil {
		t.Fatal(err)
	}
	items := got["credentialSubject"].(map[string]interface{})["items"].([]interface{})
	if len(items) != 2 || items[0].(map[string]interface{})["name"] != "first" || items[1].(map[string]interface{})["name"] != "second" {
		t.Fatalf("selected items = %#v", items)
	}
	if _, ok := items[0].(map[string]interface{})["secret"]; ok {
		t.Fatalf("selection leaked item secret: %#v", items[0])
	}
}

func TestSelectJSONLDDeduplicatesPointersWithoutChangingResult(t *testing.T) {
	document := map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"profile": map[string]interface{}{
				"name": "Alice",
				"role": "member",
			},
		},
	}

	once, err := SelectJSONLD(document, []string{"/credentialSubject/profile"})
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := SelectJSONLD(document, []string{
		"/credentialSubject/profile",
		"/credentialSubject/profile",
		"/credentialSubject/profile",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(repeated, once) {
		t.Fatalf("repeated selection = %#v, want %#v", repeated, once)
	}
}

func TestSelectJSONLDEscapesPointerTokens(t *testing.T) {
	document := map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"a/b": map[string]interface{}{"~key": "value"},
		},
	}

	got, err := SelectJSONLD(document, []string{"/credentialSubject/a~1b/~0key"})
	if err != nil {
		t.Fatal(err)
	}
	subject := got["credentialSubject"].(map[string]interface{})
	if subject["a/b"].(map[string]interface{})["~key"] != "value" {
		t.Fatalf("escaped selection = %#v", got)
	}
}

func TestSelectJSONLDTreatsNumericObjectKeysAsObjectKeys(t *testing.T) {
	document := map[string]interface{}{
		"credentialSubject": map[string]interface{}{"0": "Alice"},
	}
	got, err := SelectJSONLD(document, []string{"/credentialSubject/0"})
	if err != nil {
		t.Fatal(err)
	}
	if got["credentialSubject"].(map[string]interface{})["0"] != "Alice" {
		t.Fatalf("numeric object-key selection = %#v", got)
	}
}

func TestSelectJSONLDHandlesRootAndMissingPointers(t *testing.T) {
	document := map[string]interface{}{"name": "Alice"}
	root, err := SelectJSONLD(document, []string{""})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(root, document) {
		t.Fatalf("root selection = %#v, want %#v", root, document)
	}
	root["name"] = "Changed"
	if document["name"] != "Alice" {
		t.Fatal("root selection mutated the source document")
	}

	if _, err := SelectJSONLD(document, []string{"/missing"}); err == nil {
		t.Fatal("missing pointer error = nil")
	}
}

func TestArrayIndexRejectsOverflowAndNonCanonicalTokens(t *testing.T) {
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
		{"9223372036854775807", 9223372036854775807, true},
		{"9223372036854775808", 0, false},
		{"99999999999999999999999", 0, false},
	}
	for _, tc := range cases {
		got, ok := arrayIndex(tc.token)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("arrayIndex(%q) = (%d, %v), want (%d, %v)", tc.token, got, ok, tc.want, tc.ok)
		}
	}
}

func TestSelectJSONLDRejectsOverflowingArrayIndex(t *testing.T) {
	document := map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"items": []interface{}{"a", "b"},
		},
	}
	for _, pointer := range []string{
		"/credentialSubject/items/9223372036854775808",
		"/credentialSubject/items/18446744073709551617",
		"/credentialSubject/items/2",
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("SelectJSONLD(%q) panicked: %v", pointer, r)
				}
			}()
			if _, err := SelectJSONLD(document, []string{pointer}); err == nil {
				t.Fatalf("SelectJSONLD(%q) succeeded, want error", pointer)
			}
		}()
	}
}

func TestSelectJSONLDRejectsPointerWithoutLeadingSlash(t *testing.T) {
	document := map[string]interface{}{
		"name": "top-level",
		"credentialSubject": map[string]interface{}{
			"name": "nested",
		},
	}
	for _, pointer := range []string{"name", "credentialSubject/name"} {
		if got, err := SelectJSONLD(document, []string{pointer}); err == nil {
			t.Fatalf("SelectJSONLD(%q) = %v, want error", pointer, got)
		}
	}
}

func TestSelectJSONLDNestedPointersSelectTheOutermostOnce(t *testing.T) {
	document := map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"tags": []interface{}{"a", "b", "c"},
			"profile": map[string]interface{}{
				"name": "Alice",
				"role": "member",
			},
		},
	}
	want, err := SelectJSONLD(document, []string{"/credentialSubject"})
	if err != nil {
		t.Fatal(err)
	}
	for name, pointers := range map[string][]string{
		"outer first": {"/credentialSubject", "/credentialSubject/profile", "/credentialSubject/profile/name", "/credentialSubject/tags/1"},
		"outer last":  {"/credentialSubject/tags/1", "/credentialSubject/profile/name", "/credentialSubject/profile", "/credentialSubject"},
	} {
		got, err := SelectJSONLD(document, pointers)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: selection = %#v, want %#v", name, got, want)
		}
	}

	if got, err := SelectJSONLD(document, []string{"", "credentialSubject"}); err != nil || !reflect.DeepEqual(got, document) {
		t.Fatalf("root pointer before a malformed one = %#v, %v; want the whole document", got, err)
	}

	_, err = SelectJSONLD(document, []string{"/credentialSubject", "/credentialSubject/missing"})
	if err == nil || !strings.Contains(err.Error(), `"/credentialSubject/missing"`) {
		t.Fatalf("pointer under a selected one that matches nothing: error = %v, want it named", err)
	}
}

// A chain /a, /a/a, /a/a/a, ... over a large leaf copied the leaf once per
// pointer: these 200 pointers over 16384 leaf members allocated 257 MiB.
func TestSelectJSONLDCopiesNestedSelectionOnce(t *testing.T) {
	const depth = 200
	leaf := make(map[string]interface{}, 16<<10)
	for i := 0; i < 16<<10; i++ {
		leaf["k"+strconv.Itoa(i)] = "v"
	}
	var node interface{} = leaf
	for i := 0; i < depth; i++ {
		node = map[string]interface{}{"a": node}
	}
	document := map[string]interface{}{"a": node}
	pointers := make([]string, 0, depth)
	for i, pointer := 0, ""; i < depth; i++ {
		pointer += "/a"
		pointers = append(pointers, pointer)
	}

	if allocated := allocatedBySelect(t, document, pointers, false); allocated > 64<<20 {
		t.Fatalf("allocated %d MiB for one copy of the leaf, want at most 64", allocated>>20)
	}
}

// The same pointer listed 200 times over a leaf of 16384 members must copy
// the leaf once, not once per listing.
func TestSelectJSONLDCopiesRepeatedPointerOnce(t *testing.T) {
	leaf := make(map[string]interface{}, 16<<10)
	for i := 0; i < 16<<10; i++ {
		leaf["k"+strconv.Itoa(i)] = "v"
	}
	pointers := make([]string, 200)
	for i := range pointers {
		pointers[i] = "/a"
	}
	document := map[string]interface{}{"a": leaf}
	if allocated := allocatedBySelect(t, document, pointers, false); allocated > 64<<20 {
		t.Fatalf("allocated %d MiB for one copy of the leaf, want at most 64", allocated>>20)
	}
}

// A pointer of 1 MiB of "/" names one million empty members. Indexing every
// token of it before checking the document allocated about 300 MiB.
func TestSelectJSONLDBoundsAPointerThatMatchesNothing(t *testing.T) {
	pointers := []string{strings.Repeat("/", 1<<20)}
	if allocated := allocatedBySelect(t, map[string]interface{}{}, pointers, true); allocated > 64<<20 {
		t.Fatalf("allocated %d MiB for a pointer that matches nothing, want at most 64", allocated>>20)
	}
}

func allocatedBySelect(t *testing.T, document map[string]interface{}, pointers []string, wantErr bool) uint64 {
	t.Helper()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := SelectJSONLD(document, pointers)
	runtime.ReadMemStats(&after)
	if (err != nil) != wantErr {
		t.Fatalf("SelectJSONLD error = %v, want error %v", err, wantErr)
	}
	return after.TotalAlloc - before.TotalAlloc
}
