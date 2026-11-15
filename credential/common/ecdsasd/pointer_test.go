package ecdsasd

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// #183: a pointer without a leading "/" was read as the root pointer "", so a
// holder who wrote "credentialSubject" disclosed every statement, and one who
// wrote "x/validFrom" disclosed /validFrom. RFC 6901 §3 starts every reference
// token with "/", so these are errors.
func TestSelectJsonLdRefusesAPointerWithoutLeadingSlash(t *testing.T) {
	cred := w3cCred(t)
	for _, pointer := range []string{"credentialSubject", "credentialSubject/sailNumber", "x/validFrom"} {
		got, err := selectJsonLd(cred, []string{"/issuer", pointer})
		if err == nil || !strings.Contains(err.Error(), "must start with /") {
			t.Errorf("%q: selection %v, error %v; want a leading-slash error", pointer, got != nil, err)
		}
	}
}

// The two entry points that take pointers from a caller refuse one without a
// leading "/" before anything is disclosed or signed.
func TestProofsRefuseAPointerWithoutLeadingSlash(t *testing.T) {
	cred := w3cCred(t)
	exp := w3cLoadExpected(t)

	if _, _, err := DeriveProof(cred, exp.BaseProofValue, []string{"credentialSubject"}); err == nil {
		t.Error("DeriveProof: error = nil, want a leading-slash error")
	}

	proofConfig := w3cProofConfig(exp, cred["@context"])
	if _, err := CreateBaseProof(cred, proofConfig, []string{"credentialSubject"}, unreachableSigner{}); err == nil ||
		!strings.Contains(err.Error(), "must start with /") {
		t.Errorf("CreateBaseProof: error = %v, want a leading-slash error", err)
	}
}

// unreachableSigner fails the test's expectation if signing is reached.
type unreachableSigner struct{}

func (unreachableSigner) Sign([]byte) ([]byte, error) {
	return nil, errors.New("signing reached: the pointer was not refused first")
}

// VC-DI-ECDSA §3.4.12: a pointer that matches nothing is an error, whatever its
// place next to the root pointer.
func TestSelectJsonLdRootPointerStillChecksTheOthers(t *testing.T) {
	document := map[string]interface{}{"name": "Alice"}
	for _, pointers := range [][]string{{"", "/missing"}, {"/missing", ""}} {
		if _, err := selectJsonLd(document, pointers); err == nil {
			t.Errorf("%q: error = nil, want a missing pointer error", pointers)
		}
	}

	got, err := selectJsonLd(document, []string{"", "/name"})
	if err != nil || !reflect.DeepEqual(got, document) {
		t.Errorf(`["", "/name"] = %v, %v; want the whole document`, got, err)
	}
}

// Densifying removes the holes the selection leaves in an array. A null the
// document holds is data and stays.
func TestSelectJsonLdKeepsNullArrayItems(t *testing.T) {
	document := map[string]interface{}{"list": []interface{}{"a", nil, "b"}}
	cases := map[string]interface{}{
		"/list":   []interface{}{"a", nil, "b"},
		"/list/1": []interface{}{nil},
		"/list/2": []interface{}{"b"},
	}
	for pointer, want := range cases {
		got, err := selectJsonLd(document, []string{pointer})
		if err != nil {
			t.Fatalf("%s: %v", pointer, err)
		}
		if !reflect.DeepEqual(got["list"], want) {
			t.Errorf("%s: list = %#v, want %#v", pointer, got["list"], want)
		}
	}
}

// A later pointer can fill a hole an earlier one left: /a/1/x first leaves a
// hole at /a/0, which /a/0/y then fills. Treating the hole as a selected value
// drops /a/0/y without an error.
func TestSelectJsonLdFillsAHoleALaterPointerReaches(t *testing.T) {
	document := map[string]interface{}{"a": []interface{}{
		map[string]interface{}{"y": "Y0", "secret": "s0"},
		map[string]interface{}{"x": "X1", "secret": "s1"},
	}}
	want := []interface{}{map[string]interface{}{"y": "Y0"}, map[string]interface{}{"x": "X1"}}

	for _, pointers := range [][]string{{"/a/0/y", "/a/1/x"}, {"/a/1/x", "/a/0/y"}} {
		got, err := selectJsonLd(document, pointers)
		if err != nil {
			t.Fatalf("%q: %v", pointers, err)
		}
		if !reflect.DeepEqual(got["a"], want) {
			t.Errorf("%q: a = %#v, want %#v", pointers, got["a"], want)
		}
	}
}

// A pointer can come from a base proof, so an error quotes only its start: a
// 1 MB pointer must not make a 1 MB error.
func TestSelectJsonLdErrorsQuoteOnlyTheStartOfAPointer(t *testing.T) {
	long := strings.Repeat("a", 1<<20)
	document := map[string]interface{}{"a": map[string]interface{}{}}
	for name, pointers := range map[string][]string{
		"no leading slash":           {long},
		"missing next to the root":   {"", "/" + long},
		"missing member":             {"/" + long},
		"missing under selected one": {"/a", "/a/" + long},
	} {
		_, err := selectJsonLd(document, pointers)
		if err == nil || len(err.Error()) > 1024 {
			t.Errorf("%s: error = %.80v (%d bytes), want an error of at most 1024 bytes", name, err, len(fmt.Sprint(err)))
		}
	}
}
