package sdjwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func encodeDisclosureForTest(t *testing.T, arr []interface{}) string {
	t.Helper()
	b, err := json.Marshal(arr)
	if err != nil {
		t.Fatalf("failed to marshal disclosure: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestParseDisclosure_ValidObjectField(t *testing.T) {
	disc := encodeDisclosureForTest(t, []interface{}{"salt-1", "name", "Alice"})

	info, err := parseDisclosure(disc)
	if err != nil {
		t.Fatalf("parseDisclosure failed: %v", err)
	}

	if info.salt != "salt-1" {
		t.Fatalf("expected salt salt-1, got %q", info.salt)
	}
	if info.objectField != "name" {
		t.Fatalf("expected field name, got %q", info.objectField)
	}
	if info.isArrayElem {
		t.Fatal("expected object-field disclosure, got array disclosure")
	}
	if v, ok := info.value.(string); !ok || v != "Alice" {
		t.Fatalf("expected value Alice, got %#v", info.value)
	}
}

func TestParseDisclosure_ValidArrayElement(t *testing.T) {
	disc := encodeDisclosureForTest(t, []interface{}{"salt-2", 42.0})

	info, err := parseDisclosure(disc)
	if err != nil {
		t.Fatalf("parseDisclosure failed: %v", err)
	}

	if !info.isArrayElem {
		t.Fatal("expected array-element disclosure")
	}
	if info.objectField != "" {
		t.Fatalf("expected empty objectField, got %q", info.objectField)
	}
}

func TestParseDisclosure_InvalidShapes(t *testing.T) {
	tests := []struct {
		name    string
		disc    string
		wantErr string
	}{
		{name: "invalid-base64", disc: "not-base64@", wantErr: "failed to decode disclosure"},
		{name: "invalid-json", disc: base64.RawURLEncoding.EncodeToString([]byte("{")), wantErr: "failed to unmarshal disclosure"},
		{name: "invalid-len", disc: encodeDisclosureForTest(t, []interface{}{"only-one"}), wantErr: "invalid disclosure structure"},
		{name: "salt-not-string", disc: encodeDisclosureForTest(t, []interface{}{1.0, "name", "Alice"}), wantErr: "salt must be a string"},
		{name: "field-not-string", disc: encodeDisclosureForTest(t, []interface{}{"salt", 1.0, "Alice"}), wantErr: "field name must be a string"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseDisclosure(tc.disc)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestHashDisclosure_UnsupportedAlgorithm(t *testing.T) {
	_, err := hashDisclosure("sha-999", "abc")
	if err == nil {
		t.Fatal("expected error for unsupported hash algorithm")
	}
	if !strings.Contains(err.Error(), "unsupported sd_alg") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildSDJWTPresentation_SkipEmptyDisclosure(t *testing.T) {
	got := BuildSDJWTPresentation("a.b.c", []string{"d1", "", "d2"})
	if got != "a.b.c~d1~d2~" {
		t.Fatalf("unexpected presentation: %q", got)
	}
}

func TestIsSDJWT(t *testing.T) {
	jwt := "aaa.bbb.ccc"
	sd := jwt + "~D1~D2~"

	assert.False(t, IsSDJWT(""), "empty string is not SD-JWT")
	assert.False(t, IsSDJWT(jwt), "plain JWT is not SD-JWT")
	assert.True(t, IsSDJWT(sd), "JWT with disclosures and '~' should be SD-JWT")
	assert.False(t, IsSDJWT("not-a-jwt~something~"), "invalid JWT prefix should not be SD-JWT")
}

func TestParseSDJWT(t *testing.T) {
	jwt := "aaa.bbb.ccc"
	arr1 := []interface{}{"salt1", "name", "Alice"}
	arr2 := []interface{}{"salt2", "age", float64(30)}
	b1, _ := json.Marshal(arr1)
	b2, _ := json.Marshal(arr2)
	d1 := base64.RawURLEncoding.EncodeToString(b1)
	d2 := base64.RawURLEncoding.EncodeToString(b2)

	sd := jwt + "~" + d1 + "~" + d2 + "~"

	parsed, err := Parse(sd)
	require.NoError(t, err)
	assert.Equal(t, jwt, parsed.BaseJWT)
	assert.Equal(t, []string{d1, d2}, parsed.Disclosures)
	assert.Len(t, parsed.DecodedDisclosures, 2)
}

func TestCreatePresentation(t *testing.T) {
	issuerJWT := "header.payload.sig"
	all := []string{"D1", "D2", "D3"}

	full := BuildSDJWTPresentation(issuerJWT, all)
	assert.Equal(t, "header.payload.sig~D1~D2~D3~", full)

	subset := BuildSDJWTPresentation(issuerJWT, []string{all[0], all[2]})
	assert.Equal(t, "header.payload.sig~D1~D3~", subset)

	none := BuildSDJWTPresentation(issuerJWT, nil)
	assert.Equal(t, "header.payload.sig", none)

	empty := BuildSDJWTPresentation(issuerJWT, []string{"", "D1", ""})
	assert.Equal(t, "header.payload.sig~D1~", empty)
}

func TestPresentation(t *testing.T) {
	arr1 := []interface{}{"salt1", "firstname", "John"}
	arr2 := []interface{}{"salt2", "lastname", "Doe"}
	b1, _ := json.Marshal(arr1)
	b2, _ := json.Marshal(arr2)
	d1 := base64.RawURLEncoding.EncodeToString(b1)
	d2 := base64.RawURLEncoding.EncodeToString(b2)

	sd := "aaa.bbb.ccc~" + d1 + "~" + d2 + "~"
	parsed, err := Parse(sd)
	require.NoError(t, err)

	assert.Equal(t, "aaa.bbb.ccc", parsed.BaseJWT)
	assert.Equal(t, []string{d1, d2}, parsed.Disclosures)

	out := BuildSDJWTPresentation(parsed.BaseJWT, []string{d1})
	assert.Equal(t, "aaa.bbb.ccc~"+d1+"~", out)
}

// Test Parse edge case: last segment is JWT-like without trailing ~
func TestParse_LastSegmentJWTLike(t *testing.T) {
	// "aaa.bbb.ccc~xxx.yyy.zzz" - the last segment looks like JWT
	// but without trailing ~, should be treated as disclosure (not holder binding)
	jwt := "aaa.bbb.ccc"
	// Create a disclosure that when parsed produces JWT-like string after decoding
	// Valid disclosure format: ["salt", "field", "value"]
	arr := []interface{}{"salt", "sub", "123"}
	b, _ := json.Marshal(arr)
	disclosure := base64.RawURLEncoding.EncodeToString(b)

	sd := jwt + "~" + disclosure
	parsed, err := Parse(sd)
	require.NoError(t, err)

	assert.Equal(t, jwt, parsed.BaseJWT)
	assert.Contains(t, parsed.Disclosures, disclosure)
}

// Test Parse with holder binding JWT at end (proper format)
func TestParse_WithHolderBindingJWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
	arr := []interface{}{"salt", "name", "Alice"}
	b, _ := json.Marshal(arr)
	d := base64.RawURLEncoding.EncodeToString(b)

	sd := jwt + "~" + d + "~"
	parsed, err := Parse(sd)
	require.NoError(t, err)

	assert.Equal(t, jwt, parsed.BaseJWT)
	assert.Equal(t, []string{d}, parsed.Disclosures)
}

// Test Parse with empty disclosure strings
func TestParse_EmptyDisclosureStrings(t *testing.T) {
	jwt := "aaa.bbb.ccc"
	sd := jwt + "~" + "~" + "~"

	parsed, err := Parse(sd)
	require.NoError(t, err)
	assert.Equal(t, jwt, parsed.BaseJWT)
	assert.Empty(t, parsed.Disclosures)
}

// Test appendSD with invalid _sd type
func TestAppendSD_InvalidType(t *testing.T) {
	m := map[string]interface{}{
		"_sd": 123, // invalid type
	}
	appendSD(m, "some-digest")
	_, isInt := m["_sd"].(int)
	assert.True(t, isInt, "_sd should remain unchanged")
}

// Test appendSD with []string type
func TestAppendSD_StringSlice(t *testing.T) {
	m := map[string]interface{}{
		"_sd": []string{"existing-hash"},
	}
	appendSD(m, "new-hash")
	sd, ok := m["_sd"].([]interface{})
	require.True(t, ok)
	assert.Len(t, sd, 2)
}
