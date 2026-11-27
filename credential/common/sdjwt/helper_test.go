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

	// A holder revealing nothing is still presenting an SD-JWT, and § 4 ends the
	// combined format with "~". Returning a bare JWT here made IsSDJWT say no, so
	// the digests were never folded out of the payload.
	none := BuildSDJWTPresentation(issuerJWT, nil)
	assert.Equal(t, "header.payload.sig~", none)

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
// RFC 9901 §4: an SD-JWT ends in "~", and without it the last segment is a
// Key Binding JWT, not a disclosure.
func TestParse_LastSegmentJWTLike(t *testing.T) {
	arr := []interface{}{"salt", "sub", "123"}
	b, _ := json.Marshal(arr)
	disclosure := base64.RawURLEncoding.EncodeToString(b)

	_, err := Parse("aaa.bbb.ccc~" + disclosure)
	require.Error(t, err)

	parsed, err := Parse("aaa.bbb.ccc~" + disclosure + "~")
	require.NoError(t, err)
	assert.Equal(t, "aaa.bbb.ccc", parsed.BaseJWT)
	assert.Equal(t, []string{disclosure}, parsed.Disclosures)
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
// RFC 9901 §4: an empty disclosure between two "~" is malformed.
func TestParse_EmptyDisclosureStrings(t *testing.T) {
	_, err := Parse("aaa.bbb.ccc~~~")
	require.Error(t, err)
}

// DecodeDisclosures must reject the reserved claim names "...", "_sd" and
// "_sd_alg". Before the fix it delegated to parseDisclosure, which does not
// check names. After the fix it delegates to jose/sdjwt.ParseDisclosure, which
// does. This is the regression test: it fails before the fix because
// DecodeDisclosures accepted the reserved names.
func TestDecodeDisclosures_RejectsReservedNames(t *testing.T) {
	for _, name := range []string{"...", "_sd", "_sd_alg"} {
		t.Run(name, func(t *testing.T) {
			disc := encodeDisclosureForTest(t, []interface{}{"salt", name, "value"})
			_, err := DecodeDisclosures([]string{disc})
			if err == nil {
				t.Fatalf("DecodeDisclosures accepted a disclosure named %q; want an error", name)
			}
			if !strings.Contains(err.Error(), "reserved") {
				t.Fatalf("error = %v, want it to mention 'reserved'", err)
			}
		})
	}
}
