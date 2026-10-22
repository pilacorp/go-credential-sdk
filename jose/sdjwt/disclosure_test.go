package sdjwt

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// Every digest/disclosure pair listed in RFC 9901 section 5 and Appendix A,
// some with non-ASCII values written as \uXXXX by the issuer.
func TestParseDisclosureRFCDigests(t *testing.T) {
	n := 0
	for _, ex := range loadRFCExamples(t) {
		for _, pair := range ex.digests {
			d, err := ParseDisclosure(pair[1])
			if err != nil {
				t.Fatalf("%s: %v", ex.name, err)
			}
			if d.Digest != pair[0] || d.Encoded != pair[1] {
				t.Fatalf("%s: digest %s, want %s", ex.name, d.Digest, pair[0])
			}
			n++
		}
	}
	if n != 77 {
		t.Fatalf("checked %d pairs, want 77", n)
	}
}

// The same value written three ways (RFC 9901 Appendix B) gives one value
// and three digests, each over the string as received.
func TestDigestOverReceivedString(t *testing.T) {
	escaped := `["salt", "family_name", "M` + "\\" + `u00f6bius"]`
	encodings := []string{
		encodeDisclosure(`["salt","family_name","Möbius"]`),
		encodeDisclosure(`["salt", "family_name", "Möbius"]`),
		encodeDisclosure(escaped),
	}
	seen := map[string]bool{}
	for _, e := range encodings {
		d, err := ParseDisclosure(e)
		mustNoErr(t, err)
		if d.Value != "Möbius" || d.Name != "family_name" || d.Salt != "salt" {
			t.Fatalf("decoded %+v", d)
		}
		sum := sha256.Sum256([]byte(e))
		if d.Digest != jose.EncodeSegment(sum[:]) {
			t.Fatalf("digest %s is not SHA-256 of the received string", d.Digest)
		}
		seen[d.Digest] = true
	}
	if len(seen) != 3 {
		t.Fatalf("%d distinct digests, want 3", len(seen))
	}
}

func TestParseDisclosureKinds(t *testing.T) {
	prop := mustParse(t, encodeDisclosure(`["s","given_name",{"a":1}]`))[0]
	if prop.ArrayElement || prop.Name != "given_name" {
		t.Fatalf("object property read as %+v", prop)
	}
	assertJSONEqual(t, prop.Value, mustObject(t, `{"a":1}`))

	elem := mustParse(t, encodeDisclosure(`["s","VN"]`))[0]
	if !elem.ArrayElement || elem.Name != "" || elem.Value != "VN" {
		t.Fatalf("array element read as %+v", elem)
	}

	// "" is a valid claim name: still an object property.
	empty := mustParse(t, encodeDisclosure(`["s","","x"]`))[0]
	if empty.ArrayElement || empty.Name != "" || empty.Value != "x" {
		t.Fatalf("property with empty name read as %+v", empty)
	}
}

func TestParseDisclosureRejects(t *testing.T) {
	valid := encodeDisclosure(`["salt","given_name","A"]`)
	for _, tc := range []struct {
		name    string
		encoded string
		want    error
	}{
		{"line break", valid[:10] + "\n" + valid[10:], jose.ErrMalformed},
		{"carriage return", valid[:10] + "\r" + valid[10:], jose.ErrMalformed},
		{"non-zero trailing bits", withTrailingBit(t, encodeDisclosure(`["salt","n","v"]`)), jose.ErrMalformed},
		{"padding", encodeDisclosure(`["salt","n","v"]`) + "=", jose.ErrMalformed},
		{"empty", "", ErrMalformed},
		{"not JSON", encodeDisclosure(`salt`), ErrMalformed},
		{"trailing data", encodeDisclosure(`["s","n","v"] 1`), ErrMalformed},
		{"invalid UTF-8", encodeDisclosure("[\"s\",\"n\",\"\xff\"]"), ErrMalformed},
		{"duplicate key in value", encodeDisclosure(`["s","n",{"a":1,"a":2}]`), ErrMalformed},
		{"duplicate key deep in value", encodeDisclosure(`["s","n",[{"b":{"_sd":[],"_sd":[]}}]]`), ErrMalformed},
		{"object", encodeDisclosure(`{"salt":"s"}`), ErrDisclosureShape},
		{"string", encodeDisclosure(`"s"`), ErrDisclosureShape},
		{"empty array", encodeDisclosure(`[]`), ErrDisclosureShape},
		{"one item", encodeDisclosure(`["s"]`), ErrDisclosureShape},
		{"four items", encodeDisclosure(`["s","n","v","x"]`), ErrDisclosureShape},
		{"salt not a string (3 items)", encodeDisclosure(`[1,"n","v"]`), ErrDisclosureShape},
		{"salt not a string (2 items)", encodeDisclosure(`[null,"v"]`), ErrDisclosureShape},
		{"name not a string", encodeDisclosure(`["s",1,"v"]`), ErrDisclosureShape},
		{"name _sd", encodeDisclosure(`["s","_sd",["x"]]`), ErrReservedName},
		{"name ...", encodeDisclosure(`["s","...","x"]`), ErrReservedName},
		{"name _sd_alg", encodeDisclosure(`["s","_sd_alg","sha-256"]`), ErrReservedName},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseDisclosure(tc.encoded)
			wantErr(t, err, tc.want)
		})
	}
}

// withTrailingBit sets a non-zero bit in the unused low bits of the last
// character, the other spelling of the same bytes that strict decoding
// refuses.
func withTrailingBit(t *testing.T, s string) string {
	t.Helper()
	if len(s)%4 == 0 {
		t.Fatalf("%q has no trailing bits", s)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	i := strings.IndexByte(alphabet, s[len(s)-1])
	return s[:len(s)-1] + string(alphabet[i|1])
}
