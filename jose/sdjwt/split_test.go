package sdjwt

import (
	"slices"
	"strings"
	"testing"
)

const testJWT = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ4In0.c2ln"

func TestSplit(t *testing.T) {
	kb := "a.b.c"
	for _, tc := range []struct {
		name    string
		compact string
		ds      []string
		kb      string
	}{
		{"no disclosures", testJWT + "~", nil, ""},
		{"issuance", testJWT + "~D1~D2~", []string{"D1", "D2"}, ""},
		{"presentation with KB-JWT", testJWT + "~D1~" + kb, []string{"D1"}, kb},
		{"KB-JWT only", testJWT + "~" + kb, nil, kb},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jwt, ds, gotKB, err := Split(tc.compact)
			mustNoErr(t, err)
			if jwt != testJWT || !slices.Equal(ds, tc.ds) || gotKB != tc.kb {
				t.Fatalf("got %q %q %q", jwt, ds, gotKB)
			}
		})
	}
}

func TestSplitRejects(t *testing.T) {
	for _, tc := range []struct {
		name    string
		compact string
		want    error
	}{
		{"plain JWT", testJWT, ErrMalformed},
		{"empty", "", ErrMalformed},
		{"issuer JWT of two parts", "a.b~D1~", ErrMalformed},
		{"issuer JWT with an empty part", "a..c~D1~", ErrMalformed},
		{"empty issuer JWT", "~D1~", ErrMalformed},
		{"empty disclosure", testJWT + "~D1~~D2~", ErrMalformed},
		{"empty disclosure first", testJWT + "~~D1~", ErrMalformed},
		{"duplicate disclosure", testJWT + "~D1~D2~D1~", ErrMalformed},
		{"missing trailing ~", testJWT + "~D1", ErrMalformed},
		{"KB-JWT of four parts", testJWT + "~D1~a.b.c.d", ErrMalformed},
		{"too many disclosures", testJWT + "~" + strings.Repeat("D~", DefaultMaxDisclosures+1), ErrTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := Split(tc.compact)
			wantErr(t, err, tc.want)
		})
	}
}

// Size is checked before anything else: an oversized input is ErrTooLarge
// even when it is also malformed.
func TestSplitSizeLimit(t *testing.T) {
	_, _, _, err := Split(strings.Repeat("x", DefaultMaxBytes+1))
	wantErr(t, err, ErrTooLarge)

	ok := testJWT + "~D1~D2~"
	_, _, _, err = Limits{MaxBytes: len(ok)}.Split(ok)
	mustNoErr(t, err)
	_, _, _, err = Limits{MaxBytes: len(ok) - 1}.Split(ok)
	wantErr(t, err, ErrTooLarge)
	_, _, _, err = Limits{MaxDisclosures: 1}.Split(ok)
	wantErr(t, err, ErrTooLarge)
}
