package sdjwt

import (
	"errors"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// errorsOf are the sentinels every rejection must wrap.
var errorsOf = []error{
	ErrMalformed, ErrTooLarge, ErrReservedName, ErrDisclosureShape, ErrDuplicateDigest,
	ErrUnreferencedDisclosure, ErrClaimExists, ErrSDAlg,
}

func wrapsKnown(err error) bool {
	for _, target := range errorsOf {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

func FuzzParseDisclosure(f *testing.F) {
	for _, s := range []string{
		encodeDisclosure(`["salt","given_name","A"]`),
		encodeDisclosure(`["salt","VN"]`),
		encodeDisclosure(`["s","n",{"a":[1,{"b":null}]}]`),
		"WyJzIiwibiJd", "", "\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, encoded string) {
		d, err := ParseDisclosure(encoded)
		if err != nil {
			if !wrapsKnown(err) {
				t.Fatalf("error %v wraps no sentinel", err)
			}
			return
		}
		if d.Encoded != encoded || d.Digest != digestOf(encoded) {
			t.Fatalf("digest not over the received string")
		}
		if (d.ArrayElement && d.Name != "") || checkClaimName(d.Name) != nil {
			t.Fatalf("accepted %+v", d)
		}
	})
}

func FuzzSplit(f *testing.F) {
	f.Add(testJWT + "~D1~D2~")
	f.Add(testJWT + "~D1~a.b.c")
	f.Add("~~")
	f.Add("a.b.c")
	f.Fuzz(func(t *testing.T, compact string) {
		jwt, ds, kb, err := Limits{MaxBytes: 4096, MaxDisclosures: 16}.Split(compact)
		if err != nil {
			if !wrapsKnown(err) {
				t.Fatalf("error %v wraps no sentinel", err)
			}
			return
		}
		joined := jwt + "~" + strings.Join(ds, "~")
		if len(ds) > 0 {
			joined += "~"
		}
		if joined+kb != compact || len(ds) > 16 {
			t.Fatalf("split %q into %q %q %q", compact, jwt, ds, kb)
		}
		for _, d := range ds {
			if d == "" || strings.Contains(d, "~") {
				t.Fatalf("disclosure %q", d)
			}
		}
	})
}

// FuzzRecreate feeds a payload and ~-separated disclosures; Recreate must
// either refuse them with a sentinel or return claims with no _sd, _sd_alg or
// placeholder left.
func FuzzRecreate(f *testing.F) {
	for _, v := range loadPyVectors(f) {
		raw, _ := jose.EncodeJSON(v.payload)
		f.Add(string(raw), strings.Join(v.presented, "~"))
	}
	given, givenDigest := digestOfJSON(`["s1","given_name","A"]`)
	f.Add(`{"_sd":["`+givenDigest+`"],"a":[{"...":"`+givenDigest+`"}]}`, given)
	f.Fuzz(func(t *testing.T, payloadJSON, disclosures string) {
		payload, err := jose.DecodeJSONObject([]byte(payloadJSON))
		if err != nil {
			return
		}
		var ds []Disclosure
		if disclosures != "" {
			for _, e := range strings.Split(disclosures, "~") {
				ds = append(ds, Disclosure{Encoded: e})
			}
		}
		r, err := Limits{MaxDisclosures: 64}.Recreate(payload, ds)
		if err != nil {
			if !wrapsKnown(err) {
				t.Fatalf("error %v wraps no sentinel", err)
			}
			return
		}
		var check func(v any)
		check = func(v any) {
			switch x := v.(type) {
			case map[string]any:
				for k, c := range x {
					if k == keySD || k == keySDAlg || k == keyEllipsis {
						t.Fatalf("%q left in %v", k, r.Claims)
					}
					check(c)
				}
			case []any:
				for _, c := range x {
					check(c)
				}
			}
		}
		check(r.Claims)
	})
}
