package sdjwt

import (
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/jose"
)

func roundTripClaims() map[string]any {
	return map[string]any{
		"iss":            "https://issuer.example",
		"given_name":     "Ana",
		"address":        map[string]any{"street": "1 Main St", "locality": "Hanoi"},
		"nationalities":  []any{"VN", "FR"},
		"place_of_birth": map[string]any{"country": "VN"},
	}
}

// Conceal an object property, an array element and a path nested in another
// concealed claim, with MinDigests 3, with and without decoys in arrays;
// Recreate with every disclosure gives the claims back, and the caller's map
// is left as it was.
func TestConcealRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		opts         ConcealOptions
		placeholders int // in nationalities, which has 1 concealed element
	}{
		{ConcealOptions{MinDigests: 3}, 3},
		{ConcealOptions{MinDigests: 3, NoArrayDecoys: true}, 1},
	} {
		t.Run(strconv.FormatBool(tc.opts.NoArrayDecoys), func(t *testing.T) {
			testConcealRoundTrip(t, tc.opts, tc.placeholders)
		})
	}
}

func testConcealRoundTrip(t *testing.T, opts ConcealOptions, placeholders int) {
	claims := roundTripClaims()
	paths := []Path{{"given_name"}, {"address"}, {"address", "locality"}, {"nationalities", 1}}
	payload, ds, err := Conceal(claims, paths, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(claims, roundTripClaims()) {
		t.Fatalf("Conceal modified its input: %v", claims)
	}
	if len(ds) != len(paths) {
		t.Fatalf("%d disclosures, want %d", len(ds), len(paths))
	}
	if payload["_sd_alg"] != "sha-256" {
		t.Errorf("_sd_alg %v", payload["_sd_alg"])
	}

	// Every object holds max(concealed, 3) digests in _sd, sorted, and every
	// array max(concealed, 3) placeholders, or only the concealed ones
	// without array decoys: 2 concealed at the top, none in
	// place_of_birth, 1 in the value of the address disclosure, 1 in
	// nationalities.
	var sdLens, placeholderLens []int
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			sd, _ := x["_sd"].([]any)
			if !slices.IsSortedFunc(sd, func(a, b any) int { return strings.Compare(a.(string), b.(string)) }) {
				t.Errorf("_sd not sorted: %v", sd)
			}
			sdLens = append(sdLens, len(sd))
			for k, child := range x {
				if k != "_sd" {
					walk(child)
				}
			}
		case []any:
			n := 0
			for _, el := range x {
				if _, ok := placeholder(el); ok {
					n++
				} else {
					walk(el)
				}
			}
			placeholderLens = append(placeholderLens, n)
		}
	}
	walk(payload)
	for _, d := range ds {
		walk(d.Value)
	}
	if !slices.Equal(sdLens, []int{3, 3, 3}) || !slices.Equal(placeholderLens, []int{placeholders}) {
		t.Errorf("_sd lengths %v, placeholder counts %v; want [3 3 3] and [%d]", sdLens, placeholderLens, placeholders)
	}

	r, err := Recreate(payload, ds)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Claims, roundTripClaims()) {
		t.Errorf("recreated %v", r.Claims)
	}
}

// Caller mistakes that would produce an SD-JWT a verifier misreads or refuses.
func TestConcealRejects(t *testing.T) {
	// 21 objects and arrays (the claims, "a" and 19 elements) × 1000 decoys.
	wide := make([]any, 19)
	for i := range wide {
		wide[i] = map[string]any{}
	}
	many := map[string]any{}
	var manyPaths []Path
	for i := range 1001 {
		name := strconv.Itoa(i)
		many[name] = i
		manyPaths = append(manyPaths, Path{name})
	}
	for _, tc := range []struct {
		name   string
		claims map[string]any
		paths  []Path
		opts   ConcealOptions
	}{
		// §4.1 rule 7: an _sd in the input would read as digests.
		{"_sd in claims", map[string]any{"a": map[string]any{"_sd": []any{"x"}}}, nil, ConcealOptions{}},
		{"MinDigests 1001", map[string]any{"a": 1}, nil, ConcealOptions{MinDigests: 1001}},
		{"21 containers × MinDigests 1000", map[string]any{"a": wide}, nil, ConcealOptions{MinDigests: 1000}},
		{"1001 paths", many, manyPaths, ConcealOptions{}},
		// {"A"} goes first and gives the claims object an _sd, which {"_sd"}
		// must not then conceal.
		{"path to an _sd Conceal made", map[string]any{"A": 1}, []Path{{"A"}, {"_sd"}}, ConcealOptions{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := Conceal(tc.claims, tc.paths, tc.opts); !errors.Is(err, jose.ErrInvalidArgument) {
				t.Fatalf("got %v, want jose.ErrInvalidArgument", err)
			}
		})
	}
}
