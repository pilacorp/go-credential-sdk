package sdjwt

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// Conceal with each sd-jwt-python vector's salts and a Python-style Encode
// gives the same disclosures, byte for byte, and the same payload.
func TestConcealPythonVectors(t *testing.T) {
	for _, v := range loadPyVectors(t) {
		t.Run(v.name, func(t *testing.T) {
			claims := v.userClaims
			if v.keyBinding {
				// sd-jwt-python adds cnf after concealing; it is never concealed.
				claims["cnf"] = v.payload["cnf"]
			}
			payload, ds, err := Conceal(claims, v.paths, ConcealOptions{Salts: fixedSalts(v.salts), Encode: v.enc.encode})
			mustNoErr(t, err)
			assertJSONEqual(t, payload, v.payload)
			got := make([]string, len(ds))
			for i, d := range ds {
				got[i] = d.Encoded
			}
			slices.Sort(got)
			want := slices.Sorted(slices.Values(v.disclosures))
			if !slices.Equal(got, want) {
				t.Fatalf("disclosures\n got %q\nwant %q", got, want)
			}
		})
	}
}

func ageClaims() map[string]any {
	return map[string]any{
		"iss":               "https://issuer.example",
		"age_equal_or_over": map[string]any{"18": true, "21": true, "65": false},
		"nationalities":     []any{"VN", "US", "DE"},
	}
}

func agePaths() []Path {
	return []Path{
		{"age_equal_or_over"},
		{"age_equal_or_over", "18"},
		{"age_equal_or_over", "21"},
		{"age_equal_or_over", "65"},
		{"nationalities", 1},
	}
}

func ageSalts() SaltProvider {
	return fixedSalts(map[string]string{
		Path{"age_equal_or_over"}.key():       "salt-age",
		Path{"age_equal_or_over", "18"}.key(): "salt-18",
		Path{"age_equal_or_over", "21"}.key(): "salt-21",
		Path{"age_equal_or_over", "65"}.key(): "salt-65",
		Path{"nationalities", 1}.key():        "salt-us",
	})
}

func byName(ds []Disclosure) map[string]Disclosure {
	m := map[string]Disclosure{}
	for _, d := range ds {
		name := d.Name
		if d.ArrayElement {
			name = fmt.Sprint(d.Value)
		}
		m[name] = d
	}
	return m
}

// A child concealed together with its parent ends up inside the parent's
// disclosure, whatever the order of paths.
func TestConcealNestedDeepestFirst(t *testing.T) {
	payload, ds, err := Conceal(ageClaims(), agePaths(), ConcealOptions{Salts: ageSalts()})
	mustNoErr(t, err)
	if _, ok := payload["age_equal_or_over"]; ok {
		t.Fatal("concealed claim left in the payload")
	}
	m := byName(ds)
	age := m["age_equal_or_over"]
	inner, ok := age.Value.(map[string]any)
	if !ok || len(inner) != 1 {
		t.Fatalf("parent disclosure value %v, want only _sd", age.Value)
	}
	wantInner := []any{m["18"].Digest, m["21"].Digest, m["65"].Digest}
	slices.SortFunc(wantInner, func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
	assertJSONEqual(t, inner[keySD], wantInner)
	if !slices.Contains(payload[keySD].([]any), any(age.Digest)) {
		t.Fatal("parent digest not in the top-level _sd")
	}

	// Reversed input order: same payload, same disclosures.
	rev := slices.Clone(agePaths())
	slices.Reverse(rev)
	payload2, ds2, err := Conceal(ageClaims(), rev, ConcealOptions{Salts: ageSalts()})
	mustNoErr(t, err)
	assertJSONEqual(t, payload2, payload)
	assertJSONEqual(t, ds2, ds)
}

func TestConcealArrayElement(t *testing.T) {
	payload, ds, err := Conceal(ageClaims(), []Path{{"nationalities", 1}}, ConcealOptions{Salts: ageSalts()})
	mustNoErr(t, err)
	if len(ds) != 1 || !ds[0].ArrayElement || ds[0].Name != "" || ds[0].Value != "US" {
		t.Fatalf("disclosure %+v", ds)
	}
	raw, err := jose.DecodeSegment(ds[0].Encoded)
	mustNoErr(t, err)
	if string(raw) != `["salt-us","US"]` {
		t.Fatalf("disclosure JSON %s", raw)
	}
	assertJSONEqual(t, payload["nationalities"], []any{"VN", map[string]any{"...": ds[0].Digest}, "DE"})
	if _, ok := payload[keySD]; ok {
		t.Fatal("_sd added to an object with no concealed property")
	}
}

// Decoys go into every _sd array, including those inside disclosures, and
// never into arrays or objects with no concealed property.
func TestConcealDecoys(t *testing.T) {
	claims := map[string]any{
		"a": "x",
		"b": map[string]any{"c": 1, "d": 2},
		"e": []any{1, 2},
		"f": map[string]any{"x": 1},
		"g": map[string]any{"h": 1},
	}
	paths := []Path{{"a"}, {"b", "c"}, {"e", 0}, {"g"}, {"g", "h"}}
	payload, ds, err := Conceal(claims, paths, ConcealOptions{Decoys: 3, Salts: counterSalts()})
	mustNoErr(t, err)
	if n := len(payload[keySD].([]any)); n != 2+3 {
		t.Fatalf("top-level _sd has %d digests, want 2 real + 3 decoys", n)
	}
	if n := len(payload["b"].(map[string]any)[keySD].([]any)); n != 1+3 {
		t.Fatalf("nested _sd has %d digests, want 1 real + 3 decoys", n)
	}
	if n := len(payload["e"].([]any)); n != 2 {
		t.Fatalf("array has %d elements, want 2 (no decoys in arrays)", n)
	}
	if _, ok := payload["f"].(map[string]any)[keySD]; ok {
		t.Fatal("decoys added to an object with no concealed property")
	}
	g := byName(ds)["g"].Value.(map[string]any)
	if n := len(g[keySD].([]any)); n != 1+3 {
		t.Fatalf("_sd inside a disclosure has %d digests, want 1 real + 3 decoys", n)
	}
	// A decoy looks like a digest: 32 bytes of base64url.
	for _, d := range payload[keySD].([]any) {
		if b, err := jose.DecodeSegment(d.(string)); err != nil || len(b) != 32 {
			t.Fatalf("digest %v is not base64url of 32 bytes", d)
		}
	}
	// Recreate ignores the decoys.
	r, err := Recreate(payload, ds)
	mustNoErr(t, err)
	assertJSONEqual(t, r.Claims, mustObject(t, `{"a":"x","b":{"c":1,"d":2},"e":[1,2],"f":{"x":1},"g":{"h":1}}`))
}

// Every _sd array is sorted, so its order does not reveal the claims' order.
func TestConcealSortsSD(t *testing.T) {
	claims := map[string]any{"n": map[string]any{}}
	var paths []Path
	for i := range 8 {
		k := fmt.Sprintf("c%d", i)
		claims[k] = i
		claims["n"].(map[string]any)[k] = i
		paths = append(paths, Path{k}, Path{"n", k})
	}
	paths = append(paths, Path{"n"})
	payload, ds, err := Conceal(claims, paths, ConcealOptions{Salts: counterSalts()})
	mustNoErr(t, err)
	isSorted := func(v any) bool {
		return slices.IsSortedFunc(v.([]any), func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
	}
	if !isSorted(payload[keySD]) {
		t.Fatalf("top-level _sd not sorted: %v", payload[keySD])
	}
	if n := byName(ds)["n"].Value.(map[string]any)[keySD]; !isSorted(n) {
		t.Fatalf("_sd inside a disclosure not sorted: %v", n)
	}
}

func TestConcealSDAlg(t *testing.T) {
	payload, _, err := Conceal(ageClaims(), nil, ConcealOptions{})
	mustNoErr(t, err)
	if payload[keySDAlg] != "sha-256" {
		t.Fatalf("_sd_alg %v", payload[keySDAlg])
	}
	payload, ds, err := Conceal(ageClaims(), agePaths(), ConcealOptions{})
	mustNoErr(t, err)
	if payload[keySDAlg] != "sha-256" {
		t.Fatalf("_sd_alg %v", payload[keySDAlg])
	}
	if _, ok := byName(ds)["age_equal_or_over"].Value.(map[string]any)[keySDAlg]; ok {
		t.Fatal("_sd_alg below the top level")
	}
}

func TestConcealDefaultSalts(t *testing.T) {
	_, ds, err := Conceal(ageClaims(), agePaths(), ConcealOptions{})
	mustNoErr(t, err)
	seen := map[string]bool{}
	for _, d := range ds {
		b, err := jose.DecodeSegment(d.Salt)
		if err != nil || len(b) != 16 {
			t.Fatalf("salt %q is not 16 bytes of base64url", d.Salt)
		}
		if seen[d.Salt] {
			t.Fatalf("salt %q repeated", d.Salt)
		}
		seen[d.Salt] = true
	}
}

func TestConcealRejectsBadSalts(t *testing.T) {
	providerErr := errors.New("vault down")
	for _, tc := range []struct {
		name  string
		paths []Path
		salts SaltProvider
		want  error
	}{
		{"repeated", agePaths(), func(Path) (string, error) { return "same", nil }, ErrSalt},
		{"empty", []Path{{"iss"}}, func(Path) (string, error) { return "", nil }, ErrSalt},
		{"provider error", agePaths(), func(Path) (string, error) { return "", providerErr }, providerErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Conceal(ageClaims(), tc.paths, ConcealOptions{Salts: tc.salts})
			wantErr(t, err, tc.want)
		})
	}
}

// The default encoding is compact, without HTML escaping, with UTF-8 kept.
func TestConcealDefaultEncoding(t *testing.T) {
	claims := map[string]any{"name": `a<b>&"Nguyễn"`, "obj": map[string]any{"z": 1, "a": []any{true, nil}}}
	_, ds, err := Conceal(claims, []Path{{"name"}, {"obj"}}, ConcealOptions{Salts: counterSalts()})
	mustNoErr(t, err)
	want := map[string]string{
		"name": `["salt-001","name","a<b>&\"Nguyễn\""]`,
		"obj":  `["salt-002","obj",{"a":[true,null],"z":1}]`,
	}
	for _, d := range ds {
		raw, err := jose.DecodeSegment(d.Encoded)
		mustNoErr(t, err)
		if string(raw) != want[d.Name] {
			t.Fatalf("disclosure JSON %s, want %s", raw, want[d.Name])
		}
	}
}

func TestConcealRejects(t *testing.T) {
	claims := func() map[string]any {
		return map[string]any{
			"address":       map[string]any{"locality": "Hà Nội"},
			"nationalities": []any{"VN"},
		}
	}
	for _, tc := range []struct {
		name   string
		claims map[string]any
		paths  []Path
		want   error
	}{
		{"empty path", claims(), []Path{{}}, ErrInvalidPath},
		{"float element", claims(), []Path{{"nationalities", 0.0}}, ErrInvalidPath},
		{"nil element", claims(), []Path{{nil}}, ErrInvalidPath},
		{"negative index", claims(), []Path{{"nationalities", -1}}, ErrInvalidPath},
		{"missing key", claims(), []Path{{"address", "region"}}, ErrInvalidPath},
		{"string through an array", claims(), []Path{{"nationalities", "0"}}, ErrInvalidPath},
		{"int through an object", claims(), []Path{{"address", 0}}, ErrInvalidPath},
		{"index out of range", claims(), []Path{{"nationalities", 1}}, ErrInvalidPath},
		{"path given twice", claims(), []Path{{"address"}, {"nationalities"}, {"address"}}, ErrInvalidPath},
		{"_sd in claims", map[string]any{"a": []any{map[string]any{"_sd": []any{}}}}, nil, ErrReservedName},
		{"_sd_alg in claims", map[string]any{"a": map[string]any{"_sd_alg": "sha-256"}}, nil, ErrReservedName},
		{"... in claims", map[string]any{"a": []any{map[string]any{"...": "x"}}}, nil, ErrReservedName},
		{"_sd_alg at top level", map[string]any{"_sd_alg": "sha-256"}, nil, ErrReservedName},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Conceal(tc.claims, tc.paths, ConcealOptions{})
			wantErr(t, err, tc.want)
		})
	}
	if _, _, err := Conceal(claims(), nil, ConcealOptions{Decoys: -1}); err == nil {
		t.Fatal("negative Decoys accepted")
	}
}

func TestConcealKeepsCallerClaims(t *testing.T) {
	claims := ageClaims()
	before, _ := jose.EncodeJSON(claims)
	_, _, err := Conceal(claims, agePaths(), ConcealOptions{Decoys: 2})
	mustNoErr(t, err)
	after, _ := jose.EncodeJSON(claims)
	if string(before) != string(after) {
		t.Fatalf("claims modified:\n%s\n%s", before, after)
	}
}

// Claims are read through JSON, so typed Go values work like decoded ones.
func TestConcealGoValues(t *testing.T) {
	type address struct {
		Locality string `json:"locality"`
	}
	claims := map[string]any{"nationalities": []string{"VN", "US"}, "address": address{"Hà Nội"}}
	_, ds, err := Conceal(claims, []Path{{"nationalities", 1}, {"address", "locality"}}, ConcealOptions{})
	mustNoErr(t, err)
	if len(ds) != 2 {
		t.Fatalf("%d disclosures", len(ds))
	}
}
