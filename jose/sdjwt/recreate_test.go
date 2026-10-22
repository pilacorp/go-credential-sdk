package sdjwt

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// Recreate on each sd-jwt-python vector's presentation gives the expected
// verified claims; with every issued disclosure it succeeds too.
func TestRecreatePythonVectors(t *testing.T) {
	for _, v := range loadPyVectors(t) {
		t.Run(v.name, func(t *testing.T) {
			r, err := Recreate(v.payload, mustParse(t, v.presented...))
			mustNoErr(t, err)
			assertJSONEqual(t, r.Claims, v.expected)
			_, err = Recreate(v.payload, mustParse(t, v.disclosures...))
			mustNoErr(t, err)
		})
	}
}

// RFC 9901 section 5 and Appendix A: each presentation, checked with the key
// of Appendix A.5, recreates exactly the Processed SD-JWT Payload.
func TestRecreateRFCExamples(t *testing.T) {
	issuerKey := rfcIssuerKey(t)
	for _, ex := range loadRFCExamples(t) {
		t.Run(ex.name, func(t *testing.T) {
			issuerJWT, encoded, _, err := Split(ex.presentation)
			mustNoErr(t, err)
			_, raw, err := jose.Verify(issuerJWT, issuerKey, []string{jose.AlgES256})
			mustNoErr(t, err)
			payload, err := jose.DecodeJSONObject(raw)
			mustNoErr(t, err)
			r, err := Recreate(payload, mustParse(t, encoded...))
			mustNoErr(t, err)
			assertJSONEqual(t, r.Claims, ex.processed)
		})
	}
}

func digestOfJSON(jsonText string) (encoded, digest string) {
	encoded = encodeDisclosure(jsonText)
	return encoded, digestOf(encoded)
}

func TestRecreateRejects(t *testing.T) {
	given, givenDigest := digestOfJSON(`["s1","given_name","A"]`)
	given2, given2Digest := digestOfJSON(`["s2","given_name","B"]`)
	elem, elemDigest := digestOfJSON(`["s3","VN"]`)
	algInside, algInsideDigest := digestOfJSON(`["s4","a",{"_sd_alg":"sha-256"}]`)
	wrapper, wrapperDigest := digestOfJSON(fmt.Sprintf(`["s5","w",{"_sd":[%q]}]`, givenDigest))
	decoy := digestOf("decoy")

	for _, tc := range []struct {
		name        string
		payload     string
		disclosures []string
		want        error
	}{
		{"_sd not an array", `{"_sd":"x"}`, nil, ErrMalformed},
		{"_sd holds a number", `{"_sd":[1]}`, nil, ErrMalformed},
		{"_sd holds null", fmt.Sprintf(`{"_sd":[%q,null]}`, givenDigest), []string{given}, ErrMalformed},
		{"2-item disclosure from _sd", fmt.Sprintf(`{"_sd":[%q]}`, elemDigest), []string{elem}, ErrDisclosureShape},
		{"3-item disclosure from an array", fmt.Sprintf(`{"a":[{"...":%q}]}`, givenDigest), []string{given}, ErrDisclosureShape},
		{"name exists in plaintext", fmt.Sprintf(`{"given_name":"X","_sd":[%q]}`, givenDigest), []string{given}, ErrClaimExists},
		{"name disclosed twice", fmt.Sprintf(`{"_sd":[%q,%q]}`, givenDigest, given2Digest), []string{given, given2}, ErrClaimExists},
		{"... with another key in an array", fmt.Sprintf(`{"a":[{"...":%q,"x":1}]}`, elemDigest), []string{elem}, ErrReservedName},
		{"... outside an array", fmt.Sprintf(`{"a":{"...":%q}}`, elemDigest), []string{elem}, ErrReservedName},
		{"... holding a number", `{"a":[{"...":5}]}`, nil, ErrReservedName},
		{"nested _sd_alg", `{"a":{"_sd_alg":"sha-256"}}`, nil, ErrSDAlg},
		{"_sd_alg in a disclosed value", fmt.Sprintf(`{"_sd":[%q]}`, algInsideDigest), []string{algInside}, ErrSDAlg},
		{"top-level _sd_alg sha-512", `{"_sd_alg":"sha-512"}`, nil, ErrSDAlg},
		{"top-level _sd_alg not a string", `{"_sd_alg":1}`, nil, ErrSDAlg},
		{"same digest twice in _sd", fmt.Sprintf(`{"_sd":[%q,%q]}`, givenDigest, givenDigest), []string{given}, ErrDuplicateDigest},
		{"same decoy twice", fmt.Sprintf(`{"_sd":[%q],"a":{"_sd":[%q]}}`, decoy, decoy), nil, ErrDuplicateDigest},
		{"same placeholder twice", fmt.Sprintf(`{"a":[{"...":%q},{"...":%q}]}`, elemDigest, elemDigest), []string{elem}, ErrDuplicateDigest},
		{"digest in payload and in a disclosure", fmt.Sprintf(`{"_sd":[%q],"x":{"_sd":[%q]}}`, wrapperDigest, givenDigest), []string{wrapper, given}, ErrDuplicateDigest},
		{"same disclosure twice", fmt.Sprintf(`{"_sd":[%q]}`, givenDigest), []string{given, given}, ErrDuplicateDigest},
		{"unreferenced disclosure", `{"iss":"x"}`, []string{given}, ErrUnreferencedDisclosure},
		{"disclosure for a removed element only", `{"a":[1]}`, []string{elem}, ErrUnreferencedDisclosure},
		{"bad disclosure", `{}`, []string{"not base64!"}, ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Recreate(mustObject(t, tc.payload), mustDisclosures(tc.disclosures))
			wantErr(t, err, tc.want)
		})
	}
}

// mustDisclosures wraps encoded strings without parsing them, so Recreate
// itself must read them.
func mustDisclosures(encoded []string) []Disclosure {
	ds := make([]Disclosure, len(encoded))
	for i, e := range encoded {
		ds[i] = Disclosure{Encoded: e}
	}
	return ds
}

// Only Encoded counts: a caller-built Disclosure with other fields changed
// cannot smuggle a value in.
func TestRecreateReadsEncoded(t *testing.T) {
	given, givenDigest := digestOfJSON(`["s1","given_name","A"]`)
	forged := Disclosure{Salt: "x", Name: "admin", Value: true, Encoded: given, Digest: givenDigest}
	r, err := Recreate(mustObject(t, fmt.Sprintf(`{"_sd":[%q]}`, givenDigest)), []Disclosure{forged})
	mustNoErr(t, err)
	assertJSONEqual(t, r.Claims, map[string]any{"given_name": "A"})
}

// Unmatched digests are ignored, unmatched array placeholders removed, _sd
// and _sd_alg removed, and an object left empty stays {}.
func TestRecreateUndisclosed(t *testing.T) {
	payload := mustObject(t, fmt.Sprintf(`{"_sd_alg":"sha-256","a":{"_sd":[%q]},"arr":[{"...":%q},1,{"...":%q}]}`,
		digestOf("d1"), digestOf("d2"), digestOf("d3")))
	r, err := Recreate(payload, nil)
	mustNoErr(t, err)
	assertJSONEqual(t, r.Claims, mustObject(t, `{"a":{},"arr":[1]}`))

	// Absent _sd_alg means sha-256.
	given, givenDigest := digestOfJSON(`["s1","given_name","A"]`)
	r, err = Recreate(mustObject(t, fmt.Sprintf(`{"_sd":[%q]}`, givenDigest)), mustParse(t, given))
	mustNoErr(t, err)
	assertJSONEqual(t, r.Claims, map[string]any{"given_name": "A"})
}

func nestedArrays(depth int) string {
	return strings.Repeat("[", depth) + strings.Repeat("]", depth)
}

func TestRecreateLimits(t *testing.T) {
	// Depth: the payload object is level 1.
	_, err := Recreate(mustObject(t, `{"a":`+nestedArrays(DefaultMaxDepth-1)+`}`), nil)
	mustNoErr(t, err)
	_, err = Recreate(mustObject(t, `{"a":`+nestedArrays(DefaultMaxDepth)+`}`), nil)
	wantErr(t, err, ErrTooLarge)

	// Depth counts disclosed values in place.
	deep, deepDigest := digestOfJSON(`["s","x",{"y":{"z":1}}]`)
	payload := mustObject(t, fmt.Sprintf(`{"_sd":[%q]}`, deepDigest))
	_, err = Limits{MaxDepth: 3}.Recreate(payload, mustParse(t, deep))
	mustNoErr(t, err)
	_, err = Limits{MaxDepth: 2}.Recreate(payload, mustParse(t, deep))
	wantErr(t, err, ErrTooLarge)

	// Number of disclosures.
	var encoded, digests []string
	for i := range DefaultMaxDisclosures + 1 {
		e, d := digestOfJSON(fmt.Sprintf(`["s%d","c%d",%d]`, i, i, i))
		encoded, digests = append(encoded, e), append(digests, fmt.Sprintf("%q", d))
	}
	payload = mustObject(t, `{"_sd":[`+strings.Join(digests, ",")+`]}`)
	_, err = Recreate(payload, mustParse(t, encoded...))
	wantErr(t, err, ErrTooLarge)
	_, err = Recreate(payload, mustParse(t, encoded[:DefaultMaxDisclosures]...))
	mustNoErr(t, err)
	_, err = Limits{MaxDisclosures: 2}.Recreate(payload, mustParse(t, encoded[:3]...))
	wantErr(t, err, ErrTooLarge)
}

func TestRecreateKeepsPayload(t *testing.T) {
	given, givenDigest := digestOfJSON(`["s1","given_name","A"]`)
	payload := mustObject(t, fmt.Sprintf(`{"_sd":[%q],"_sd_alg":"sha-256","n":{"_sd":[]}}`, givenDigest))
	before, _ := jose.EncodeJSON(payload)
	_, err := Recreate(payload, mustParse(t, given))
	mustNoErr(t, err)
	after, _ := jose.EncodeJSON(payload)
	if string(before) != string(after) {
		t.Fatalf("payload modified:\n%s\n%s", before, after)
	}
}

// Disclosures(path) gives a claim's concealed ancestors and the claim itself,
// never its descendants (the map Present selects from).
func TestRecreatedDisclosures(t *testing.T) {
	payload, ds, err := Conceal(ageClaims(), append(agePaths(), Path{"nationalities", 0}), ConcealOptions{})
	mustNoErr(t, err)
	r, err := Recreate(payload, ds)
	mustNoErr(t, err)
	names := func(path Path) []string {
		got, ok := r.Disclosures(path)
		if !ok {
			t.Fatalf("%s not found", path)
		}
		out := []string{}
		for _, d := range got {
			if d.ArrayElement {
				out = append(out, fmt.Sprint(d.Value))
			} else {
				out = append(out, d.Name)
			}
		}
		return out
	}
	if got := names(Path{"age_equal_or_over", "18"}); !slices.Equal(got, []string{"age_equal_or_over", "18"}) {
		t.Fatalf("child: %v, want its parent's disclosure then its own", got)
	}
	if got := names(Path{"age_equal_or_over"}); !slices.Equal(got, []string{"age_equal_or_over"}) {
		t.Fatalf("parent: %v, want only its own disclosure", got)
	}
	if got := names(Path{"nationalities", 1}); len(got) != 1 || got[0] != "US" {
		t.Fatalf("array element: %v", got)
	}
	if got := names(Path{"nationalities", 2}); len(got) != 0 {
		t.Fatalf("plaintext element: %v", got)
	}
	if got := names(Path{"iss"}); len(got) != 0 {
		t.Fatalf("plaintext claim: %v", got)
	}
	for _, p := range []Path{{"nope"}, {"age_equal_or_over", "17"}, {"nationalities", 3}, {}, {1.5}} {
		if _, ok := r.Disclosures(p); ok {
			t.Fatalf("%s reported as present", p)
		}
	}

	// Indices are those of the recreated array: without the VN disclosure,
	// "US" is element 0.
	var some []Disclosure
	for _, d := range ds {
		if d.Value != "VN" {
			some = append(some, d)
		}
	}
	r, err = Recreate(payload, some)
	mustNoErr(t, err)
	if got := names(Path{"nationalities", 0}); len(got) != 1 || got[0] != "US" {
		t.Fatalf("recreated index 0: %v", got)
	}
}
