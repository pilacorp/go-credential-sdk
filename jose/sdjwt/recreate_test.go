package sdjwt

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// Each presentation of RFC 9901 §5.2 and Appendix A.1 to A.4, as printed
// there, recreates exactly the Processed SD-JWT Payload printed after it.
// §5.2, A.3 and A.4 end with a KB-JWT, A.1 and A.2 with "~".
func TestRecreateRFCExamples(t *testing.T) {
	raw, err := os.ReadFile("testdata/rfc9901-examples.json")
	if err != nil {
		t.Fatal(err)
	}
	examples, err := jose.DecodeJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range examples.([]any) {
		ex := e.(map[string]any)
		t.Run(ex["source"].(string), func(t *testing.T) {
			issuerJWT, encoded, _, err := Split(ex["presentation"].(string))
			if err != nil {
				t.Fatal(err)
			}
			payload := decodePayload(t, issuerJWT)
			ds := make([]Disclosure, len(encoded))
			for i, s := range encoded {
				ds[i] = Disclosure{Encoded: s}
			}
			r, err := Recreate(payload, ds)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(r.Claims, ex["processed_payload"]) {
				t.Errorf("got %v\nwant %v", r.Claims, ex["processed_payload"])
			}
		})
	}
}

// decodePayload reads the payload of a compact JWS without checking the
// signature, which is not what these tests are about.
func decodePayload(t *testing.T, compact string) map[string]any {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", compact)
	}
	raw, err := jose.DecodeSegment(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	obj, err := jose.DecodeJSONObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	return obj
}

// disclose encodes disclosure JSON as given and computes its digest by hand
// (RFC 9901 §4.2.3), so the fixtures do not depend on the code under test.
func disclose(jsonText string) (encoded, digest string) {
	encoded = base64.RawURLEncoding.EncodeToString([]byte(jsonText))
	sum := sha256.Sum256([]byte(encoded))
	return encoded, base64.RawURLEncoding.EncodeToString(sum[:])
}

// The rejections RFC 9901 §7.1 requires, and the bounds on untrusted input.
func TestRecreateRejects(t *testing.T) {
	given, givenDigest := disclose(`["s1","given_name","A"]`)
	elem, elemDigest := disclose(`["s2","VN"]`)
	dots, dotsDigest := disclose(`["s3","...","x"]`)

	// 1001 disclosures, each referenced from the top-level _sd.
	var many []Disclosure
	var manyDigests []string
	for i := range 1001 {
		e, d := disclose(fmt.Sprintf(`["s%d","c%d",%d]`, i, i, i))
		many = append(many, Disclosure{Encoded: e})
		manyDigests = append(manyDigests, fmt.Sprintf("%q", d))
	}

	for _, tc := range []struct {
		name        string
		payload     string
		disclosures []Disclosure
		text        string // "": any ErrMalformed text
	}{
		// §7.1 step 4: a digest value encountered more than once.
		{"digest twice", fmt.Sprintf(`{"_sd":[%q],"x":{"_sd":[%q]}}`, givenDigest, givenDigest), []Disclosure{{Encoded: given}}, ""},
		// §7.1 step 5.
		{"unreferenced disclosure", `{"iss":"x"}`, []Disclosure{{Encoded: given}}, ""},
		// §7.1 step 5 whatever the disclosure holds: it is only hashed.
		{"unreferenced disclosure, not base64url", `{"iss":"x"}`, []Disclosure{{Encoded: "!!!"}}, "no digest references"},
		// §4.2.4.2: {"...": d} stands only for an array element.
		{"... outside an array", fmt.Sprintf(`{"a":{"...":%q}}`, elemDigest), nil, ""},
		// §4.2.1, §7.1 step 3c.ii.2: ... is never a claim name.
		{"disclosure named ...", fmt.Sprintf(`{"_sd":[%q]}`, dotsDigest), []Disclosure{{Encoded: dots}}, ""},
		// §4.1.1, §7.1 step 2d: only sha-256 is supported.
		{"_sd_alg sha-512", `{"_sd_alg":"sha-512"}`, nil, ""},
		// §7.1 step 3c.ii.1: a digest in _sd needs a [salt, name, value] disclosure.
		{"_sd references [salt, value]", fmt.Sprintf(`{"_sd":[%q]}`, elemDigest), []Disclosure{{Encoded: elem}}, ""},
		// §7.1 step 3c.iii.1: an array element needs a [salt, value] disclosure.
		{"array element references [salt, name, value]", fmt.Sprintf(`{"a":[{"...":%q}]}`, givenDigest), []Disclosure{{Encoded: given}}, ""},
		// §7.1 step 3c.ii.3.
		{"claim name exists", fmt.Sprintf(`{"given_name":"X","_sd":[%q]}`, givenDigest), []Disclosure{{Encoded: given}}, ""},
		{"1001 disclosures", `{"_sd":[` + strings.Join(manyDigests, ",") + `]}`, many, ""},
		// The payload object is level 1: 33 levels in all.
		{"depth 33", `{"a":` + strings.Repeat("[", 32) + strings.Repeat("]", 32) + `}`, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := jose.DecodeJSONObject([]byte(tc.payload))
			if err != nil {
				t.Fatal(err)
			}
			_, err = Recreate(payload, tc.disclosures)
			if !errors.Is(err, jose.ErrMalformed) || !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("got %v, want jose.ErrMalformed %q", err, tc.text)
			}
		})
	}
}

// RFC 9901 §4.2.6 and §7.2 presentation steps 1 and 2: a path selects its
// concealed ancestors and its own disclosure, nothing else, even when another
// concealed claim shares a name with an element of the path.
func TestDisclosuresSelectOnlyThePath(t *testing.T) {
	claims := map[string]any{"x": map[string]any{"y": "1"}, "y": "2", "a": map[string]any{"y": "3"}}
	payload, ds, err := Conceal(claims, []Path{{"y"}, {"a"}, {"a", "y"}}, ConcealOptions{})
	if err != nil {
		t.Fatal(err)
	}
	name := map[string]string{}
	for _, d := range ds {
		name[d.Encoded] = fmt.Sprint(d.Name, "=", d.Value)
	}
	r, err := Recreate(payload, ds)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path Path
		ok   bool
		want string
	}{
		{Path{"x", "y"}, true, "[]"},
		{Path{"y"}, true, "[y=2]"},
		{Path{"a", "y"}, true, "[a=map[] y=3]"},
		{Path{"a", "zz"}, false, "[]"},
		{Path{}, false, "[]"},
	} {
		got, ok := r.Disclosures(tc.path)
		var names []string
		for _, d := range got {
			n := name[d.Encoded]
			if d.Name == "a" {
				n = "a=map[]"
			}
			names = append(names, n)
		}
		if s := fmt.Sprint(names); ok != tc.ok || (ok && s != tc.want) {
			t.Errorf("%v: got %s %v, want %s %v", tc.path, s, ok, tc.want, tc.ok)
		}
	}
}

// A claim is disclosed when it, an ancestor or a descendant came from a
// disclosure: draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 forbids some claims
// "including any of their sub-claims" in disclosures.
func TestDisclosed(t *testing.T) {
	claims := map[string]any{"a": map[string]any{"b": "1"}, "c": map[string]any{"d": "2"}, "e": "3"}
	payload, ds, err := Conceal(claims, []Path{{"a"}, {"c", "d"}}, ConcealOptions{})
	if err != nil {
		t.Fatal(err)
	}
	r, err := Recreate(payload, ds)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path Path
		want bool
	}{
		{Path{"a", "b"}, true}, // inside a concealed object
		{Path{"c"}, true},      // holds a concealed claim
		{Path{"e"}, false},
	} {
		if got := r.Disclosed(tc.path); got != tc.want {
			t.Errorf("Disclosed(%v) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TC-47: Issued keeps every array element in its place at issuance, a hidden
// one included, and counts the digests of an object that have no disclosure.
func TestIssued(t *testing.T) {
	first, firstDigest := disclose(`["s1","VN"]`)
	_, hiddenDigest := disclose(`["s2","FR"]`)
	given, givenDigest := disclose(`["s3","given_name","Ana"]`)
	_, familyDigest := disclose(`["s4","family_name","Le"]`)
	payload := map[string]any{
		"_sd":           []any{givenDigest, familyDigest},
		"nationalities": []any{map[string]any{"...": firstDigest}, map[string]any{"...": hiddenDigest}, "DE"},
		"iss":           "https://issuer.example",
	}
	r, err := Recreate(payload, []Disclosure{{Encoded: first}, {Encoded: given}})
	if err != nil {
		t.Fatal(err)
	}
	root := r.Issued()
	if root.HiddenFields != 1 || len(root.Fields) != 3 || root.Disclosed {
		t.Fatalf("root: %d hidden fields, fields %v", root.HiddenFields, root.Fields)
	}
	if !root.Fields["given_name"].Disclosed || root.Fields["iss"].Disclosed {
		t.Error("given_name must be Disclosed, iss must not")
	}
	elems := root.Fields["nationalities"].Elems
	if len(elems) != 3 {
		t.Fatalf("%d elements, want 3", len(elems))
	}
	if !elems[0].Disclosed || elems[0].Value != "VN" || !elems[1].Hidden || elems[1].Value != nil || elems[2].Disclosed || elems[2].Value != "DE" {
		t.Errorf("elements %+v %+v %+v", *elems[0], *elems[1], *elems[2])
	}
	if !reflect.DeepEqual(root.Fields["nationalities"].Value, []any{"VN", "DE"}) {
		t.Errorf("array Value %v, want the recreated array", root.Fields["nationalities"].Value)
	}
	if (*Recreated)(nil).Issued() != nil {
		t.Error("nil Recreated gives a Node")
	}
}
