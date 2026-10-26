package digitalcredential

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/statuslist"
	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jwk"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
	"github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

// The holder key is the secp256k1 generator G of SEC 2 v2.0 §2.4.1, x and y
// base64url-encoded, so cnf.jwk can be compared with a literal.
var holderJWK = map[string]any{
	"kty": "EC",
	"crv": "secp256k1",
	"x":   "eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g",
	"y":   "SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg",
}

// Issue, then what a verifier does: the signature with the issuer key, Split,
// the disclosures and Recreate. Every claim comes back. iss, vct, nbf, exp
// and the never-disclosable claims sit in the signed payload as given, with
// no decoy although MinDigests pads every other object and array.
func TestIssueRoundTrip(t *testing.T) {
	req, key := testRequest(t)
	req.Disclose = []sdjwt.Path{{"iat"}, {"sub"}, {"given_name"}, {"address", "locality"}, {"nationalities", 0}}
	req.MinDigests = 2
	compact, err := Issue(req, key)
	if err != nil {
		t.Fatal(err)
	}

	issuerJWT, encoded, kb, err := sdjwt.Split(compact)
	if err != nil || kb != "" || len(encoded) != 5 {
		t.Fatalf("Split = %d disclosures, KB-JWT %q, %v; want 5 disclosures and no KB-JWT", len(encoded), kb, err)
	}
	header, body, err := jws.Verify(issuerJWT, key.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(header) != 3 || header.Alg() != "ES256" || header.Typ() != "dc+sd-jwt" || header.Kid() != "issuer-key-1" {
		t.Errorf("header = %v, want alg ES256, typ dc+sd-jwt, kid issuer-key-1", header)
	}
	payload, err := jose.DecodeJSONObject(body)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"aka_vcts": `["urn:example:id"]`,
		"cnf":      `{"jwk":{"crv":"secp256k1","kty":"EC","x":"eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g","y":"SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg"}}`,
		"status":   `{"status_list":{"idx":7,"uri":"http://status.example/lists/1"}}`,
	} {
		if got := encodeJSON(t, payload[name]); got != want {
			t.Errorf("signed %s = %s, want %s", name, got, want)
		}
	}

	disclosures := make([]sdjwt.Disclosure, len(encoded))
	for i, e := range encoded {
		if disclosures[i], err = sdjwt.ParseDisclosure(e); err != nil {
			t.Fatal(err)
		}
	}
	r, err := sdjwt.Recreate(payload, disclosures)
	if err != nil {
		t.Fatal(err)
	}
	// iat: IssuedAt is 1700000000.9 s, written in whole seconds.
	want := `{"address":{"country":"VN","locality":"Hanoi"},"aka_vcts":["urn:example:id"],` +
		`"cnf":{"jwk":{"crv":"secp256k1","kty":"EC","x":"eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g","y":"SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg"}},` +
		`"exp":1800000000,"given_name":"An","iat":1700000000,"iss":"https://issuer.example","nationalities":["VN","FR"],` +
		`"nbf":1700000100,"status":{"status_list":{"idx":7,"uri":"http://status.example/lists/1"}},"sub":"user-42",` +
		`"vct":"urn:example:pid","vct#integrity":"sha256-vJKakJAQkDYkIhGrT1M3nxRuSj9udH0l1PXB06QHto8="}`
	if got := encodeJSON(t, r.Claims); got != want {
		t.Errorf("recreated claims\n got %s\nwant %s", got, want)
	}
}

// draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3: these claims, and any of their
// sub-claims, MUST NOT be included in Disclosures.
func TestIssueRefusesNeverDisclosable(t *testing.T) {
	req, key := testRequest(t)
	if _, err := Issue(req, key); err != nil {
		t.Fatalf("Issue without Disclose: %v", err)
	}
	for _, p := range []sdjwt.Path{
		{"iss"}, {"nbf"}, {"exp"}, {"cnf"}, {"vct"}, {"vct#integrity"}, {"aka_vcts"}, {"status"},
		{"aka_vcts", 0},
	} {
		req.Disclose = []sdjwt.Path{p}
		if compact, err := Issue(req, key); compact != "" || !errors.Is(err, jose.ErrInvalidArgument) {
			t.Errorf("Disclose %s: Issue = %q, %v; want jose.ErrInvalidArgument", p, compact, err)
		}
	}
}

// draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.5: with no selectively disclosable
// claim the credential MUST NOT contain _sd, which decoys alone would add,
// nor any Disclosure. With vct, the one claim §2.2.2.3 requires, and an exp
// given in Claims with a fraction (RFC 7519 §2 NumericDate), the payload
// holds the two as given: iss is OPTIONAL.
func TestIssueWithoutDisclose(t *testing.T) {
	req, key := testRequest(t)
	req.MinDigests = 1
	if compact, err := Issue(req, key); compact != "" || !errors.Is(err, jose.ErrInvalidArgument) {
		t.Errorf("MinDigests 1, no Disclose: Issue = %q, %v; want jose.ErrInvalidArgument", compact, err)
	}

	compact, err := Issue(IssueRequest{VCT: "urn:example:pid", Claims: map[string]any{"exp": 1686920170.5}}, key)
	if err != nil {
		t.Fatal(err)
	}
	issuerJWT, ok := strings.CutSuffix(compact, "~")
	if !ok || strings.Contains(issuerJWT, "~") {
		t.Fatalf("Issue = %q, want an Issuer-signed JWT and one ~", compact)
	}
	_, body, err := jws.Verify(issuerJWT, key.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"exp":1686920170.5,"vct":"urn:example:pid"}`; string(body) != want {
		t.Errorf("payload = %s, want %s", body, want)
	}
}

// Each request breaks a rule of IssueRequest: no vct (draft 19 §2.2.2.3:
// REQUIRED), an aka_vcts draft 19 §2.2.2.2 forbids, a Status
// draft-ietf-oauth-status-list-21 §6.2 forbids, a reserved name in a cnf
// from Claims (RFC 9901 §4.1), or a claim a field writes given in Claims
// too, so that each claim has one source (testRequest sets every field).
func TestIssueRefusesRequest(t *testing.T) {
	cases := map[string]func(*IssueRequest){
		"no VCT":                 func(r *IssueRequest) { r.VCT = "" },
		"aka_vcts empty":         func(r *IssueRequest) { r.Claims["aka_vcts"] = []any{} },
		"aka_vcts not an array":  func(r *IssueRequest) { r.Claims["aka_vcts"] = "urn:example:id" },
		"aka_vcts with a number": func(r *IssueRequest) { r.Claims["aka_vcts"] = []any{"urn:example:id", 7} },
		"aka_vcts holding vct":   func(r *IssueRequest) { r.Claims["aka_vcts"] = []string{"urn:example:id", "urn:example:pid"} },
		"status idx -1":          func(r *IssueRequest) { r.Status.Index = -1 },
		"status uri not a URI":   func(r *IssueRequest) { r.Status.URI = "not a uri" },
		"cnf in Claims with _sd": func(r *IssueRequest) { r.HolderKey = nil; r.Claims["cnf"] = map[string]any{"_sd": []any{"x"}} },
	}
	for _, name := range []string{"iss", "vct", "iat", "nbf", "exp", "cnf", "status"} {
		cases["Claims holding "+name] = func(r *IssueRequest) { r.Claims = map[string]any{name: "x"} }
	}
	for name, mutate := range cases {
		req, key := testRequest(t)
		mutate(&req)
		if compact, err := Issue(req, key); compact != "" || !errors.Is(err, jose.ErrInvalidArgument) {
			t.Errorf("%s: Issue = %q, %v; want jose.ErrInvalidArgument", name, compact, err)
		}
	}
}

// testRequest sets every field, so every claim of §2.2.2.3 is present.
func testRequest(t *testing.T) (IssueRequest, statuslist.SigningKey) {
	t.Helper()
	holder, err := jwk.ToPublicKey(holderJWK)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	req := IssueRequest{
		Issuer:    "https://issuer.example",
		VCT:       "urn:example:pid",
		IssuedAt:  time.Unix(1700000000, 900_000_000),
		NotBefore: time.Unix(1700000100, 0),
		Expiry:    time.Unix(1800000000, 0),
		HolderKey: holder,
		Status:    &statuslist.Ref{URI: "http://status.example/lists/1", Index: 7},
		Claims: map[string]any{
			"sub":           "user-42",
			"given_name":    "An",
			"address":       map[string]any{"locality": "Hanoi", "country": "VN"},
			"nationalities": []any{"VN", "FR"},
			"vct#integrity": "sha256-vJKakJAQkDYkIhGrT1M3nxRuSj9udH0l1PXB06QHto8=",
			"aka_vcts":      []string{"urn:example:id"},
		},
	}
	return req, statuslist.SigningKey{Signer: memSigner{priv}, Public: &priv.PublicKey, KID: "issuer-key-1"}
}

func encodeJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := jose.EncodeJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// memSigner signs in memory and answers 64-byte r||s, as jws.Signer requires.
type memSigner struct{ *ecdsa.PrivateKey }

func (s memSigner) Sign(digest []byte) ([]byte, error) {
	r, sv, err := ecdsa.Sign(rand.Reader, s.PrivateKey, digest)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	sv.FillBytes(out[32:])
	return out, nil
}
