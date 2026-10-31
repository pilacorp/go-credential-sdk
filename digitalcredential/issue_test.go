package dc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/statuslist"
	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
	"github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

// TC-14 (REQ-21, REQ-22, REQ-23): each request breaks a rule of
// IssueRequest, and Validate gives the error Issue gives.
func TestIssueRefusesRequest(t *testing.T) {
	cases := map[string]func(*IssueRequest){
		"no VCT (draft 19 §2.2.2.3)": func(r *IssueRequest) { r.VCT = "" },
		// draft 19 §2.2.2.3: aka_vcts and its sub-claims MUST NOT be concealed.
		"Disclose aka_vcts[0]": func(r *IssueRequest) { r.Disclose = []sdjwt.Path{{"aka_vcts", 0}} },
		// draft 19 §2.2.2.5: no _sd without a selectively disclosable claim.
		"MinDigests without Disclose": func(r *IssueRequest) { r.Disclose, r.MinDigests = nil, 3 },
		"Claims holding iss":          func(r *IssueRequest) { r.Claims["iss"] = "https://other.example" },
		"Claims holding exp and Expiry set": func(r *IssueRequest) {
			r.Claims["exp"] = 1800000000
		},
		// draft 19 §2.2.2.2: aka_vcts MUST NOT contain the vct value.
		"aka_vcts holding vct":   func(r *IssueRequest) { r.Claims["aka_vcts"] = []string{"urn:example:id", "urn:example:pid"} },
		"aka_vcts empty":         func(r *IssueRequest) { r.Claims["aka_vcts"] = []string{} },
		"aka_vcts a string":      func(r *IssueRequest) { r.Claims["aka_vcts"] = "urn:example:id" },
		"aka_vcts an empty name": func(r *IssueRequest) { r.Claims["aka_vcts"] = []string{""} },
		"aka_vcts a number":      func(r *IssueRequest) { r.Claims["aka_vcts"] = []any{1} },
		// draft 19 §5.3: vct#integrity is an integrity metadata string.
		"vct#integrity a number": func(r *IssueRequest) { r.Claims["vct#integrity"] = 1 },
		"vct#integrity null":     func(r *IssueRequest) { r.Claims["vct#integrity"] = nil },
		"vct#integrity an array": func(r *IssueRequest) { r.Claims["vct#integrity"] = []any{} },
		// Deeper than jose.MaxJSONDepth: the request's mistake, not a
		// malformed token.
		"Claims nested too deep": func(r *IssueRequest) { r.Claims["deep"] = nested(70) },
		"Disclose path absent":   func(r *IssueRequest) { r.Disclose = []sdjwt.Path{{"family_name"}} },
		"Claims exp a time.Time": func(r *IssueRequest) { r.Expiry = time.Time{}; r.Claims["exp"] = time.Unix(1800000000, 0) },
		// draft-ietf-oauth-status-list-21 §6.2: idx is a non-negative integer.
		"Status with a negative Index": func(r *IssueRequest) {
			r.Status = &statuslist.Ref{URI: "https://status.example/lists/1", Index: -1}
		},
		"Claims holding status and Status set": func(r *IssueRequest) {
			r.Status = &statuslist.Ref{URI: "https://status.example/lists/1", Index: 7}
			r.Claims["status"] = map[string]any{"status_list": map[string]any{"idx": 7, "uri": "https://status.example/lists/1"}}
		},
		// RFC 7800 §3: iss or sub MUST be present beside cnf.
		"cnf without iss or sub": func(r *IssueRequest) { r.Issuer = ""; delete(r.Claims, "sub") },
		// RFC 9901 §4.1: _sd is reserved, in the eight claims too.
		"cnf in Claims with _sd": func(r *IssueRequest) {
			r.HolderKey = nil
			r.Claims["cnf"] = map[string]any{"_sd": []any{"x"}}
		},
	}
	key := testKey(t)
	for name, mutate := range cases {
		req := testRequest(t)
		mutate(&req)
		c, err := Issue(t.Context(), req, key)
		if c != nil || !errors.Is(err, jose.ErrInvalidArgument) {
			t.Errorf("%s: Issue = %v, %v; want jose.ErrInvalidArgument", name, c, err)
			continue
		}
		if verr := req.Validate(); verr == nil || verr.Error() != err.Error() {
			t.Errorf("%s: Validate = %v; want the error of Issue, %v", name, verr, err)
		}
	}
	if err := testRequest(t).Validate(); err != nil {
		t.Errorf("Validate of a valid request: %v", err)
	}
}

// TC-15 (REQ-22, REQ-23): the eight claims of draft 19 §2.2.2.3, here cnf and
// status from Claims, sit in the signed payload as given, with no disclosure
// and no decoy, although MinDigests pads every other object.
func TestIssueKeepsEightClaimsPlain(t *testing.T) {
	req := testRequest(t)
	req.HolderKey = nil
	req.Claims["cnf"] = map[string]any{"kid": "holder-key-1"}
	req.Claims["status"] = map[string]any{"status_list": map[string]any{"idx": 7, "uri": "https://status.example/lists/1"}}
	req.Disclose = []sdjwt.Path{{"iat"}, {"given_name"}, {"address", "locality"}}
	req.MinDigests = 2
	key := testKey(t)
	c, err := Issue(t.Context(), req, key)
	if err != nil {
		t.Fatal(err)
	}
	issuerJWT, encoded, kb, err := sdjwt.Split(c.Serialize())
	if err != nil || kb != "" || len(encoded) != 3 {
		t.Fatalf("Split: %d disclosures, KB-JWT %q, %v; want 3 and none", len(encoded), kb, err)
	}
	header, body, err := jws.Verify(issuerJWT, key.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(header) != 3 || header["typ"] != "dc+sd-jwt" || header["kid"] != "issuer-key-1" {
		t.Errorf("header = %v, want alg, typ dc+sd-jwt and kid", header)
	}
	payload, err := jose.DecodeJSONObject(body)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"cnf":      `{"kid":"holder-key-1"}`,
		"status":   `{"status_list":{"idx":7,"uri":"https://status.example/lists/1"}}`,
		"aka_vcts": `["urn:example:id"]`,
		"iss":      `"https://issuer.example"`,
		"vct":      `"urn:example:pid"`,
		"nbf":      `1700000100`,
		"exp":      `1800000000`,
	} {
		if got := encodeJSON(t, payload[name]); got != want {
			t.Errorf("signed %s = %s, want %s", name, got, want)
		}
	}
	ds := make([]sdjwt.Disclosure, len(encoded))
	for i, e := range encoded {
		ds[i] = sdjwt.Disclosure{Encoded: e}
	}
	r, err := sdjwt.Recreate(payload, ds)
	if err != nil {
		t.Fatal(err)
	}
	// iat: IssuedAt is 1700000000.9 s, written in whole seconds.
	if got := encodeJSON(t, r.Claims["iat"]); got != "1700000000" {
		t.Errorf("iat = %s, want 1700000000", got)
	}
	for _, name := range []string{"cnf", "status"} {
		if n := r.Issued().Fields[name]; n == nil || n.Disclosed || n.HiddenFields != 0 {
			t.Errorf("%s: concealed or padded with decoys: %+v", name, n)
		}
	}
}

// testRequest sets every field, so every claim of draft 19 §2.2.2.3 but
// status is present.
func testRequest(t *testing.T) IssueRequest {
	t.Helper()
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return IssueRequest{
		Issuer:    "https://issuer.example",
		VCT:       "urn:example:pid",
		IssuedAt:  time.Unix(1700000000, 900_000_000),
		NotBefore: time.Unix(1700000100, 0),
		Expiry:    time.Unix(1800000000, 0),
		HolderKey: &holder.PublicKey,
		Claims: map[string]any{
			"sub":           "user-42",
			"given_name":    "An",
			"address":       map[string]any{"locality": "Hanoi", "country": "VN"},
			"nationalities": []string{"VN", "FR", "US"},
			"vct#integrity": "sha256-vJKakJAQkDYkIhGrT1M3nxRuSj9udH0l1PXB06QHto8=",
			"aka_vcts":      []string{"urn:example:id"},
		},
	}
}

func nested(depth int) any {
	var v any = "leaf"
	for range depth {
		v = []any{v}
	}
	return v
}

func testKey(t *testing.T) issuerkey.SigningKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.PrivateKeySigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return issuerkey.SigningKey{Signer: s, Public: &priv.PublicKey, KID: "issuer-key-1"}
}

func encodeJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := jose.EncodeJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
