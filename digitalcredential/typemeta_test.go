package dc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/typemeta"
	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

const (
	vct42 = "https://betelgeuse.example.com/education_credential/v42"
	// openssl dgst -sha256 -binary typemeta/testdata/figure30.json | base64
	fig30SHA256 = "sha256-0NNETsymXj4lLpt500run69TjKZK3Auh+Nzyo62cFy4="
)

// fig29 is the Issue request of draft-ietf-oauth-sd-jwt-vc-19 Appendix A.2:
// the Figure 29 payload, disclosing what Figure 30 marks sd: always, with
// the Type Metadata of Figure 30 and the resolver it came from.
func fig29(t *testing.T) (IssueRequest, typemeta.Resolver) {
	t.Helper()
	read := func(name string) []byte {
		b, err := os.ReadFile("typemeta/testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	types, err := typemeta.Static(read("figure30.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := typemeta.Load(t.Context(), types, typemeta.Ref{VCT: vct42, Integrity: fig30SHA256})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := jose.DecodeJSONObject(read("figure29.json"))
	if err != nil {
		t.Fatal(err)
	}
	delete(claims, "vct")
	claims["vct#integrity"] = fig30SHA256
	disclose := []sdjwt.Path{{"name"}, {"address"}, {"address", "street_address"}}
	for i := range 3 {
		disclose = append(disclose, sdjwt.Path{"degrees", i}, sdjwt.Path{"degrees", i, "date_awarded"})
	}
	return IssueRequest{Issuer: "https://betelgeuse.example.com", VCT: vct42, Claims: claims, Disclose: disclose, TypeMetadata: m}, types
}

func issueWith(t *testing.T, req IssueRequest) (string, setting) {
	t.Helper()
	key := testKey(t)
	c, err := Issue(t.Context(), req, key)
	if err != nil {
		t.Fatal(err)
	}
	return c.Serialize(), setting{
		issuers: keysOf{req.Issuer: {{KID: key.KID, Public: key.Public}}},
		now:     time.Unix(1800000000, 0),
	}
}

// TC-41: Figure 29 issued with the Type Metadata of Figure 30, then verified
// against it, by a Verifier and by the Holder.
func TestTypeMetadataFigure30(t *testing.T) {
	req, types := fig29(t)
	req.MinDigests = 5
	compact, s := issueWith(t, req)
	for _, extra := range [][]VerifyOption{{WithTypeMetadata(types)}, {WithTypeMetadata(types), WithAllDisclosures()}} {
		s.extra = extra
		res, err := s.verify(t.Context(), compact)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.TypeMetadata.Claims()) != 7 || len(res.TypeMetadata.Display()) != 2 {
			t.Fatalf("TypeMetadata = %+v", res.TypeMetadata)
		}
	}
	// No decoy in an array: §5.6 counts its elements as issued.
	_, payload, _ := splitJWS(t, compact)
	b, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	p, err := jose.DecodeJSONObject(b)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(p["degrees"].([]any)); n != 3 {
		t.Errorf("degrees has %d elements as issued, want 3", n)
	}
}

func TestTypeMetadataRejects(t *testing.T) {
	req, types := fig29(t)
	tm := req.TypeMetadata
	req.TypeMetadata = nil

	// field_of_study is sd: never.
	never := req
	never.Disclose = append(never.Disclose[:len(never.Disclose):len(never.Disclose)], sdjwt.Path{"degrees", 0, "field_of_study"})
	compact, s := issueWith(t, never)
	for _, o := range []VerifyOption{WithTypeMetadata(types), WithOptionalTypeMetadata(types)} {
		s.extra = []VerifyOption{o}
		if _, err := s.verify(t.Context(), compact); codeOf(err) != CodeTypeMetadataViolated {
			t.Errorf("sd never disclosed: got %v, want TYPE_METADATA_VIOLATED", err)
		}
	}

	// name is mandatory: an object with undisclosed digests may hold it,
	// unless the caller holds every Disclosure.
	noName := req
	noName.Claims = map[string]any{"address": req.Claims["address"], "vct#integrity": fig30SHA256}
	noName.Disclose = []sdjwt.Path{{"address"}, {"address", "street_address"}}
	noName.MinDigests = 3
	compact, s = issueWith(t, noName)
	s.extra = []VerifyOption{WithTypeMetadata(types)}
	if _, err := s.verify(t.Context(), compact); err != nil {
		t.Errorf("mandatory claim maybe hidden: %v", err)
	}
	s.extra = append(s.extra, WithAllDisclosures())
	if _, err := s.verify(t.Context(), compact); codeOf(err) != CodeTypeMetadataViolated {
		t.Errorf("mandatory claim missing, all disclosures: got %v, want TYPE_METADATA_VIOLATED", err)
	}

	// A Key Binding JWT says a Verifier, which never holds every Disclosure.
	fig8 := draft19Setting(t)
	figTypes, err := typemeta.Static([]byte(`{"vct":"https://credentials.example.com/identity_credential"}`))
	if err != nil {
		t.Fatal(err)
	}
	fig8.extra = []VerifyOption{WithTypeMetadata(figTypes), WithAllDisclosures()}
	if _, err := fig8.verify(t.Context(), draft19Fig8); !errors.Is(err, ErrPolicy) {
		t.Errorf("WithAllDisclosures with a KB-JWT: got %v, want ErrPolicy", err)
	}

	// Claim metadata that breaks §5.6 rejects under either option (§5.7);
	// a type no resolver has is skipped only under the optional one.
	badClaims, err := typemeta.Static([]byte(`{"vct":"` + vct42 + `","claims":[{"path":[]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	other, err := typemeta.Static([]byte(`{"vct":"https://other.example/t"}`))
	if err != nil {
		t.Fatal(err)
	}
	// Without vct#integrity, so that the claims are read whatever the document.
	plain := req
	plain.Claims = cloneClaims(req.Claims)
	delete(plain.Claims, "vct#integrity")
	compact, s = issueWith(t, plain)
	for _, tt := range []struct {
		opt  VerifyOption
		want Code
	}{
		{WithTypeMetadata(badClaims), CodeTypeMetadataInvalid},
		{WithOptionalTypeMetadata(badClaims), CodeTypeMetadataInvalid},
		{WithTypeMetadata(other), CodeTypeMetadataNotFound},
		{WithTypeMetadata(types), ""},
	} {
		s.extra = []VerifyOption{tt.opt}
		if _, err := s.verify(t.Context(), compact); codeOf(err) != tt.want {
			t.Errorf("got %v, want %q", err, tt.want)
		}
	}
	s.extra = []VerifyOption{WithOptionalTypeMetadata(other)}
	if res, err := s.verify(t.Context(), compact); err != nil || res.TypeMetadata != nil || !errors.Is(res.TypeMetadataSkipped, typemeta.ErrNotFound) {
		t.Errorf("optional, not found: %v, %+v", err, res)
	}
	// A credential whose vct#integrity names another document.
	stale := req
	stale.Claims = cloneClaims(req.Claims)
	stale.Claims["vct#integrity"] = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
	compact, s = issueWith(t, stale)
	s.extra = []VerifyOption{WithTypeMetadata(types)}
	if _, err := s.verify(t.Context(), compact); codeOf(err) != CodeTypeMetadataInvalid {
		t.Errorf("vct#integrity of another document: got %v, want TYPE_METADATA_INVALID", err)
	}

	// A vct#integrity that is present and empty names no hash: the document
	// cannot be accepted (§6), so it is INVALID, or skipped when optional.
	_, own := ownCredentials(t)
	emptyIntegrity := own.issue(map[string]any{"iss": testRequest(t).Issuer, "vct": vct42, "vct#integrity": ""}, nil)
	var es setting
	own.set(&es)
	es.extra = []VerifyOption{WithTypeMetadata(types)}
	if _, err := es.verify(t.Context(), emptyIntegrity); codeOf(err) != CodeTypeMetadataInvalid {
		t.Errorf("empty vct#integrity: got %v, want TYPE_METADATA_INVALID", err)
	}
	es.extra = []VerifyOption{WithOptionalTypeMetadata(types)}
	if res, err := es.verify(t.Context(), emptyIntegrity); err != nil || !errors.Is(res.TypeMetadataSkipped, typemeta.ErrInvalid) {
		t.Errorf("empty vct#integrity, optional: %v, %+v", err, res)
	}

	// Claim metadata whose check over this payload reads more values than
	// the SDK's limit cannot be processed: §5.7 rejects under either option.
	wide := make([]any, 1100)
	for i := range wide {
		wide[i] = map[string]any{}
	}
	wideClaims := make([]map[string]any, 1000)
	for i := range wideClaims {
		wideClaims[i] = map[string]any{"path": []any{"a", nil, "k" + strconv.Itoa(i)}}
	}
	wideDoc, err := json.Marshal(map[string]any{"vct": vct42, "claims": wideClaims})
	if err != nil {
		t.Fatal(err)
	}
	wideTypes, err := typemeta.Static(wideDoc)
	if err != nil {
		t.Fatal(err)
	}
	compact, s = issueWith(t, IssueRequest{Issuer: req.Issuer, VCT: vct42, Claims: map[string]any{"a": wide}})
	for _, o := range []VerifyOption{WithTypeMetadata(wideTypes), WithOptionalTypeMetadata(wideTypes)} {
		s.extra = []VerifyOption{o}
		if _, err := s.verify(t.Context(), compact); codeOf(err) != CodeTypeMetadataInvalid || !errors.Is(err, typemeta.ErrClaims) {
			t.Errorf("claim check over the SDK's limit: got %v, want TYPE_METADATA_INVALID wrapping typemeta.ErrClaims", err)
		}
	}
	// One claim whose 64 KiB key is looked up in each of the 1100 elements:
	// every lookup hashes the whole key, so it counts toward the limit.
	longDoc, err := json.Marshal(map[string]any{"vct": vct42, "claims": []any{map[string]any{"path": []any{"a", nil, strings.Repeat("k", 64<<10)}}}})
	if err != nil {
		t.Fatal(err)
	}
	longTypes, err := typemeta.Static(longDoc)
	if err != nil {
		t.Fatal(err)
	}
	s.extra = []VerifyOption{WithTypeMetadata(longTypes)}
	if _, err := s.verify(t.Context(), compact); codeOf(err) != CodeTypeMetadataInvalid || !errors.Is(err, typemeta.ErrClaims) {
		t.Errorf("long key over the SDK's limit: got %v, want TYPE_METADATA_INVALID wrapping typemeta.ErrClaims", err)
	}

	// TC-44, TC-49: Issue refuses before signing.
	key := testKey(t)
	issue := func(name string, mut func(*IssueRequest), violated bool) {
		r := req
		r.TypeMetadata = tm
		r.Claims = cloneClaims(req.Claims)
		mut(&r)
		_, err := Issue(t.Context(), r, key)
		if !errors.Is(err, jose.ErrInvalidArgument) || errors.Is(err, typemeta.ErrViolated) != violated {
			t.Errorf("%s: got %v", name, err)
		}
	}
	issue("mandatory missing", func(r *IssueRequest) { delete(r.Claims, "name"); r.Disclose = r.Disclose[1:] }, true)
	issue("sd always in the clear", func(r *IssueRequest) { r.Disclose = r.Disclose[1:] }, true)
	issue("other type", func(r *IssueRequest) { r.VCT = "https://other.example/t" }, false)
	issue("zero Metadata", func(r *IssueRequest) { r.TypeMetadata = &typemeta.Metadata{} }, false)
	issue("vct#integrity of another document", func(r *IssueRequest) {
		r.Claims["vct#integrity"] = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
	}, false)
	issue("vct#integrity md5 only", func(r *IssueRequest) { r.TypeMetadata = nil; r.Claims["vct#integrity"] = "md5-x" }, false)
	issue("vct#integrity with a token that is not metadata", func(r *IssueRequest) {
		r.TypeMetadata = nil
		r.Claims["vct#integrity"] = fig30SHA256 + " %%%"
	}, false)
}

// TC-45: WithAcceptedVCTs, by vct, aka_vcts and the extends chain.
func TestAcceptedVCTs(t *testing.T) {
	const child, parent = "https://a.example/child", "https://a.example/parent"
	types, err := typemeta.Static([]byte(`{"vct":"`+child+`","extends":"`+parent+`"}`), []byte(`{"vct":"`+parent+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req := IssueRequest{Issuer: "https://issuer.example", VCT: child, Claims: map[string]any{"aka_vcts": []string{"urn:example:aka"}}}
	compact, s := issueWith(t, req)
	for _, tt := range []struct {
		opts []VerifyOption
		want Code
	}{
		{[]VerifyOption{WithAcceptedVCTs(child)}, ""},
		{[]VerifyOption{WithAcceptedVCTs("urn:example:aka")}, ""},
		{[]VerifyOption{WithAcceptedVCTs(parent)}, CodeVCTNotAccepted},
		{[]VerifyOption{WithAcceptedVCTs(parent), WithExtendedVCTMatch(), WithTypeMetadata(types)}, ""},
		{[]VerifyOption{WithAcceptedVCTs("https://A.example/child")}, CodeVCTNotAccepted},
	} {
		s.extra = tt.opts
		if _, err := s.verify(t.Context(), compact); codeOf(err) != tt.want {
			t.Errorf("%d options: got %v, want %q", len(tt.opts), err, tt.want)
		}
	}
	for _, opts := range [][]VerifyOption{
		{WithAcceptedVCTs()},
		{WithAcceptedVCTs(child), WithExtendedVCTMatch()},
		{WithAllDisclosures()},
		{WithTypeMetadata(types), WithOptionalTypeMetadata(types)},
		{WithTypeMetadata(nil)},
	} {
		s.extra = opts
		if _, err := s.verify(t.Context(), compact); !errors.Is(err, ErrPolicy) {
			t.Errorf("%d options: got %v, want ErrPolicy", len(opts), err)
		}
	}
}

func codeOf(err error) Code {
	if e := (*Error)(nil); errors.As(err, &e) {
		return e.Code
	}
	if err != nil {
		return "other: " + Code(err.Error())
	}
	return ""
}

func cloneClaims(c map[string]any) map[string]any {
	out := make(map[string]any, len(c))
	for k, v := range c {
		out[k] = v
	}
	return out
}
