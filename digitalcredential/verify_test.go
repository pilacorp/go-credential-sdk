package dc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuermeta"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/statuslist"
	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jwk"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
	"github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

// draft-ietf-oauth-sd-jwt-vc-19 §2.3.2 Figure 8, a presentation with a
// KB-JWT, and Figure 10, one without, line breaks removed.
const draft19Fig8 = "" +
	"eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCIsICJraWQiOiAiZG9jLXNpZ25lci0wNS0yNS0yMDIyIn0.eyJf" +
	"c2QiOiBbIjA5dktySk1PbHlUV00wc2pwdV9wZE9CVkJRMk0xeTNLaHBINTE1blhrcFkiLCAiMnJzakdiYUMwa3k4bVQwcEpy" +
	"UGlvV1RxMF9kYXcxc1g3NnBvVWxnQ3diSSIsICJFa084ZGhXMGRIRUpidlVIbEVfVkNldUM5dVJFTE9pZUxaaGg3WGJVVHRB" +
	"IiwgIklsRHpJS2VpWmREd3BxcEs2WmZieXBoRnZ6NUZnbldhLXNONndxUVhDaXciLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVa" +
	"dTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwg" +
	"IlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiamRyVEU4WWNiWTRFaWZ1Z2loaUFlX0JQ" +
	"ZWt4SlFaSUNlaVVRd1k5UXF4SSIsICJqc3U5eVZ1bHdRUWxoRmxNXzNKbHpNYVNGemdsaFFHMERwZmF5UXdMVUs0Il0sICJp" +
	"c3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4cCI6IDE4ODMwMDAwMDAs" +
	"ICJ2Y3QiOiAiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwgIl9zZF9hbGci" +
	"OiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIlRDQUVSMTla" +
	"dnUzT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLCAieSI6ICJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1" +
	"ZWNDRTZ0NGpUOUYySFpRIn19fQ.EO_qzbkRHC_Kyzfd3yQiL3uNzuwfJ1MR3-i-YIXg82Y4ar7m8i0ksfqhsy3RzEhKro9MJ" +
	"f7F6iuJipJ78MWD_w~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImlzX292ZXJfNjUiLCB0cnVlXQ~WyJRZ19PNjR6cUF" +
	"4ZTQxMmExMDhpcm9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5Ijo" +
	"gIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~eyJhbGciOiAiRVMyNTYiLCAidHl" +
	"wIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaW" +
	"VyIiwgImlhdCI6IDE3ODgyMDk5NzgsICJzZF9oYXNoIjogIlhSQUhCTjhRa0JQMm1mYUh3bmhnV3BvTG1haS1JNElnX2hSNm" +
	"FadWJLTjAifQ.P3Stdkgrv_Q46LpQBzLJBP1mnryWb-4FJoOpi2vwOT0_HBy4h3gWZNfNAUWmM1ZQK4yBoLkUzQqzkWmXZuK" +
	"KUw"
const draft19Fig10 = "" +
	"eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCJ9.eyJfc2QiOiBbIjA5dktySk1PbHlUV00wc2pwdV9wZE9CVkJ" +
	"RMk0xeTNLaHBINTE1blhrcFkiLCAiMnJzakdiYUMwa3k4bVQwcEpyUGlvV1RxMF9kYXcxc1g3NnBvVWxnQ3diSSIsICJFa08" +
	"4ZGhXMGRIRUpidlVIbEVfVkNldUM5dVJFTE9pZUxaaGg3WGJVVHRBIiwgIklsRHpJS2VpWmREd3BxcEs2WmZieXBoRnZ6NUZ" +
	"nbldhLXNONndxUVhDaXciLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnB" +
	"LdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnR" +
	"Ec3JaemZVYW9tTG8iLCAiamRyVEU4WWNiWTRFaWZ1Z2loaUFlX0JQZWt4SlFaSUNlaVVRd1k5UXF4SSIsICJqc3U5eVZ1bHd" +
	"RUWxoRmxNXzNKbHpNYVNGemdsaFFHMERwZmF5UXdMVUs0Il0sICJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXI" +
	"iLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4cCI6IDE4ODMwMDAwMDAsICJ2Y3QiOiAiaHR0cHM6Ly9jcmVkZW50aWFscy5leGF" +
	"tcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwgIl9zZF9hbGciOiAic2hhLTI1NiJ9.NpdjRPpZ4naL6ceMyUZ_JpqHJq" +
	"8M5pRL1TOTUeKtv8niRGTc_UpjCn5AVPUz6omZDmGX5wTpLrEiOKyjNPkaAQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiw" +
	"gImlzX292ZXJfNjUiLCB0cnVlXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRy" +
	"ZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50" +
	"cnkiOiAiVVMifV0~"

// keysOf is a Resolver over a fixed map of issuers.
type keysOf map[string][]issuerkey.PublicKey

func (k keysOf) Keys(_ context.Context, iss string) ([]issuerkey.PublicKey, error) {
	return k[iss], nil
}

// failingResolver answers every iss with err.
type failingResolver struct{ err error }

func (r failingResolver) Keys(context.Context, string) ([]issuerkey.PublicKey, error) {
	return nil, r.err
}

// fixedStatus is a StatusChecker that answers v and err for one reference
// of one issuer, and fails for any other.
type fixedStatus struct {
	ref statuslist.Ref
	iss string
	v   uint8
	err error
}

func (c fixedStatus) Status(_ context.Context, ref statuslist.Ref, iss string) (uint8, error) {
	if ref != c.ref || iss != c.iss {
		return 0, errors.New("fixedStatus: asked for another reference or issuer")
	}
	return c.v, c.err
}

// recordingStatus is a StatusChecker that answers 0, VALID, and records each
// reference it is asked for.
type recordingStatus struct{ refs []statuslist.Ref }

func (c *recordingStatus) Status(_ context.Context, ref statuslist.Ref, _ string) (uint8, error) {
	c.refs = append(c.refs, ref)
	return 0, nil
}

// setting is one call of Verify: the resolver, the options every test sets,
// and extra options.
type setting struct {
	issuers         issuerkey.Resolver
	audience, nonce string
	now             time.Time
	extra           []VerifyOption
}

func (s setting) verify(ctx context.Context, compact string) (*Result, error) {
	c, err := Parse(compact)
	if err != nil {
		return nil, err
	}
	opts := []VerifyOption{WithNow(s.now)}
	if s.audience != "" {
		opts = append(opts, WithAudience(s.audience))
	}
	if s.nonce != "" {
		opts = append(opts, WithNonce(s.nonce))
	}
	return c.Verify(ctx, s.issuers, append(opts, s.extra...)...)
}

// draft19Key is the RFC 9901 Appendix A.5 issuer key, which signs the
// examples of draft-ietf-oauth-sd-jwt-vc-19.
func draft19Key(t *testing.T) any {
	t.Helper()
	key, err := jwk.ToPublicKey(map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ",
		"y": "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8",
	})
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// draft19Setting verifies the examples of draft 19 §2.3.2: the A.5 key under
// the kid of §4.2 Figure 14, the Figure 8 aud and nonce, and a time at its
// KB-JWT iat.
func draft19Setting(t *testing.T) setting {
	t.Helper()
	return setting{
		issuers:  keysOf{"https://example.com/issuer": {{KID: "doc-signer-05-25-2022", Public: draft19Key(t)}}},
		audience: "https://example.com/verifier",
		nonce:    "1234567890",
		now:      time.Unix(1788209978, 0),
	}
}

// TC-19: draft 19 §2.3.2, Figure 8 verifies, the processed payload is Figure
// 9, and the claims of its Key Binding JWT come back only when that KB-JWT is
// checked.
func TestVerifyDraft19Example(t *testing.T) {
	ctx := t.Context()
	s := draft19Setting(t)
	got, err := s.verify(ctx, draft19Fig8)
	if err != nil {
		t.Fatal(err)
	}
	fig9, err := jose.DecodeJSONObject([]byte(`{
		"iss": "https://example.com/issuer",
		"iat": 1683000000,
		"exp": 1883000000,
		"vct": "https://credentials.example.com/identity_credential",
		"cnf": {"jwk": {"kty": "EC", "crv": "P-256",
			"x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
			"y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"}},
		"is_over_65": true,
		"address": {"street_address": "123 Main St", "locality": "Anytown",
			"region": "Anystate", "country": "US"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if encodeJSON(t, got.Claims) != encodeJSON(t, fig9) || !got.KeyBound || got.Status != nil || got.StatusSkipped {
		t.Errorf("got %s, KeyBound %v, Status %v, StatusSkipped %v; want Figure 9, true, nil, false",
			encodeJSON(t, got.Claims), got.KeyBound, got.Status, got.StatusSkipped)
	}
	if got.Issuer != "https://example.com/issuer" || got.VCT != "https://credentials.example.com/identity_credential" || got.AKAVCTs != nil {
		t.Errorf("Issuer %q, VCT %q, AKAVCTs %v; want the Figure 9 iss and vct, no aka_vcts", got.Issuer, got.VCT, got.AKAVCTs)
	}
	if kb := got.KeyBindingClaims; kb["aud"] != "https://example.com/verifier" || kb["nonce"] != "1234567890" {
		t.Errorf("KeyBindingClaims = %v, want the aud and nonce of the Figure 8 KB-JWT", kb)
	}

	// RFC 9901 §7.2, §4: a KB-JWT that is not checked is rejected, unless
	// the caller ignores it; then none of its claims may come back.
	s.extra = []VerifyOption{WithKeyBinding(KeyBindingNotRequired)}
	var e *Error
	if _, err := s.verify(ctx, draft19Fig8); !errors.As(err, &e) || e.Code != CodeKBUnexpected {
		t.Errorf("KeyBindingNotRequired: %v, want KB_UNEXPECTED", err)
	}
	s.extra = append(s.extra, WithIgnoreUncheckedKBJWT())
	got, err = s.verify(ctx, draft19Fig8)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyBound || got.KeyBindingClaims != nil {
		t.Errorf("ignored KB-JWT: KeyBound %v, KeyBindingClaims %v; want false, nil", got.KeyBound, got.KeyBindingClaims)
	}
}

// TC-19: draft 19 §2.5 and §4, Figure 8 verifies through an
// issuermeta.Resolver, its key found in the jwks of Figure 14 published for
// the Figure 8 iss at the location of §4.1.
func TestVerifyDraft19IssuerMetadata(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jwt-vc-issuer/issuer" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"issuer":"https://example.com/issuer","jwks":{"keys":[
			{"kid":"doc-signer-05-25-2022","kty":"EC","crv":"P-256","x":"b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ","y":"Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"},
			{"kid":"doc-signer-06-05-2025","kty":"EC","crv":"P-256","x":"DfjUx4WHBds61vGbqUQhsy3FGX13fAS13QWh2EHIkX8","y":"NfqJt9Kp0EA93xq9ysO80DRZ_hCGlISz-pYLgv4RFvg"}
		]}}`))
	}))
	defer srv.Close()
	// The client reaches the server for example.com, a name the httptest
	// certificate holds.
	client := srv.Client()
	addr := srv.Listener.Addr().String()
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	r, err := issuermeta.NewResolver(issuermeta.Config{Allowed: []string{"https://example.com/"}, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	s := draft19Setting(t)
	s.issuers = r
	if _, err := s.verify(t.Context(), draft19Fig8); err != nil {
		t.Fatal(err)
	}
}

// TC-20, TC-22, TC-23: each rejection has its one Code, or is ErrPolicy for
// the caller's mistake.
func TestVerifyRejects(t *testing.T) {
	issuerJWT, disclosures, kbJWT, err := sdjwt.Split(draft19Fig8)
	if err != nil {
		t.Fatal(err)
	}
	header, payload, sig := splitJWS(t, issuerJWT)
	withHeader := func(h string) string {
		return jose.EncodeSegment([]byte(h)) + "." + payload + "." + sig + "~" + strings.Join(disclosures, "~") + "~" + kbJWT
	}
	sigBytes, err := jose.DecodeSegment(sig)
	if err != nil {
		t.Fatal(err)
	}
	sigBytes[0] ^= 1
	tampered := strings.Replace(draft19Fig8, sig, jose.EncodeSegment(sigBytes), 1)
	stripped := strings.TrimSuffix(draft19Fig8, kbJWT)
	// The KB-JWT signed sd_hash over both disclosures.
	dropped := strings.Replace(draft19Fig8, "~"+disclosures[0]+"~", "~", 1)

	// Figure 8's header and signature over a payload with a duplicate claim:
	// the signature is checked before the payload is decoded in full.
	dupClaim := header + "." + jose.EncodeSegment([]byte(`{"iss":"https://example.com/issuer","vct":"x","vct":"y"}`)) + "." + sig + "~"
	// A Key Binding JWT whose alg the caller does not allow; its signature
	// is never reached.
	kbES256K := strings.Replace(draft19Fig8, kbJWT[:strings.IndexByte(kbJWT, '.')], jose.EncodeSegment([]byte(`{"alg":"ES256K","typ":"kb+jwt"}`)), 1)
	// A 60 KB header key, twice: the text quotes it bounded.
	longKey := strings.Repeat("é", 15000)
	echo := withHeader(`{"alg":"ES256","typ":"dc+sd-jwt","` + longKey + `":1,"` + longKey + `":2}`)

	issued, own := ownCredentials(t)
	// testRequest's issuer, and the status_list ownCredentials sets.
	ref, iss := statuslist.Ref{URI: "http://status.example/lists/1", Index: 7}, "https://issuer.example"
	withStatus := func(c StatusChecker) func(*setting) {
		return func(s *setting) { own.set(s); s.extra = []VerifyOption{WithStatus(c)} }
	}
	// draft 19 §2.2.2.3: claims that MUST NOT be in a Disclosure. The
	// credential is valid but for the concealed claim; a concealed iss
	// leaves none, which the resolver answers too.
	neverDisclosed := map[string]any{
		"iss": iss, "vct": "urn:example:pid", "exp": 1800000000, "nbf": 1700000100,
		"status": map[string]any{"status_list": map[string]any{"uri": ref.URI, "idx": ref.Index}},
	}
	concealed := func(s *setting) {
		own.set(s)
		s.issuers = keysOf{iss: own.keys, "": own.keys}
		s.extra = []VerifyOption{WithoutStatusCheck()}
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a5 := draft19Key(t)

	type row struct {
		name    string
		compact string
		set     func(*setting)
		want    Code  // "": ErrPolicy
		is      error // when set, errors.Is must hold too
	}
	rows := []row{
		// RFC 9901 §9.11, draft 19 §2.2.1 and Appendix C: the profile's
		// explicit type, vc+sd-jwt no longer.
		{"typ vc+sd-jwt", withHeader(`{"alg":"ES256","typ":"vc+sd-jwt","kid":"doc-signer-05-25-2022"}`), nil, CodeTypInvalid, nil},
		// RFC 9901 §7.1 step 2a: none is never accepted.
		{"alg none", withHeader(`{"alg":"none","typ":"dc+sd-jwt","kid":"doc-signer-05-25-2022"}`), nil, CodeAlgNotAllowed, nil},
		// RFC 8725 §3.1: only the algorithms the verifier allows.
		{"issuer alg not allowed", draft19Fig8, func(s *setting) { s.extra = []VerifyOption{WithAllowedAlgs(jws.AlgES256K)} }, CodeAlgNotAllowed, nil},
		{"signature altered", tampered, nil, CodeSignatureInvalid, nil},
		{"bad signature over a duplicate claim", dupClaim, nil, CodeSignatureInvalid, nil},
		// RFC 7515 §10.12, RFC 7519 §4: a duplicate header key, quoted bounded.
		{"duplicate 60 KB header key", echo, nil, CodeMalformed, nil},
		// RFC 7519 §4.1.4: on or after exp, here exp + the 1 minute skew.
		{"expired", draft19Fig8, func(s *setting) { s.now = time.Unix(1883000060, 0) }, CodeExpired, nil},
		// RFC 7519 §4.1.3: the credential's own aud, not the KB-JWT's.
		{"credential for another audience", own.withAud, func(s *setting) {
			own.set(s)
			s.extra = []VerifyOption{WithCredentialAudience("https://other.example")}
		}, CodeAudienceMismatch, nil},
		{"credential aud, no WithCredentialAudience", own.withAud, own.set, CodeAudienceMismatch, nil},
		// draft 19 §2.5: the issuer's keys, by the REQ-32 table.
		{"issuer not supported", draft19Fig8, func(s *setting) {
			s.issuers = failingResolver{fmt.Errorf("resolver: %w", issuerkey.ErrIssuerNotSupported)}
		}, CodeIssuerNotSupported, issuerkey.ErrIssuerNotSupported},
		{"issuer keys unavailable", draft19Fig8, func(s *setting) { s.issuers = failingResolver{errors.New("resolver: connection refused")} }, CodeIssuerKeyUnavailable, nil},
		{"resolver wiring", draft19Fig8, func(s *setting) { s.issuers = failingResolver{fmt.Errorf("resolver: %w", jose.ErrInvalidArgument)} }, "", nil},
		{"two keys share the kid", draft19Fig8, func(s *setting) {
			s.issuers = keysOf{"https://example.com/issuer": {{KID: "doc-signer-05-25-2022", Public: a5}, {KID: "doc-signer-05-25-2022", Public: a5}}}
		}, CodeIssuerKeyNotFound, nil},
		{"resolver key on P-384", draft19Fig8, func(s *setting) {
			s.issuers = keysOf{"https://example.com/issuer": {{KID: "doc-signer-05-25-2022", Public: &p384.PublicKey}}}
		}, "", jose.ErrUnsupportedKey},
		// RFC 9901 §7.3 step 2, §9.5: the credential binds a key (cnf).
		{"KB-JWT stripped", stripped, nil, CodeKBMissing, nil},
		{"KB-JWT stripped, KeyBindingRequired", stripped, func(s *setting) { s.extra = []VerifyOption{WithKeyBinding(KeyBindingRequired)} }, CodeKBMissing, nil},
		// draft 19 §2.4: Key Binding is checked with cnf, and Figure 10 has
		// none, so no presentation can pass, Figure 8's KB-JWT included.
		// Figure 10 has no kid, which Select accepts from an issuer of one key.
		{"no cnf, KeyBindingRequired", draft19Fig10 + kbJWT, func(s *setting) { s.extra = []VerifyOption{WithKeyBinding(KeyBindingRequired)} }, CodeKBUnsupported, nil},
		// draft 19 §2.4: no cnf, so no key checks the KB-JWT that came.
		{"KB-JWT with no cnf", draft19Fig10 + kbJWT, nil, CodeKBUnexpected, nil},
		// RFC 9901 §7.3 step 5f: a KB-JWT to check needs aud and nonce.
		{"KB-JWT, no WithAudience", draft19Fig8, func(s *setting) { s.audience = "" }, "", nil},
		// RFC 9901 §7.3 step 5b, RFC 8725 §3.1: the holder's alg too.
		{"KB-JWT alg not allowed", kbES256K, func(s *setting) { s.extra = []VerifyOption{WithAllowedAlgs(jws.AlgES256)} }, CodeKBInvalid, jws.ErrAlgNotAllowed},
		// RFC 9901 §7.3 step 5e: 3 minutes old, past a 1 minute max age and
		// the 1 minute skew, within the 5 minute default.
		{"KB-JWT older than WithMaxKBAge", draft19Fig8, func(s *setting) {
			s.now = time.Unix(1788209978+180, 0)
			s.extra = []VerifyOption{WithMaxKBAge(time.Minute)}
		}, CodeKBInvalid, nil},
		// RFC 9901 §7.3 step 5e: iat 30 s ahead, with no skew allowed.
		{"KB-JWT iat ahead, WithClockSkew(0)", draft19Fig8, func(s *setting) {
			s.now = time.Unix(1788209978-30, 0)
			s.extra = []VerifyOption{WithClockSkew(0)}
		}, CodeKBInvalid, nil},
		// RFC 9901 §7.3 steps 5f and 5g.
		{"KB-JWT for another verifier", draft19Fig8, func(s *setting) { s.audience = "https://other.example" }, CodeKBAudienceMismatch, nil},
		{"KB-JWT for another transaction", draft19Fig8, func(s *setting) { s.nonce = "0987654321" }, CodeKBNonceMismatch, nil},
		{"disclosure dropped after binding", dropped, nil, CodeKBSDHashMismatch, nil},
		// draft 19 §2.2.2.3: cnf and its sub-claims stay out of Disclosures.
		{"cnf.jwk in a Disclosure", own.concealedJWK, own.set, CodeDisclosureInvalid, nil},
		// RFC 7800 §3.1: one proof-of-possession key.
		{"cnf with jwk and jku", own.twoMethods, own.set, CodeMalformed, nil},
		// RFC 9901 §4.3: aud is a single string; an array is not a mismatch.
		{"KB-JWT aud an array", own.kbAudArray, own.set, CodeKBInvalid, nil},
		// draft 19 §2.2.2.1-2.2.2.3, §5.3: the type claims.
		{"no vct", own.issue(map[string]any{"iss": iss}, nil), own.set, CodeMalformed, nil},
		{"aka_vcts holding vct", own.issue(map[string]any{"iss": iss, "vct": "urn:example:pid", "aka_vcts": []any{"urn:example:pid"}}, nil), own.set, CodeMalformed, nil},
		{"vct#integrity a number", own.issue(map[string]any{"iss": iss, "vct": "urn:example:pid", "vct#integrity": 1}, nil), own.set, CodeMalformed, nil},
		// draft-ietf-oauth-status-list-21 §6.2: status is an object.
		{"status a string", own.issue(map[string]any{"iss": iss, "vct": "urn:example:pid", "status": "valid"}, nil), withStatus(&recordingStatus{}), CodeMalformed, nil},
		// draft-ietf-oauth-status-list-21 §8.3 step 1: the one mechanism checked.
		{"status without status_list", own.issue(map[string]any{"iss": iss, "vct": "urn:example:pid", "status": map[string]any{"other": map[string]any{}}}, nil), withStatus(&recordingStatus{}), CodeStatusUnavailable, nil},
		// draft 19 §2.2.2.3 lets cnf hold any RFC 7800 method; this SDK binds
		// cnf.jwk only.
		{"cnf without jwk", own.issue(map[string]any{"iss": iss, "vct": "urn:example:pid", "cnf": map[string]any{"kid": "holder-key-1"}}, nil), own.set, CodeKBUnsupported, ErrKeyBindingUnsupported},
		// draft-ietf-oauth-status-list-21 §7.1: 0x01 is INVALID.
		{"revoked", issued, withStatus(fixedStatus{ref: ref, iss: iss, v: 0x01}), CodeRevoked, nil},
		{"suspended", issued, withStatus(fixedStatus{ref: ref, iss: iss, v: 0x02}), CodeSuspended, nil},
		{"status 0x03", issued, withStatus(fixedStatus{ref: ref, iss: iss, v: 0x03}), CodeStatusNotAccepted, nil},
		// draft-ietf-oauth-status-list-21 §8.3: no statement can be made.
		{"status unavailable", issued, withStatus(fixedStatus{ref: ref, iss: iss, err: errors.New("list unreachable")}), CodeStatusUnavailable, nil},
		// draft-ietf-oauth-status-list-21 §8.3 step 6: MUST be rejected.
		{"idx out of bounds", issued, withStatus(fixedStatus{ref: ref, iss: iss, err: fmt.Errorf("list: %w", statuslist.ErrIndexOutOfBounds)}), CodeMalformed, statuslist.ErrIndexOutOfBounds},
		// The checker's wiring, as a statuslist.Checker reports a resolver key
		// it cannot verify with.
		{"status checker wiring", issued, withStatus(fixedStatus{ref: ref, iss: iss, err: fmt.Errorf("%w: statuslist: Config.Issuers returned a key that cannot verify", jose.ErrInvalidArgument)}), "", nil},
		// draft 21 §8.3: status is checked unless the caller opts out.
		{"status and no WithStatus", issued, own.set, "", nil},
	}
	// Named here, not taken from the code under test.
	for _, name := range []string{"iss", "exp", "nbf", "vct", "status"} {
		rows = append(rows, row{name + " in a Disclosure", own.issue(neverDisclosed, []sdjwt.Path{{name}}), concealed, CodeDisclosureInvalid, nil})
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			s := draft19Setting(t)
			if tc.set != nil {
				tc.set(&s)
			}
			res, err := s.verify(t.Context(), tc.compact)
			var e *Error
			switch {
			case res != nil:
				t.Fatalf("accepted: %s", encodeJSON(t, res.Claims))
			case tc.want == "":
				if !errors.Is(err, ErrPolicy) || errors.As(err, &e) {
					t.Fatalf("got %v; want ErrPolicy only", err)
				}
			case !errors.As(err, &e) || e.Code != tc.want || errors.Is(err, ErrPolicy):
				t.Fatalf("got %v; want Code %s", err, tc.want)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("got %v; want it to match %v", err, tc.is)
			}
			// Texts quote token content bounded, whatever the token holds.
			if n := len(err.Error()); n > 1024 {
				t.Fatalf("error text is %d bytes", n)
			}
		})
	}
}

// TC-23 (REQ-32, REQ-33): with ctx ended, a resolver's or checker's error
// wraps ctx.Err() and has no Code, except the definite answers.
func TestVerifyContextEnded(t *testing.T) {
	ended, cancel := context.WithCancel(t.Context())
	cancel()
	issued, own := ownCredentials(t)
	ref := statuslist.Ref{URI: "http://status.example/lists/1", Index: 7}
	var e *Error

	s := draft19Setting(t)
	s.issuers = failingResolver{errors.New("resolver: request canceled")}
	if _, err := s.verify(ended, draft19Fig8); !errors.Is(err, context.Canceled) || errors.As(err, &e) || errors.Is(err, ErrPolicy) {
		t.Errorf("resolver failing: %v; want context.Canceled only", err)
	}
	s.issuers = failingResolver{fmt.Errorf("resolver: %w", issuerkey.ErrNoUsableKey)}
	if _, err := s.verify(ended, draft19Fig8); !errors.As(err, &e) || e.Code != CodeIssuerKeyNotFound {
		t.Errorf("ErrNoUsableKey: %v; want ISSUER_KEY_NOT_FOUND", err)
	}

	own.set(&s)
	s.extra = []VerifyOption{WithStatus(fixedStatus{ref: ref, iss: "https://issuer.example", err: errors.New("list: request canceled")})}
	if _, err := s.verify(ended, issued); !errors.Is(err, context.Canceled) || errors.As(err, &e) || errors.Is(err, ErrPolicy) {
		t.Errorf("checker failing: %v; want context.Canceled only", err)
	}
	s.extra = []VerifyOption{WithStatus(fixedStatus{ref: ref, iss: "https://issuer.example", err: statuslist.ErrIndexOutOfBounds})}
	if _, err := s.verify(ended, issued); !errors.As(err, &e) || e.Code != CodeMalformed {
		t.Errorf("ErrIndexOutOfBounds: %v; want MALFORMED", err)
	}
}

// TC-22 (REQ-31): status is checked, skipped only when the caller says so,
// and accepted by the caller's set.
func TestVerifyStatusSkipped(t *testing.T) {
	issued, own := ownCredentials(t)
	var s setting
	own.set(&s)
	s.extra = []VerifyOption{WithoutStatusCheck()}
	res, err := s.verify(t.Context(), issued)
	if err != nil || !res.StatusSkipped || res.Status != nil {
		t.Fatalf("WithoutStatusCheck: %+v, %v; want StatusSkipped", res, err)
	}
	// draft 21 §7.1: which status values pass is the Verifier's policy.
	s.extra = []VerifyOption{WithStatus(fixedStatus{ref: statuslist.Ref{URI: "http://status.example/lists/1", Index: 7}, iss: "https://issuer.example", v: 0x02}), WithAcceptedStatus(0x00, 0x02)}
	res, err = s.verify(t.Context(), issued)
	if err != nil || res.Status == nil || *res.Status != 0x02 {
		t.Fatalf("WithAcceptedStatus(0x00, 0x02), status 0x02: %+v, %v; want Status 0x02", res, err)
	}
	s.extra = nil
	res, err = s.verify(t.Context(), own.noStatus)
	if err != nil || res.StatusSkipped || res.Status != nil {
		t.Fatalf("no status: %+v, %v; want Status nil, StatusSkipped false", res, err)
	}
}

// TC-35, TC-37 (REQ-29 step 1, REQ-53): the caller's mistakes are ErrPolicy
// before the token is read, and the checker is not called.
func TestVerifyPolicy(t *testing.T) {
	issued, own := ownCredentials(t)
	rec := &recordingStatus{}
	cases := map[string][]VerifyOption{
		"WithoutStatusCheck twice":             {WithoutStatusCheck(), WithoutStatusCheck()},
		"WithStatus and WithoutStatusCheck":    {WithStatus(rec), WithoutStatusCheck()},
		"a nil option":                         {WithStatus(rec), nil},
		"WithAcceptedStatus()":                 {WithStatus(rec), WithAcceptedStatus()},
		"WithStatus(nil)":                      {WithStatus(nil)},
		"WithKeyBinding(7)":                    {WithStatus(rec), WithKeyBinding(7)},
		"WithMaxKBAge(0)":                      {WithStatus(rec), WithMaxKBAge(0)},
		"WithClockSkew(-1s)":                   {WithStatus(rec), WithClockSkew(-time.Second)},
		"WithAllowedAlgs()":                    {WithStatus(rec), WithAllowedAlgs()},
		"WithAllowedAlgs(RS256)":               {WithStatus(rec), WithAllowedAlgs("RS256")},
		"WithNow twice":                        {WithStatus(rec), WithNow(time.Unix(1700000500, 0))},
		"KeyBindingRequired without WithNonce": {WithStatus(rec), WithKeyBinding(KeyBindingRequired)},
	}
	for name, extra := range cases {
		var s setting
		own.set(&s)
		if name == "KeyBindingRequired without WithNonce" {
			s.nonce = ""
		}
		s.extra = extra
		_, err := s.verify(t.Context(), issued)
		var e *Error
		if !errors.Is(err, ErrPolicy) || errors.As(err, &e) {
			t.Errorf("%s: %v; want ErrPolicy", name, err)
		}
		if name == "WithAllowedAlgs(RS256)" && !errors.Is(err, jose.ErrUnsupportedAlg) {
			t.Errorf("%s: %v; want jose.ErrUnsupportedAlg too", name, err)
		}
	}
	if len(rec.refs) != 0 {
		t.Errorf("checker asked %v; want no call", rec.refs)
	}
	// Options are checked before the token is read, so a credential without
	// status refuses WithStatus(nil) too; the zero time is no time of check.
	for name, s := range map[string]setting{
		"WithStatus(nil), no status": {extra: []VerifyOption{WithStatus(nil)}},
		"WithNow(time.Time{})":       {},
	} {
		own.set(&s)
		if name == "WithNow(time.Time{})" {
			s.now = time.Time{}
		}
		if _, err := s.verify(t.Context(), own.noStatus); !errors.Is(err, ErrPolicy) {
			t.Errorf("%s: %v; want ErrPolicy", name, err)
		}
	}

	c, err := Parse(issued)
	if err != nil {
		t.Fatal(err)
	}
	var nilCtx context.Context
	if _, err := c.Verify(nilCtx, keysOf{}); !errors.Is(err, ErrPolicy) {
		t.Errorf("nil ctx: %v; want ErrPolicy", err)
	}
	if _, err := c.Verify(t.Context(), nil); !errors.Is(err, ErrPolicy) {
		t.Errorf("nil issuers: %v; want ErrPolicy", err)
	}
}

// TC-50 (REQ-29 step 1): the defaults are a 1 minute skew and a 5 minute
// Key Binding JWT age, and a passed option is used with exactly its value.
func TestVerifyTimeOptions(t *testing.T) {
	req := testRequest(t)
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jws.PrivateKeySigner(holder)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000030, 0)
	req.HolderKey = &holder.PublicKey // exp is 1800000000, 30 s before now
	key := testKey(t)
	cred, err := Issue(t.Context(), req, key)
	if err != nil {
		t.Fatal(err)
	}
	kb := &KeyBinding{Signer: signer, Audience: "https://verifier.example", Nonce: "n-1", IssuedAt: now.Add(-7 * time.Minute)}
	bound, err := cred.Present(t.Context(), PresentRequest{KeyBinding: kb})
	if err != nil {
		t.Fatal(err)
	}
	s := setting{
		issuers:  keysOf{req.Issuer: {{KID: key.KID, Public: key.Public}}},
		audience: kb.Audience, nonce: kb.Nonce, now: now,
	}
	for _, tc := range []struct {
		name string
		opts []VerifyOption
		want Code // "": accepted
	}{
		{"defaults", nil, CodeKBInvalid},
		{"WithClockSkew(0)", []VerifyOption{WithClockSkew(0)}, CodeExpired},
		{"WithMaxKBAge(10m)", []VerifyOption{WithMaxKBAge(10 * time.Minute)}, ""},
	} {
		s.extra = tc.opts
		_, err := s.verify(t.Context(), bound.Serialize())
		var e *Error
		if tc.want == "" && err != nil || tc.want != "" && (!errors.As(err, &e) || e.Code != tc.want) {
			t.Errorf("%s: %v; want %q", tc.name, err, tc.want)
		}
	}
}

// draft-ietf-oauth-status-list-21 §6.2: idx is a non-negative Integer, a
// value, which RFC 8259 §6 writes in many forms. Each form below is read as
// its exact value, refused, or, past an int, past every list (§8.3 step 6),
// with status checked and skipped, and the checker is asked only for a valid
// idx.
func TestVerifyStatusIdx(t *testing.T) {
	const uri = "http://status.example/lists/1"
	_, own := ownCredentials(t)
	type class int
	const (
		accepted class = iota
		refused        // MALFORMED in both modes
		pastInt        // ErrIndexOutOfBounds, or skipped
	)
	tests := []struct {
		idx   any // nil: absent
		class class
		want  int64 // the index, for accepted rows
	}{
		{json.Number("1.0"), accepted, 1},
		{json.Number("1e3"), accepted, 1000},
		{json.Number("1E+3"), accepted, 1000},
		{json.Number("10e-1"), accepted, 1},
		{json.Number("1.5e1"), accepted, 15},
		{json.Number("-0"), accepted, 0},
		{json.Number("-0.0"), accepted, 0},
		{json.Number("0e5"), accepted, 0},
		// 2^53+1: a float64 reads it as 2^53.
		{json.Number("9007199254740993.0"), accepted, 9007199254740993},
		{json.Number("9007199254740993e0"), accepted, 9007199254740993},
		{json.Number("0e-99999999999999999999"), accepted, 0},
		{json.Number("9223372036854775807"), accepted, 9223372036854775807},
		{json.Number("1.5"), refused, 0},
		{json.Number("-1"), refused, 0},
		{json.Number("1e-1"), refused, 0},
		{json.Number("-10e-1"), refused, 0},
		{json.Number("1.00000000000000000001"), refused, 0},
		{json.Number("1e-99999999999999999999"), refused, 0},
		{"1", refused, 0},
		{nil, refused, 0},
		{json.Number("1e400"), pastInt, 0},
		{json.Number("1e99999999999999999999"), pastInt, 0},
		{json.Number("99999999999999999999"), pastInt, 0},
		{json.Number("9223372036854775808"), pastInt, 0}, // one past the largest 64-bit int
	}
	for _, tc := range tests {
		list := map[string]any{"uri": uri}
		if tc.idx != nil {
			list["idx"] = tc.idx
		}
		compact := own.issue(map[string]any{"iss": "https://issuer.example", "vct": "urn:example:pid", "status": map[string]any{"status_list": list}}, nil)
		for _, skip := range []bool{false, true} {
			t.Run(fmt.Sprintf("%#v skip=%v", tc.idx, skip), func(t *testing.T) {
				if tc.want != int64(int(tc.want)) {
					t.Skip("the index needs a 64-bit int")
				}
				rec := &recordingStatus{}
				var s setting
				own.set(&s)
				s.extra = []VerifyOption{WithStatus(rec)}
				if skip {
					s.extra = []VerifyOption{WithoutStatusCheck()}
				}
				res, err := s.verify(t.Context(), compact)
				var e *Error
				switch {
				case tc.class == refused || (tc.class == pastInt && !skip):
					oob := tc.class == pastInt
					if res != nil || !errors.As(err, &e) || e.Code != CodeMalformed || errors.Is(err, statuslist.ErrIndexOutOfBounds) != oob {
						t.Fatalf("got %v, %v; want MALFORMED, ErrIndexOutOfBounds %v", res, err, oob)
					}
					if n, ok := tc.idx.(json.Number); ok && len(n) > 4 && strings.Contains(err.Error(), string(n)) {
						t.Errorf("the error quotes idx: %v", err)
					}
				case err != nil:
					t.Fatalf("got %v; want it accepted", err)
				case skip:
					if !res.StatusSkipped || res.Status != nil {
						t.Errorf("StatusSkipped %v, Status %v; want true, nil", res.StatusSkipped, res.Status)
					}
				default:
					want := []statuslist.Ref{{URI: uri, Index: int(tc.want)}}
					if res.Status == nil || *res.Status != 0 || !slices.Equal(rec.refs, want) {
						t.Errorf("Status %v, checker asked %v; want 0, %v", res.Status, rec.refs, want)
					}
				}
				if len(rec.refs) != 0 && tc.class != accepted {
					t.Errorf("checker asked %v; want no call", rec.refs)
				}
				if res != nil {
					got := res.Claims["status"].(map[string]any)["status_list"].(map[string]any)["idx"]
					if got != tc.idx {
						t.Errorf("Claims idx = %#v; want %#v as signed", got, tc.idx)
					}
				}
			})
		}
	}
}

// splitJWS returns the three segments of a compact JWS.
func splitJWS(t *testing.T, compact string) (header, payload, sig string) {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("%d parts", len(parts))
	}
	return parts[0], parts[1], parts[2]
}

// ownTokens are rejections no standard example shows, signed with a
// generated issuer key; set verifies them.
type ownTokens struct {
	set          func(*setting)
	keys         []issuerkey.PublicKey                                    // the issuer's
	issue        func(claims map[string]any, conceal []sdjwt.Path) string // signs an SD-JWT
	withAud      string                                                   // aud "https://verifier.example", no cnf
	noStatus     string                                                   // no cnf, no status
	concealedJWK string                                                   // cnf.jwk concealed under a plain cnf
	twoMethods   string                                                   // cnf with jwk and jku, and a KB-JWT
	kbAudArray   string                                                   // a valid presentation but for a KB-JWT aud ["v"]
}

// ownCredentials returns an Issue'd credential with status and no cnf, from
// testRequest, and the ownTokens.
func ownCredentials(t *testing.T) (string, ownTokens) {
	t.Helper()
	req, key := testRequest(t), testKey(t)
	req.HolderKey = nil
	req.Status = &statuslist.Ref{URI: "http://status.example/lists/1", Index: 7}
	issued, err := Issue(t.Context(), req, key)
	if err != nil {
		t.Fatal(err)
	}
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderSigner, err := jws.PrivateKeySigner(holder)
	if err != nil {
		t.Fatal(err)
	}
	holderJWK, err := jwk.FromPublicKey(&holder.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000500, 0)
	sign := func(s jws.Signer, pub *ecdsa.PublicKey, typ string, claims map[string]any) string {
		t.Helper()
		token, err := jws.Sign(t.Context(), s, pub, jws.Header{"typ": typ, "kid": key.KID}, []byte(encodeJSON(t, claims)))
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	issuerPub := key.Public.(*ecdsa.PublicKey)
	issue := func(claims map[string]any, conceal []sdjwt.Path) string {
		t.Helper()
		payload, ds, err := sdjwt.Conceal(claims, conceal, sdjwt.ConcealOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return compactSDJWT(sign(key.Signer, issuerPub, typDCSDJWT, payload), ds)
	}
	credential := func(cnf map[string]any, conceal []sdjwt.Path) string {
		t.Helper()
		return issue(map[string]any{"iss": req.Issuer, "vct": req.VCT, "cnf": cnf}, conceal)
	}
	keys := []issuerkey.PublicKey{{KID: key.KID, Public: key.Public}}
	bound := credential(map[string]any{"jwk": holderJWK}, nil)
	kb := sign(holderSigner, &holder.PublicKey, "kb+jwt", map[string]any{
		"aud": []any{"https://verifier.example"}, "nonce": "n-1", "iat": now.Unix(), "sd_hash": sdjwt.SDHash(bound),
	})
	return issued.Serialize(), ownTokens{
		set: func(s *setting) {
			s.issuers = keysOf{req.Issuer: keys}
			s.audience, s.nonce, s.now = "https://verifier.example", "n-1", now
		},
		concealedJWK: credential(map[string]any{"jwk": holderJWK}, []sdjwt.Path{{"cnf", "jwk"}}),
		twoMethods:   credential(map[string]any{"jwk": holderJWK, "jku": "https://issuer.example/jwks"}, nil) + "eyJhbGciOiJFUzI1NiJ9.e30.c2ln",
		kbAudArray:   bound + kb,
		keys:         keys,
		issue:        issue,
		withAud:      issue(map[string]any{"iss": req.Issuer, "vct": req.VCT, "aud": "https://verifier.example"}, nil),
		noStatus:     issue(map[string]any{"iss": req.Issuer, "vct": req.VCT}, nil),
	}
}
