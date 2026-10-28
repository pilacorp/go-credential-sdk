package digitalcredential

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
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
type keysOf map[string][]issuerkey.Key

func (k keysOf) Keys(_ context.Context, iss string) ([]issuerkey.Key, error) { return k[iss], nil }

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

// draft19Policy verifies the examples of draft-ietf-oauth-sd-jwt-vc-19
// §2.3.2: the RFC 9901 Appendix A.5 key under the kid of §4.2 Figure 14, the
// Figure 8 aud and nonce, and a time at its KB-JWT iat.
func draft19Policy(t *testing.T) Policy {
	t.Helper()
	key, err := jwk.ToPublicKey(map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ",
		"y": "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8",
	})
	if err != nil {
		t.Fatal(err)
	}
	return Policy{
		Issuers:  keysOf{"https://example.com/issuer": {{KID: "doc-signer-05-25-2022", Key: key}}},
		Audience: "https://example.com/verifier",
		Nonce:    "1234567890",
		Now:      time.Unix(1788209978, 0),
	}
}

// failingResolver answers every iss with err.
type failingResolver struct{ err error }

func (r failingResolver) Keys(context.Context, string) ([]issuerkey.Key, error) { return nil, r.err }

// A resolver's ErrNoUsableKey is a definite answer, so it is
// ISSUER_KEY_NOT_FOUND even when ctx has ended; jose.ErrInvalidArgument is
// the resolver's wiring, so ErrPolicy.
func TestVerifyResolverAnswers(t *testing.T) {
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	p := draft19Policy(t)
	p.Issuers = failingResolver{fmt.Errorf("resolver: %w", issuerkey.ErrNoUsableKey)}
	var vErr *Error
	if _, err := Verify(ended, draft19Fig8, p); !errors.As(err, &vErr) || vErr.Code != CodeIssuerKeyNotFound {
		t.Errorf("ErrNoUsableKey, ctx ended: err = %v, want ISSUER_KEY_NOT_FOUND", err)
	}
	p.Issuers = failingResolver{fmt.Errorf("resolver: %w", jose.ErrInvalidArgument)}
	if _, err := Verify(context.Background(), draft19Fig8, p); !errors.Is(err, ErrPolicy) {
		t.Errorf("jose.ErrInvalidArgument: err = %v, want ErrPolicy", err)
	}
}

// draft-ietf-oauth-sd-jwt-vc-19 §2.3.2: Figure 8 verifies, and the
// processed payload is Figure 9.
func TestVerifyDraft19Example(t *testing.T) {
	got, err := Verify(context.Background(), draft19Fig8, draft19Policy(t))
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
}

// Each refusal has its one Code, or is ErrPolicy for the caller's mistake.
func TestVerifyRejects(t *testing.T) {
	ctx := context.Background()
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
	// A Key Binding JWT whose alg the policy does not allow; its signature is
	// never reached.
	kbES256K := strings.Replace(draft19Fig8, kbJWT[:strings.IndexByte(kbJWT, '.')], jose.EncodeSegment([]byte(`{"alg":"ES256K","typ":"kb+jwt"}`)), 1)
	// A 60 KB header key, twice: the text quotes it bounded.
	longKey := strings.Repeat("é", 15000)
	echo := withHeader(`{"alg":"ES256","typ":"dc+sd-jwt","` + longKey + `":1,"` + longKey + `":2}`)

	issued, own := ownCredentials(t)
	// testRequest's status_list and issuer.
	ref, iss := statuslist.Ref{URI: "http://status.example/lists/1", Index: 7}, "https://issuer.example"
	withStatus := func(c fixedStatus) func(*Policy) {
		return func(p *Policy) { own.policy(p); p.Status = c }
	}
	// draft 19 §2.2.2.3: claims that MUST NOT be in a Disclosure. The
	// credential is valid but for the concealed claim; a concealed iss
	// leaves none, which the resolver answers too.
	neverDisclosed := map[string]any{
		"iss": iss, "vct": "urn:example:pid", "exp": 1800000000, "nbf": 1700000100,
		"status": map[string]any{"status_list": map[string]any{"uri": ref.URI, "idx": ref.Index}},
	}
	concealedPolicy := func(p *Policy) {
		own.policy(p)
		p.Issuers = keysOf{iss: own.keys, "": own.keys}
		p.SkipStatus = true
	}

	type row struct {
		name    string
		compact string
		policy  func(*Policy)
		want    Code  // "": ErrPolicy
		is      error // when set, errors.Is must hold too
	}
	rows := []row{
		// RFC 9901 §9.11, draft 19 §2.2.1: the profile's explicit type.
		{"typ vc+sd-jwt", withHeader(`{"alg":"ES256","typ":"vc+sd-jwt","kid":"doc-signer-05-25-2022"}`), nil, CodeTypInvalid, nil},
		// RFC 9901 §7.1 step 2a: none is never accepted.
		{"alg none", withHeader(`{"alg":"none","typ":"dc+sd-jwt","kid":"doc-signer-05-25-2022"}`), nil, CodeAlgNotAllowed, nil},
		// RFC 8725 §3.1: only the algorithms the verifier allows.
		{"issuer alg not allowed", draft19Fig8, func(p *Policy) { p.AllowedAlgs = []string{jws.AlgES256K} }, CodeAlgNotAllowed, nil},
		{"signature altered", tampered, nil, CodeSignatureInvalid, nil},
		{"bad signature over a duplicate claim", dupClaim, nil, CodeSignatureInvalid, nil},
		// RFC 7515 §10.12, RFC 7519 §4: a duplicate header key, quoted bounded.
		{"duplicate 60 KB header key", echo, nil, CodeMalformed, nil},
		// RFC 7519 §4.1.4: on or after exp, here exp + the 1 minute skew.
		{"expired", draft19Fig8, func(p *Policy) { p.Now = time.Unix(1883000060, 0) }, CodeExpired, nil},
		// RFC 7519 §4.1.3: the credential's own aud, not the KB-JWT's.
		{"credential for another audience", own.withAud, func(p *Policy) {
			own.policy(p)
			p.CredentialAudience = "https://other.example"
			p.Audience = "https://verifier.example"
		}, CodeAudienceMismatch, nil},
		// RFC 9901 §7.3 step 2, §9.5: the credential binds a key (cnf).
		{"KB-JWT stripped", stripped, nil, CodeKBMissing, nil},
		{"KB-JWT stripped, KeyBindingRequired", stripped, func(p *Policy) { p.KeyBinding = KeyBindingRequired }, CodeKBMissing, nil},
		// draft 19 §2.4: Key Binding is checked with cnf, and Figure 10 has
		// none, so no presentation can pass, Figure 8's KB-JWT included.
		// Figure 10 has no kid, which Select accepts from an issuer of one key.
		{"no cnf, KeyBindingRequired", draft19Fig10 + kbJWT, func(p *Policy) { p.KeyBinding = KeyBindingRequired }, CodeKBUnsupported, nil},
		// RFC 9901 §4 and §7.2: a Holder, or a verifier expecting an SD-JWT.
		{"KB-JWT sent, KeyBindingNotRequired", draft19Fig8, func(p *Policy) { p.KeyBinding = KeyBindingNotRequired }, CodeKBUnexpected, nil},
		// RFC 9901 §7.3 step 5b, RFC 8725 §3.1: the holder's alg too.
		{"KB-JWT alg not allowed", kbES256K, func(p *Policy) { p.AllowedAlgs = []string{jws.AlgES256} }, CodeKBInvalid, jws.ErrAlgNotAllowed},
		// RFC 9901 §7.3 step 5e: 3 minutes old, past a 1 minute MaxKBAge and
		// the 1 minute skew, within the 5 minute default.
		{"KB-JWT older than MaxKBAge", draft19Fig8, func(p *Policy) {
			p.Now = time.Unix(1788209978+180, 0)
			p.MaxKBAge = time.Minute
		}, CodeKBInvalid, nil},
		// RFC 9901 §7.3 steps 5f and 5g.
		{"KB-JWT for another verifier", draft19Fig8, func(p *Policy) { p.Audience = "https://other.example" }, CodeKBAudienceMismatch, nil},
		{"KB-JWT for another transaction", draft19Fig8, func(p *Policy) { p.Nonce = "0987654321" }, CodeKBNonceMismatch, nil},
		{"disclosure dropped after binding", dropped, nil, CodeKBSDHashMismatch, nil},
		// draft 19 §2.2.2.3: cnf and its sub-claims stay out of Disclosures.
		{"cnf.jwk in a Disclosure", own.concealedJWK, own.policy, CodeDisclosureInvalid, nil},
		// RFC 7800 §3.1: one proof-of-possession key.
		{"cnf with jwk and jku", own.twoMethods, own.policy, CodeMalformed, nil},
		// RFC 9901 §4.3: aud is a single string; an array is not a mismatch.
		{"KB-JWT aud an array", own.kbAudArray, own.policy, CodeKBInvalid, nil},
		// draft-ietf-oauth-status-list-21 §7.1: 0x01 is INVALID.
		{"revoked", issued, withStatus(fixedStatus{ref: ref, iss: iss, v: 0x01}), CodeRevoked, nil},
		// draft-ietf-oauth-status-list-21 §8.3: no statement can be made.
		{"status unavailable", issued, withStatus(fixedStatus{ref: ref, iss: iss, err: errors.New("list unreachable")}), CodeStatusUnavailable, nil},
		// draft-ietf-oauth-status-list-21 §8.3 step 6: MUST be rejected.
		{"idx out of bounds", issued, withStatus(fixedStatus{ref: ref, iss: iss, err: fmt.Errorf("list: %w", statuslist.ErrIndexOutOfBounds)}), CodeMalformed, statuslist.ErrIndexOutOfBounds},
		// draft 19 §2.4: status SHOULD be checked, so not checking is opted into.
		{"status and no Policy.Status", issued, own.policy, "", nil},
	}
	// Named here, not taken from the code under test.
	for _, name := range []string{"iss", "exp", "nbf", "vct", "status"} {
		rows = append(rows, row{name + " in a Disclosure", own.issue(neverDisclosed, []sdjwt.Path{{name}}), concealedPolicy, CodeDisclosureInvalid, nil})
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			p := draft19Policy(t)
			if tc.policy != nil {
				tc.policy(&p)
			}
			res, err := Verify(ctx, tc.compact, p)
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
			case tc.is != nil && !errors.Is(err, tc.is):
				t.Fatalf("got %v; want it to match %v", err, tc.is)
			}
			// Texts quote token content bounded, whatever the token holds.
			if n := len(err.Error()); n > 1024 {
				t.Fatalf("error text is %d bytes", n)
			}
		})
	}
}

// splitJWS returns the three segments of a compact JWS.
// recordingStatus is a StatusChecker that answers 0, VALID, and records
// each reference it is asked for.
type recordingStatus struct{ refs []statuslist.Ref }

func (c *recordingStatus) Status(_ context.Context, ref statuslist.Ref, _ string) (uint8, error) {
	c.refs = append(c.refs, ref)
	return 0, nil
}

// draft-ietf-oauth-status-list-21 §6.2: idx is a non-negative Integer, a
// value, which RFC 8259 §6 writes in many forms. Each form below is read
// as its exact value, refused, or, past an int, past every list (§8.3 step
// 6), in both status modes, and the checker is asked only for a valid idx.
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
				p := draft19Policy(t)
				own.policy(&p)
				p.Status, p.SkipStatus = rec, skip
				res, err := Verify(context.Background(), compact, p)
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
				if len(rec.refs) != 0 && (skip || tc.class != accepted) {
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

func splitJWS(t *testing.T, compact string) (header, payload, sig string) {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("%d parts", len(parts))
	}
	return parts[0], parts[1], parts[2]
}

// ownTokens are refusals no standard example shows, signed with a generated
// issuer key; policy verifies them.
type ownTokens struct {
	policy       func(*Policy)
	keys         []issuerkey.Key                                          // the issuer's
	issue        func(claims map[string]any, conceal []sdjwt.Path) string // signs an SD-JWT
	withAud      string                                                   // aud "https://verifier.example", no cnf
	concealedJWK string                                                   // cnf.jwk concealed under a plain cnf
	twoMethods   string                                                   // cnf with jwk and jku, and a KB-JWT
	kbAudArray   string                                                   // a valid presentation but for a KB-JWT aud ["v"]
}

// ownCredentials returns an Issue'd credential with status and no cnf, from
// testRequest, and the ownTokens.
func ownCredentials(t *testing.T) (string, ownTokens) {
	t.Helper()
	req, key := testRequest(t)
	req.HolderKey = nil
	issued, err := Issue(req, key)
	if err != nil {
		t.Fatal(err)
	}
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
		token, err := jws.Sign(s, pub, jws.Header{"typ": typ, "kid": key.KID}, []byte(encodeJSON(t, claims)))
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	issue := func(claims map[string]any, conceal []sdjwt.Path) string {
		t.Helper()
		payload, ds, err := sdjwt.Conceal(claims, conceal, sdjwt.ConcealOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return compactSDJWT(sign(key.Signer, key.Public, typDCSDJWT, payload), ds)
	}
	credential := func(cnf map[string]any, conceal []sdjwt.Path) string {
		t.Helper()
		return issue(map[string]any{"iss": req.Issuer, "vct": req.VCT, "cnf": cnf}, conceal)
	}
	keys := []issuerkey.Key{{KID: key.KID, Key: key.Public}}
	bound := credential(map[string]any{"jwk": holderJWK}, nil)
	kb := sign(memSigner{holder}, &holder.PublicKey, "kb+jwt", map[string]any{
		"aud": []any{"https://verifier.example"}, "nonce": "n-1", "iat": now.Unix(), "sd_hash": sdjwt.SDHash(bound),
	})
	return issued, ownTokens{
		policy: func(p *Policy) {
			p.Issuers = keysOf{req.Issuer: keys}
			p.Audience, p.Nonce, p.Now = "https://verifier.example", "n-1", now
		},
		concealedJWK: credential(map[string]any{"jwk": holderJWK}, []sdjwt.Path{{"cnf", "jwk"}}),
		twoMethods:   credential(map[string]any{"jwk": holderJWK, "jku": "https://issuer.example/jwks"}, nil) + "eyJhbGciOiJFUzI1NiJ9.e30.c2ln",
		kbAudArray:   bound + kb,
		keys:         keys,
		issue:        issue,
		withAud:      issue(map[string]any{"iss": req.Issuer, "vct": req.VCT, "aud": "https://verifier.example"}, nil),
	}
}
