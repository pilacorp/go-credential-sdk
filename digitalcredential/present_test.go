package dc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jwk"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
	"github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

// TC-16, TC-17 (REQ-25, REQ-26): the issued PID of draft-ietf-oauth-sd-jwt-vc-19
// Appendix A.1 (Figure 24). age_equal_or_over is a concealed object holding a
// concealed "18"; nationalities is a concealed array whose elements are not.
func TestPresentA1(t *testing.T) {
	b, err := os.ReadFile("testdata/draft-ietf-oauth-sd-jwt-vc-19-A.1-figure24.txt")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := Parse(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	issuerJWT, _, _, _ := sdjwt.Split(cred.Serialize())
	for _, tc := range []struct {
		name   string
		reveal []sdjwt.Path
		want   []string // names of the disclosures sent, in credential order
	}{
		// RFC 9901 §4.2.6: a nested claim goes with its parent's disclosure.
		{"a nested claim", []sdjwt.Path{{"age_equal_or_over", "18"}}, []string{"18", "age_equal_or_over"}},
		{"nothing", nil, nil},
		{"one claim named twice", []sdjwt.Path{{"given_name"}, {"given_name"}}, []string{"given_name"}},
		// OpenID4VP 1.0 §7.1.1: null selects every element of the array.
		{"all elements of an array", []sdjwt.Path{{"nationalities", nil}}, []string{"nationalities"}},
		// address and its locality are both concealed.
		{"a concealed claim in a concealed object", []sdjwt.Path{{"address", "locality"}}, []string{"locality", "address"}},
	} {
		got, err := cred.Present(t.Context(), PresentRequest{Reveal: tc.reveal})
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if names := disclosureNames(t, got); !slices.Equal(names, tc.want) {
			t.Errorf("%s: sent %q, want %q", tc.name, names, tc.want)
		}
		if !strings.HasPrefix(got.Serialize(), issuerJWT+"~") || !strings.HasSuffix(got.Serialize(), "~") {
			t.Errorf("%s: %q is not the Issuer-signed JWT with disclosures and no KB-JWT", tc.name, got.Serialize())
		}
	}
	for name, p := range map[string]sdjwt.Path{
		"empty path":                        {},
		"absent claim":                      {"family_name_birth"},
		"key into a string element":         {"nationalities", nil, "x"},
		"null on an object":                 {"age_equal_or_over", nil},
		"index past the end":                {"nationalities", 5},
		"negative index":                    {"nationalities", -1},
		"a float component":                 {"nationalities", 1.0},
		"index on an object":                {"address", 0},
		"key into a top-level array member": {"nationalities", 0, "x"},
	} {
		c, err := cred.Present(t.Context(), PresentRequest{Reveal: []sdjwt.Path{p}})
		if c != nil || !errors.Is(err, jose.ErrInvalidArgument) || errors.Is(err, jose.ErrMalformed) {
			t.Errorf("%s: Present = %v, %v; want jose.ErrInvalidArgument only", name, c, err)
		}
	}
}

// TC-17 (REQ-26): null over an array whose elements are concealed sends the
// array's disclosure and every element's; an index sends one element's.
func TestPresentConcealedArray(t *testing.T) {
	req := testRequest(t)
	req.Claims["degrees"] = []any{map[string]any{"type": "BSc"}, map[string]any{"name": "Hanoi University"}}
	req.Claims["mixed"] = []any{map[string]any{"type": "BSc"}, "BA", []any{"MSc"}}
	req.Disclose = []sdjwt.Path{{"nationalities"}, {"nationalities", 0}, {"nationalities", 1}, {"nationalities", 2}, {"degrees", 0}, {"degrees", 1}}
	cred, err := Issue(t.Context(), req, testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		reveal sdjwt.Path
		want   int
	}{
		{sdjwt.Path{"nationalities", nil}, 4},
		{sdjwt.Path{"nationalities", 1}, 2},
		{sdjwt.Path{"nationalities"}, 1},
		// OpenID4VP 1.0 §7.1.1: the second degree has no type, so it drops
		// out and only the first one's disclosure goes.
		{sdjwt.Path{"degrees", nil, "type"}, 1},
	} {
		got, err := cred.Present(t.Context(), PresentRequest{Reveal: []sdjwt.Path{tc.reveal}})
		if err != nil {
			t.Fatalf("%v: %v", tc.reveal, err)
		}
		if n := len(disclosureNames(t, got)); n != tc.want {
			t.Errorf("%v: sent %d disclosures, want %d", tc.reveal, n, tc.want)
		}
	}
	// The element an index names is the one sent: VN, FR, US in order.
	for i, want := range []string{"VN", "FR", "US"} {
		got, err := cred.Present(t.Context(), PresentRequest{Reveal: []sdjwt.Path{{"nationalities", i}}})
		if err != nil {
			t.Fatal(err)
		}
		_, encoded, _, err := sdjwt.Split(got.Serialize())
		if err != nil {
			t.Fatal(err)
		}
		var values []any
		for _, e := range encoded {
			d, err := sdjwt.ParseDisclosure(e)
			if err != nil {
				t.Fatal(err)
			}
			if d.ArrayElement {
				values = append(values, d.Value)
			}
		}
		if len(values) != 1 || values[0] != want {
			t.Errorf("nationalities[%d]: sent %v, want [%s]", i, values, want)
		}
	}
	// OpenID4VP 1.0 §7.1.1: one selected element of the wrong type aborts
	// the selection, even when the others fit.
	for _, p := range []sdjwt.Path{{"mixed", nil, "type"}, {"mixed", nil, nil}, {"mixed", nil, 0}} {
		if _, err := cred.Present(t.Context(), PresentRequest{Reveal: []sdjwt.Path{p}}); !errors.Is(err, jose.ErrInvalidArgument) {
			t.Errorf("%v: %v, want jose.ErrInvalidArgument", p, err)
		}
	}
}

// TC-18 (REQ-27, REQ-28): the Key Binding JWT signs exactly the SD-JWT sent
// before it (RFC 9901 §4.3.1), with the key of cnf.jwk.
func TestPresentKeyBinding(t *testing.T) {
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jws.PrivateKeySigner(holder)
	if err != nil {
		t.Fatal(err)
	}
	req := testRequest(t)
	req.HolderKey = &holder.PublicKey
	// address is concealed and not presented, so the SD-JWT sent differs
	// from the one issued.
	req.Disclose = []sdjwt.Path{{"given_name"}, {"address"}}
	cred, err := Issue(t.Context(), req, testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	iat := time.Unix(1700000500, 0)
	kb := &KeyBinding{Signer: signer, Audience: "https://verifier.example", Nonce: "n-0S6_WzA2Mj", IssuedAt: iat}
	reveal := []sdjwt.Path{{"given_name"}}

	bare, err := cred.Present(t.Context(), PresentRequest{Reveal: reveal})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, kbJWT, _ := sdjwt.Split(bare.Serialize()); kbJWT != "" {
		t.Error("KeyBinding nil wrote a Key Binding JWT")
	}
	bound, err := cred.Present(t.Context(), PresentRequest{Reveal: reveal, KeyBinding: kb})
	if err != nil {
		t.Fatal(err)
	}
	sdJWT, kbJWT, _ := strings.Cut(bound.Serialize(), bare.Serialize())
	if sdJWT != "" || kbJWT == "" {
		t.Fatalf("SD-JWT+KB %q does not start with the SD-JWT sent without KeyBinding", bound.Serialize())
	}
	if _, err := sdjwt.VerifyKBJWT(kbJWT, &holder.PublicKey, sdjwt.KBVerifyParams{
		Audience: kb.Audience, Nonce: kb.Nonce, SDHash: sdjwt.SDHash(bare.Serialize()),
		Now: iat, MaxAge: time.Minute,
	}); err != nil {
		t.Errorf("VerifyKBJWT: %v", err)
	}
	// RFC 9901 §7.2: a Holder MUST reject an SD-JWT+KB.
	again, err := Parse(bound.Serialize())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := again.Present(t.Context(), PresentRequest{}); !errors.Is(err, jose.ErrMalformed) {
		t.Errorf("Present of an SD-JWT+KB: %v, want jose.ErrMalformed", err)
	}

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := jws.PrivateKeySigner(other)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*KeyBinding){
		"a Signer of another key": func(k *KeyBinding) { k.Signer = wrong },
		"no Audience":             func(k *KeyBinding) { k.Audience = "" },
		"Claims holding sd_hash":  func(k *KeyBinding) { k.Claims = map[string]any{"sd_hash": "x"} },
	} {
		k := *kb
		mutate(&k)
		_, err := cred.Present(t.Context(), PresentRequest{Reveal: reveal, KeyBinding: &k})
		want := jose.ErrInvalidArgument
		if name == "a Signer of another key" {
			want = jws.ErrSelfCheck
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
	}
}

// TC-18 (REQ-27): what cnf holds decides the error class, and each error
// matches exactly one of the three.
func TestPresentKeyBindingCnf(t *testing.T) {
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jws.PrivateKeySigner(holder)
	if err != nil {
		t.Fatal(err)
	}
	jwkP256, err := jwk.FromPublicKey(&holder.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	kb := &KeyBinding{Signer: signer, Audience: "https://verifier.example", Nonce: "n", IssuedAt: time.Unix(1700000500, 0)}
	classes := []error{jose.ErrInvalidArgument, ErrKeyBindingUnsupported, jose.ErrMalformed}
	for _, tc := range []struct {
		name string
		cnf  any // nil: no cnf
		want []error
	}{
		{"no cnf", nil, []error{jose.ErrInvalidArgument}},
		{"cnf with kid only", map[string]any{"kid": "holder-1"}, []error{ErrKeyBindingUnsupported}},
		// RFC 8037 OKP: a key type jose/jwk does not convert.
		{"Ed25519 cnf.jwk", map[string]any{"jwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}},
			[]error{ErrKeyBindingUnsupported, jose.ErrUnsupportedKey}},
		// RFC 7800 §3.1: one proof-of-possession key.
		{"jwk and jku", map[string]any{"jwk": jwkP256, "jku": "https://holder.example/jwks"}, []error{jose.ErrMalformed}},
		// RFC 7800 §3.2: no symmetric key in a JWS.
		{"symmetric cnf.jwk", map[string]any{"jwk": map[string]any{"kty": "oct", "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}},
			[]error{jose.ErrMalformed, jwk.ErrBadKey}},
		{"cnf a string", "holder-1", []error{jose.ErrMalformed, jwk.ErrBadKey}},
		{"cnf.jwk a string", map[string]any{"jwk": "holder-1"}, []error{jose.ErrMalformed, jwk.ErrBadKey}},
		{"cnf.jwk off the curve", map[string]any{"jwk": map[string]any{"kty": "EC", "crv": "P-256", "x": jwkP256["x"], "y": jwkP256["x"]}},
			[]error{jose.ErrMalformed, jwk.ErrBadKey}},
	} {
		// Issue refuses the malformed ones, so every credential is signed
		// here, as one from another issuer.
		claims := map[string]any{"iss": "https://issuer.example", "vct": "urn:example:pid"}
		if tc.cnf != nil {
			claims["cnf"] = tc.cnf
		}
		_, err = signedCredential(t, claims, nil).Present(t.Context(), PresentRequest{KeyBinding: kb})
		for _, w := range tc.want {
			if !errors.Is(err, w) {
				t.Errorf("%s: %v, want %v", tc.name, err, w)
			}
		}
		n := 0
		for _, c := range classes {
			if errors.Is(err, c) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%s: %v matches %d of the three classes, want 1", tc.name, err, n)
		}
	}
}

// signedCredential signs payload as an Issuer-signed JWT with testKey and
// parses it with disclosures: a credential Issue would not write.
func signedCredential(t *testing.T, payload map[string]any, disclosures []sdjwt.Disclosure) *Credential {
	t.Helper()
	body, err := jose.EncodeJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	key := testKey(t)
	issuerJWT, err := jws.Sign(t.Context(), key.Signer, key.Public, jws.Header{"typ": "dc+sd-jwt"}, body)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := Parse(compactSDJWT(issuerJWT, disclosures))
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

// TC-18 (REQ-27): draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 forbids cnf and its
// sub-claims in a disclosure; Issue never writes one, so the credential is
// built with jose directly.
func TestPresentConcealedCnf(t *testing.T) {
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jws.PrivateKeySigner(holder)
	if err != nil {
		t.Fatal(err)
	}
	jwkP256, err := jwk.FromPublicKey(&holder.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	kb := &KeyBinding{Signer: signer, Audience: "https://verifier.example", Nonce: "n", IssuedAt: time.Unix(1700000500, 0)}
	withKID := maps.Clone(jwkP256)
	withKID["kid"] = "holder-1"
	// draft 19 §2.2.2.3 forbids cnf "including any of their sub-claims" in a
	// disclosure; a disclosed jku next to a signed jwk would be a second key.
	for _, tc := range []struct {
		cnf     map[string]any
		conceal sdjwt.Path
	}{
		{map[string]any{"jwk": jwkP256}, sdjwt.Path{"cnf"}},
		{map[string]any{"jwk": jwkP256}, sdjwt.Path{"cnf", "jwk"}},
		{map[string]any{"jwk": jwkP256, "jku": "https://holder.example/jwks"}, sdjwt.Path{"cnf", "jku"}},
		{map[string]any{"jwk": withKID}, sdjwt.Path{"cnf", "jwk", "kid"}},
	} {
		conceal := tc.conceal
		claims := map[string]any{"iss": "https://issuer.example", "vct": "urn:example:pid", "cnf": tc.cnf}
		payload, ds, err := sdjwt.Conceal(claims, []sdjwt.Path{conceal}, sdjwt.ConcealOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = signedCredential(t, payload, ds).Present(t.Context(), PresentRequest{KeyBinding: kb})
		if !errors.Is(err, jose.ErrMalformed) || errors.Is(err, ErrKeyBindingUnsupported) || errors.Is(err, jose.ErrInvalidArgument) {
			t.Errorf("%v concealed: %v, want jose.ErrMalformed only", conceal, err)
		}
	}
}

// TC-36 (REQ-51): Issue signs what Present cannot read back; Present keeps
// the 1 MiB limit of sdjwt.Split.
func TestPresentOverLimit(t *testing.T) {
	req := testRequest(t)
	req.Claims["photo"] = strings.Repeat("A", 1<<20)
	cred, err := Issue(t.Context(), req, testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cred.Present(t.Context(), PresentRequest{}); !errors.Is(err, jose.ErrMalformed) {
		t.Errorf("Present over 1 MiB: %v, want jose.ErrMalformed", err)
	}
}

// disclosureNames returns the claim name of each disclosure c sends, or "[]"
// for an array element.
func disclosureNames(t *testing.T, c *Credential) []string {
	t.Helper()
	_, encoded, _, err := sdjwt.Split(c.Serialize())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range encoded {
		d, err := sdjwt.ParseDisclosure(e)
		if err != nil {
			t.Fatal(err)
		}
		if d.ArrayElement {
			names = append(names, "[]")
		} else {
			names = append(names, d.Name)
		}
	}
	return names
}
