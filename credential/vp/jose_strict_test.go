// Tests for the stricter checks the jose module enforces on VP paths.
// Each test exercises one item from issue #99. The jose module's strict
// checks (crit, UTF-8, strict base64url) are enforced in jws.Verify, which
// runs during Verify(), not during Parse().
package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/internal/jwttest"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
	"github.com/pilacorp/go-credential-sdk/jose"
)

func vpJoseSetup(t *testing.T) (string, *ecdsa.PrivateKey, vmpkg.ResolverProvider) {
	t.Helper()
	const did = "did:example:vp-jose-strict"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(did, mustP256VM(t, did, "key-1", &priv.PublicKey)))
	return did, priv, resolver
}

func signedJOSEPresentation(t *testing.T, did string, priv *ecdsa.PrivateKey, resolver vmpkg.ResolverProvider) string {
	t.Helper()
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}
	pres, err := vp.NewJOSEPresentation(joseVPContents(did),
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new jose presentation: %v", err)
	}
	if err := pres.AddProofByProvider(prov, vp.WithResolver(resolver)); err != nil {
		t.Fatalf("sign: %v", err)
	}
	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return serialized.(string)
}

// --- #99 item 1: crit header rejection ---

func TestVPJOSEStrict_CritHeaderRejected(t *testing.T) {
	did, priv, resolver := vpJoseSetup(t)
	token := signedJOSEPresentation(t, did, priv, resolver)

	parts := strings.SplitN(token, ".", 3)
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatal(err)
	}
	header["crit"] = []string{"urn:example:unsupported"}
	header["urn:example:unsupported"] = true
	newHeader, _ := json.Marshal(header)
	tampered := base64.RawURLEncoding.EncodeToString(newHeader) + "." + parts[1] + "." + parts[2]

	// Parse may succeed; the crit check is in jws.Verify via jwt.VerifyJWT.
	pres, err := vp.ParsePresentation([]byte(tampered), vp.WithResolver(resolver))
	if err != nil {
		if strings.Contains(err.Error(), "crit") {
			return
		}
		t.Fatalf("parse failed for a reason other than crit: %v", err)
	}
	err = pres.Verify(vp.WithResolver(resolver))
	if err == nil {
		t.Fatal("accepted a VP with crit in header; want rejection")
	}
	if !strings.Contains(err.Error(), "crit") {
		t.Fatalf("err = %v, want one mentioning crit", err)
	}
}

// --- #99 item 7: non-strict base64url ---

func TestVPJOSEStrict_PadBitAliasRejected(t *testing.T) {
	did, priv, resolver := vpJoseSetup(t)
	parts := strings.SplitN(signedJOSEPresentation(t, did, priv, resolver), ".", 3)
	tampered := parts[0] + "." + parts[1] + "." + jwttest.PadBitAlias(t, parts[2])

	pres, err := vp.ParsePresentation([]byte(tampered), vp.WithResolver(resolver))
	if err == nil {
		err = pres.Verify(vp.WithResolver(resolver))
	}
	if !errors.Is(err, jose.ErrMalformed) || !strings.Contains(err.Error(), "base64url") {
		t.Fatalf("err = %v, want the signature segment refused as malformed base64url", err)
	}
}

// The VC 1.1 presentation parser reads the header by the rules VerifyJWT
// uses, also when called directly.
func TestJWT11_BrokenPresentationHeaderRefusedAtParse(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	payload := enc([]byte(`{"vp":{}}`))
	for _, h := range []string{`null`, `{"typ":"JWT","typ":"JWT"}`} {
		if _, err := vp.ParseJWTPresentation(enc([]byte(h)) + "." + payload + ".c2ln"); err == nil || !strings.Contains(err.Error(), "invalid JWT header") {
			t.Errorf("header %s: err = %v, want it refused", h, err)
		}
	}
}

// resignES256VP signs header and payload with priv for VP tests.
func resignES256VP(t *testing.T, priv *ecdsa.PrivateKey, header []byte, payloadB64 string) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString(header) + "." + payloadB64
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// --- #99 item 5: enveloped credential id and @context ---

// vpTokenWithEnvelopedVC builds a signed vp+jwt whose payload contains a
// single enveloped credential entry with the given fields. The token is
// structurally valid apart from whatever the caller tampers with.
func vpTokenWithEnvelopedVC(t *testing.T, priv *ecdsa.PrivateKey, did string, entry map[string]interface{}) string {
	t.Helper()
	header := map[string]interface{}{
		"typ": "vp+jwt",
		"alg": "ES256",
		"kid": did + "#key-1",
	}
	payload := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               did,
		"iss":                  did,
		"verifiableCredential": []interface{}{entry},
	}
	hJSON, _ := json.Marshal(header)
	pJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(pJSON)
	return resignES256VP(t, priv, hJSON, payloadB64)
}

func TestVPJOSEStrict_EnvelopedCredentialIDNotDataURL(t *testing.T) {
	did, priv, _ := vpJoseSetup(t)
	entry := map[string]interface{}{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type":     "EnvelopedVerifiableCredential",
		"id":       "https://example.com/vc/1",
	}
	token := vpTokenWithEnvelopedVC(t, priv, did, entry)
	_, err := vp.ParseJOSEPresentation(token)
	if err == nil {
		t.Fatal("accepted an enveloped credential whose id is not a data: URL")
	}
	if !strings.Contains(err.Error(), "data:") {
		t.Fatalf("error = %v, want one mentioning data: URL", err)
	}
}

func TestVPJOSEStrict_EnvelopedCredentialMissingContext(t *testing.T) {
	did, priv, _ := vpJoseSetup(t)
	entry := map[string]interface{}{
		"type": "EnvelopedVerifiableCredential",
		"id":   "data:application/vc+jwt,eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.c2ln",
	}
	token := vpTokenWithEnvelopedVC(t, priv, did, entry)
	_, err := vp.ParseJOSEPresentation(token)
	if err == nil {
		t.Fatal("accepted an enveloped credential without @context")
	}
	if !strings.Contains(err.Error(), "@context") {
		t.Fatalf("error = %v, want one mentioning @context", err)
	}
}

func TestVPJOSEStrict_EnvelopedCredentialValidDataURL(t *testing.T) {
	did, priv, resolver := vpJoseSetup(t)
	// The scheme and media type of a data: URL are case-insensitive
	// (RFC 2397, RFC 2045 section 5.1), so another implementation's
	// capitalization is accepted too.
	for _, id := range []string{
		"data:application/vc+jwt,eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.c2ln",
		"DATA:Application/VC+JWT,eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.c2ln",
	} {
		t.Run(id[:24], func(t *testing.T) {
			entry := map[string]interface{}{
				"@context": "https://www.w3.org/ns/credentials/v2",
				"type":     "EnvelopedVerifiableCredential",
				"id":       id,
			}
			token := vpTokenWithEnvelopedVC(t, priv, did, entry)
			pres, err := vp.ParsePresentation([]byte(token), vp.WithResolver(resolver))
			if err != nil {
				t.Fatalf("ParsePresentation with valid enveloped credential: %v", err)
			}
			if err := pres.Verify(vp.WithResolver(resolver)); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

// An uppercase DATA:Application/VC+JWT prefix must pass ParsePresentation AND
// Verify(WithVCValidation): the VP gate and the credential unwrap must agree on
// case folding, or the credential reads as a JSON object with no issuer.
func TestVPJOSEStrict_UppercaseEnvelopeParsesCredential(t *testing.T) {
	const did = "did:example:vp-jose-uppercase-envelope"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}
	resolver := vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(did, mustP256VM(t, did, "key-1", &priv.PublicKey)))

	cred, err := vc.NewJOSECredential(joseVPCredentialContents(did),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new jose cred: %v", err)
	}
	if err := cred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign jose cred: %v", err)
	}
	token, err := cred.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	entry := map[string]interface{}{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type":     "EnvelopedVerifiableCredential",
		"id":       "DATA:Application/VC+JWT," + token.(string),
	}
	vpToken := vpTokenWithEnvelopedVC(t, priv, did, entry)
	pres, err := vp.ParsePresentation([]byte(vpToken), vp.WithResolver(resolver))
	if err != nil {
		t.Fatalf("ParsePresentation: %v", err)
	}
	if err := pres.Verify(vp.WithResolver(resolver),
		vp.WithVCValidation(vc.WithResolver(resolver))); err != nil {
		t.Fatalf("Verify with WithVCValidation: %v", err)
	}
}

// The envelope's @context must include the v2 context, not start with it.
// ["https://example.org/ctx", v2] is a valid envelope.
func TestVPJOSEStrict_EnvelopeContextIncludesV2(t *testing.T) {
	did, priv, resolver := vpJoseSetup(t)
	entry := map[string]interface{}{
		"@context": []interface{}{"https://example.org/ctx", "https://www.w3.org/ns/credentials/v2"},
		"type":     "EnvelopedVerifiableCredential",
		"id":       "data:application/vc+jwt,eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.c2ln",
	}
	token := vpTokenWithEnvelopedVC(t, priv, did, entry)
	pres, err := vp.ParsePresentation([]byte(token), vp.WithResolver(resolver))
	if err != nil {
		t.Fatalf("ParsePresentation refused a valid envelope @context: %v", err)
	}
	if err := pres.Verify(vp.WithResolver(resolver)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// An envelope whose data: URL carries no token is refused where the envelope
// is checked, as the JSON presentation path does, not later when the
// credential is opened.
func TestVPJOSEStrict_EnvelopeEmptyTokenRefused(t *testing.T) {
	did, priv, resolver := vpJoseSetup(t)
	entry := map[string]interface{}{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type":     "EnvelopedVerifiableCredential",
		"id":       "data:application/vc+jwt,",
	}
	token := vpTokenWithEnvelopedVC(t, priv, did, entry)
	_, err := vp.ParsePresentation([]byte(token), vp.WithResolver(resolver))
	if err == nil || !strings.Contains(err.Error(), "no token") {
		t.Fatalf("err = %v, want the empty envelope token refused", err)
	}
}

// Every presentation parser reads header and payload by jose's rules: a
// duplicate key is refused at parse.
func TestDuplicateKeyRefusedByEveryPresentationParser(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for name, parse := range map[string]func() error{
		"vp+jwt header": func() error {
			_, err := vp.ParseJOSEPresentation(enc(`{"alg":"ES256","typ":"vp+jwt","typ":"vp+jwt"}`) + "." + enc(`{}`) + ".c2ln")
			return err
		},
		"vp+jwt payload": func() error {
			_, err := vp.ParseJOSEPresentation(enc(`{"alg":"ES256","typ":"vp+jwt"}`) + "." + enc(`{"holder":"a","holder":"b"}`) + ".c2ln")
			return err
		},
		"VC-JWT 1.1 presentation payload": func() error {
			_, err := vp.ParseJWTPresentation(enc(`{"alg":"ES256K","typ":"JWT"}`) + "." + enc(`{"vp":{},"vp":{}}`) + ".c2ln")
			return err
		},
	} {
		if err := parse(); err == nil || !strings.Contains(err.Error(), "duplicate key") {
			t.Errorf("%s: err = %v, want the duplicate key refused", name, err)
		}
	}
}

// A JOSE header over 64 KiB is refused before it is decoded on every
// presentation route.
func TestOversizedHeaderRefusedOnEveryPresentationRoute(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	h := enc(`{"alg":"ES256","typ":"vp+jwt","x":"` + strings.Repeat("a", 70<<10) + `"}`)
	tok := h + "." + enc(`{}`) + ".c2ln"
	for name, parse := range map[string]func() error{
		// The router reads the header to pick a parser: its own refusal.
		"ParsePresentation": func() error {
			_, err := vp.ParsePresentation([]byte(tok))
			if err != nil && !strings.HasPrefix(err.Error(), "failed to parse presentation: invalid JWT header") {
				return fmt.Errorf("refused after routing, not by the router: %v", err)
			}
			return err
		},
		"ParseJOSEPresentation": func() error { _, err := vp.ParseJOSEPresentation(tok); return err },
		"ParseJWTPresentation":  func() error { _, err := vp.ParseJWTPresentation(tok); return err },
	} {
		if err := parse(); !errors.Is(err, jose.ErrMalformed) || !strings.Contains(err.Error(), "header is over") {
			t.Errorf("%s: err = %v, want the header refused for its size", name, err)
		}
	}
}

// A verification method whose id would put the header over 64 KiB is refused
// when the presentation is built, before any signer runs.
func TestVPJOSEStrict_OversizedKidRefusedAtBuild(t *testing.T) {
	did := "did:example:" + strings.Repeat("a", 70<<10)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, mustP256VM(t, did, "key-1", &priv.PublicKey)))
	jwtContents := jwtVPContents()
	jwtContents.Holder = did
	for name, build := range map[string]func() error{
		"vp+jwt": func() error {
			_, err := vp.NewJOSEPresentation(joseVPContents(did), vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
			return err
		},
		"VP-JWT 1.1": func() error {
			_, err := vp.NewJWTPresentation(jwtContents, vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
			return err
		},
	} {
		if err := build(); !errors.Is(err, jose.ErrInvalidArgument) || !strings.Contains(err.Error(), "header is over") {
			t.Errorf("%s: err = %v, want the oversized header refused at build", name, err)
		}
	}
}

// A header or payload segment whose last character sets unused bits
// (RFC 4648 §3.5) is refused at parse, as the signature segment is.
func TestVPJOSEStrict_HeaderAndPayloadPadBitAliasRefusedAtParse(t *testing.T) {
	seg := func(j string) string {
		for len(j)%3 != 1 {
			j = strings.TrimSuffix(j, "}") + " }"
		}
		return base64.RawURLEncoding.EncodeToString([]byte(j))
	}
	sig := strings.Repeat("A", 86)
	payload := `{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiablePresentation"],"holder":"did:example:h"}`
	for _, typ := range []string{"vp+jwt", "JWT"} {
		h := seg(`{"alg":"ES256","typ":"` + typ + `"}`)
		p := seg(payload)
		for name, tok := range map[string]string{
			"header":  jwttest.PadBitAlias(t, h) + "." + p + "." + sig,
			"payload": h + "." + jwttest.PadBitAlias(t, p) + "." + sig,
		} {
			if _, err := vp.ParsePresentation([]byte(tok)); !errors.Is(err, jose.ErrMalformed) {
				t.Errorf("%s %s: err = %v, want the aliased segment refused as malformed", typ, name, err)
			}
		}
	}
}

// typ is a media type: case is ignored and "application/" is implied
// (RFC 7515 §4.1.9), so each spelling routes to the vp+jwt parser.
func TestVPJOSEStrict_TypCaseInsensitive(t *testing.T) {
	did, priv, resolver := vpJoseSetup(t)
	parts := strings.SplitN(signedJOSEPresentation(t, did, priv, resolver), ".", 3)
	var header map[string]interface{}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"VP+JWT", "Application/vp+jwt"} {
		header["typ"] = typ
		h, err := json.Marshal(header)
		if err != nil {
			t.Fatal(err)
		}
		tok := base64.RawURLEncoding.EncodeToString(h) + "." + parts[1] + "." + parts[2]
		p, err := vp.ParsePresentation([]byte(tok))
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if _, ok := p.(*vp.JOSEPresentation); !ok {
			t.Fatalf("%s: parsed as %T, want *vp.JOSEPresentation", typ, p)
		}
	}
}

// A megabyte @context in an unsigned vp+jwt does not come back as a
// megabyte error text.
func TestVPJOSEStrict_ErrorTextBoundedForPayloadValues(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	payload := `{"@context":["` + strings.Repeat("a", 1<<20) + `"],"type":["VerifiablePresentation"],"holder":"did:example:h"}`
	tok := enc(`{"alg":"ES256","typ":"vp+jwt"}`) + "." + enc(payload) + "." + strings.Repeat("A", 86)
	if _, err := vp.ParsePresentation([]byte(tok)); err == nil || len(err.Error()) > 1024 {
		t.Fatalf("err of %d bytes, want a bounded refusal", len(fmt.Sprint(err)))
	}
}

// --- #99 item 8: ParsePresentation returns untyped nil on error ---

func TestParsePresentation_ReturnsUntypedNilOnError(t *testing.T) {
	// A VC 1.1 JWT missing the vp claim reaches ParseJWTPresentation's error
	// path through ParsePresentation. If the concrete nil leaks through, the
	// caller gets a non-nil Presentation interface.
	jwtHeader, _ := json.Marshal(map[string]interface{}{"alg": "ES256", "typ": "JWT"})
	jwtPayload, _ := json.Marshal(map[string]interface{}{"iss": "did:example:123"})
	jwtToken := base64.RawURLEncoding.EncodeToString(jwtHeader) + "." +
		base64.RawURLEncoding.EncodeToString(jwtPayload) + ".fakesig"

	cases := []struct {
		name  string
		input []byte
	}{
		{"empty", nil},
		{"JWT missing vp claim", []byte(jwtToken)},
		{"garbage", []byte(`not-a-presentation!!!`)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := vp.ParsePresentation(tc.input)
			if err == nil {
				t.Fatal("expected an error")
			}
			if p != nil {
				t.Fatalf("ParsePresentation returned a non-nil Presentation (%T) on error", p)
			}
		})
	}
}
