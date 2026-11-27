// Tests for the stricter checks the jose module enforces on VP paths.
// Each test exercises one item from issue #99. The jose module's strict
// checks (crit, UTF-8, strict base64url) are enforced in jws.Verify, which
// runs during Verify(), not during Parse().
package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/internal/jwttest"
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
