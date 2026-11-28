// Tests for the stricter checks the jose module enforces once the VC/VP paths
// route through jose/jws and jose/sdjwt. Each test exercises one item from
// issue #99. Header and payload are read by jose's JSON rules (duplicate
// keys, UTF-8, one base64url spelling) at Parse(); crit and the signature
// segment are checked by jws.Verify during Verify(). SD-JWT structural checks
// (array element removal, forbidden disclosure names, KB-JWT acceptance) are
// enforced by jose/sdjwt during Parse().
package vc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
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
	"github.com/pilacorp/go-credential-sdk/jose"
)

// signedJOSEToken issues a vc+jwt credential and returns its compact
// serialization as a string.
func signedJOSEToken(t *testing.T, did string, priv *ecdsa.PrivateKey, resolver vmpkg.ResolverProvider) string {
	t.Helper()
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}
	cred, err := vc.NewJOSECredential(joseContents(did),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new jose credential: %v", err)
	}
	if err := cred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign: %v", err)
	}
	serialized, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return serialized.(string)
}

// signedSDJWTToken issues a vc+sd-jwt credential and returns it.
func signedSDJWTToken(t *testing.T, did string, priv *ecdsa.PrivateKey, resolver vmpkg.ResolverProvider) string {
	t.Helper()
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}
	contents := joseContents(did)
	contents.Subject = []vc.Subject{{ID: "did:example:subject", CustomFields: map[string]interface{}{
		"name": "Alice", "secret": "hidden",
	}}}
	cred, err := vc.NewJOSECredential(contents,
		vc.WithSDSelectivePaths([]string{"credentialSubject.secret"}),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new sd-jwt credential: %v", err)
	}
	if err := cred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign: %v", err)
	}
	serialized, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return serialized.(string)
}

func joseSetup(t *testing.T) (string, *ecdsa.PrivateKey, vmpkg.ResolverProvider) {
	t.Helper()
	const did = "did:example:jose-strict"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(did, mustP256VM(t, did, "key-1", &priv.PublicKey)))
	return did, priv, resolver
}

// --- #99 item 1: crit header rejection ---

// TestJOSEStrict_CritHeaderRejected checks that a VC with a "crit" claim in
// the JOSE header is rejected at verification time (RFC 7515 section 4.1.11).
// The crit check lives in jws.Verify, which runs during Verify(), not Parse().
func TestJOSEStrict_CritHeaderRejected(t *testing.T) {
	did, priv, resolver := joseSetup(t)
	token := signedJOSEToken(t, did, priv, resolver)

	// Inject crit into the header. The signature will not match, but
	// jws.UnverifiedHeader (called in jwt.VerifyJWT before the crypto
	// check) rejects crit per RFC 7515 section 4.1.11.
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
	newHeader, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	tampered := base64.RawURLEncoding.EncodeToString(newHeader) + "." + parts[1] + "." + parts[2]

	// Parse may succeed (it does not check crit), so test through Verify.
	cred, err := vc.ParseCredential([]byte(tampered), vc.WithResolver(resolver))
	if err != nil {
		// If parse itself rejects it, that also satisfies the check.
		if strings.Contains(err.Error(), "crit") {
			return
		}
		t.Fatalf("parse failed for a reason other than crit: %v", err)
	}
	err = cred.Verify(vc.WithResolver(resolver))
	if err == nil {
		t.Fatal("accepted a token with crit in header; want rejection")
	}
	if !strings.Contains(err.Error(), "crit") {
		t.Fatalf("err = %v, want one mentioning crit", err)
	}
}

// --- #99 item 2: undisclosed array element removed ---

// TestJOSEStrict_UndisclosedArrayElementRemoved checks that an SD-JWT with an
// undisclosed array element produces a shorter array, not one with a
// {"...": digest} placeholder (RFC 9901 section 7.1 step 3d), whatever hash
// the payload declares in _sd_alg.
func TestJOSEStrict_UndisclosedArrayElementRemoved(t *testing.T) {
	did, priv, resolver := joseSetup(t)
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}

	for _, alg := range []string{"sha-256", "sha-384", "sha-512"} {
		t.Run(alg, func(t *testing.T) {
			contents := joseContents(did)
			contents.Subject = []vc.Subject{{ID: "did:example:subject", CustomFields: map[string]interface{}{
				"skills": []interface{}{"go", "rust", "python"},
			}}}
			cred, err := vc.NewJOSECredential(contents,
				vc.WithSDSelectivePaths([]string{"credentialSubject.skills[1]"}), vc.WithSDHashAlgorithm(alg),
				vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
			if err != nil {
				t.Fatal(err)
			}
			if err := cred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
				t.Fatal(err)
			}

			// Present with no disclosures withholds the array element.
			presented, err := cred.Present(nil)
			if err != nil {
				t.Fatalf("present: %v", err)
			}
			serialized, err := presented.Serialize()
			if err != nil {
				t.Fatal(err)
			}

			parsed, err := vc.ParseCredential([]byte(serialized.(string)), vc.WithResolver(resolver))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			subject, ok := parsed.ExtractField("credentialSubject").(map[string]interface{})
			if !ok {
				t.Fatal("credentialSubject not an object")
			}
			skills, ok := subject["skills"].([]interface{})
			if !ok {
				t.Fatalf("skills is %T, want []interface{}", subject["skills"])
			}
			// The withheld element is removed, so "rust" and its {"...": digest}
			// placeholder are both gone.
			if len(skills) != 2 || skills[0] != "go" || skills[1] != "python" {
				t.Fatalf("skills = %v, want [go python]", skills)
			}
		})
	}
}

// --- #99 item 3: forbidden disclosure names ---

// TestJOSEStrict_ForbiddenDisclosureNameRejected checks that disclosures with
// reserved claim names (_sd, _sd_alg, ...) are rejected by jose/sdjwt.
func TestJOSEStrict_ForbiddenDisclosureNameRejected(t *testing.T) {
	did, priv, resolver := joseSetup(t)
	token := signedSDJWTToken(t, did, priv, resolver)

	for _, name := range []string{"_sd", "_sd_alg", "..."} {
		t.Run(name, func(t *testing.T) {
			// Build the disclosure JSON manually and encode with
			// base64.RawURLEncoding to match the jose module's encoding.
			fakeArr, _ := json.Marshal([]interface{}{"c2FsdA", name, "value"})
			fakeDisc := base64.RawURLEncoding.EncodeToString(fakeArr)

			// The token already ends with ~, so append the fake disclosure.
			tampered := token + fakeDisc + "~"

			_, err := vc.ParseCredential([]byte(tampered), vc.WithResolver(resolver))
			if err == nil {
				t.Fatal("accepted a disclosure with reserved name; want rejection")
			}
			if !strings.Contains(err.Error(), "reserved") {
				t.Fatalf("err = %v, want one mentioning reserved", err)
			}
		})
	}
}

// --- #99 item 6: non-UTF-8 header ---

// TestJOSEStrict_NonUTF8HeaderRejected checks that a token whose header
// contains invalid UTF-8 bytes (after base64url decoding) is rejected.
// The check lives in jws.UnverifiedHeader / jws.Verify (jose module).
func TestJOSEStrict_NonUTF8HeaderRejected(t *testing.T) {
	did, priv, resolver := joseSetup(t)
	parts := strings.SplitN(signedJOSEToken(t, did, priv, resolver), ".", 3)
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	// json.Marshal refuses invalid UTF-8, so the byte is written by hand.
	header = append(header[:len(header)-1], []byte(`,"x-note":"`+"\xff"+`"}`)...)
	tampered := resignES256(t, priv, header, parts[1])

	cred, err := vc.ParseCredential([]byte(tampered), vc.WithResolver(resolver))
	if err == nil {
		err = cred.Verify(vc.WithResolver(resolver))
	}
	if !errors.Is(err, jose.ErrMalformed) || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("err = %v, want the non-UTF-8 header refused as malformed", err)
	}
}

// A payload with a duplicate key reads as two documents: encoding/json keeps
// the last issuer, another reader the first. Parsing refuses it before any
// caller reads the claims, as jose/jws.Verify does.
func TestJOSEStrict_DuplicatePayloadKeyRejectedAtParse(t *testing.T) {
	did, priv, resolver := joseSetup(t)
	parts := strings.SplitN(signedJOSEToken(t, did, priv, resolver), ".", 3)
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload[:len(payload)-1], []byte(`,"issuer":"did:example:other"}`)...)
	tampered := resignES256(t, priv, header, base64.RawURLEncoding.EncodeToString(payload))

	_, err = vc.ParseCredential([]byte(tampered), vc.WithResolver(resolver))
	if err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("err = %v, want the duplicate key refused at parse", err)
	}
}

// ParseCredential picks the parser from typ. A header with typ twice
// ("vc+jwt" then "JWT") routed by the last value to the VC 1.1 parser, which
// does not read the header; it is refused before routing.
func TestJOSEStrict_DuplicateTypRefusedAtRouting(t *testing.T) {
	did, priv, resolver := joseSetup(t)
	parts := strings.SplitN(signedJOSEToken(t, did, priv, resolver), ".", 3)
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	header = append(header[:len(header)-1], []byte(`,"typ":"JWT"}`)...)
	tampered := resignES256(t, priv, header, parts[1])
	if _, err := vc.ParseCredential([]byte(tampered), vc.WithResolver(resolver)); err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("err = %v, want the duplicate typ refused", err)
	}
}

// --- #99 item 7: non-strict base64url ---

// TestJOSEStrict_PadBitAliasRejected checks that a token whose signature
// segment has trailing pad bits set (aliasing) is rejected.
// The check is in jose.DecodeSegment used by jws.Verify.
func TestJOSEStrict_PadBitAliasRejected(t *testing.T) {
	did, priv, resolver := joseSetup(t)
	parts := strings.SplitN(signedJOSEToken(t, did, priv, resolver), ".", 3)
	tampered := parts[0] + "." + parts[1] + "." + jwttest.PadBitAlias(t, parts[2])

	cred, err := vc.ParseCredential([]byte(tampered), vc.WithResolver(resolver))
	if err == nil {
		err = cred.Verify(vc.WithResolver(resolver))
	}
	if !errors.Is(err, jose.ErrMalformed) || !strings.Contains(err.Error(), "base64url") {
		t.Fatalf("err = %v, want the signature segment refused as malformed base64url", err)
	}
}

// resignES256 signs header and payload with priv, so a test can change the
// header and still carry a valid ES256 signature: the token is then refused
// only for the property under test, not for a broken signature.
func resignES256(t *testing.T, priv *ecdsa.PrivateKey, header []byte, payloadB64 string) string {
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

// --- #99 item 12: KB-JWT acceptance ---

// RFC 9901 section 7.2: a Holder that receives an SD-JWT+KB MUST reject it,
// and section 4: a Verifier expecting an SD-JWT checks the final component
// is empty. ParseJOSECredential is both receive paths. Until the SDK
// verifies a Key Binding JWT, a token carrying one is refused rather than
// parsed with the KB-JWT dropped (#209 review).
func TestJOSEStrict_KBJWTRefused(t *testing.T) {
	did, priv, resolver := joseSetup(t)
	token := signedSDJWTToken(t, did, priv, resolver)

	kbHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"kb+jwt","alg":"ES256"}`))
	kbPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"nonce":"n","aud":"a","iat":1700000000}`))
	kbSig := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"kb+jwt","alg":"none"}`))

	// The token already ends with ~, so the KB-JWT is appended as is.
	for name, kb := range map[string]string{
		"ES256 KB-JWT": kbHeader + "." + kbPayload + "." + kbSig,
		"opaque a.b.c": "a.b.c",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := vc.ParseCredential([]byte(token+kb), vc.WithResolver(resolver))
			if err == nil || !strings.Contains(err.Error(), "key binding JWT") {
				t.Fatalf("err = %v, want the key binding JWT refused", err)
			}
		})
	}
	// An alg none KB-JWT has an empty signature, which Split already refuses
	// as malformed; either way it does not parse.
	if _, err := vc.ParseCredential([]byte(token+noneHeader+"."+kbPayload+"."), vc.WithResolver(resolver)); err == nil {
		t.Fatal("an SD-JWT with an alg none KB-JWT was accepted")
	}
}

// --- Hash stability ---

// WithSDHashAlgorithm accepts sha-384 and sha-512 (RFC 9901 section 4.1.1
// allows any IANA hash): a credential the SDK issued with any of them must
// parse and verify.
func TestJOSEStrict_SDHashAlgorithmsRoundTrip(t *testing.T) {
	did, priv, resolver := joseSetup(t)
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range []string{"sha-256", "sha-384", "sha-512"} {
		t.Run(alg, func(t *testing.T) {
			cred, err := vc.NewJOSECredential(joseContents(did),
				vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver),
				vc.WithSDSelectivePaths([]string{"credentialSubject.name"}), vc.WithSDHashAlgorithm(alg))
			if err != nil {
				t.Fatal(err)
			}
			if err := cred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
				t.Fatal(err)
			}
			s, err := cred.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := vc.ParseCredential([]byte(s.(string)), vc.WithResolver(resolver), vc.WithVerifyProof()); err != nil {
				t.Fatalf("parse %s SD-JWT: %v", alg, err)
			}
		})
	}
}

// A disclosure named "_sd" or "..." (RFC 9901 section 4.2.1), or "_sd_alg"
// (section 4.1.1 keeps it at the top level), is refused whatever hash the
// SD-JWT uses.
func TestJOSEStrict_ReservedDisclosureNameRefusedForSHA384(t *testing.T) {
	did, _, resolver := joseSetup(t)
	for _, name := range []string{"_sd_alg", "..."} {
		t.Run(name, func(t *testing.T) {
			b, err := json.Marshal([]interface{}{"c2FsdFpac2FsdFpac2FsdFpa", name, "x"})
			if err != nil {
				t.Fatal(err)
			}
			d := base64.RawURLEncoding.EncodeToString(b)
			sum := sha512.Sum384([]byte(d))
			contents := joseContents(did)
			contents.Subject[0].CustomFields["_sd"] = []interface{}{base64.RawURLEncoding.EncodeToString(sum[:])}
			_, err = vc.NewJOSECredential(contents,
				vc.WithSDDisclosures([]string{d}), vc.WithSDHashAlgorithm("sha-384"),
				vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
			if err == nil || !strings.Contains(err.Error(), "reserved") {
				t.Fatalf("err = %v, want the disclosure name %q refused as reserved", err, name)
			}
		})
	}
}

// RFC 9901 section 4.1 rule 7 and section 4.2.4.2: {"...": digest} belongs in
// an array only, under every hash the SDK issues.
func TestJOSEStrict_PayloadShapeRulesForEveryHash(t *testing.T) {
	did, _, resolver := joseSetup(t)
	for _, alg := range []string{"sha-256", "sha-384", "sha-512"} {
		t.Run(alg, func(t *testing.T) {
			contents := joseContents(did)
			contents.Subject = []vc.Subject{{ID: "did:example:subject", CustomFields: map[string]interface{}{
				"name": "Alice",
				"x":    map[string]interface{}{"...": "abc"},
			}}}
			_, err := vc.NewJOSECredential(contents,
				vc.WithSDSelectivePaths([]string{"credentialSubject.name"}), vc.WithSDHashAlgorithm(alg),
				vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
			if !errors.Is(err, jose.ErrInvalidArgument) || !strings.Contains(err.Error(), `reserved name "..."`) {
				t.Fatalf("%s: err = %v, want {\"...\": digest} outside an array refused", alg, err)
			}
		})
	}
}

// The SDK must not sign an SD-JWT its own parser refuses: jose/sdjwt.Split
// caps a token at 1 MiB and 1000 disclosures (#209 review).
func TestJOSEStrict_RefusesToSignWhatItCannotParse(t *testing.T) {
	did, _, resolver := joseSetup(t)

	// Over 1 MiB: refused at build, so neither signing path is reached.
	big := joseContents(did)
	big.Subject = []vc.Subject{{ID: "did:example:subject", CustomFields: map[string]interface{}{
		"name": strings.Repeat("a", 1<<20),
	}}}
	if _, err := vc.NewJOSECredential(big, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver),
		vc.WithSDSelectivePaths([]string{"credentialSubject.name"})); err == nil || !strings.Contains(err.Error(), "cannot parse back") {
		t.Errorf("over 1 MiB: err = %v, want it refused at build as unparsable", err)
	}

	// 1001 disclosures never get that far: the builder refuses the paths.
	many := joseContents(did)
	fields := map[string]interface{}{}
	paths := make([]string, 0, 1001)
	for i := 0; i < 1001; i++ {
		k := fmt.Sprintf("f%04d", i)
		fields[k] = i
		paths = append(paths, "credentialSubject."+k)
	}
	many.Subject = []vc.Subject{{ID: "did:example:subject", CustomFields: fields}}
	if _, err := vc.NewJOSECredential(many, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver),
		vc.WithSDSelectivePaths(paths)); err == nil || !strings.Contains(err.Error(), "at most 1000") {
		t.Errorf("1001 paths: err = %v, want them refused at build", err)
	}
}

// The VC 1.1 parser reads the header by the rules VerifyJWT uses, also when
// called directly rather than through ParseCredential.
func TestJWT11_BrokenHeaderRefusedAtParse(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	payload := enc([]byte(`{"vc":{}}`))
	for _, h := range []string{`null`, `{"typ":"JWT","typ":"JWT"}`} {
		if _, err := vc.ParseJWTCredential(enc([]byte(h)) + "." + payload + ".c2ln"); err == nil || !strings.Contains(err.Error(), "invalid JWT header") {
			t.Errorf("header %s: err = %v, want it refused", h, err)
		}
	}
}

// Nesting limits sit where the token is read: a plain vc+jwt is not held to
// the SD-JWT limit of 32 levels, and no builder signs a payload deeper than
// the 64 levels every parser reads (jose.MaxJSONDepth).
func TestJOSEStrict_NestingLimitsMatchTheReaders(t *testing.T) {
	did, priv, resolver := joseSetup(t)
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}
	nested := func(depth int) vc.CredentialContents {
		v := interface{}("x")
		for i := 0; i < depth; i++ {
			v = map[string]interface{}{"d": v}
		}
		c := joseContents(did)
		c.Subject[0].CustomFields["deep"] = v
		return c
	}
	cred, err := vc.NewJOSECredential(nested(40), vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("plain vc+jwt at depth 40: %v", err)
	}
	if err := cred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
		t.Fatal(err)
	}
	s, err := cred.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vc.ParseCredential([]byte(s.(string)), vc.WithResolver(resolver), vc.WithVerifyProof()); err != nil {
		t.Fatalf("parse depth 40: %v", err)
	}
	if _, err := vc.NewJWTCredential(nested(60), vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver)); err != nil {
		t.Fatalf("VC-JWT 1.1 at depth 60: %v", err)
	}
	if _, err := vc.NewJWTCredential(nested(70), vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver)); err == nil || !strings.Contains(err.Error(), "nesting deeper than 64") {
		t.Fatalf("VC-JWT 1.1 at depth 70: err = %v, want it refused at build", err)
	}
}

// A vc+jwt is a plain JWS (vc-jose-cose §3.1.1): _sd, _sd_alg or
// {"...": digest} in its payload are claims, kept as issued and verified
// like any other, never read as SD-JWT.
func TestJOSEStrict_PlainVCJWTKeepsSDNamedClaims(t *testing.T) {
	did, priv, resolver := joseSetup(t)
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}
	placeholder := []interface{}{map[string]interface{}{"...": "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"}}
	for name, field := range map[string]struct {
		key string
		v   interface{}
	}{
		"_sd":         {"_sd", "x"},
		"_sd array":   {"_sd", []interface{}{"X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"}},
		"placeholder": {"tags", placeholder},
		"_sd_alg":     {"_sd_alg", "sha-256"},
	} {
		c := joseContents(did)
		c.Subject[0].CustomFields[field.key] = field.v
		cred, err := vc.NewJOSECredential(c, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
		if err != nil {
			t.Fatalf("%s: build: %v", name, err)
		}
		if err := cred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
			t.Fatalf("%s: sign: %v", name, err)
		}
		tok, err := cred.Serialize()
		if err != nil {
			t.Fatalf("%s: serialize: %v", name, err)
		}
		parsed, err := vc.ParseJOSECredential(tok.(string), vc.WithResolver(resolver))
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		if err := parsed.Verify(vc.WithResolver(resolver)); err != nil {
			t.Fatalf("%s: verify: %v", name, err)
		}
		got := parsed.ExtractField("credentialSubject." + field.key)
		if fmt.Sprint(got) != fmt.Sprint(field.v) {
			t.Errorf("%s: credentialSubject.%s = %v, want %v as issued", name, field.key, got, field.v)
		}
	}

	// Outside the subject too, at the root and inside another property.
	digest := "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"
	tok := signJOSEByHand(t, prov, vc.TypeVCJWT, did+"#key-1", map[string]interface{}{
		"@context":          []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":              []interface{}{"VerifiableCredential"},
		"issuer":            did,
		"validFrom":         "2026-01-01T00:00:00Z",
		"credentialSubject": map[string]interface{}{"id": "did:example:subject"},
		"_sd":               []interface{}{digest},
		"_sd_alg":           "sha-256",
		"evidence":          []interface{}{map[string]interface{}{"_sd": []interface{}{digest}}},
	})
	parsed, err := vc.ParseJOSECredential(tok, vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("root members: parse: %v", err)
	}
	if err := parsed.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("root members: verify: %v", err)
	}
	if got := fmt.Sprint(parsed.ExtractField("_sd"), parsed.ExtractField("_sd_alg")); got != fmt.Sprint([]interface{}{digest}, "sha-256") {
		t.Errorf("root members = %s, want them as issued", got)
	}
}

// Every parser reads header and payload by jose's rules, called directly or
// through ParseCredential: a duplicate key is refused at parse.
func TestDuplicateKeyRefusedByEveryCredentialParser(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for name, parse := range map[string]func() error{
		"vc+jwt header": func() error {
			_, err := vc.ParseJOSECredential(enc(`{"alg":"ES256","typ":"vc+jwt","typ":"vc+jwt"}`) + "." + enc(`{}`) + ".c2ln")
			return err
		},
		"VC-JWT 1.1 payload": func() error {
			_, err := vc.ParseJWTCredential(enc(`{"alg":"ES256K","typ":"JWT"}`) + "." + enc(`{"vc":{},"vc":{}}`) + ".c2ln")
			return err
		},
	} {
		if err := parse(); err == nil || !strings.Contains(err.Error(), "duplicate key") {
			t.Errorf("%s: err = %v, want the duplicate key refused", name, err)
		}
	}
}

// A vc+sd-jwt must end in "~" (RFC 9901 §4); without it, it is refused
// before its payload is read, as common/sdjwt.Parse refuses it.
func TestJOSEStrict_SDJWTWithoutTildeRefused(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	tok := enc(`{"alg":"ES256","typ":"vc+sd-jwt"}`) + "." + enc(`{"_sd_alg":"sha-256"}`) + ".c2ln"
	for _, parse := range []func() error{
		func() error { _, err := vc.ParseCredential([]byte(tok)); return err },
		func() error { _, err := vc.ParseJOSECredential(tok); return err },
	} {
		if err := parse(); !errors.Is(err, jose.ErrMalformed) {
			t.Errorf("err = %v, want the missing ~ refused", err)
		}
	}
}

// A JOSE header over 64 KiB, which jws.Verify refuses, is refused before it
// is decoded on every credential route.
func TestJOSEStrict_OversizedHeaderRefusedOnEveryRoute(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	h := enc(`{"alg":"ES256","typ":"vc+jwt","x":"` + strings.Repeat("a", 70<<10) + `"}`)
	tok := h + "." + enc(`{}`) + ".c2ln"
	for name, parse := range map[string]func() error{
		// The router reads the header to pick a parser: its own refusal.
		"ParseCredential": func() error {
			_, err := vc.ParseCredential([]byte(tok))
			if err != nil && !strings.HasPrefix(err.Error(), "failed to parse credential: invalid JWT header") {
				return fmt.Errorf("refused after routing, not by the router: %v", err)
			}
			return err
		},
		"ParseJOSECredential": func() error { _, err := vc.ParseJOSECredential(tok); return err },
		"ParseJWTCredential":  func() error { _, err := vc.ParseJWTCredential(tok); return err },
	} {
		if err := parse(); !errors.Is(err, jose.ErrMalformed) || !strings.Contains(err.Error(), "header is over") {
			t.Errorf("%s: err = %v, want the header refused for its size", name, err)
		}
	}
}

// A holder who presents a claim nested in a concealed object without the
// object's disclosure is told which one to add (alone, the child matches no
// presented digest, RFC 9901 §7.1 step 5), and nothing is revealed unasked.
// With both selected it presents, under every hash.
func TestJOSEStrict_PresentNamesTheMissingParent(t *testing.T) {
	did, priv, resolver := joseSetup(t)
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range []string{"sha-256", "sha-384", "sha-512"} {
		t.Run(alg, func(t *testing.T) {
			c := joseContents(did)
			c.Subject[0].CustomFields["address"] = map[string]interface{}{"city": "Hanoi", "street": "1"}
			cred, err := vc.NewJOSECredential(c, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver),
				vc.WithSDSelectivePaths([]string{"credentialSubject.address", "credentialSubject.address.city"}), vc.WithSDHashAlgorithm(alg))
			if err != nil {
				t.Fatal(err)
			}
			if err := cred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
				t.Fatal(err)
			}
			discs, err := cred.DecodedDisclosures()
			if err != nil {
				t.Fatal(err)
			}
			var city, address string
			for _, d := range discs {
				switch d.FieldName {
				case "city":
					city = d.Disclosure
				case "address":
					address = d.Disclosure
				}
			}
			_, err = cred.Present([]string{city})
			var perr *vc.ParentDisclosureError
			if !errors.Is(err, vc.ErrParentDisclosureNotSelected) || !errors.As(err, &perr) ||
				len(perr.Missing) != 1 || perr.Missing[0] != address || !strings.Contains(err.Error(), `"address"`) {
				t.Fatalf("%s: err = %v, want the address disclosure named and listed", alg, err)
			}
			presented, err := cred.Present([]string{city, address})
			if err != nil {
				t.Fatalf("%s: present city with address: %v", alg, err)
			}
			contents, err := presented.GetContents()
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(contents), `"city":"Hanoi"`) {
				t.Fatalf("%s: presented contents %s lack the city", alg, contents)
			}
		})
	}
}

// One refusal lists every missing ancestor, innermost first.
func TestJOSEStrict_PresentListsTheWholeMissingChain(t *testing.T) {
	did, priv, resolver := joseSetup(t)
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}
	c := joseContents(did)
	c.Subject[0].CustomFields["address"] = map[string]interface{}{"geo": map[string]interface{}{"lat": "1"}}
	cred, err := vc.NewJOSECredential(c, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver),
		vc.WithSDSelectivePaths([]string{"credentialSubject.address", "credentialSubject.address.geo", "credentialSubject.address.geo.lat"}))
	if err != nil {
		t.Fatal(err)
	}
	if err := cred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
		t.Fatal(err)
	}
	discs, err := cred.DecodedDisclosures()
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]string{}
	for _, d := range discs {
		byName[d.FieldName] = d.Disclosure
	}
	_, err = cred.Present([]string{byName["lat"]})
	var perr *vc.ParentDisclosureError
	if !errors.As(err, &perr) || len(perr.Missing) != 2 || perr.Missing[0] != byName["geo"] || perr.Missing[1] != byName["address"] {
		t.Fatalf("err = %v, want geo then address listed", err)
	}
	if want := `disclosure "lat" is inside a concealed claim that is not selected; select 2 more disclosure(s), "geo", "address"`; !strings.Contains(err.Error(), want) {
		t.Errorf("err = %q, want it to contain %q", err, want)
	}
	if built := (&vc.ParentDisclosureError{Disclosure: byName["lat"], Missing: perr.Missing}).Error(); built != err.Error() {
		t.Errorf("a ParentDisclosureError built from the same fields reads %q, want %q", built, err)
	}
	if _, err := cred.Present(append([]string{byName["lat"]}, perr.Missing...)); err != nil {
		t.Fatalf("present with the listed disclosures: %v", err)
	}
}

// Two selected disclosures in two concealed claims: one refusal lists both
// parents, so presenting with Missing added succeeds the first time.
func TestJOSEStrict_PresentListsEveryMissingParent(t *testing.T) {
	did, priv, resolver := joseSetup(t)
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}
	c := joseContents(did)
	c.Subject[0].CustomFields["address"] = map[string]interface{}{"city": "Hanoi"}
	c.Subject[0].CustomFields["contact"] = map[string]interface{}{"phone": "1"}
	cred, err := vc.NewJOSECredential(c, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver),
		vc.WithSDSelectivePaths([]string{"credentialSubject.address", "credentialSubject.address.city",
			"credentialSubject.contact", "credentialSubject.contact.phone"}))
	if err != nil {
		t.Fatal(err)
	}
	if err := cred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
		t.Fatal(err)
	}
	discs, err := cred.DecodedDisclosures()
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]string{}
	for _, d := range discs {
		byName[d.FieldName] = d.Disclosure
	}
	selected := []string{byName["city"], byName["phone"]}
	_, err = cred.Present(selected)
	var perr *vc.ParentDisclosureError
	if !errors.As(err, &perr) || len(perr.Missing) != 2 || perr.Missing[0] != byName["address"] || perr.Missing[1] != byName["contact"] {
		t.Fatalf("err = %v, want address then contact listed", err)
	}
	if _, err := cred.Present(append(selected, perr.Missing...)); err != nil {
		t.Fatalf("present with the listed disclosures: %v", err)
	}
}

type downResolver struct{ calls int }

func (r *downResolver) ResolveDocument(context.Context, string) (*vmpkg.DIDDocument, error) {
	r.calls++
	return nil, errors.New("resolver down")
}

// A bad SD-JWT configuration is refused before the DID is resolved: the
// issuer sees its own mistake, at no network cost, even with the registry
// down.
func TestJOSEStrict_BadSDConfigRefusedBeforeResolving(t *testing.T) {
	r := &downResolver{}
	c := joseContents("did:example:x")
	_, err := vc.NewJOSECredential(c, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(r),
		vc.WithSDDecoyDigests([]vc.Decoy{{Path: "type", Count: 2}}))
	if err == nil || strings.Contains(err.Error(), "resolver down") || r.calls != 0 {
		t.Fatalf("err = %v after %d resolver calls, want the decoy in type refused first", err, r.calls)
	}
}

// A verification method whose id would put the header over 64 KiB is refused
// at build, before any signer runs.
func TestJOSEStrict_OversizedKidRefusedAtBuild(t *testing.T) {
	did := "did:example:" + strings.Repeat("a", 70<<10)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, mustP256VM(t, did, "key-1", &priv.PublicKey)))
	if _, err := vc.NewJOSECredential(joseContents(did), vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver)); !errors.Is(err, jose.ErrInvalidArgument) || !strings.Contains(err.Error(), "header is over") {
		t.Fatalf("err = %v, want the oversized header refused at build", err)
	}
}

// The verification method's id is known only once the DID is resolved, and
// it lengthens the header after the first check ran with the pinned
// fragment. An SD-JWT that the real header pushes over jose/sdjwt.Split's
// 1 MiB is refused before it is signed.
func TestJOSEStrict_ResolvedKidPushingPastTheCapRefused(t *testing.T) {
	did := "did:example:" + strings.Repeat("d", 20000)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, mustP256VM(t, did, "key-1", &priv.PublicKey)))
	build := func(n int) (*vc.JOSECredential, error) {
		c := joseContents(did)
		c.Subject = []vc.Subject{{ID: "did:example:subject", CustomFields: map[string]interface{}{"name": strings.Repeat("a", n)}}}
		return vc.NewJOSECredential(c, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver),
			vc.WithSDSelectivePaths([]string{"credentialSubject.name"}))
	}
	// Measured with the real header: each byte of the value adds 4/3 to the
	// disclosure, and the signature adds "." plus 86 characters.
	small, err := build(1000)
	if err != nil {
		t.Fatal(err)
	}
	s, err := small.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	signed := len(s.(string)) + 87
	// Aim 8 KiB past the cap: the pinned "key-1" header is about 26 KiB
	// shorter, so the first check passes and only the second can refuse.
	n := 1000 + ((1<<20)+8<<10-signed)*3/4
	if _, err := build(n); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("err = %v, want the token the resolved kid makes over 1 MiB refused", err)
	}
}

// A header or payload segment whose last character sets unused bits spells
// the same bytes as the canonical one (RFC 4648 §3.5); every parse route
// refuses it before the signature is looked at.
func TestJOSEStrict_HeaderAndPayloadPadBitAliasRefusedAtParse(t *testing.T) {
	// seg encodes j padded with JSON whitespace so its base64url ends in a
	// character with four unused bits, which PadBitAlias then sets.
	seg := func(j string) string {
		for len(j)%3 != 1 {
			j = strings.TrimSuffix(j, "}") + " }"
		}
		return base64.RawURLEncoding.EncodeToString([]byte(j))
	}
	sig := strings.Repeat("A", 86)
	payload := `{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"issuer":"did:example:i","credentialSubject":{"id":"did:example:s"}}`
	for _, typ := range []string{"vc+jwt", "vc+sd-jwt", "JWT"} {
		h := seg(`{"alg":"ES256","typ":"` + typ + `"}`)
		p := seg(payload)
		tail := "." + sig
		if typ == "vc+sd-jwt" {
			tail += "~"
		}
		for name, tok := range map[string]string{
			"header":  jwttest.PadBitAlias(t, h) + "." + p + tail,
			"payload": h + "." + jwttest.PadBitAlias(t, p) + tail,
		} {
			if _, err := vc.ParseCredential([]byte(tok)); !errors.Is(err, jose.ErrMalformed) {
				t.Errorf("%s %s: err = %v, want the aliased segment refused as malformed", typ, name, err)
			}
		}
	}
}

// Values read from an unsigned token are quoted in errors by a bounded
// prefix only: a megabyte @context or type does not come back as a
// megabyte error text.
func TestJOSEStrict_ErrorTextBoundedForPayloadValues(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	big := strings.Repeat("a", 1<<20)
	for name, payload := range map[string]string{
		"@context": `{"@context":["` + big + `"],"type":["VerifiableCredential"],"issuer":"did:example:i","credentialSubject":{"id":"did:example:s"}}`,
		"type":     `{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["` + big + `"],"issuer":"did:example:i","credentialSubject":{"id":"did:example:s"}}`,
	} {
		tok := enc(`{"alg":"ES256","typ":"vc+jwt"}`) + "." + enc(payload) + "." + strings.Repeat("A", 86)
		_, err := vc.ParseCredential([]byte(tok))
		if err == nil || len(err.Error()) > 1024 {
			t.Errorf("%s: err of %d bytes, want a bounded refusal", name, len(fmt.Sprint(err)))
		}
	}
}

// CID 1.0 §3.3 on the JOSE route, as on the Data Integrity ones: a method
// whose controller, or whose DID, is not the document's is refused.
func TestJOSEStrict_VerificationMethodControllerChecked(t *testing.T) {
	const did, other = "did:example:jose-ctl", "did:example:other"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]interface{}{
		"@context":          []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":              []interface{}{"VerifiableCredential"},
		"issuer":            did,
		"validFrom":         "2026-01-01T00:00:00Z",
		"credentialSubject": map[string]interface{}{"id": "did:example:subject"},
	}
	for name, tc := range map[string]struct {
		vmDID, controller, want string
	}{
		"controller of another DID": {did, other, "controller"},
		"method of another DID":     {other, other, "is not the DID"},
	} {
		vm := mustP256VM(t, tc.vmDID, "key-1", &priv.PublicKey)
		vm.Controller = tc.controller
		resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))
		tok := signJOSEByHand(t, prov, vc.TypeVCJWT, tc.vmDID+"#key-1", payload)
		parsed, err := vc.ParseJOSECredential(tok, vc.WithResolver(resolver))
		if err == nil {
			err = parsed.Verify(vc.WithResolver(resolver))
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want the method refused (%q)", name, err, tc.want)
		}
	}
}

// A top-level path or decoy is refused at build: the builder writes no exp or
// nbf, so Verify would refuse the credential once a top-level digest is
// withheld, or with root decoys alone.
func TestJOSEStrict_RootConcealmentRefusedAtBuild(t *testing.T) {
	did, _, resolver := joseSetup(t)
	for name, opt := range map[string]vc.CredentialOpt{
		"path":  vc.WithSDSelectivePaths([]string{"id"}),
		"decoy": vc.WithSDDecoyDigests([]vc.Decoy{{Path: "", Count: 2}}),
	} {
		_, err := vc.NewJOSECredential(joseContents(did), opt, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
		if err == nil || !strings.Contains(err.Error(), "fails Verify") {
			t.Errorf("%s: err = %v, want the root concealment refused", name, err)
		}
	}
}
