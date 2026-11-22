// Tests for the stricter checks the jose module enforces once the VC/VP paths
// route through jose/jws and jose/sdjwt. Each test exercises one item from
// issue #99. The jose module's strict checks (crit, UTF-8, strict base64url)
// are enforced in jws.Verify, which runs during Verify(), not during Parse().
// SD-JWT structural checks (array element removal, forbidden disclosure
// names, KB-JWT acceptance) are enforced by jose/sdjwt during Parse().
package vc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
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
// {"...": digest} placeholder (RFC 9901 section 7.1).
func TestJOSEStrict_UndisclosedArrayElementRemoved(t *testing.T) {
	did, priv, resolver := joseSetup(t)
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}

	contents := joseContents(did)
	contents.Subject = []vc.Subject{{ID: "did:example:subject", CustomFields: map[string]interface{}{
		"skills": []interface{}{"go", "rust", "python"},
	}}}
	cred, err := vc.NewJOSECredential(contents,
		vc.WithSDSelectivePaths([]string{"credentialSubject.skills[1]"}),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatal(err)
	}
	if err := cred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
		t.Fatal(err)
	}

	// Use Present with no disclosures to withhold the array element.
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

	// With the jose module, the undisclosed element is removed entirely.
	// On main (old common/sdjwt.Reconstruct), it stayed as {"...": digest},
	// so len(skills) would be 3.
	if len(skills) != 2 {
		t.Fatalf("len(skills) = %d, want 2 (undisclosed element removed); skills = %v", len(skills), skills)
	}
	// First element "go" and third "python" should remain; "rust" was withheld.
	if skills[0] != "go" || skills[1] != "python" {
		t.Fatalf("skills = %v, want [go python]", skills)
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
	if err == nil {
		t.Fatal("accepted a signed token whose header is not UTF-8; want rejection")
	}
}

// --- #99 item 7: non-strict base64url ---

// TestJOSEStrict_PadBitAliasRejected checks that a token whose signature
// segment has trailing pad bits set (aliasing) is rejected.
// The check is in jose.DecodeSegment used by jws.Verify.
func TestJOSEStrict_PadBitAliasRejected(t *testing.T) {
	did, priv, resolver := joseSetup(t)
	parts := strings.SplitN(signedJOSEToken(t, did, priv, resolver), ".", 3)
	tampered := parts[0] + "." + parts[1] + "." + padBitAlias(t, parts[2])

	cred, err := vc.ParseCredential([]byte(tampered), vc.WithResolver(resolver))
	if err == nil {
		err = cred.Verify(vc.WithResolver(resolver))
	}
	if err == nil {
		t.Fatal("accepted a signature segment with unused bits set; want rejection")
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

// padBitAlias sets the lowest unused bit of the last character of an
// unpadded base64url segment whose length is 2 mod 4 (a 64-byte signature
// is 86 characters, the last one carrying 4 unused bits). A lenient decoder
// returns the same bytes; RFC 7515 base64url with unused bits set is not
// the canonical encoding and a strict decoder refuses it.
func padBitAlias(t *testing.T, seg string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	v := strings.IndexByte(alphabet, seg[len(seg)-1])
	if v < 0 || v&0x0f != 0 {
		t.Fatalf("last character %q is not a canonical 4-unused-bit character", seg[len(seg)-1])
	}
	return seg[:len(seg)-1] + string(alphabet[v|1])
}

// --- #99 item 12: KB-JWT acceptance ---

// TestJOSEStrict_KBJWTAccepted checks that an SD-JWT with a trailing Key
// Binding JWT is accepted (jose/sdjwt.Split accepts it per RFC 9901), not
// rejected as the old common/sdjwt.Parse did.
func TestJOSEStrict_KBJWTAccepted(t *testing.T) {
	did, priv, resolver := joseSetup(t)
	token := signedSDJWTToken(t, did, priv, resolver)

	// Build a fake KB-JWT (not cryptographically valid, but structurally
	// correct): header.payload.signature.
	kbHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"kb+jwt","alg":"ES256"}`))
	kbPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"nonce":"n","aud":"a","iat":1700000000}`))
	kbSig := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	kb := kbHeader + "." + kbPayload + "." + kbSig

	// The token already ends with ~, so just append the KB-JWT.
	withKB := token + kb

	// Parse should succeed: the KB-JWT is accepted but not verified.
	_, err := vc.ParseCredential([]byte(withKB), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("rejected SD-JWT with KB-JWT: %v", err)
	}
}

// --- Hash stability ---

// TestJOSEStrict_HashStability issues a credential, records its hash, then
// re-parses the serialized form and checks that Hash() returns the same value.
// This confirms that the jose migration did not change Serialize() output.
func TestJOSEStrict_HashStability(t *testing.T) {
	did, priv, resolver := joseSetup(t)
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		opts []vc.CredentialOpt
	}{
		{name: "plain vc+jwt"},
		{name: "vc+sd-jwt",
			opts: []vc.CredentialOpt{vc.WithSDSelectivePaths([]string{"credentialSubject.name"})}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := append([]vc.CredentialOpt{
				vc.WithVerificationMethodKey("key-1"),
				vc.WithResolver(resolver),
			}, tc.opts...)
			cred, err := vc.NewJOSECredential(joseContents(did), opts...)
			if err != nil {
				t.Fatal(err)
			}
			if err := cred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
				t.Fatal(err)
			}
			hash1, err := cred.Hash()
			if err != nil {
				t.Fatal(err)
			}

			serialized, err := cred.Serialize()
			if err != nil {
				t.Fatal(err)
			}

			parsed, err := vc.ParseCredential([]byte(serialized.(string)), vc.WithResolver(resolver))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			hash2, err := parsed.Hash()
			if err != nil {
				t.Fatal(err)
			}
			if hash1 != hash2 {
				t.Fatalf("hash changed after round-trip: %s -> %s", hash1, hash2)
			}
		})
	}
}

// TestJOSEStrict_WireFormatUnchanged issues a credential, serializes it, then
// re-parses and re-serializes, and checks byte equality.
func TestJOSEStrict_WireFormatUnchanged(t *testing.T) {
	did, priv, resolver := joseSetup(t)
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		opts []vc.CredentialOpt
	}{
		{name: "plain vc+jwt"},
		{name: "vc+sd-jwt",
			opts: []vc.CredentialOpt{vc.WithSDSelectivePaths([]string{"credentialSubject.name"})}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := append([]vc.CredentialOpt{
				vc.WithVerificationMethodKey("key-1"),
				vc.WithResolver(resolver),
			}, tc.opts...)
			cred, err := vc.NewJOSECredential(joseContents(did), opts...)
			if err != nil {
				t.Fatal(err)
			}
			if err := cred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
				t.Fatal(err)
			}
			ser1, err := cred.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			wire1 := ser1.(string)

			parsed, err := vc.ParseCredential([]byte(wire1), vc.WithResolver(resolver))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			ser2, err := parsed.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			wire2 := ser2.(string)

			if wire1 != wire2 {
				t.Fatalf("wire format changed after round-trip:\n  before: %s\n  after:  %s", wire1, wire2)
			}
		})
	}
}

// --- #99 item 4: case-insensitive typ ---

// TestJOSEStrict_TypCaseInsensitive checks that ParseCredential routes a
// token with an uppercase or mixed-case typ to the JOSE parser (RFC 7515
// section 4.1.9: media type values are case-insensitive).
func TestJOSEStrict_TypCaseInsensitive(t *testing.T) {
	did, priv, resolver := joseSetup(t)
	token := signedJOSEToken(t, did, priv, resolver)

	for _, tc := range []struct {
		name string
		typ  string
	}{
		{"uppercase VC+JWT", "VC+JWT"},
		{"full prefix Application/vc+jwt", "Application/vc+jwt"},
		{"application/VC+JWT", "application/VC+JWT"},
		{"mixed Vc+Jwt", "Vc+Jwt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Rewrite the header with the new typ and re-sign so the token
			// verifies.
			parts := strings.SplitN(token, ".", 3)
			headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err != nil {
				t.Fatal(err)
			}
			var header map[string]interface{}
			if err := json.Unmarshal(headerBytes, &header); err != nil {
				t.Fatal(err)
			}
			header["typ"] = tc.typ
			newHeader, _ := json.Marshal(header)
			tampered := resignES256(t, priv, newHeader, parts[1])

			cred, err := vc.ParseCredential([]byte(tampered), vc.WithResolver(resolver))
			if err != nil {
				t.Fatalf("ParseCredential with typ %q: %v", tc.typ, err)
			}
			if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
				t.Fatalf("Verify with typ %q: %v", tc.typ, err)
			}
		})
	}
}

// WithSDHashAlgorithm accepts sha-384 and sha-512 (RFC 9901 section 4.1.1
// allows any IANA hash). module jose recreates sha-256 payloads only, so a
// credential the SDK issued with another hash must still parse and verify.
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

// --- #99 item 8: ParseCredential returns untyped nil on error ---

func TestParseCredential_ReturnsUntypedNilOnError(t *testing.T) {
	// Each input triggers a different concrete parser (JSON, JOSE, JWT) and
	// must return an untyped nil Credential on the error path, not a typed
	// (*ConcreteType)(nil) which would satisfy `c != nil`.
	cases := []struct {
		name  string
		input []byte
	}{
		{"empty", nil},
		{"invalid JSON object", []byte(`{"type": "not-a-credential"}`)},
		{"invalid JWT", []byte(`eyJhbGciOiJub25lIn0.eyJpc3MiOiJ0ZXN0In0.`)},
		{"garbage", []byte(`not-a-credential-at-all!!!`)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := vc.ParseCredential(tc.input)
			if err == nil {
				t.Fatal("expected an error")
			}
			if c != nil {
				t.Fatalf("ParseCredential returned a non-nil Credential (%T) on error", c)
			}
		})
	}
}

// --- #99 item 14: low-S normalization ---

// extractS returns the s component from a 64-byte ECDSA signature embedded in
// a vc+jwt token's third segment.
func extractS(t *testing.T, token string) *big.Int {
	t.Helper()
	parts := strings.Split(token, ".")
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[len(parts)-1])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if len(sigBytes) != 64 {
		t.Fatalf("sig length = %d, want 64", len(sigBytes))
	}
	return new(big.Int).SetBytes(sigBytes[32:])
}

// signer.NewP256Provider already normalizes s, so the P-256 case uses a
// signer that returns high-S, as a Vault or KMS signer may. The token must
// carry the low-S form and still verify.
func TestJOSE_LowS_P256_HighSInput(t *testing.T) {
	const did = "did:example:lows-p256"
	n := elliptic.P256().Params().N
	halfN := new(big.Int).Rsh(n, 1)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}
	highS := &highSSecp256k1Signer{inner: inner, n: n}
	resolver := vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(did, mustP256VM(t, did, "key-1", &priv.PublicKey)))

	for i := 0; i < 20; i++ {
		cred, err := vc.NewJOSECredential(joseContents(did),
			vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
		if err != nil {
			t.Fatal(err)
		}
		if err := cred.AddProofByProvider(highS, vc.WithResolver(resolver)); err != nil {
			t.Fatal(err)
		}
		ser, err := cred.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		token := ser.(string)
		if s := extractS(t, token); s.Cmp(halfN) > 0 {
			t.Fatalf("iteration %d: the token carries a high-S signature", i)
		}
		parsed, err := vc.ParseCredential([]byte(token), vc.WithResolver(resolver))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := parsed.Verify(vc.WithResolver(resolver)); err != nil {
			t.Fatalf("verify: %v", err)
		}
	}
}

// highSSecp256k1Signer wraps a real signer and flips every signature to high-S
// before returning it. n is the order of the signer's curve, so it serves
// P-256 too.
type highSSecp256k1Signer struct {
	inner signer.SignerProvider
	n     *big.Int
}

func (h *highSSecp256k1Signer) Sign(digest []byte) ([]byte, error) {
	raw, err := h.inner.Sign(digest)
	if err != nil {
		return nil, err
	}
	// Trim recovery byte if present.
	sig := raw
	if len(sig) == 65 {
		sig = sig[:64]
	}
	halfN := new(big.Int).Rsh(h.n, 1)
	s := new(big.Int).SetBytes(sig[32:])
	if s.Cmp(halfN) <= 0 {
		// Flip to high-S.
		s.Sub(h.n, s)
		s.FillBytes(sig[32:])
	}
	return sig, nil
}

func TestJOSE_LowS_Secp256k1_HighSInput(t *testing.T) {
	const (
		did  = "did:example:lows-secp"
		priv = "57600b3f2b7e1054094e14cd85c72a40dc74c4ee062bb381cea604b55ce56aec"
	)

	inner, err := signer.NewDefaultProvider(priv)
	if err != nil {
		t.Fatal(err)
	}
	// secp256k1 order from decred
	n, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	highS := &highSSecp256k1Signer{inner: inner, n: n}
	halfN := new(big.Int).Rsh(n, 1)

	vm := vmpkg.NewSecp256k1VM(did, "key-1", pubHex(t, priv))
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

	cred, err := vc.NewJOSECredential(joseContents(did),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatal(err)
	}
	if err := cred.AddProofByProvider(highS, vc.WithResolver(resolver)); err != nil {
		t.Fatal(err)
	}
	ser, err := cred.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	token := ser.(string)

	s := extractS(t, token)
	if s.Cmp(halfN) > 0 {
		t.Fatal("adapter did not normalize high-S to low-S")
	}

	// The normalized token must still verify.
	parsed, err := vc.ParseCredential([]byte(token), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := parsed.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// --- #99 item 18: relative kid resolution ---

// resignES256VC signs header||payload with a P-256 key and returns a compact JWS.
func resignES256VC(t *testing.T, priv *ecdsa.PrivateKey, header []byte, payloadB64 string) string {
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

func TestJOSE_RelativeKid_WithIss(t *testing.T) {
	const did = "did:example:rel-kid"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resolver := vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(did, mustP256VM(t, did, "key-1", &priv.PublicKey)))

	// Issue a valid token, then rewrite kid to relative form and re-sign.
	token := signedJOSEToken(t, did, priv, resolver)
	parts := strings.SplitN(token, ".", 3)
	headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatal(err)
	}
	header["kid"] = "#key-1" // relative kid
	newHeader, _ := json.Marshal(header)

	// Ensure the payload has iss.
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatal(err)
	}
	payload["iss"] = did
	newPayload, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(newPayload)

	tampered := resignES256VC(t, priv, newHeader, payloadB64)
	cred, err := vc.ParseCredential([]byte(tampered), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("parse with relative kid: %v", err)
	}
	if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify with relative kid and iss: %v", err)
	}
}

func TestJOSE_RelativeKid_WithoutIss_Rejected(t *testing.T) {
	const did = "did:example:rel-kid-no-iss"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resolver := vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(did, mustP256VM(t, did, "key-1", &priv.PublicKey)))

	// Build a vc+jwt payload WITHOUT iss, relying only on the issuer property.
	header := map[string]interface{}{
		"typ": "vc+jwt",
		"alg": "ES256",
		"kid": "#key-1", // relative
	}
	payload := map[string]interface{}{
		"@context":          []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":              []interface{}{"VerifiableCredential"},
		"issuer":            did,
		"credentialSubject": map[string]interface{}{"id": "did:example:subject"},
	}
	hJSON, _ := json.Marshal(header)
	pJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(pJSON)
	token := resignES256VC(t, priv, hJSON, payloadB64)

	cred, err := vc.ParseCredential([]byte(token), vc.WithResolver(resolver))
	if err != nil {
		// Rejected at parse; that is fine.
		if !strings.Contains(err.Error(), "relative kid") {
			t.Fatalf("rejected for wrong reason: %v", err)
		}
		return
	}
	err = cred.Verify(vc.WithResolver(resolver))
	if err == nil {
		t.Fatal("accepted a relative kid without iss")
	}
	if !strings.Contains(err.Error(), "relative kid") {
		t.Fatalf("rejected for wrong reason: %v", err)
	}
}

// RFC 9901 section 4.2.1 refuses the claim names "_sd", "_sd_alg" and "..."
// in a disclosure whatever hash the SD-JWT uses. The sha-384 and sha-512 path
// reconstructs with the previous reader, so the names are checked before it.
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
