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
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
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
	tampered := parts[0] + "." + parts[1] + "." + padBitAlias(t, parts[2])

	pres, err := vp.ParsePresentation([]byte(tampered), vp.WithResolver(resolver))
	if err == nil {
		err = pres.Verify(vp.WithResolver(resolver))
	}
	if err == nil {
		t.Fatal("accepted a VP signature segment with unused bits set; want rejection")
	}
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

// --- #99 item 4: case-insensitive typ ---

func TestVPJOSEStrict_TypCaseInsensitive(t *testing.T) {
	did, priv, resolver := vpJoseSetup(t)
	token := signedJOSEPresentation(t, did, priv, resolver)

	for _, tc := range []struct {
		name string
		typ  string
	}{
		{"uppercase VP+JWT", "VP+JWT"},
		{"full prefix Application/vp+jwt", "Application/vp+jwt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
			tampered := resignES256VP(t, priv, newHeader, parts[1])

			pres, err := vp.ParsePresentation([]byte(tampered), vp.WithResolver(resolver))
			if err != nil {
				t.Fatalf("ParsePresentation with typ %q: %v", tc.typ, err)
			}
			if err := pres.Verify(vp.WithResolver(resolver)); err != nil {
				t.Fatalf("Verify with typ %q: %v", tc.typ, err)
			}
		})
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
		"@context":               []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                   []interface{}{"VerifiablePresentation"},
		"holder":                 did,
		"iss":                    did,
		"verifiableCredential":   []interface{}{entry},
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
	entry := map[string]interface{}{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type":     "EnvelopedVerifiableCredential",
		"id":       "data:application/vc+jwt,eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.c2ln",
	}
	token := vpTokenWithEnvelopedVC(t, priv, did, entry)
	pres, err := vp.ParsePresentation([]byte(token), vp.WithResolver(resolver))
	if err != nil {
		t.Fatalf("ParsePresentation with valid enveloped credential: %v", err)
	}
	// Verify should work (signature is valid).
	if err := pres.Verify(vp.WithResolver(resolver)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// --- Hash and wire format stability ---

func TestVPJOSEStrict_HashStability(t *testing.T) {
	did, priv, resolver := vpJoseSetup(t)
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}

	pres, err := vp.NewJOSEPresentation(joseVPContents(did),
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
	if err != nil {
		t.Fatal(err)
	}
	if err := pres.AddProofByProvider(prov, vp.WithResolver(resolver)); err != nil {
		t.Fatal(err)
	}
	hash1, err := pres.Hash()
	if err != nil {
		t.Fatal(err)
	}

	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := vp.ParsePresentation([]byte(serialized.(string)), vp.WithResolver(resolver))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	joseP, ok := parsed.(*vp.JOSEPresentation)
	if !ok {
		t.Fatalf("parsed presentation is %T, want *vp.JOSEPresentation", parsed)
	}
	hash2, err := joseP.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if hash1 != hash2 {
		t.Fatalf("hash changed after round-trip: %s -> %s", hash1, hash2)
	}
}

func TestVPJOSEStrict_WireFormatUnchanged(t *testing.T) {
	did, priv, resolver := vpJoseSetup(t)
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}

	pres, err := vp.NewJOSEPresentation(joseVPContents(did),
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
	if err != nil {
		t.Fatal(err)
	}
	if err := pres.AddProofByProvider(prov, vp.WithResolver(resolver)); err != nil {
		t.Fatal(err)
	}
	ser1, err := pres.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	wire1 := ser1.(string)

	parsed, err := vp.ParsePresentation([]byte(wire1), vp.WithResolver(resolver))
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
