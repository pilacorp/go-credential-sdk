package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// A presentation signed with a challenge/domain verifies only against the same
// expected values: the verifier-issued nonce cannot be swapped or dropped.
func TestVP_ChallengeDomain_SignAndVerify(t *testing.T) {
	const holder = "did:example:vp-challenge"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("p256: %v", err)
	}
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(holder,
		mustP256VM(t, holder, "key-1", &priv.PublicKey)))

	pres, err := vp.ParseJSONPresentation(vpDoc(holder))
	if err != nil {
		t.Fatalf("parse vp: %v", err)
	}
	err = pres.AddProofByProvider(prov, vp.WithResolver(resolver),
		vp.WithChallenge("nonce-123"), vp.WithDomain("verifier.example"))
	if err != nil {
		t.Fatalf("sign vp: %v", err)
	}

	if pres.ExtractField("proof.challenge") != "nonce-123" || pres.ExtractField("proof.domain") != "verifier.example" {
		t.Fatalf("proof lacks challenge/domain: %v", pres.ExtractField("proof"))
	}

	cases := []struct {
		name    string
		opts    []vp.PresentationOpt
		wantErr string
	}{
		{"matching challenge and domain", []vp.PresentationOpt{vp.WithExpectedChallenge("nonce-123"), vp.WithExpectedDomain("verifier.example")}, ""},
		{"no expectation", nil, ""},
		{"wrong challenge", []vp.PresentationOpt{vp.WithExpectedChallenge("nonce-999")}, "challenge"},
		{"wrong domain", []vp.PresentationOpt{vp.WithExpectedDomain("attacker.example")}, "domain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := pres.Verify(append([]vp.PresentationOpt{vp.WithResolver(resolver)}, tc.opts...)...)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("verify: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("verify err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}

	// Round-trip through JSON keeps the signed options and the signature valid.
	raw, err := pres.GetContents()
	if err != nil {
		t.Fatalf("contents: %v", err)
	}
	reparsed, err := vp.ParseJSONPresentation(raw)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if err := reparsed.Verify(vp.WithResolver(resolver), vp.WithExpectedChallenge("nonce-123")); err != nil {
		t.Fatalf("verify re-parsed: %v", err)
	}
}

// A presentation signed WITHOUT a challenge must fail when the verifier expects
// one — silently accepting it would defeat the replay protection.
func TestVP_ChallengeDomain_MissingChallengeRejected(t *testing.T) {
	const holder = "did:example:vp-nochallenge"
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	prov, _ := signer.NewP256Provider(priv)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(holder,
		mustP256VM(t, holder, "key-1", &priv.PublicKey)))

	pres, err := vp.ParseJSONPresentation(vpDoc(holder))
	if err != nil {
		t.Fatalf("parse vp: %v", err)
	}
	if err := pres.AddProofByProvider(prov, vp.WithResolver(resolver)); err != nil {
		t.Fatalf("sign vp: %v", err)
	}
	if err := pres.Verify(vp.WithResolver(resolver), vp.WithExpectedChallenge("nonce-123")); err == nil {
		t.Fatal("expected verification to fail without a challenge in the proof")
	}
}

// WithExpectedChallenge/WithExpectedDomain imply WithVerifyProof: passing them
// to Parse must verify the proof and enforce the expected values, never skip.
func TestVP_ChallengeDomain_ExpectedImpliesVerify(t *testing.T) {
	const holder = "did:example:vp-implies"
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	prov, _ := signer.NewP256Provider(priv)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(holder,
		mustP256VM(t, holder, "key-1", &priv.PublicKey)))

	pres, err := vp.ParseJSONPresentation(vpDoc(holder))
	if err != nil {
		t.Fatalf("parse vp: %v", err)
	}
	if err := pres.AddProofByProvider(prov, vp.WithResolver(resolver),
		vp.WithChallenge("nonce-123"), vp.WithDomain("example.com")); err != nil {
		t.Fatalf("sign vp: %v", err)
	}
	raw, err := pres.GetContents()
	if err != nil {
		t.Fatalf("contents: %v", err)
	}

	cases := []struct {
		name    string
		opts    []vp.PresentationOpt
		wantErr string
	}{
		{"matching challenge", []vp.PresentationOpt{vp.WithResolver(resolver), vp.WithExpectedChallenge("nonce-123")}, ""},
		{"matching domain", []vp.PresentationOpt{vp.WithResolver(resolver), vp.WithExpectedDomain("example.com")}, ""},
		{"wrong challenge", []vp.PresentationOpt{vp.WithResolver(resolver), vp.WithExpectedChallenge("other")}, "challenge"},
		{"wrong domain", []vp.PresentationOpt{vp.WithResolver(resolver), vp.WithExpectedDomain("evil.example")}, "domain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := vp.ParseJSONPresentation(raw, tc.opts...)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("parse err = %v, want nil", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("parse err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}

	// An unsigned document cannot satisfy an expected challenge: proof
	// verification now runs and fails instead of silently passing.
	if _, err := vp.ParseJSONPresentation(vpDoc(holder), vp.WithResolver(resolver), vp.WithExpectedChallenge("nonce-123")); err == nil {
		t.Fatal("expected parse of unsigned VP with expected challenge to fail")
	}
}

func jwtVPContents() vp.PresentationContents {
	return vp.PresentationContents{
		Context: []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:      "urn:uuid:jwt-challenge-test",
		Types:   []string{"VerifiablePresentation"},
		Holder:  testDID,
	}
}

func jwtPayloadClaims(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		t.Fatalf("malformed jwt: %s", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return m
}

// WithChallenge/WithDomain map to the standard nonce/aud JWT claims and are
// enforced by WithExpectedChallenge/WithExpectedDomain on verify.
func TestJWTVP_ChallengeDomain_SignAndVerify(t *testing.T) {
	resolver := testResolver(t)

	pres, err := vp.NewJWTPresentation(jwtVPContents(), vp.WithVerificationMethodKey("#key-1"),
		vp.WithResolver(resolver),
		vp.WithChallenge("nonce-123"),
		vp.WithDomain("verifier.example"))
	if err != nil {
		t.Fatalf("new jwt vp: %v", err)
	}
	if err := pres.AddProofByProvider(mustDefaultSigner(t, testSecpPrivHex)); err != nil {
		t.Fatalf("sign jwt vp: %v", err)
	}
	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	token := serialized.(string)

	claims := jwtPayloadClaims(t, token)
	if claims["nonce"] != "nonce-123" {
		t.Fatalf("nonce claim = %v, want nonce-123", claims["nonce"])
	}
	if claims["aud"] != "verifier.example" {
		t.Fatalf("aud claim = %v, want verifier.example", claims["aud"])
	}

	cases := []struct {
		name    string
		opts    []vp.PresentationOpt
		wantErr string
	}{
		{"matching both", []vp.PresentationOpt{vp.WithExpectedChallenge("nonce-123"), vp.WithExpectedDomain("verifier.example")}, ""},
		{"no expectations", nil, ""},
		{"wrong challenge", []vp.PresentationOpt{vp.WithExpectedChallenge("nonce-999")}, "nonce"},
		{"wrong domain", []vp.PresentationOpt{vp.WithExpectedDomain("evil.example")}, "aud"},
	}
	for _, tc := range cases {
		t.Run("in-memory/"+tc.name, func(t *testing.T) {
			err := pres.Verify(append([]vp.PresentationOpt{vp.WithResolver(resolver)}, tc.opts...)...)
			checkErr(t, err, tc.wantErr)
		})
		t.Run("reparsed/"+tc.name, func(t *testing.T) {
			reparsed, err := vp.ParseJWTPresentation(token)
			if err != nil {
				t.Fatalf("re-parse: %v", err)
			}
			err = reparsed.Verify(append([]vp.PresentationOpt{vp.WithResolver(resolver)}, tc.opts...)...)
			checkErr(t, err, tc.wantErr)
		})
	}
}

// A JWT VP signed WITHOUT nonce/aud must fail when the verifier expects them;
// silently accepting it would defeat the replay protection.
func TestJWTVP_ChallengeDomain_MissingRejected(t *testing.T) {
	resolver := testResolver(t)

	pres, err := vp.NewJWTPresentation(jwtVPContents(), vp.WithVerificationMethodKey("#key-1"), vp.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new jwt vp: %v", err)
	}
	if err := pres.AddProofByProvider(mustDefaultSigner(t, testSecpPrivHex)); err != nil {
		t.Fatalf("sign jwt vp: %v", err)
	}
	if err := pres.Verify(vp.WithResolver(resolver), vp.WithExpectedChallenge("nonce-123")); err == nil {
		t.Fatal("expected verification to fail without nonce in the JWT")
	}
	if err := pres.Verify(vp.WithResolver(resolver), vp.WithExpectedDomain("verifier.example")); err == nil {
		t.Fatal("expected verification to fail without aud in the JWT")
	}
}

// Tampering with the signed claims (e.g. swapping aud) must fail signature
// verification before the claim comparison is ever reached.
func TestJWTVP_ChallengeDomain_TamperedAudRejected(t *testing.T) {
	resolver := testResolver(t)

	pres, err := vp.NewJWTPresentation(jwtVPContents(), vp.WithVerificationMethodKey("#key-1"), vp.WithResolver(resolver), vp.WithDomain("verifier.example"))
	if err != nil {
		t.Fatalf("new jwt vp: %v", err)
	}
	if err := pres.AddProofByProvider(mustDefaultSigner(t, testSecpPrivHex)); err != nil {
		t.Fatalf("sign jwt vp: %v", err)
	}
	serialized, _ := pres.Serialize()
	parts := strings.Split(serialized.(string), ".")

	claims := jwtPayloadClaims(t, serialized.(string))
	claims["aud"] = "evil.example"
	payloadJSON, _ := json.Marshal(claims)
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payloadJSON) + "." + parts[2]

	reparsed, err := vp.ParseJWTPresentation(tampered)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := reparsed.Verify(vp.WithResolver(resolver), vp.WithExpectedDomain("evil.example")); err == nil {
		t.Fatal("tampered token must fail signature verification")
	}
}

func checkErr(t *testing.T, err error, want string) {
	t.Helper()
	if want == "" && err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
		t.Fatalf("err = %v, want containing %q", err, want)
	}
}

// A JWT VP bound to a P-256 verification method must carry alg ES256 and
// verify with a P-256 signer; the header alg is derived from the VM, not fixed.
func TestJWTVP_P256VerificationMethod(t *testing.T) {
	resolver := testResolver(t)

	pres, err := vp.NewJWTPresentation(jwtVPContents(),
		vp.WithResolver(resolver), vp.WithVerificationMethodKey("#key-2"))
	if err != nil {
		t.Fatalf("new jwt vp: %v", err)
	}
	if err := pres.AddProofByProvider(mustP256Signer(t)); err != nil {
		t.Fatalf("sign jwt vp: %v", err)
	}
	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	token := serialized.(string)

	headerRaw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if header["alg"] != "ES256" {
		t.Fatalf("alg = %v, want ES256", header["alg"])
	}
	if header["kid"] != testDID+"#key-2" {
		t.Fatalf("kid = %v, want %s#key-2", header["kid"], testDID)
	}

	if err := pres.Verify(vp.WithResolver(resolver)); err != nil {
		t.Fatalf("verify: %v", err)
	}
	reparsed, err := vp.ParseJWTPresentation(token)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if err := reparsed.Verify(vp.WithResolver(resolver)); err != nil {
		t.Fatalf("verify re-parsed: %v", err)
	}
}

// Verify-time options passed to AddProofByProvider run against the signed
// token, and a failed check leaves the presentation unsigned.
func TestJWTVP_AddProofByProvider_VerifyOptions(t *testing.T) {
	resolver := testResolver(t)

	pres, err := vp.NewJWTPresentation(jwtVPContents(),
		vp.WithResolver(resolver), vp.WithVerificationMethodKey("#key-1"), vp.WithChallenge("nonce-123"))
	if err != nil {
		t.Fatalf("new jwt vp: %v", err)
	}

	if err := pres.AddProofByProvider(mustDefaultSigner(t, testSecpPrivHex),
		vp.WithResolver(resolver), vp.WithExpectedChallenge("wrong")); err == nil {
		t.Fatal("expected sign+verify with wrong challenge to fail")
	}
	if serialized, _ := pres.Serialize(); strings.Count(serialized.(string), ".") != 1 {
		t.Fatalf("presentation must stay unsigned after a failed check, got %q", serialized)
	}

	if err := pres.AddProofByProvider(mustDefaultSigner(t, testSecpPrivHex),
		vp.WithResolver(resolver), vp.WithExpectedChallenge("nonce-123")); err != nil {
		t.Fatalf("sign+verify: %v", err)
	}
	if serialized, _ := pres.Serialize(); strings.Count(serialized.(string), ".") != 2 {
		t.Fatalf("presentation must be signed, got %q", serialized)
	}
}

// WithChallenge/WithDomain given at signing time (as with JSON presentations)
// overwrite the nonce/aud claims before the token is signed.
func TestJWTVP_ChallengeDomain_SetAtSignTime(t *testing.T) {
	resolver := testResolver(t)

	pres, err := vp.NewJWTPresentation(jwtVPContents(),
		vp.WithResolver(resolver), vp.WithVerificationMethodKey("#key-1"),
		vp.WithChallenge("stale"), vp.WithDomain("stale.example"))
	if err != nil {
		t.Fatalf("new jwt vp: %v", err)
	}
	if err := pres.AddProofByProvider(mustDefaultSigner(t, testSecpPrivHex),
		vp.WithChallenge("nonce-123"), vp.WithDomain("verifier.example")); err != nil {
		t.Fatalf("sign jwt vp: %v", err)
	}
	serialized, _ := pres.Serialize()
	claims := jwtPayloadClaims(t, serialized.(string))
	if claims["nonce"] != "nonce-123" || claims["aud"] != "verifier.example" {
		t.Fatalf("claims not overwritten at sign time: nonce=%v aud=%v", claims["nonce"], claims["aud"])
	}
	if err := pres.Verify(vp.WithResolver(resolver),
		vp.WithExpectedChallenge("nonce-123"), vp.WithExpectedDomain("verifier.example")); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := pres.Verify(vp.WithResolver(resolver), vp.WithExpectedChallenge("stale")); err == nil {
		t.Fatal("stale challenge must not verify")
	}
}
