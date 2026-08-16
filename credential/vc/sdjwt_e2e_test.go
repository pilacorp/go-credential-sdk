package vc_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// A fixed secp256k1 scalar so the SD-JWT tests are deterministic.
const sdJWTIssuerPriv = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

const sdJWTIssuerDID = "did:example:sdjwt-issuer"

// sdJWTEnv holds the issuer key material and the resolver a Verifier uses.
type sdJWTEnv struct {
	provider signer.SignerProvider
	resolver vmpkg.ResolverProvider
}

func newSDJWTEnv(t *testing.T) sdJWTEnv {
	t.Helper()

	provider, err := signer.NewDefaultProvider(sdJWTIssuerPriv)
	if err != nil {
		t.Fatalf("issuer provider: %v", err)
	}

	vm := vmpkg.NewSecp256k1VM(sdJWTIssuerDID, "key-1", pubHex(t, sdJWTIssuerPriv))

	return sdJWTEnv{
		provider: provider,
		resolver: vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(sdJWTIssuerDID, vm)),
	}
}

// sdJWTContents builds the credential every SD-JWT test issues from.
func sdJWTContents() vc.CredentialContents {
	return vc.CredentialContents{
		Context: []interface{}{"https://www.w3.org/2018/credentials/v1"},
		ID:      "urn:uuid:sdjwt-e2e-001",
		Issuer:  sdJWTIssuerDID,
		Types:   []string{"VerifiableCredential"},
		Subject: []vc.Subject{
			{
				ID: "did:example:sdjwt-subject",
				CustomFields: map[string]interface{}{
					"firstname":   "Nguyen",
					"family_name": "Van A",
					"email":       "vana@example.com",
					"tags":        []interface{}{"gold", "verified"},
				},
			},
		},
		ValidFrom:  time.Now().Add(-time.Hour),
		ValidUntil: time.Now().Add(24 * time.Hour),
	}
}

// issueSDJWT issues and signs an SD-JWT, returning the serialized string.
func issueSDJWT(t *testing.T, env sdJWTEnv, opts ...vc.CredentialOpt) (*vc.JWTCredential, string) {
	t.Helper()

	opts = append([]vc.CredentialOpt{vc.WithVerificationMethodKey("key-1")}, opts...)

	cred, err := vc.NewJWTCredential(sdJWTContents(), opts...)
	if err != nil {
		t.Fatalf("new SD-JWT credential: %v", err)
	}
	if err := cred.AddProofByProvider(env.provider); err != nil {
		t.Fatalf("add proof: %v", err)
	}

	serialized, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	s, ok := serialized.(string)
	if !ok {
		t.Fatalf("serialized SD-JWT is %T, want string", serialized)
	}

	return cred, s
}

// TestSDJWT_E2E_IssueAndVerify is the end-to-end acceptance path: an Issuer
// issues an SD-JWT with selectively disclosable claims and a Verifier calls
// Verify() on it successfully. Before the disclosures were split off ahead of
// signature verification, Verify() failed on every SD-JWT.
func TestSDJWT_E2E_IssueAndVerify(t *testing.T) {
	env := newSDJWTEnv(t)

	paths := []string{
		"credentialSubject.firstname",
		"credentialSubject.family_name",
		"credentialSubject.email",
	}
	issued, sdJWT := issueSDJWT(t, env, vc.WithSDSelectivePaths(paths))

	// The issuer's own credential object verifies.
	if err := issued.Verify(vc.WithResolver(env.resolver)); err != nil {
		t.Fatalf("verify issued credential: %v", err)
	}

	// So does the credential a Verifier parses off the wire.
	parsed, err := vc.ParseCredential([]byte(sdJWT), vc.WithResolver(env.resolver), vc.WithVerifyProof())
	if err != nil {
		t.Fatalf("parse and verify SD-JWT: %v", err)
	}

	// All three disclosures were sent, so all three claims are reconstructed.
	for path, want := range map[string]string{
		"credentialSubject.firstname":   "Nguyen",
		"credentialSubject.family_name": "Van A",
		"credentialSubject.email":       "vana@example.com",
	} {
		if got := parsed.ExtractField(path); got != want {
			t.Errorf("%s = %v, want %q", path, got, want)
		}
	}
}

// TestSDJWT_E2E_HolderPresentsSubset covers the selective-sharing flow: the
// Holder drops a disclosure and the Verifier still verifies, seeing only the
// claims that were actually presented.
func TestSDJWT_E2E_HolderPresentsSubset(t *testing.T) {
	env := newSDJWTEnv(t)

	paths := []string{
		"credentialSubject.firstname",
		"credentialSubject.family_name",
		"credentialSubject.email",
	}
	_, sdJWT := issueSDJWT(t, env, vc.WithSDSelectivePaths(paths))

	held, err := vc.ParseJWTCredential(sdJWT)
	if err != nil {
		t.Fatalf("holder parse: %v", err)
	}

	discs, err := held.DecodedDisclosures()
	if err != nil {
		t.Fatalf("decoded disclosures: %v", err)
	}
	if len(discs) != len(paths) {
		t.Fatalf("got %d disclosures, want %d", len(discs), len(paths))
	}

	// Reveal only firstname; family_name and email stay hidden.
	var selected []string
	for _, d := range discs {
		if d.FieldName == "firstname" {
			selected = append(selected, d.Disclosure)
		}
	}
	if len(selected) != 1 {
		t.Fatalf("could not find the firstname disclosure among %d", len(discs))
	}

	presented, err := held.Present(selected)
	if err != nil {
		t.Fatalf("present subset: %v", err)
	}
	if err := presented.Verify(vc.WithResolver(env.resolver)); err != nil {
		t.Fatalf("verify presented subset: %v", err)
	}

	if got := presented.ExtractField("credentialSubject.firstname"); got != "Nguyen" {
		t.Errorf("firstname = %v, want %q", got, "Nguyen")
	}
	for _, hidden := range []string{"credentialSubject.family_name", "credentialSubject.email"} {
		if got := presented.ExtractField(hidden); got != nil {
			t.Errorf("%s = %v, want it withheld", hidden, got)
		}
	}
}

// TestSDJWT_E2E_ArrayElementAndDecoys checks that array-element disclosures,
// decoy digests and a non-default hash algorithm all still verify. Decoys are
// digests with no matching disclosure, so the digest check must tolerate them.
func TestSDJWT_E2E_ArrayElementAndDecoys(t *testing.T) {
	env := newSDJWTEnv(t)

	_, sdJWT := issueSDJWT(t, env,
		vc.WithSDSelectivePaths([]string{
			"credentialSubject.email",
			"credentialSubject.tags[0]",
		}),
		vc.WithSDHashAlgorithm("sha-384"),
		vc.WithSDShuffle(true),
		vc.WithSDDecoyDigests([]vc.Decoy{
			{Path: "", Count: 2},
			{Path: "credentialSubject", Count: 3},
		}),
	)

	parsed, err := vc.ParseCredential([]byte(sdJWT), vc.WithResolver(env.resolver), vc.WithVerifyProof())
	if err != nil {
		t.Fatalf("parse and verify SD-JWT with decoys: %v", err)
	}

	if got := parsed.ExtractField("credentialSubject.email"); got != "vana@example.com" {
		t.Errorf("email = %v, want %q", got, "vana@example.com")
	}
	// ExtractField has no array-index syntax, so index the slice directly.
	tags, ok := parsed.ExtractField("credentialSubject.tags").([]interface{})
	if !ok || len(tags) == 0 {
		t.Fatalf("tags = %v, want a non-empty array", parsed.ExtractField("credentialSubject.tags"))
	}
	if tags[0] != "gold" {
		t.Errorf("tags[0] = %v, want %q", tags[0], "gold")
	}
}

// TestSDJWT_E2E_RejectsForgedDisclosure is the counterpart to the happy path:
// the issuer signature covers only the digests, so a disclosure appended or
// altered after issuance must be rejected rather than silently ignored.
func TestSDJWT_E2E_RejectsForgedDisclosure(t *testing.T) {
	env := newSDJWTEnv(t)

	_, sdJWT := issueSDJWT(t, env, vc.WithSDSelectivePaths([]string{"credentialSubject.email"}))

	cases := []struct {
		name   string
		mutate func(t *testing.T, sdJWT string) string
	}{
		{
			name: "injected disclosure",
			mutate: func(t *testing.T, sdJWT string) string {
				return appendDisclosure(t, sdJWT, []interface{}{"c2FsdA", "role", "admin"})
			},
		},
		{
			name: "injected array element",
			mutate: func(t *testing.T, sdJWT string) string {
				return appendDisclosure(t, sdJWT, []interface{}{"c2FsdA", "platinum"})
			},
		},
		{
			name: "tampered value in an issued disclosure",
			mutate: func(t *testing.T, sdJWT string) string {
				base, discs := splitSDJWTString(t, sdJWT)
				if len(discs) != 1 {
					t.Fatalf("got %d disclosures, want 1", len(discs))
				}

				var arr []interface{}
				decodeDisclosure(t, discs[0], &arr)
				arr[2] = "attacker@example.com"

				return base + "~" + encodeDisclosure(t, arr) + "~"
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forged := tc.mutate(t, sdJWT)

			_, err := vc.ParseCredential([]byte(forged), vc.WithResolver(env.resolver), vc.WithVerifyProof())
			if err == nil {
				t.Fatal("verify accepted a forged disclosure, want an error")
			}
			if !strings.Contains(err.Error(), "invalid SD-JWT disclosure") {
				t.Errorf("error = %v, want it to mention the invalid disclosure", err)
			}
		})
	}
}

// TestSDJWT_E2E_PlainJWTStillVerifies guards the non-SD path against the
// disclosure handling added to the verifier.
func TestSDJWT_E2E_PlainJWTStillVerifies(t *testing.T) {
	env := newSDJWTEnv(t)

	_, plain := issueSDJWT(t, env)
	if strings.Contains(plain, "~") {
		t.Fatalf("expected a plain JWT without disclosures, got %q", plain)
	}

	if _, err := vc.ParseCredential([]byte(plain), vc.WithResolver(env.resolver), vc.WithVerifyProof()); err != nil {
		t.Fatalf("verify plain JWT: %v", err)
	}
}

// splitSDJWTString splits an SD-JWT into its issuer-signed JWT and disclosures.
func splitSDJWTString(t *testing.T, sdJWT string) (string, []string) {
	t.Helper()

	parts := strings.Split(strings.TrimSuffix(sdJWT, "~"), "~")
	if len(parts) < 2 {
		t.Fatalf("expected an SD-JWT with disclosures, got %q", sdJWT)
	}

	return parts[0], parts[1:]
}

// appendDisclosure tacks an extra disclosure onto an SD-JWT, leaving the
// issuer-signed JWT untouched.
func appendDisclosure(t *testing.T, sdJWT string, arr []interface{}) string {
	t.Helper()
	return strings.TrimSuffix(sdJWT, "~") + "~" + encodeDisclosure(t, arr) + "~"
}

func encodeDisclosure(t *testing.T, arr []interface{}) string {
	t.Helper()

	b, err := json.Marshal(arr)
	if err != nil {
		t.Fatalf("marshal disclosure: %v", err)
	}

	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeDisclosure(t *testing.T, disclosure string, out interface{}) {
	t.Helper()

	b, err := base64.RawURLEncoding.DecodeString(disclosure)
	if err != nil {
		t.Fatalf("decode disclosure: %v", err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("unmarshal disclosure: %v", err)
	}
}
