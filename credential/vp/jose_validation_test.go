package vp_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	jwtpkg "github.com/pilacorp/go-credential-sdk/credential/common/jwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// signJOSEVP signs payload as a vp+jwt by hand, so a test can present a payload
// NewJOSEPresentation would never build.
func signJOSEVP(t *testing.T, prov signer.SignerProvider, kid string, payload map[string]interface{}) string {
	t.Helper()

	header, err := json.Marshal(map[string]interface{}{"typ": "vp+jwt", "alg": "ES256", "kid": kid})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(body)
	sig, err := jwtpkg.NewJWTSigner(prov).SignString(signingInput)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	return signingInput + "." + sig
}

// A signature says who produced the bytes, not what the bytes are. Every payload
// below is correctly signed by a key the DID document grants, and none of them is
// a verifiable presentation — the bare {"holder": ...} one used to verify to nil
// and come back as one.
func TestJOSEPresentation_RefusesANonVCDM2Payload(t *testing.T) {
	const did = "did:example:jose-vp-shape"
	resolver, prov := joseVPFixture(t, did)
	kid := did + "#key-1"

	for _, tc := range []struct {
		name    string
		payload map[string]interface{}
		wantErr string
	}{
		{
			name: "no @context",
			payload: map[string]interface{}{
				"type": []interface{}{"VerifiablePresentation"}, "holder": did},
			wantErr: "must name",
		},
		{
			name: "the VC 1.1 context",
			payload: map[string]interface{}{
				"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
				"type":     []interface{}{"VerifiablePresentation"}, "holder": did},
			wantErr: "must name",
		},
		{
			name: "v2 context but not first",
			payload: map[string]interface{}{
				"@context": []interface{}{"https://example.org/custom", "https://www.w3.org/ns/credentials/v2"},
				"type":     []interface{}{"VerifiablePresentation"}, "holder": did},
			wantErr: "must name",
		},
		{
			name: "no type",
			payload: map[string]interface{}{
				"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"}, "holder": did},
			wantErr: "must have type VerifiablePresentation",
		},
		{
			name: "a credential wearing the vp+jwt label",
			payload: map[string]interface{}{
				"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
				"type":     []interface{}{"VerifiableCredential"}, "holder": did},
			wantErr: "must have type VerifiablePresentation",
		},
		{
			name:    "nothing but a holder",
			payload: map[string]interface{}{"holder": did},
			wantErr: "must name",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := signJOSEVP(t, prov, kid, tc.payload)

			_, err := vp.ParseJOSEPresentation(token, vp.WithResolver(resolver))
			if err == nil {
				t.Fatal("a payload that is not a verifiable presentation was accepted")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one mentioning %q", err, tc.wantErr)
			}
		})
	}
}

// The shape is checked whenever the payload is read, not only when
// WithVCValidation asks for the embedded credentials to be verified. Those are
// different questions, and the cheap one should not hide behind the expensive
// option.
func TestJOSEPresentation_ShapeIsCheckedWithoutVCValidation(t *testing.T) {
	const did = "did:example:jose-vp-ungated"
	resolver, prov := joseVPFixture(t, did)

	token := signJOSEVP(t, prov, did+"#key-1", map[string]interface{}{"holder": did})
	if _, err := vp.ParsePresentation([]byte(token), vp.WithResolver(resolver)); err == nil {
		t.Fatal("accepted with no options at all")
	}
}

// The build side refuses what the parse side refuses. Defaulting an empty
// @context is a convenience; signing a v1 document under a v2 label is not.
func TestNewJOSEPresentation_RefusesANonV2Context(t *testing.T) {
	const did = "did:example:jose-vp-build"
	resolver, _ := joseVPFixture(t, did)

	contents := joseVPContents(did)
	contents.Context = []interface{}{"https://www.w3.org/2018/credentials/v1"}

	_, err := vp.NewJOSEPresentation(contents,
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
	if err == nil || !strings.Contains(err.Error(), "must name") {
		t.Fatalf("err = %v, want a v1 context to be refused before signing", err)
	}
}

// vc-jose-cose § 3.1.2: credentials inside a presentation MUST use the Enveloped
// Verifiable Credential type. NewJOSEPresentation envelopes what it carries and
// refuses a Data Integrity credential outright — so the bare JSON-LD case below
// is one this SDK will not produce but used to accept.
func TestJOSEPresentation_RefusesBareCredentials(t *testing.T) {
	const did = "did:example:jose-vp-envelope"
	resolver, prov := joseVPFixture(t, did)
	kid := did + "#key-1"

	joseCred, err := vc.NewJOSECredential(joseVPCredentialContents(did),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new jose credential: %v", err)
	}
	if err := joseCred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign jose credential: %v", err)
	}
	serialized, err := joseCred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	token, ok := serialized.(string)
	if !ok {
		t.Fatalf("serialized credential is %T, want string", serialized)
	}

	jsonLDCred, err := vc.NewJSONCredential(joseVPCredentialContents(did),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new json-ld credential: %v", err)
	}
	if err := jsonLDCred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign json-ld credential: %v", err)
	}
	jsonLDRaw, err := jsonLDCred.Serialize()
	if err != nil {
		t.Fatalf("serialize json-ld: %v", err)
	}
	jsonLDBytes, err := json.Marshal(jsonLDRaw)
	if err != nil {
		t.Fatalf("marshal json-ld: %v", err)
	}
	var jsonLDObject interface{}
	if err := json.Unmarshal(jsonLDBytes, &jsonLDObject); err != nil {
		t.Fatalf("unmarshal json-ld: %v", err)
	}

	enveloped := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"EnvelopedVerifiableCredential"},
		"id":       "data:application/vc+jwt," + token,
	}

	for _, tc := range []struct {
		name    string
		item    interface{}
		wantErr bool
	}{
		{name: "enveloped, as the spec requires", item: enveloped},
		{name: "a bare vc+jwt string", item: token, wantErr: true},
		{name: "a bare JSON-LD credential object", item: jsonLDObject, wantErr: true},
		{
			name: "an envelope missing its type",
			item: map[string]interface{}{
				"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
				"id":       "data:application/vc+jwt," + token},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vpToken := signJOSEVP(t, prov, kid, map[string]interface{}{
				"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
				"type":                 []interface{}{"VerifiablePresentation"},
				"holder":               did,
				"verifiableCredential": []interface{}{tc.item},
			})

			pres, err := vp.ParseJOSEPresentation(vpToken, vp.WithResolver(resolver))
			if tc.wantErr {
				if err == nil {
					t.Fatal("a bare credential inside a vp+jwt was accepted")
				}
				if !strings.Contains(err.Error(), "EnvelopedVerifiableCredential") {
					t.Fatalf("err = %v, want one naming the envelope type", err)
				}

				return
			}
			if err != nil {
				t.Fatalf("a correctly enveloped credential was refused: %v", err)
			}
			if err := pres.Verify(vp.WithResolver(resolver), vp.WithVCValidation()); err != nil {
				t.Fatalf("verify: %v", err)
			}
		})
	}
}
