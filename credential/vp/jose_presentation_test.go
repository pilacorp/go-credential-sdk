package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

func joseVPContents(holderDID string) vp.PresentationContents {
	return vp.PresentationContents{
		Context: []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:      "urn:uuid:jose-vp-001",
		Types:   []string{"VerifiablePresentation"},
		Holder:  holderDID,
	}
}

func joseVPHeader(t *testing.T, pres vp.Presentation) (string, string) {
	t.Helper()
	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	token, ok := serialized.(string)
	if !ok {
		t.Fatalf("serialized JOSE presentation is %T, want string", serialized)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	return header.Typ, header.Alg
}

func joseVPPayload(t *testing.T, pres vp.Presentation) map[string]interface{} {
	t.Helper()
	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	token := serialized.(string)
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return payload
}

func TestJOSEPresentation_MultiKey_IssueVerify(t *testing.T) {
	const secpPriv = "57600b3f2b7e1054094e14cd85c72a40dc74c4ee062bb381cea604b55ce56aec"

	p256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}

	cases := []struct {
		name     string
		did      string
		provider func(t *testing.T) signer.SignerProvider
		vm       vmpkg.VerificationMethodEntry
		wantAlg  string
	}{
		{
			name: "secp256k1/ES256K",
			did:  "did:example:jose-vp-secp",
			provider: func(t *testing.T) signer.SignerProvider {
				p, err := signer.NewDefaultProvider(secpPriv)
				if err != nil {
					t.Fatalf("secp provider: %v", err)
				}
				return p
			},
			vm:      vmpkg.NewSecp256k1VM("did:example:jose-vp-secp", "key-1", secpPubHex(t, secpPriv)),
			wantAlg: "ES256K",
		},
		{
			name: "P-256/ES256",
			did:  "did:example:jose-vp-p256",
			provider: func(t *testing.T) signer.SignerProvider {
				p, err := signer.NewP256Provider(p256Priv)
				if err != nil {
					t.Fatalf("p256 provider: %v", err)
				}
				return p
			},
			vm:      mustP256VM(t, "did:example:jose-vp-p256", "key-1", &p256Priv.PublicKey),
			wantAlg: "ES256",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(tc.did, tc.vm))

			pres, err := vp.NewJOSEPresentation(joseVPContents(tc.did),
				vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
			if err != nil {
				t.Fatalf("new jose presentation: %v", err)
			}

			// 1. Header checks per W3C vc-jose-cose
			gotTyp, gotAlg := joseVPHeader(t, pres)
			if gotTyp != "vp+jwt" {
				t.Fatalf("header typ = %q, want 'vp+jwt'", gotTyp)
			}
			if gotAlg != tc.wantAlg {
				t.Fatalf("header alg = %q, want %q", gotAlg, tc.wantAlg)
			}

			// 2. Payload checks: flat payload, NO "vp" or "vc" claim
			payload := joseVPPayload(t, pres)
			if _, hasVP := payload["vp"]; hasVP {
				t.Fatalf("payload contains forbidden 'vp' claim")
			}
			if _, hasVC := payload["vc"]; hasVC {
				t.Fatalf("payload contains forbidden 'vc' claim")
			}
			if payload["iss"] != tc.did && payload["holder"] != tc.did {
				t.Fatalf("payload iss/holder != %q, got iss=%v, holder=%v", tc.did, payload["iss"], payload["holder"])
			}

			// 3. Add proof and verify
			if err := pres.AddProofByProvider(tc.provider(t)); err != nil {
				t.Fatalf("add proof: %v", err)
			}
			if err := pres.Verify(vp.WithResolver(resolver)); err != nil {
				t.Fatalf("verify: %v", err)
			}

			// 4. Hash check
			h, err := pres.Hash()
			if err != nil || len(h) != 64 {
				t.Fatalf("hash: %v (len %d), want 64 hex chars", err, len(h))
			}

			// 5. Serialize / Parse round trip with ParseJOSEPresentation
			serialized, err := pres.Serialize()
			if err != nil {
				t.Fatalf("serialize: %v", err)
			}
			jwtStr := serialized.(string)
			parsed, err := vp.ParseJOSEPresentation(jwtStr)
			if err != nil {
				t.Fatalf("parse jose presentation: %v", err)
			}
			if err := parsed.Verify(vp.WithResolver(resolver)); err != nil {
				t.Fatalf("verify after parse: %v", err)
			}
			if parsed.GetType() != "JOSE" {
				t.Errorf("type = %q, want 'JOSE'", parsed.GetType())
			}

			// 6. Smart auto-detection via vp.ParsePresentation
			autoParsed, err := vp.ParsePresentation([]byte(jwtStr), vp.WithResolver(resolver))
			if err != nil {
				t.Fatalf("ParsePresentation auto-detection error: %v", err)
			}
			if autoParsed.GetType() != "JOSE" {
				t.Fatalf("auto-detected presentation type = %q, want 'JOSE'", autoParsed.GetType())
			}
			if err := autoParsed.Verify(vp.WithResolver(resolver)); err != nil {
				t.Fatalf("auto-detected verify error: %v", err)
			}
		})
	}
}

func TestJOSEPresentation_RejectsForbiddenVPClaim(t *testing.T) {
	header := map[string]interface{}{"typ": "vp+jwt", "alg": "ES256", "kid": "did:example:123#key-1"}
	payload := map[string]interface{}{"vp": map[string]interface{}{"id": "123"}}

	hJSON, _ := json.Marshal(header)
	pJSON, _ := json.Marshal(payload)

	fakeToken := base64.RawURLEncoding.EncodeToString(hJSON) + "." +
		base64.RawURLEncoding.EncodeToString(pJSON) + ".fakesig"

	_, err := vp.ParseJOSEPresentation(fakeToken)
	if err == nil || !strings.Contains(err.Error(), "'vp' claim MUST NOT be present") {
		t.Fatalf("expected rejection of 'vp' claim, got: %v", err)
	}
}

func TestJOSEPresentation_RejectsInvalidTyp(t *testing.T) {
	header := map[string]interface{}{"typ": "JWT", "alg": "ES256", "kid": "did:example:123#key-1"}
	payload := map[string]interface{}{"holder": "did:example:123"}

	hJSON, _ := json.Marshal(header)
	pJSON, _ := json.Marshal(payload)

	fakeToken := base64.RawURLEncoding.EncodeToString(hJSON) + "." +
		base64.RawURLEncoding.EncodeToString(pJSON) + ".fakesig"

	_, err := vp.ParseJOSEPresentation(fakeToken)
	if err == nil || !strings.Contains(err.Error(), "invalid typ header") {
		t.Fatalf("expected rejection of non-vp+jwt typ, got: %v", err)
	}
}

func TestJOSEPresentation_WithVCValidation_EnvelopedVC(t *testing.T) {
	const (
		issuerDID = "did:example:jose-issuer"
		holderDID = "did:example:jose-holder"
		secpPriv  = "57600b3f2b7e1054094e14cd85c72a40dc74c4ee062bb381cea604b55ce56aec"
	)

	p256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}

	issuerVM := vmpkg.NewSecp256k1VM(issuerDID, "key-1", secpPubHex(t, secpPriv))
	holderVM := mustP256VM(t, holderDID, "key-1", &p256Priv.PublicKey)

	resolver := vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(issuerDID, issuerVM),
		vmpkg.NewDIDDocument(holderDID, holderVM),
	)

	issuerProv, _ := signer.NewDefaultProvider(secpPriv)
	holderProv, _ := signer.NewP256Provider(p256Priv)

	// 1. Create and sign JOSECredential (vc+jwt)
	cred, err := vc.NewJOSECredential(vc.CredentialContents{
		Context:   []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:        "urn:uuid:jose-vc-embedded",
		Types:     []string{"VerifiableCredential", "MembershipCredential"},
		Issuer:    issuerDID,
		ValidFrom: time.Now().Add(-time.Hour),
		Subject: []vc.Subject{{
			ID:           "did:example:subject",
			CustomFields: map[string]interface{}{"memberId": "MEM-1234"},
		}},
	}, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new jose cred: %v", err)
	}
	if err := cred.AddProofByProvider(issuerProv); err != nil {
		t.Fatalf("sign cred: %v", err)
	}

	// 2. Create JOSEPresentation embedding the credential
	vpContents := vp.PresentationContents{
		Context:               []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:                    "urn:uuid:jose-vp-with-vc",
		Types:                 []string{"VerifiablePresentation"},
		Holder:                holderDID,
		VerifiableCredentials: []vc.Credential{cred},
	}
	pres, err := vp.NewJOSEPresentation(vpContents,
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new jose pres: %v", err)
	}
	if err := pres.AddProofByProvider(holderProv); err != nil {
		t.Fatalf("sign pres: %v", err)
	}

	// 3. Verify presentation AND validate embedded VC
	if err := pres.Verify(vp.WithResolver(resolver), vp.WithVCValidation()); err != nil {
		t.Fatalf("verify presentation with VC validation failed: %v", err)
	}

	// Check enveloped format in payload
	payload := joseVPPayload(t, pres)
	vcs, ok := payload["verifiableCredential"].([]interface{})
	if !ok || len(vcs) != 1 {
		t.Fatalf("verifiableCredential missing or invalid in payload: %v", payload["verifiableCredential"])
	}
	envMap, ok := vcs[0].(map[string]interface{})
	if !ok {
		t.Fatalf("embedded credential is not map: %T", vcs[0])
	}
	idStr, _ := envMap["id"].(string)
	if !strings.HasPrefix(idStr, "data:application/vc+jwt,") {
		t.Fatalf("expected enveloped URI prefix 'data:application/vc+jwt,', got: %s", idStr)
	}
}

func TestJOSEPresentation_ChallengeDomain_ReplayProtection(t *testing.T) {
	const (
		holderDID = "did:example:jose-replay-holder"
		secpPriv  = "57600b3f2b7e1054094e14cd85c72a40dc74c4ee062bb381cea604b55ce56aec"
	)

	holderVM := vmpkg.NewSecp256k1VM(holderDID, "key-1", secpPubHex(t, secpPriv))
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(holderDID, holderVM))
	holderProv, _ := signer.NewDefaultProvider(secpPriv)

	pres, err := vp.NewJOSEPresentation(joseVPContents(holderDID),
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new jose pres: %v", err)
	}

	// 1. Sign with Challenge and Domain
	const (
		challenge = "test-challenge-nonce-12345"
		domain    = "verifier.example.com"
	)
	if err := pres.AddProofByProvider(holderProv, vp.WithChallenge(challenge), vp.WithDomain(domain)); err != nil {
		t.Fatalf("sign with challenge/domain: %v", err)
	}

	// 2. Successful verification with matching challenge and domain
	if err := pres.Verify(vp.WithResolver(resolver),
		vp.WithExpectedChallenge(challenge), vp.WithExpectedDomain(domain)); err != nil {
		t.Fatalf("verify with expected challenge and domain failed: %v", err)
	}

	// 3. Replay attack detection: mismatched challenge
	if err := pres.Verify(vp.WithResolver(resolver),
		vp.WithExpectedChallenge("replayed-tampered-challenge"), vp.WithExpectedDomain(domain)); err == nil {
		t.Fatalf("expected verification to fail due to challenge mismatch (replay attack)")
	}

	// 4. Phishing attack detection: mismatched domain
	if err := pres.Verify(vp.WithResolver(resolver),
		vp.WithExpectedChallenge(challenge), vp.WithExpectedDomain("attacker.phishing.com")); err == nil {
		t.Fatalf("expected verification to fail due to domain mismatch (phishing)")
	}
}

// joseVPFixture returns a DID whose single P-256 key is published, a resolver
// for it, and a signer provider, for the credential-embedding tests below.
func joseVPFixture(t *testing.T, did string) (vmpkg.ResolverProvider, signer.SignerProvider) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}
	return vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, mustP256VM(t, did, "key-1", &priv.PublicKey))), prov
}

func joseVPCredentialContents(issuerDID string) vc.CredentialContents {
	return vc.CredentialContents{
		Context:   []interface{}{"https://www.w3.org/ns/credentials/v2"},
		Types:     []string{"VerifiableCredential"},
		Issuer:    issuerDID,
		ValidFrom: time.Now().Add(-time.Hour),
		Subject:   []vc.Subject{{ID: "did:example:subject"}},
	}
}

// vc-jose-cose: "Verifiable Credentials secured in verifiable presentations
// MUST use the Enveloped Verifiable Credential type", and VCDM 2.0 requires the
// data: URL to express the credential "using an enveloping security scheme".
// Data Integrity is not one — its proof lives inside the document — so such a
// credential cannot be carried here at all, and a VC 1.1 JWT is not the scheme
// the vc+jwt label names.
func TestJOSEPresentation_RejectsNonEnvelopingCredential(t *testing.T) {
	const did = "did:example:jose-vp-kinds"
	resolver, prov := joseVPFixture(t, did)

	jsonCred, err := vc.NewJSONCredential(joseVPCredentialContents(did),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new json cred: %v", err)
	}
	if err := jsonCred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign json cred: %v", err)
	}

	legacyCred, err := vc.NewJWTCredential(joseVPCredentialContents(did),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new jwt cred: %v", err)
	}
	if err := legacyCred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign jwt cred: %v", err)
	}

	for _, tc := range []struct {
		name string
		cred vc.Credential
	}{
		{"Data Integrity credential", jsonCred},
		{"VC 1.1 JWT credential", legacyCred},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contents := joseVPContents(did)
			contents.VerifiableCredentials = []vc.Credential{tc.cred}
			_, err := vp.NewJOSEPresentation(contents,
				vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
			if err == nil || !strings.Contains(err.Error(), "can only carry enveloping-secured credentials") {
				t.Fatalf("error = %v, want a refusal of a non-enveloping credential", err)
			}
		})
	}
}

// "Credentials in verifiable presentations MUST be secured." An unsigned token
// has two segments, and the data: URL would fail far from here.
func TestJOSEPresentation_RejectsUnsignedCredential(t *testing.T) {
	const did = "did:example:jose-vp-unsigned"
	resolver, _ := joseVPFixture(t, did)

	cred, err := vc.NewJOSECredential(joseVPCredentialContents(did),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new jose cred: %v", err)
	}

	contents := joseVPContents(did)
	contents.VerifiableCredentials = []vc.Credential{cred}
	_, err = vp.NewJOSEPresentation(contents,
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
	if err == nil || !strings.Contains(err.Error(), "is not signed") {
		t.Fatalf("error = %v, want a refusal of an unsigned credential", err)
	}
}

// The media type names the scheme that actually secured the credential, so an
// embedded credential must round-trip through the parser that reads it back.
func TestJOSEPresentation_LabelsEnvelopeByScheme(t *testing.T) {
	const did = "did:example:jose-vp-label"
	resolver, prov := joseVPFixture(t, did)

	newSigned := func(opts ...vc.CredentialOpt) vc.Credential {
		t.Helper()
		opts = append(opts, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
		cred, err := vc.NewJOSECredential(joseVPCredentialContents(did), opts...)
		if err != nil {
			t.Fatalf("new jose cred: %v", err)
		}
		if err := cred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
			t.Fatalf("sign jose cred: %v", err)
		}
		return cred
	}

	cases := []struct {
		name       string
		cred       vc.Credential
		wantPrefix string
	}{
		{"plain JOSE credential", newSigned(), "data:application/vc+jwt,"},
		{
			name:       "SD-JWT credential",
			cred:       newSigned(vc.WithSDSelectivePaths([]string{"credentialSubject.id"})),
			wantPrefix: "data:application/vc+sd-jwt,",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			contents := joseVPContents(did)
			contents.VerifiableCredentials = []vc.Credential{tc.cred}
			pres, err := vp.NewJOSEPresentation(contents,
				vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
			if err != nil {
				t.Fatalf("new jose vp: %v", err)
			}

			body, err := pres.GetContents()
			if err != nil {
				t.Fatalf("contents: %v", err)
			}
			var m map[string]interface{}
			if err := json.Unmarshal(body, &m); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			list, ok := m["verifiableCredential"].([]interface{})
			if !ok || len(list) != 1 {
				t.Fatalf("verifiableCredential = %v, want one entry", m["verifiableCredential"])
			}
			entry, _ := list[0].(map[string]interface{})
			id, _ := entry["id"].(string)
			if !strings.HasPrefix(id, tc.wantPrefix) {
				t.Fatalf("envelope id = %.40q..., want the %s prefix", id, tc.wantPrefix)
			}

			// The envelope must be readable by the parser its media type names.
			raw, err := json.Marshal(entry)
			if err != nil {
				t.Fatalf("marshal entry: %v", err)
			}
			if _, err := vc.ParseCredential(raw, vc.WithResolver(resolver)); err != nil {
				t.Fatalf("the presentation produced an envelope it cannot read back: %v", err)
			}
		})
	}
}

// Nothing in this package reconstructs disclosures — both presentation parsers
// take the third dot-separated segment as the signature, so a token ending in
// "~..." produces a signature with the disclosures glued on. Say that while
// parsing instead of failing later as "illegal base64 data".
func TestParsePresentation_RejectsSDJWTShape(t *testing.T) {
	const did = "did:example:vp-sdjwt-shape"
	resolver, prov := joseVPFixture(t, did)

	pres, err := vp.NewJOSEPresentation(joseVPContents(did),
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new jose vp: %v", err)
	}
	if err := pres.AddProofByProvider(prov, vp.WithResolver(resolver)); err != nil {
		t.Fatalf("add proof: %v", err)
	}
	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	token := serialized.(string)

	if _, err := vp.ParsePresentation([]byte(token), vp.WithResolver(resolver)); err != nil {
		t.Fatalf("the unmodified presentation must still parse: %v", err)
	}

	for _, suffix := range []string{"~", "~WyJhIiwgImIiXQ", "~junk!!!"} {
		t.Run("suffix "+suffix, func(t *testing.T) {
			_, err := vp.ParsePresentation([]byte(token+suffix), vp.WithResolver(resolver))
			if err == nil || !strings.Contains(err.Error(), "SD-JWT disclosures, which are not supported") {
				t.Fatalf("error = %v, want the disclosures to be named while parsing", err)
			}
		})
	}
}

// failingSigner stands in for a remote signer that is momentarily unavailable.
type failingSigner struct{}

func (failingSigner) Sign([]byte) ([]byte, error) {
	return nil, fmt.Errorf("remote signer unavailable")
}

// challenge and domain are signed, so they must be applied before signing — but
// a signing failure must not leave them behind. Otherwise the next call, asking
// for neither, signs the previous attempt's nonce and aud into a presentation
// addressed to a verifier the caller never named.
func TestJOSEPresentation_FailedSigningLeavesNoChallengeOrDomain(t *testing.T) {
	const did = "did:example:vp-rollback"
	resolver, prov := joseVPFixture(t, did)

	pres, err := vp.NewJOSEPresentation(joseVPContents(did),
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new jose vp: %v", err)
	}

	err = pres.AddProofByProvider(failingSigner{},
		vp.WithChallenge("nonce-session-A"), vp.WithDomain("https://bank-a.example"), vp.WithResolver(resolver))
	if err == nil {
		t.Fatal("expected the failing signer to be reported")
	}

	// Second attempt asks for neither.
	if err := pres.AddProofByProvider(prov, vp.WithResolver(resolver)); err != nil {
		t.Fatalf("second sign: %v", err)
	}

	payload := joseVPPayload(t, pres)
	if nonce, ok := payload["nonce"]; ok {
		t.Fatalf("nonce %v survived the failed attempt", nonce)
	}
	if aud, ok := payload["aud"]; ok {
		t.Fatalf("aud %v survived the failed attempt", aud)
	}
	if err := pres.Verify(vp.WithResolver(resolver)); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// The rollback must not cost the feature: a successful call still signs them in.
func TestJOSEPresentation_ChallengeAndDomainAreSigned(t *testing.T) {
	const did = "did:example:vp-challenge"
	resolver, prov := joseVPFixture(t, did)

	pres, err := vp.NewJOSEPresentation(joseVPContents(did),
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new jose vp: %v", err)
	}
	if err := pres.AddProofByProvider(prov,
		vp.WithChallenge("nonce-1"), vp.WithDomain("https://bank-a.example"), vp.WithResolver(resolver)); err != nil {
		t.Fatalf("sign: %v", err)
	}

	payload := joseVPPayload(t, pres)
	if payload["nonce"] != "nonce-1" {
		t.Fatalf("nonce = %v, want nonce-1", payload["nonce"])
	}
	if payload["aud"] != "https://bank-a.example" {
		t.Fatalf("aud = %v, want https://bank-a.example", payload["aud"])
	}

	// Signed in, not merely stored: verification checks them against the bytes.
	if err := pres.Verify(vp.WithResolver(resolver),
		vp.WithExpectedChallenge("nonce-1"), vp.WithExpectedDomain("https://bank-a.example")); err != nil {
		t.Fatalf("verify with expectations: %v", err)
	}
}

// RFC 7519 §4.1.3: a verifier that does not name itself must reject a
// presentation that names an audience. Enforcing that by default would break
// verifiers that never named themselves, so it is opt-in — and this test pins
// both sides of that choice.
func TestJOSEPresentation_RequireAudience(t *testing.T) {
	const did = "did:example:vp-aud"
	resolver, prov := joseVPFixture(t, did)

	sign := func(domain string) string {
		t.Helper()
		pres, err := vp.NewJOSEPresentation(joseVPContents(did),
			vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
		if err != nil {
			t.Fatalf("new jose vp: %v", err)
		}
		opts := []vp.PresentationOpt{vp.WithResolver(resolver)}
		if domain != "" {
			opts = append(opts, vp.WithDomain(domain))
		}
		if err := pres.AddProofByProvider(prov, opts...); err != nil {
			t.Fatalf("sign: %v", err)
		}
		serialized, err := pres.Serialize()
		if err != nil {
			t.Fatalf("serialize: %v", err)
		}
		return serialized.(string)
	}

	forBankA := sign("https://bank-a.example")
	noAudience := sign("")

	cases := []struct {
		name    string
		token   string
		opts    []vp.PresentationOpt
		wantErr string
	}{
		{
			name:  "bank-a names itself",
			token: forBankA,
			opts:  []vp.PresentationOpt{vp.WithRequireAudience(), vp.WithExpectedDomain("https://bank-a.example")},
		},
		{
			name:    "bank-b names itself",
			token:   forBankA,
			opts:    []vp.PresentationOpt{vp.WithRequireAudience(), vp.WithExpectedDomain("https://bank-b.example")},
			wantErr: "does not match expected domain",
		},
		{
			name:    "bank-b names nobody, with the option",
			token:   forBankA,
			opts:    []vp.PresentationOpt{vp.WithRequireAudience()},
			wantErr: "did not name itself",
		},
		{
			// The default is deliberately unchanged, so a verifier that never
			// named itself keeps working across a version bump.
			name:  "bank-b names nobody, without the option",
			token: forBankA,
			opts:  nil,
		},
		{
			// Nothing to enforce when the presentation names no audience.
			name:  "no aud at all, with the option",
			token: noAudience,
			opts:  []vp.PresentationOpt{vp.WithRequireAudience()},
		},
		{
			name:    "no aud, but the verifier names itself",
			token:   noAudience,
			opts:    []vp.PresentationOpt{vp.WithExpectedDomain("https://bank-b.example")},
			wantErr: "does not match expected domain",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := vp.ParsePresentation([]byte(tc.token), vp.WithResolver(resolver))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			opts := append(tc.opts, vp.WithResolver(resolver))
			err = parsed.Verify(opts...)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}
