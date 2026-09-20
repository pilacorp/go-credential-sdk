package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
