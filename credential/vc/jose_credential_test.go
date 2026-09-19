package vc_test

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
)

func joseContents(issuerDID string) vc.CredentialContents {
	return vc.CredentialContents{
		Context:   []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:        "urn:uuid:jose-test-001",
		Types:     []string{"VerifiableCredential", "AlumniCredential"},
		Issuer:    issuerDID,
		ValidFrom: time.Now().Add(-time.Hour),
		Subject: []vc.Subject{{
			ID:           "did:example:subject",
			CustomFields: map[string]interface{}{"name": "Nguyen Van A"},
		}},
	}
}

func joseHeader(t *testing.T, cred vc.Credential) (string, string) {
	t.Helper()
	serialized, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	token, ok := serialized.(string)
	if !ok {
		t.Fatalf("serialized JOSE credential is %T, want string", serialized)
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

func josePayload(t *testing.T, cred vc.Credential) map[string]interface{} {
	t.Helper()
	serialized, err := cred.Serialize()
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

func TestJOSECredential_MultiKey_IssueVerify(t *testing.T) {
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
			did:  "did:example:jose-secp",
			provider: func(t *testing.T) signer.SignerProvider {
				p, err := signer.NewDefaultProvider(secpPriv)
				if err != nil {
					t.Fatalf("secp provider: %v", err)
				}
				return p
			},
			vm:      vmpkg.NewSecp256k1VM("did:example:jose-secp", "key-1", pubHex(t, secpPriv)),
			wantAlg: "ES256K",
		},
		{
			name: "P-256/ES256",
			did:  "did:example:jose-p256",
			provider: func(t *testing.T) signer.SignerProvider {
				p, err := signer.NewP256Provider(p256Priv)
				if err != nil {
					t.Fatalf("p256 provider: %v", err)
				}
				return p
			},
			vm:      mustP256VM(t, "did:example:jose-p256", "key-1", &p256Priv.PublicKey),
			wantAlg: "ES256",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(tc.did, tc.vm))

			cred, err := vc.NewJOSECredential(joseContents(tc.did),
				vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
			if err != nil {
				t.Fatalf("new jose credential: %v", err)
			}

			// 1. Header checks per W3C vc-jose-cose
			gotTyp, gotAlg := joseHeader(t, cred)
			if gotTyp != "vc+jwt" {
				t.Fatalf("header typ = %q, want 'vc+jwt'", gotTyp)
			}
			if gotAlg != tc.wantAlg {
				t.Fatalf("header alg = %q, want %q", gotAlg, tc.wantAlg)
			}

			// 2. Payload checks: flat payload, NO "vc" or "vp" claim
			payload := josePayload(t, cred)
			if _, hasVC := payload["vc"]; hasVC {
				t.Fatalf("payload contains forbidden 'vc' claim")
			}
			if _, hasVP := payload["vp"]; hasVP {
				t.Fatalf("payload contains forbidden 'vp' claim")
			}
			if payload["issuer"] != tc.did {
				t.Fatalf("payload issuer = %v, want %q", payload["issuer"], tc.did)
			}

			// 3. Add proof and verify
			if err := cred.AddProofByProvider(tc.provider(t)); err != nil {
				t.Fatalf("add proof: %v", err)
			}
			if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
				t.Fatalf("verify: %v", err)
			}

			// 4. Hash check
			h, err := cred.Hash()
			if err != nil || len(h) != 64 {
				t.Fatalf("hash: %v (len %d), want 64 hex chars", err, len(h))
			}

			// 5. Serialize / Parse round trip with ParseJOSECredential
			serialized, err := cred.Serialize()
			if err != nil {
				t.Fatalf("serialize: %v", err)
			}
			jwtStr := serialized.(string)
			parsed, err := vc.ParseJOSECredential(jwtStr)
			if err != nil {
				t.Fatalf("parse jose credential: %v", err)
			}
			if err := parsed.Verify(vc.WithResolver(resolver)); err != nil {
				t.Fatalf("verify after parse: %v", err)
			}
			if got := parsed.ExtractField("credentialSubject.name"); got != "Nguyen Van A" {
				t.Errorf("name = %v, want %q", got, "Nguyen Van A")
			}

			// 6. Smart auto-detection via vc.ParseCredential
			autoParsed, err := vc.ParseCredential([]byte(jwtStr), vc.WithResolver(resolver))
			if err != nil {
				t.Fatalf("ParseCredential auto-detection error: %v", err)
			}
			if autoParsed.GetType() != "JOSE" {
				t.Fatalf("auto-detected credential type = %q, want 'JOSE'", autoParsed.GetType())
			}
			if err := autoParsed.Verify(vc.WithResolver(resolver)); err != nil {
				t.Fatalf("auto-detected verify error: %v", err)
			}
		})
	}
}

func TestJOSECredential_RejectsForbiddenVCClaim(t *testing.T) {
	// Craft a token with typ: "vc+jwt" but having "vc" claim in payload
	header := map[string]interface{}{"typ": "vc+jwt", "alg": "ES256", "kid": "did:example:123#key-1"}
	payload := map[string]interface{}{"vc": map[string]interface{}{"id": "123"}}

	hJSON, _ := json.Marshal(header)
	pJSON, _ := json.Marshal(payload)

	fakeToken := base64.RawURLEncoding.EncodeToString(hJSON) + "." +
		base64.RawURLEncoding.EncodeToString(pJSON) + ".fakesig"

	_, err := vc.ParseJOSECredential(fakeToken)
	if err == nil || !strings.Contains(err.Error(), "'vc' claim MUST NOT be present") {
		t.Fatalf("expected rejection of 'vc' claim, got: %v", err)
	}
}

func TestJOSECredential_RejectsInvalidTyp(t *testing.T) {
	// Craft a token with typ: "JWT" (VC 1.1)
	header := map[string]interface{}{"typ": "JWT", "alg": "ES256", "kid": "did:example:123#key-1"}
	payload := map[string]interface{}{"issuer": "did:example:123"}

	hJSON, _ := json.Marshal(header)
	pJSON, _ := json.Marshal(payload)

	fakeToken := base64.RawURLEncoding.EncodeToString(hJSON) + "." +
		base64.RawURLEncoding.EncodeToString(pJSON) + ".fakesig"

	_, err := vc.ParseJOSECredential(fakeToken)
	if err == nil || !strings.Contains(err.Error(), "invalid typ header") {
		t.Fatalf("expected rejection of non-vc+jwt typ, got: %v", err)
	}
}

func TestJOSECredential_EnvelopedCredential_Unwrap(t *testing.T) {
	const secpPriv = "57600b3f2b7e1054094e14cd85c72a40dc74c4ee062bb381cea604b55ce56aec"
	const did = "did:example:jose-enveloped"

	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did,
		vmpkg.NewSecp256k1VM(did, "key-1", pubHex(t, secpPriv))))

	cred, err := vc.NewJOSECredential(joseContents(did),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new jose cred: %v", err)
	}
	p, _ := signer.NewDefaultProvider(secpPriv)
	if err := cred.AddProofByProvider(p); err != nil {
		t.Fatalf("add proof: %v", err)
	}

	serialized, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	// Create EnvelopedVerifiableCredential JSON
	enveloped := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"EnvelopedVerifiableCredential"},
		"id":       fmt.Sprintf("data:application/vc+jwt,%s", serialized.(string)),
	}
	envJSON, err := json.Marshal(enveloped)
	if err != nil {
		t.Fatalf("marshal enveloped: %v", err)
	}

	// ParseCredential should auto-unwrap data:application/vc+jwt
	parsed, err := vc.ParseCredential(envJSON, vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("ParseCredential on enveloped VC error: %v", err)
	}
	if parsed.GetType() != "JOSE" {
		t.Fatalf("parsed type = %q, want 'JOSE'", parsed.GetType())
	}
	if err := parsed.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify unpacked credential: %v", err)
	}
}


