package vc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	jwtpkg "github.com/pilacorp/go-credential-sdk/credential/common/jwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// A VC 1.1 token carries two time windows in two places. validFrom/validUntil
// sit inside the vc claim and describe the credential; exp/nbf sit beside it, at
// the top level, and describe the token. NewJWTCredential writes both — exp from
// ValidUntil, nbf from ValidFrom — but WithCheckExpiration only ever read the
// inner pair, so a token past its own exp verified.
//
// The pairs are written separately here so each one stands alone: a credential
// whose exp has passed but whose validUntil has not is exactly the case the old
// check could not see.
func TestJWTCredential_ChecksExpAndNbf(t *testing.T) {
	const did = "did:example:jwt-time"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	vmEntry := mustP256VM(t, did, "key-1", &priv.PublicKey)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vmEntry))
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	now := time.Now()

	for _, tc := range []struct {
		name    string
		claims  map[string]interface{} // top-level claims beside the vc claim
		wantErr string
	}{
		{
			name:   "inside both windows",
			claims: map[string]interface{}{"nbf": now.Add(-time.Hour).Unix(), "exp": now.Add(time.Hour).Unix()},
		},
		{
			// The case the inner pair cannot see: the credential is still valid,
			// the token signing it is not.
			name:    "exp has passed while validUntil has not",
			claims:  map[string]interface{}{"exp": now.Add(-time.Hour).Unix()},
			wantErr: "expired",
		},
		{
			name:    "nbf is in the future",
			claims:  map[string]interface{}{"nbf": now.Add(time.Hour).Unix()},
			wantErr: "not valid before",
		},
		{
			name:   "no time claims at all",
			claims: map[string]interface{}{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]interface{}{
				"iss": did,
				"vc": map[string]interface{}{
					"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
					"type":              []interface{}{"VerifiableCredential"},
					"issuer":            did,
					"issuanceDate":      now.Add(-24 * time.Hour).Format(time.RFC3339),
					"expirationDate":    now.Add(24 * time.Hour).Format(time.RFC3339),
					"credentialSubject": map[string]interface{}{"id": "did:example:subject"},
				},
			}
			for k, v := range tc.claims {
				payload[k] = v
			}

			header, err := json.Marshal(map[string]interface{}{"typ": "JWT", "alg": "ES256", "kid": vmEntry.ID})
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

			parsed, err := vc.ParseJWTCredential(signingInput+"."+sig, vc.WithResolver(resolver))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			// Without the option nothing about time is checked, here as before.
			if err := parsed.Verify(vc.WithResolver(resolver)); err != nil {
				t.Fatalf("a plain Verify must not look at time claims: %v", err)
			}

			err = parsed.Verify(vc.WithResolver(resolver), vc.WithCheckExpiration())
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("a token inside its window was refused: %v", err)
				}

				return
			}
			if err == nil {
				t.Fatal("a token outside its own time claims was accepted")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one mentioning %q", err, tc.wantErr)
			}
		})
	}
}

// NewJOSECredential and ParseJOSECredential now run the same check, so the SDK
// cannot sign a document its own verifier refuses.
//
// serializeCredentialContents already caught a missing type, issuer or
// credentialSubject. The gap was a type that exists without naming
// VerifiableCredential: that signed cleanly and failed at the far end, where the
// error reaches whoever received the credential rather than whoever made it.
func TestNewJOSECredential_RefusesWhatParseWouldRefuse(t *testing.T) {
	const did = "did:example:jose-build-shape"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, mustP256VM(t, did, "key-1", &priv.PublicKey)))

	contents := func() vc.CredentialContents {
		return vc.CredentialContents{
			Context:   []interface{}{"https://www.w3.org/ns/credentials/v2"},
			Types:     []string{"VerifiableCredential"},
			Issuer:    did,
			ValidFrom: time.Now().Add(-time.Hour),
			Subject:   []vc.Subject{{ID: "did:example:subject"}},
		}
	}

	for _, tc := range []struct {
		name    string
		types   []string
		wantErr string
	}{
		{name: "a credential", types: []string{"VerifiableCredential"}},
		{name: "a credential with extra types", types: []string{"VerifiableCredential", "AlumniCredential"}},
		{name: "a custom type alone", types: []string{"AlumniCredential"}, wantErr: "must include VerifiableCredential"},
		{name: "a presentation type", types: []string{"VerifiablePresentation"}, wantErr: "must include VerifiableCredential"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := contents()
			c.Types = tc.types

			_, err := vc.NewJOSECredential(c, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("a well-formed credential was refused: %v", err)
				}

				return
			}
			if err == nil {
				t.Fatal("a document its own verifier refuses was signed")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one mentioning %q", err, tc.wantErr)
			}
		})
	}
}
