package vc_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

const jwsIssuerDID = "did:example:jws-issuer"

func rsaJWKDIDDoc(t *testing.T, did string, pub *rsa.PublicKey) *verificationmethod.DIDDocument {
	t.Helper()
	vmID := did + "#key-1"
	return &verificationmethod.DIDDocument{
		ID: did,
		VerificationMethod: []verificationmethod.VerificationMethodEntry{{
			ID:         vmID,
			Type:       "JsonWebKey2020",
			Controller: did,
			PublicKeyJwk: &verificationmethod.JWK{
				Kty: "RSA",
				N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		}},
		AssertionMethod: []string{vmID},
		Authentication:  []string{vmID},
	}
}

func jwsCredentialJSON() []byte {
	return []byte(fmt.Sprintf(`{
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        {"@vocab": "https://example.org/vocab#"}
      ],
      "id": "urn:uuid:jws-e2e-001",
      "type": ["VerifiableCredential", "IdentityCredential"],
      "issuer": %q,
      "validFrom": "2026-01-01T00:00:00Z",
      "credentialSubject": {
        "id": "did:example:subject",
        "name": "Nguyen Van A"
      }
    }`, jwsIssuerDID))
}

func issueJWS(t *testing.T, resolver *memResolver, priv *rsa.PrivateKey) []byte {
	t.Helper()
	rsaProvider, err := signer.NewRSAProvider(priv)
	if err != nil {
		t.Fatalf("rsa provider: %v", err)
	}
	cred, err := vc.ParseJSONCredential(jwsCredentialJSON())
	if err != nil {
		t.Fatalf("parse credential: %v", err)
	}
	if err := cred.AddProofByProvider(
		rsaProvider,
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(resolver),
	); err != nil {
		t.Fatalf("add jws proof: %v", err)
	}
	if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify jws proof: %v", err)
	}
	serialized, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	b, err := json.Marshal(serialized)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestJWS2020EndToEnd_IssueVerify(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa key: %v", err)
	}
	resolver := &memResolver{docs: map[string]*verificationmethod.DIDDocument{
		jwsIssuerDID: rsaJWKDIDDoc(t, jwsIssuerDID, &priv.PublicKey),
	}}

	signedBytes := issueJWS(t, resolver, priv)

	cred, err := vc.ParseJSONCredential(signedBytes)
	if err != nil {
		t.Fatalf("parse signed: %v", err)
	}
	if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify signed: %v", err)
	}
	if got := cred.ExtractField("credentialSubject.name"); got != "Nguyen Van A" {
		t.Errorf("name = %v, want %q", got, "Nguyen Van A")
	}
}

func TestJWS2020EndToEnd_TamperRejected(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa key: %v", err)
	}
	resolver := &memResolver{docs: map[string]*verificationmethod.DIDDocument{
		jwsIssuerDID: rsaJWKDIDDoc(t, jwsIssuerDID, &priv.PublicKey),
	}}
	signedBytes := issueJWS(t, resolver, priv)

	var doc map[string]interface{}
	if err := json.Unmarshal(signedBytes, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cs, ok := doc["credentialSubject"].(map[string]interface{}); ok {
		cs["name"] = "Someone Else"
	}
	tamperedBytes, _ := json.Marshal(doc)

	tampered, err := vc.ParseJSONCredential(tamperedBytes)
	if err != nil {
		t.Fatalf("parse tampered: %v", err)
	}
	if err := tampered.Verify(vc.WithResolver(resolver)); err == nil {
		t.Fatal("tampered credential must not verify")
	}
}

func TestJWS2020EndToEnd_WrongKeyRejected(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa key: %v", err)
	}
	resolver := &memResolver{docs: map[string]*verificationmethod.DIDDocument{
		jwsIssuerDID: rsaJWKDIDDoc(t, jwsIssuerDID, &priv.PublicKey),
	}}
	signedBytes := issueJWS(t, resolver, priv)

	otherPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen other rsa key: %v", err)
	}
	badResolver := &memResolver{docs: map[string]*verificationmethod.DIDDocument{
		jwsIssuerDID: rsaJWKDIDDoc(t, jwsIssuerDID, &otherPriv.PublicKey),
	}}
	cred, err := vc.ParseJSONCredential(signedBytes)
	if err != nil {
		t.Fatalf("parse signed: %v", err)
	}
	if err := cred.Verify(vc.WithResolver(badResolver)); err == nil {
		t.Fatal("credential must not verify against the wrong issuer key")
	}
}
