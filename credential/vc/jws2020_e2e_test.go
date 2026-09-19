package vc_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
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

func dtoProofFromSerialized(t *testing.T, serialized any) *dto.Proof {
	t.Helper()
	m, ok := serialized.(map[string]interface{})
	if !ok {
		t.Fatalf("serialized type %T", serialized)
	}
	raw, err := json.Marshal(m["proof"])
	if err != nil {
		t.Fatalf("marshal proof: %v", err)
	}
	var proofs []dto.Proof
	if err := json.Unmarshal(raw, &proofs); err == nil && len(proofs) > 0 {
		p := proofs[0]
		return &p
	}
	var p dto.Proof
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("unmarshal proof: %v", err)
	}
	return &p
}

func proofFieldJSON(t *testing.T, cred *vc.JSONCredential) []byte {
	t.Helper()
	b, err := json.Marshal(cred.ExtractField("proof"))
	if err != nil {
		t.Fatalf("marshal proof field: %v", err)
	}
	return b
}

func garbageJSONProof(vm string) *dto.Proof {
	return &dto.Proof{
		Type:               "DataIntegrityProof",
		Created:            "2024-01-01T00:00:00Z",
		VerificationMethod: vm,
		ProofPurpose:       "assertionMethod",
		Cryptosuite:        "ecdsa-rdfc-2019",
		ProofValue:         "deadbeef",
	}
}

func TestJSONAddCustomProof_WithVerifyProof(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa key: %v", err)
	}
	resolver := &memResolver{docs: map[string]*verificationmethod.DIDDocument{
		jwsIssuerDID: rsaJWKDIDDoc(t, jwsIssuerDID, &priv.PublicKey),
	}}
	rsaProvider, err := signer.NewRSAProvider(priv)
	if err != nil {
		t.Fatalf("rsa provider: %v", err)
	}

	signCopy := func(t *testing.T) *dto.Proof {
		t.Helper()
		copyCred, err := vc.ParseJSONCredential(jwsCredentialJSON())
		if err != nil {
			t.Fatalf("parse copy: %v", err)
		}
		if err := copyCred.AddProofByProvider(
			rsaProvider,
			vc.WithVerificationMethodKey("key-1"),
			vc.WithResolver(resolver),
		); err != nil {
			t.Fatalf("sign copy: %v", err)
		}
		serialized, err := copyCred.Serialize()
		if err != nil {
			t.Fatalf("serialize copy: %v", err)
		}
		return dtoProofFromSerialized(t, serialized)
	}

	t.Run("fresh document + valid proof + WithVerifyProof attaches and verifies", func(t *testing.T) {
		cred, err := vc.ParseJSONCredential(jwsCredentialJSON())
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := cred.AddCustomProof(signCopy(t), vc.WithVerifyProof(), vc.WithResolver(resolver)); err != nil {
			t.Fatalf("AddCustomProof: %v", err)
		}
		if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})

	t.Run("garbage proof + WithVerifyProof refused, document unchanged", func(t *testing.T) {
		cred, err := vc.ParseJSONCredential(jwsCredentialJSON())
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		before := proofFieldJSON(t, cred)
		err = cred.AddCustomProof(garbageJSONProof(jwsIssuerDID+"#key-1"), vc.WithVerifyProof(), vc.WithResolver(resolver))
		if err == nil {
			t.Fatal("expected AddCustomProof to refuse a garbage proof")
		}
		after := proofFieldJSON(t, cred)
		if string(before) != string(after) {
			t.Fatalf("proof field changed on failure: before=%s after=%s", before, after)
		}
	})

	t.Run("no option attaches unverified", func(t *testing.T) {
		cred, err := vc.ParseJSONCredential(jwsCredentialJSON())
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := cred.AddCustomProof(garbageJSONProof(jwsIssuerDID + "#key-1")); err != nil {
			t.Fatalf("AddCustomProof without verify: %v", err)
		}
		if cred.ExtractField("proof") == nil {
			t.Fatal("expected proof field after unverified attach")
		}
	})

	t.Run("existing valid proof + garbage + WithVerifyProof refused", func(t *testing.T) {
		cred, err := vc.ParseJSONCredential(jwsCredentialJSON())
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := cred.AddCustomProof(signCopy(t)); err != nil {
			t.Fatalf("attach valid: %v", err)
		}
		if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
			t.Fatalf("verify valid: %v", err)
		}
		before := proofFieldJSON(t, cred)
		err = cred.AddCustomProof(garbageJSONProof(jwsIssuerDID+"#key-1"), vc.WithVerifyProof(), vc.WithResolver(resolver))
		if err == nil {
			t.Fatal("expected AddCustomProof to refuse garbage on top of a valid proof")
		}
		after := proofFieldJSON(t, cred)
		if string(before) != string(after) {
			t.Fatalf("proof field changed on failure: before=%s after=%s", before, after)
		}
	})
}
