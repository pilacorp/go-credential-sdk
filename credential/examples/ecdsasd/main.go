// Command ecdsasd prints an issued VC (base proof) and a derived VC (selective
// disclosure) using the ecdsa-sd-2023 cryptosuite.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

const issuerDID = "did:example:issuer"

// memResolver is an offline ResolverProvider (no network calls).
type memResolver struct {
	docs map[string]*verificationmethod.DIDDocument
}

func (r *memResolver) ResolveDocument(_ context.Context, did string) (*verificationmethod.DIDDocument, error) {
	if doc, ok := r.docs[did]; ok {
		return doc, nil
	}
	return nil, fmt.Errorf("unknown did: %s", did)
}

// p256JWKDIDDoc exposes the issuer P-256 public key as JsonWebKey2020 VM, which
// is what ecdsa-sd-2023 verification expects.
func p256JWKDIDDoc(did string, pub *ecdsa.PublicKey) *verificationmethod.DIDDocument {
	vmID := did + "#key-1"
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	pub.X.FillBytes(xb)
	pub.Y.FillBytes(yb)
	return &verificationmethod.DIDDocument{
		ID: did,
		VerificationMethod: []verificationmethod.VerificationMethodEntry{{
			ID:         vmID,
			Type:       "JsonWebKey2020",
			Controller: did,
			PublicKeyJwk: &verificationmethod.JWK{
				Kty: "EC",
				Crv: "P-256",
				X:   base64.RawURLEncoding.EncodeToString(xb),
				Y:   base64.RawURLEncoding.EncodeToString(yb),
			},
		}},
		AssertionMethod: []string{vmID},
		Authentication:  []string{vmID},
	}
}

func main() {
	issuerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate issuer p256: %v", err)
	}
	resolver := &memResolver{
		docs: map[string]*verificationmethod.DIDDocument{
			issuerDID: p256JWKDIDDoc(issuerDID, &issuerPriv.PublicKey),
		},
	}

	issuerSigner, err := signer.NewP256Provider(issuerPriv)
	if err != nil {
		log.Fatalf("issuer signer: %v", err)
	}

	// Unsigned VC (JSON-LD).
	raw := []byte(fmt.Sprintf(`{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "urn:uuid:ecdsasd-example-001",
  "type": ["VerifiableCredential", "IdentityCredential"],
  "issuer": %q,
  "validFrom": "2026-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:subject",
    "name": "Nguyen Van A",
    "dob": "1990-01-01",
    "email": "a@example.vn",
    "nationalID": "0123456789",
    "address": {
      "street": "123 Nguyen Trai",
      "ward": "Ward 1",
      "district": "District 5",
      "city": "Ho Chi Minh City",
      "country": "VN"
    },
    "employment": {
      "company": {
        "name": "Pila Corp",
        "taxCode": "0300000000"
      },
      "title": "Software Engineer",
      "startDate": "2024-03-01"
    },
    "contacts": {
      "phones": ["+84-901-000-001", "+84-901-000-002"],
      "social": {
        "telegram": "@nguyenvana",
        "zalo": "nguyenvana"
      }
    }
  }
}`, issuerDID))

	// Issue base proof.
	base, err := vc.ParseECDSASDCredential(raw)
	if err != nil {
		log.Fatalf("parse credential: %v", err)
	}
	if err := base.AddProofByProvider(
		issuerSigner,
		[]string{"issuer", "validFrom", "credentialSubject.id"},
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(resolver),
	); err != nil {
		log.Fatalf("add base proof: %v", err)
	}
	if err := base.Verify(vc.WithResolver(resolver)); err != nil {
		log.Fatalf("verify base proof: %v", err)
	}
	baseSerialized, err := base.Serialize()
	if err != nil {
		log.Fatalf("serialize base: %v", err)
	}
	basePretty, err := json.MarshalIndent(baseSerialized, "", "  ")
	if err != nil {
		log.Fatalf("marshal base: %v", err)
	}

	fmt.Println("=== VC (ECDSA-SD-2023) - BASE PROOF ===")
	fmt.Println(string(basePretty))
	fmt.Println()

	// Derive (selective disclosure).
	derived, err := base.Derive([]string{
		"credentialSubject.name",
		"credentialSubject.dob",
		"credentialSubject.address.city",
		"credentialSubject.employment.company.name",
	})
	if err != nil {
		log.Fatalf("derive: %v", err)
	}
	if err := derived.Verify(vc.WithResolver(resolver)); err != nil {
		log.Fatalf("verify derived proof: %v", err)
	}
	derivedSerialized, err := derived.Serialize()
	if err != nil {
		log.Fatalf("serialize derived: %v", err)
	}
	derivedPretty, err := json.MarshalIndent(derivedSerialized, "", "  ")
	if err != nil {
		log.Fatalf("marshal derived: %v", err)
	}

	fmt.Println("=== VC (ECDSA-SD-2023) - DERIVED PROOF ===")
	fmt.Println(string(derivedPretty))
}

