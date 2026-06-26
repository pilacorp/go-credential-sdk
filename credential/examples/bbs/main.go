// Command bbs prints an issued VC (base proof) and a derived VC (selective
// disclosure) using the bbs-2023 cryptosuite.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/pilacorp/go-credential-sdk/credential/common/bbs"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

const issuerDID = "did:example:bbs-issuer"

func main() {
	privHex := os.Getenv("BBS_ISSUER_PRIV_HEX")
	if privHex == "" {
		// Same key used in vc/bbs_credential_e2e_test.go for convenience.
		privHex = "66d36e118832af4c5e28b2dfe1b9577857e57b042a33e06bdea37b811ed09ee0"
	}

	issuerSigner, err := bbs.NewZKryptiumSignerFromPrivateKeyHex(privHex)
	if err != nil {
		log.Fatalf("bbs signer: %v", err)
	}
	engine := bbs.NewZKryptiumEngine()

	// Build an offline DID resolver for the issuer's BLS12-381 G2 key.
	publicKeyMultibase := bbs.EncodePublicKeyMultibase(issuerSigner.PublicKey())
	resolver := verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument(
			issuerDID,
			verificationmethod.NewBLS12381G2VM(issuerDID, "key-1", publicKeyMultibase),
		),
	)

	// Unsigned VC (JSON-LD). Keep contexts consistent with the ECDSA-SD example:
	// - credentials/v2 core context
	// - credentials/examples/v2 for common examples vocabulary
	raw := []byte(fmt.Sprintf(`{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "urn:uuid:bbs-example-001",
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
	base, err := vc.ParseBBSCredential(raw)
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
	if err := base.Verify(vc.WithResolver(resolver), vc.WithBBSEngine(engine)); err != nil {
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

	fmt.Println("=== VC (BBS-2023) - BASE PROOF ===")
	fmt.Println(string(basePretty))
	fmt.Println()

	// Derive (selective disclosure). Note: BBS derive needs a engine.
	derived, err := base.Derive(
		[]string{
			"credentialSubject.name",
			"credentialSubject.dob",
			"credentialSubject.address.city",
			"credentialSubject.employment.company.name",
		},
		vc.WithBBSEngine(engine),
		vc.WithBBSPresentationHeader([]byte("holder-binding-real")),
	)
	if err != nil {
		log.Fatalf("derive: %v", err)
	}
	if err := derived.Verify(vc.WithResolver(resolver), vc.WithBBSEngine(engine)); err != nil {
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

	fmt.Println("=== VC (BBS-2023) - DERIVED PROOF ===")
	fmt.Println(string(derivedPretty))
}

