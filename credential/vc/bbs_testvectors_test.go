package vc_test

import (
	"encoding/json"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/bbs"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// Test vectors from the reference bbs-2023 implementation
// (digitalbazaar/bbs-2023-cryptosuite, test/mock-data.js). The key pair below is
// the canonical interop key pair: the secret key, when loaded, MUST derive the
// published BLS12-381 G2 public key. The documents are the reference selective
// disclosure fixtures.
const (
	refSecretKeyHex        = "2de16718da397c2b021e4ebe08e76353b5799fefe4f3a31262800914b8633a58"
	refPublicKeyMultibase  = "zUC76eySqgji6uNDaCrsWnmQnwq8pj1MZUDrRGc2BGRu61baZPKPFB7YpHawussp2YohcEMAeMVGHQ9JtKvjxgGTkYSMN53ZfCH4pZ6TGYLawvzy1wE54dS6PQcut9fxdHH32gi"
)

// refAchievementCredential is the reference achievement credential: no node
// identifiers anywhere, so credentialSubject and every nested achievement, sail
// and board is a blank node. It is the canonical fixture that stresses
// blank-node label canonicalization and ordering in selective disclosure.
func refAchievementCredential() []byte {
	return []byte(`{
	  "@context": [
	    "https://www.w3.org/ns/credentials/v2",
	    "https://www.w3.org/ns/credentials/examples/v2"
	  ],
	  "type": ["VerifiableCredential", "ExampleAchievementCredential"],
	  "issuer": "` + bbsIssuerDID + `",
	  "validFrom": "2023-06-01T09:25:48Z",
	  "validUntil": "2024-06-01T09:25:48Z",
	  "credentialSubject": {
	    "name": "Jane Doe",
	    "achievements": [
	      {
	        "type": "WindsailingAchievement",
	        "sailNumber": "Earth101",
	        "sails": [
	          {"size": 5.5, "sailName": "Osprey", "year": 2023},
	          {"size": 6.1, "sailName": "Eagle-FR", "year": 2023},
	          {"size": 7.0, "sailName": "Eagle-FR", "year": 2020},
	          {"size": 7.8, "sailName": "Eagle-FR", "year": 2023}
	        ],
	        "boards": [
	          {"boardName": "CompFoil170", "brand": "Tillo", "year": 2022},
	          {"boardName": "Tillo Custom", "brand": "Tillo", "year": 2019}
	        ]
	      },
	      {
	        "type": "WindsailingAchievement",
	        "sailNumber": "Mars101",
	        "sails": [
	          {"size": 5.9, "sailName": "Chicken", "year": 2022},
	          {"size": 4.9, "sailName": "Vulture-FR", "year": 2023},
	          {"size": 6.8, "sailName": "Vulture-FR", "year": 2020},
	          {"size": 7.7, "sailName": "Vulture-FR", "year": 2023}
	        ],
	        "boards": [
	          {"boardName": "Oak620", "brand": "Excite", "year": 2020},
	          {"boardName": "Excite Custom", "brand": "Excite", "year": 2018}
	        ]
	      }
	    ]
	  }
	}`)
}

// TestBBSReferenceKeyPairVector checks that loading the reference secret key
// derives exactly the published public key, and that the multibase codec round
// trips. This is a deterministic interop check that needs no proof randomness.
func TestBBSReferenceKeyPairVector(t *testing.T) {
	signerBBS, err := bbs.NewZKryptiumSignerFromPrivateKeyHex(refSecretKeyHex)
	if err != nil {
		t.Fatalf("zkryptium signer: %v", err)
	}

	got := bbs.EncodePublicKeyMultibase(signerBBS.PublicKey())
	if got != refPublicKeyMultibase {
		t.Fatalf("derived public key multibase mismatch\n got: %s\nwant: %s", got, refPublicKeyMultibase)
	}

	decoded, err := bbs.DecodePublicKeyMultibase(refPublicKeyMultibase)
	if err != nil {
		t.Fatalf("decode public key multibase: %v", err)
	}
	if reencoded := bbs.EncodePublicKeyMultibase(decoded); reencoded != refPublicKeyMultibase {
		t.Fatalf("multibase round trip mismatch\n got: %s\nwant: %s", reencoded, refPublicKeyMultibase)
	}
}

// TestBBSReferenceSelectiveDisclosure issues a base proof over the reference
// achievement credential (deeply nested blank nodes), derives a proof revealing
// only the holder name and the first achievement's sail number, and verifies it.
// It asserts the revealed document keeps the disclosed fields and drops the rest.
func TestBBSReferenceSelectiveDisclosure(t *testing.T) {
	signerBBS, err := bbs.NewZKryptiumSignerFromPrivateKeyHex(refSecretKeyHex)
	if err != nil {
		t.Fatalf("zkryptium signer: %v", err)
	}
	engine := bbs.NewZKryptiumEngine()

	resolver := verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument(
			bbsIssuerDID,
			verificationmethod.NewBLS12381G2VM(
				bbsIssuerDID,
				"key-1",
				bbs.EncodePublicKeyMultibase(signerBBS.PublicKey()),
			),
		),
	)

	base, err := vc.ParseBBSCredential(refAchievementCredential())
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	if err := base.AddProofByProvider(
		signerBBS,
		[]string{"issuer", "validFrom", "validUntil"},
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(resolver),
	); err != nil {
		t.Fatalf("add base proof: %v", err)
	}
	if err := base.Verify(vc.WithResolver(resolver), vc.WithBBSEngine(engine)); err != nil {
		t.Fatalf("verify base proof: %v", err)
	}

	derived, err := base.Derive(
		[]string{
			"credentialSubject.name",
			"credentialSubject.achievements.0.sailNumber",
		},
		vc.WithBBSEngine(engine),
		vc.WithBBSPresentationHeader([]byte("reference-holder-binding")),
	)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if err := derived.Verify(vc.WithResolver(resolver), vc.WithBBSEngine(engine)); err != nil {
		t.Fatalf("verify derived proof: %v", err)
	}

	serialized, err := derived.Serialize()
	if err != nil {
		t.Fatalf("serialize derived: %v", err)
	}
	raw, err := json.Marshal(serialized)
	if err != nil {
		t.Fatalf("marshal derived: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal derived: %v", err)
	}
	subject, ok := doc["credentialSubject"].(map[string]interface{})
	if !ok {
		t.Fatalf("credentialSubject missing, got %T", doc["credentialSubject"])
	}
	if subject["name"] != "Jane Doe" {
		t.Fatalf("name = %v, want disclosed", subject["name"])
	}
	achievements, ok := subject["achievements"].([]interface{})
	if !ok || len(achievements) == 0 {
		t.Fatalf("achievements missing, got %T", subject["achievements"])
	}
	first, ok := achievements[0].(map[string]interface{})
	if !ok {
		t.Fatalf("achievement[0] not an object, got %T", achievements[0])
	}
	if first["sailNumber"] != "Earth101" {
		t.Fatalf("sailNumber = %v, want disclosed", first["sailNumber"])
	}
	if _, ok := first["sails"]; ok {
		t.Fatalf("sails should be hidden, got %v", first["sails"])
	}
}
