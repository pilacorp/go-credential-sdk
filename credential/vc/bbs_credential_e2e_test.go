package vc_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/mr-tron/base58"

	"github.com/pilacorp/go-credential-sdk/credential/common/bbs"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

const bbsIssuerDID = "did:example:bbs-issuer"

type fakeBBSSigner struct {
	publicKey []byte
	signature []byte
}

func (s *fakeBBSSigner) Sign(header []byte, messages [][]byte) ([]byte, error) {
	if len(header) == 0 {
		return nil, fmt.Errorf("missing header")
	}
	if len(messages) == 0 {
		return nil, fmt.Errorf("missing messages")
	}
	return append([]byte{}, s.signature...), nil
}

func (s *fakeBBSSigner) PublicKey() []byte {
	return append([]byte{}, s.publicKey...)
}

type fakeBBSEngine struct {
	publicKey              []byte
	lastPresentationHeader []byte
}

func (b *fakeBBSEngine) Verify(publicKey, signature, header []byte, messages [][]byte) error {
	if string(publicKey) != string(b.publicKey) {
		return fmt.Errorf("unexpected public key")
	}
	if len(signature) == 0 || len(header) == 0 || len(messages) == 0 {
		return fmt.Errorf("missing base verify inputs")
	}
	return nil
}

func (b *fakeBBSEngine) ProofGen(publicKey, signature, header, presentationHeader []byte, messages [][]byte, disclosedIndexes []int) ([]byte, error) {
	if string(publicKey) != string(b.publicKey) {
		return nil, fmt.Errorf("unexpected public key")
	}
	if len(signature) == 0 || len(header) == 0 || len(messages) == 0 {
		return nil, fmt.Errorf("missing proof-gen inputs")
	}
	b.lastPresentationHeader = append([]byte{}, presentationHeader...)
	return []byte("derived-proof"), nil
}

func (b *fakeBBSEngine) ProofVerify(publicKey, proof, header, presentationHeader []byte, disclosedMessages [][]byte, disclosedIndexes []int) error {
	if string(publicKey) != string(b.publicKey) {
		return fmt.Errorf("unexpected public key")
	}
	if string(proof) != "derived-proof" {
		return fmt.Errorf("unexpected derived proof")
	}
	if len(header) == 0 || len(disclosedMessages) == 0 || len(disclosedIndexes) == 0 {
		return fmt.Errorf("missing proof-verify inputs")
	}
	return nil
}

func bbsCredentialJSON() []byte {
	return []byte(fmt.Sprintf(`{
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        {"@vocab": "https://example.org/vocab#"}
      ],
      "id": "urn:uuid:bbs-e2e-001",
      "type": ["VerifiableCredential", "IdentityCredential"],
      "issuer": %q,
      "validFrom": "2026-01-01T00:00:00Z",
      "credentialSubject": {
        "id": "did:example:subject",
        "name": "Nguyen Van A",
        "email": "a@example.vn",
        "nationalID": "0123456789"
      }
    }`, bbsIssuerDID))
}

func bbsComplexCredentialJSON() []byte {
	return []byte(fmt.Sprintf(`{
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
	}`, bbsIssuerDID))
}

func TestBBSEndToEnd_IssueDeriveVerify(t *testing.T) {
	pubKey := []byte("bbs-public-key")
	signer := &fakeBBSSigner{
		publicKey: pubKey,
		signature: []byte("bbs-signature"),
	}
	engine := &fakeBBSEngine{publicKey: pubKey}

	resolver := verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument(
			bbsIssuerDID,
			verificationmethod.NewBLS12381G2VM(
				bbsIssuerDID,
				"key-1",
				"z"+base58.Encode(pubKey),
			),
		),
	)

	base, err := vc.ParseBBSCredential(bbsCredentialJSON())
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	if err := base.AddProofByProvider(
		signer,
		[]string{"issuer"},
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(resolver),
	); err != nil {
		t.Fatalf("add base proof: %v", err)
	}
	if err := base.Verify(vc.WithResolver(resolver), vc.WithBBSEngine(engine)); err != nil {
		t.Fatalf("verify base proof: %v", err)
	}

	derived, err := base.Derive([]string{"credentialSubject.name"}, vc.WithBBSEngine(engine))
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

	parsed, err := vc.ParseJSONCredential(raw)
	if err != nil {
		t.Fatalf("parse derived json: %v", err)
	}
	if got := parsed.ExtractField("credentialSubject.name"); got != "Nguyen Van A" {
		t.Fatalf("revealed name = %v", got)
	}
	if got := parsed.ExtractField("credentialSubject.email"); got != nil {
		t.Fatalf("email should be hidden, got %v", got)
	}
}

func TestBBSEndToEnd_DeriveWithPresentationHeaderAndVP(t *testing.T) {
	pubKey := []byte("bbs-public-key")
	signerBBS := &fakeBBSSigner{
		publicKey: pubKey,
		signature: []byte("bbs-signature"),
	}
	engine := &fakeBBSEngine{publicKey: pubKey}

	resolver := verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument(
			bbsIssuerDID,
			verificationmethod.NewBLS12381G2VM(
				bbsIssuerDID,
				"key-1",
				"z"+base58.Encode(pubKey),
			),
		),
		didDocFor(t, e2eHolderDID, e2eHolderPriv),
	)

	base, err := vc.ParseBBSCredential(bbsCredentialJSON())
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	if err := base.AddProofByProvider(
		signerBBS,
		[]string{"issuer"},
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(resolver),
	); err != nil {
		t.Fatalf("add base proof: %v", err)
	}

	presentationHeader := []byte("holder-binding")
	derived, err := base.Derive(
		[]string{"credentialSubject.name"},
		vc.WithBBSEngine(engine),
		vc.WithBBSPresentationHeader(presentationHeader),
	)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if string(engine.lastPresentationHeader) != string(presentationHeader) {
		t.Fatalf("presentation header = %q, want %q", engine.lastPresentationHeader, presentationHeader)
	}

	var derivedMap map[string]interface{}
	serialized, err := derived.Serialize()
	if err != nil {
		t.Fatalf("serialize derived: %v", err)
	}
	rawDerived, err := json.Marshal(serialized)
	if err != nil {
		t.Fatalf("marshal derived: %v", err)
	}
	if err := json.Unmarshal(rawDerived, &derivedMap); err != nil {
		t.Fatalf("unmarshal derived: %v", err)
	}

	vpDoc := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"id":                   "urn:uuid:bbs-vp-001",
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               e2eHolderDID,
		"verifiableCredential": []interface{}{derivedMap},
	}
	vpBytes, err := json.Marshal(vpDoc)
	if err != nil {
		t.Fatalf("marshal vp: %v", err)
	}

	presentation, err := vp.ParseJSONPresentation(vpBytes)
	if err != nil {
		t.Fatalf("parse presentation: %v", err)
	}
	holderSigner, err := signer.NewDefaultProvider(e2eHolderPriv)
	if err != nil {
		t.Fatalf("holder signer: %v", err)
	}
	if err := presentation.AddProofByProvider(
		holderSigner,
		vp.WithVerificationMethodKey("key-1"),
		vp.WithResolver(resolver),
	); err != nil {
		t.Fatalf("sign presentation: %v", err)
	}
	if err := presentation.Verify(vp.WithResolver(resolver), vp.WithBBSEngine(engine)); err != nil {
		t.Fatalf("verify presentation: %v", err)
	}
}

func TestBBSZKryptiumEndToEnd_IssueDeriveVerifyAndVP(t *testing.T) {
	signerBBS, err := bbs.NewZKryptiumSignerFromPrivateKeyHex("66d36e118832af4c5e28b2dfe1b9577857e57b042a33e06bdea37b811ed09ee0")
	if err != nil {
		t.Fatalf("zkryptium signer: %v", err)
	}
	engine := bbs.NewZKryptiumEngine()
	publicKeyMultibase := bbs.EncodePublicKeyMultibase(signerBBS.PublicKey())

	resolver := verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument(
			bbsIssuerDID,
			verificationmethod.NewBLS12381G2VM(
				bbsIssuerDID,
				"key-1",
				publicKeyMultibase,
			),
		),
		didDocFor(t, e2eHolderDID, e2eHolderPriv),
	)

	base, err := vc.ParseBBSCredential(bbsCredentialJSON())
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	if err := base.AddProofByProvider(
		signerBBS,
		[]string{"issuer"},
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(resolver),
	); err != nil {
		t.Fatalf("add base proof: %v", err)
	}
	if err := base.Verify(vc.WithResolver(resolver), vc.WithBBSEngine(engine)); err != nil {
		t.Fatalf("verify base proof: %v", err)
	}

	presentationHeader := []byte("holder-binding-real")
	derived, err := base.Derive(
		[]string{"credentialSubject.name"},
		vc.WithBBSEngine(engine),
		vc.WithBBSPresentationHeader(presentationHeader),
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
	rawDerived, err := json.Marshal(serialized)
	if err != nil {
		t.Fatalf("marshal derived: %v", err)
	}
	parsed, err := vc.ParseJSONCredential(rawDerived)
	if err != nil {
		t.Fatalf("parse derived json: %v", err)
	}
	if got := parsed.ExtractField("credentialSubject.name"); got != "Nguyen Van A" {
		t.Fatalf("revealed name = %v", got)
	}
	if got := parsed.ExtractField("credentialSubject.email"); got != nil {
		t.Fatalf("email should be hidden, got %v", got)
	}

	var derivedMap map[string]interface{}
	if err := json.Unmarshal(rawDerived, &derivedMap); err != nil {
		t.Fatalf("unmarshal derived: %v", err)
	}
	vpDoc := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"id":                   "urn:uuid:bbs-vp-real-001",
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               e2eHolderDID,
		"verifiableCredential": []interface{}{derivedMap},
	}
	vpBytes, err := json.Marshal(vpDoc)
	if err != nil {
		t.Fatalf("marshal vp: %v", err)
	}
	presentation, err := vp.ParseJSONPresentation(vpBytes)
	if err != nil {
		t.Fatalf("parse presentation: %v", err)
	}
	holderSigner, err := signer.NewDefaultProvider(e2eHolderPriv)
	if err != nil {
		t.Fatalf("holder signer: %v", err)
	}
	if err := presentation.AddProofByProvider(
		holderSigner,
		vp.WithVerificationMethodKey("key-1"),
		vp.WithResolver(resolver),
	); err != nil {
		t.Fatalf("sign presentation: %v", err)
	}
	if err := presentation.Verify(vp.WithResolver(resolver), vp.WithBBSEngine(engine)); err != nil {
		t.Fatalf("verify presentation: %v", err)
	}
}

func TestBBSZKryptiumEndToEnd_ComplexExampleDerivedVerify(t *testing.T) {
	signerBBS, err := bbs.NewZKryptiumSignerFromPrivateKeyHex("66d36e118832af4c5e28b2dfe1b9577857e57b042a33e06bdea37b811ed09ee0")
	if err != nil {
		t.Fatalf("zkryptium signer: %v", err)
	}
	engine := bbs.NewZKryptiumEngine()
	publicKeyMultibase := bbs.EncodePublicKeyMultibase(signerBBS.PublicKey())

	resolver := verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument(
			bbsIssuerDID,
			verificationmethod.NewBLS12381G2VM(
				bbsIssuerDID,
				"key-1",
				publicKeyMultibase,
			),
		),
	)

	base, err := vc.ParseBBSCredential(bbsComplexCredentialJSON())
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	if err := base.AddProofByProvider(
		signerBBS,
		[]string{"issuer", "validFrom", "credentialSubject.id"},
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(resolver),
	); err != nil {
		t.Fatalf("add base proof: %v", err)
	}
	if err := base.Verify(vc.WithResolver(resolver), vc.WithBBSEngine(engine)); err != nil {
		t.Fatalf("verify base proof: %v", err)
	}
	serializedBase, err := base.Serialize()
	if err != nil {
		t.Fatalf("serialize base: %v", err)
	}
	if _, err := json.MarshalIndent(serializedBase, "", "  "); err != nil {
		t.Fatalf("marshal base: %v", err)
	}

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
		t.Fatalf("derive: %v", err)
	}
	if err := derived.Verify(vc.WithResolver(resolver), vc.WithBBSEngine(engine)); err != nil {
		t.Fatalf("verify derived proof: %v", err)
	}
}
