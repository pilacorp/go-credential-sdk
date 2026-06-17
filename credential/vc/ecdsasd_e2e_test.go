package vc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

const (
	e2eIssuerDID  = "did:example:issuer"
	e2eHolderPriv = "8da4ef21b864d2cc526dbdb2a120bd2874c36c9d0a1fb7f8c63d7f7a8b41de8f"
	e2eHolderDID  = "did:example:holder"
)

// memResolver is an offline ResolverProvider for tests.
type memResolver struct{ docs map[string]*verificationmethod.DIDDocument }

func (r *memResolver) ResolveDocument(_ context.Context, did string) (*verificationmethod.DIDDocument, error) {
	if doc, ok := r.docs[did]; ok {
		return doc, nil
	}
	return nil, fmt.Errorf("unknown did: %s", did)
}

// e2eSetup bundles an offline resolver with the issuer's P-256 key so issuance
// and resolution stay consistent.
type e2eSetup struct {
	resolver   *memResolver
	issuerPriv *ecdsa.PrivateKey
}

func newE2E(t *testing.T) e2eSetup {
	t.Helper()
	issuerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("issuer p256: %v", err)
	}
	resolver := &memResolver{docs: map[string]*verificationmethod.DIDDocument{
		e2eIssuerDID: p256JWKDIDDoc(t, e2eIssuerDID, &issuerPriv.PublicKey),
		e2eHolderDID: didDocFor(t, e2eHolderDID, e2eHolderPriv),
	}}
	return e2eSetup{resolver: resolver, issuerPriv: issuerPriv}
}

// p256JWKDIDDoc builds an issuer DID document exposing a P-256 key as a
// JsonWebKey2020 verification method (the format ecdsa-sd-2023 verification
// expects).
func p256JWKDIDDoc(t *testing.T, did string, pub *ecdsa.PublicKey) *verificationmethod.DIDDocument {
	t.Helper()
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

// didDocFor builds a secp256k1 DID document (used for the holder, who signs the
// VP with ecdsa-rdfc-2019).
func didDocFor(t *testing.T, did, privHex string) *verificationmethod.DIDDocument {
	t.Helper()
	vmID := did + "#key-1"
	return &verificationmethod.DIDDocument{
		ID: did,
		VerificationMethod: []verificationmethod.VerificationMethodEntry{{
			ID:           vmID,
			Type:         "EcdsaSecp256k1VerificationKey2019",
			Controller:   did,
			PublicKeyHex: pubHex(t, privHex),
		}},
		AssertionMethod: []string{vmID},
		Authentication:  []string{vmID},
	}
}

func pubHex(t *testing.T, privHex string) string {
	t.Helper()
	priv, err := crypto.HexToECDSA(privHex)
	if err != nil {
		t.Fatalf("priv: %v", err)
	}
	return hex.EncodeToString(crypto.FromECDSAPub(&priv.PublicKey))
}

func e2eCredentialJSON() []byte {
	return []byte(fmt.Sprintf(`{
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        {"@vocab": "https://example.org/vocab#"}
      ],
      "id": "urn:uuid:sd-e2e-001",
      "type": ["VerifiableCredential", "IdentityCredential"],
      "issuer": %q,
      "validFrom": "2026-01-01T00:00:00Z",
      "credentialSubject": {
        "id": "did:example:subject",
        "name": "Nguyen Van A",
        "dob": "1990-01-01",
        "email": "a@example.vn",
        "nationalID": "0123456789"
      }
    }`, e2eIssuerDID))
}

// issueBase issues a base ecdsa-sd-2023 credential and returns its serialized
// JSON bytes.
func issueBase(t *testing.T, s e2eSetup) []byte {
	t.Helper()
	issuerSigner, err := signer.NewP256Provider(s.issuerPriv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	base, err := vc.ParseECDSASDCredential(e2eCredentialJSON())
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	if err := base.AddProofByProvider(
		issuerSigner,
		[]string{"issuer", "validFrom", "credentialSubject.id"},
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(s.resolver),
	); err != nil {
		t.Fatalf("add base proof: %v", err)
	}
	if err := base.Verify(vc.WithResolver(s.resolver)); err != nil {
		t.Fatalf("verify base proof: %v", err)
	}
	serialized, err := base.Serialize()
	if err != nil {
		t.Fatalf("serialize base: %v", err)
	}
	b, err := json.Marshal(serialized)
	if err != nil {
		t.Fatalf("marshal base: %v", err)
	}
	return b
}

// deriveAndSerialize derives a selective-disclosure credential and returns its
// serialized JSON bytes.
func deriveAndSerialize(t *testing.T, baseBytes []byte, selective []string) []byte {
	t.Helper()
	base, err := vc.ParseECDSASDCredential(baseBytes)
	if err != nil {
		t.Fatalf("parse base for derive: %v", err)
	}
	derived, err := base.Derive(selective)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	serialized, err := derived.Serialize()
	if err != nil {
		t.Fatalf("serialize derived: %v", err)
	}
	b, err := json.Marshal(serialized)
	if err != nil {
		t.Fatalf("marshal derived: %v", err)
	}
	return b
}

func TestECDSASDEndToEnd_IssueDeriveVerify(t *testing.T) {
	s := newE2E(t)

	baseBytes := issueBase(t, s)
	derivedBytes := deriveAndSerialize(t, baseBytes,
		[]string{"credentialSubject.name", "credentialSubject.dob"})

	derived, err := vc.ParseJSONCredential(derivedBytes)
	if err != nil {
		t.Fatalf("parse derived: %v", err)
	}
	if err := derived.Verify(vc.WithResolver(s.resolver)); err != nil {
		t.Fatalf("verify derived: %v", err)
	}

	// Revealed claims present.
	if got := derived.ExtractField("credentialSubject.name"); got != "Nguyen Van A" {
		t.Errorf("revealed name = %v, want %q", got, "Nguyen Van A")
	}
	if got := derived.ExtractField("credentialSubject.dob"); got != "1990-01-01" {
		t.Errorf("revealed dob = %v, want %q", got, "1990-01-01")
	}
	// Mandatory claims present.
	if got := derived.ExtractField("issuer"); got != e2eIssuerDID {
		t.Errorf("issuer = %v, want %q", got, e2eIssuerDID)
	}
	// Hidden claims absent.
	if got := derived.ExtractField("credentialSubject.email"); got != nil {
		t.Errorf("email should be hidden, got %v", got)
	}
	if got := derived.ExtractField("credentialSubject.nationalID"); got != nil {
		t.Errorf("nationalID should be hidden, got %v", got)
	}
}

func TestECDSASDEndToEnd_RevealNothingExtra(t *testing.T) {
	s := newE2E(t)
	baseBytes := issueBase(t, s)

	// Derive revealing only the mandatory set.
	derivedBytes := deriveAndSerialize(t, baseBytes, nil)
	derived, err := vc.ParseJSONCredential(derivedBytes)
	if err != nil {
		t.Fatalf("parse derived: %v", err)
	}
	if err := derived.Verify(vc.WithResolver(s.resolver)); err != nil {
		t.Fatalf("verify mandatory-only derived: %v", err)
	}
	if got := derived.ExtractField("credentialSubject.name"); got != nil {
		t.Errorf("name should be hidden in mandatory-only derivation, got %v", got)
	}
}

func TestECDSASDEndToEnd_TamperRejected(t *testing.T) {
	s := newE2E(t)
	baseBytes := issueBase(t, s)
	derivedBytes := deriveAndSerialize(t, baseBytes, []string{"credentialSubject.name"})

	var doc map[string]interface{}
	if err := json.Unmarshal(derivedBytes, &doc); err != nil {
		t.Fatalf("unmarshal derived: %v", err)
	}
	if cs, ok := doc["credentialSubject"].(map[string]interface{}); ok {
		cs["name"] = "Someone Else"
	}
	tamperedBytes, _ := json.Marshal(doc)

	tampered, err := vc.ParseJSONCredential(tamperedBytes)
	if err != nil {
		t.Fatalf("parse tampered: %v", err)
	}
	if err := tampered.Verify(vc.WithResolver(s.resolver)); err == nil {
		t.Fatal("tampered derived credential must not verify")
	}
}

func TestECDSASDEndToEnd_WrongIssuerKeyRejected(t *testing.T) {
	s := newE2E(t)
	baseBytes := issueBase(t, s)
	derivedBytes := deriveAndSerialize(t, baseBytes, []string{"credentialSubject.name"})

	// Resolver advertises a different P-256 public key for the issuer DID.
	otherPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("other p256: %v", err)
	}
	badResolver := &memResolver{docs: map[string]*verificationmethod.DIDDocument{
		e2eIssuerDID: p256JWKDIDDoc(t, e2eIssuerDID, &otherPriv.PublicKey),
	}}
	derived, err := vc.ParseJSONCredential(derivedBytes)
	if err != nil {
		t.Fatalf("parse derived: %v", err)
	}
	if err := derived.Verify(vc.WithResolver(badResolver)); err == nil {
		t.Fatal("derived credential must not verify against the wrong issuer key")
	}
}

func TestECDSASDEndToEnd_InPresentation(t *testing.T) {
	s := newE2E(t)
	baseBytes := issueBase(t, s)
	derivedBytes := deriveAndSerialize(t, baseBytes,
		[]string{"credentialSubject.name", "credentialSubject.dob"})

	// Build the VP document directly and parse it, so embedding the derived
	// credential does not trigger NewJSONPresentation's eager verification
	// against the default HTTP resolver (the example DIDs are offline-only).
	var derivedMap map[string]interface{}
	if err := json.Unmarshal(derivedBytes, &derivedMap); err != nil {
		t.Fatalf("unmarshal derived: %v", err)
	}
	vpDoc := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"id":                   "urn:uuid:vp-e2e-001",
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
		vp.WithResolver(s.resolver),
	); err != nil {
		t.Fatalf("sign presentation: %v", err)
	}
	if err := presentation.Verify(vp.WithResolver(s.resolver)); err != nil {
		t.Fatalf("verify presentation: %v", err)
	}
}
