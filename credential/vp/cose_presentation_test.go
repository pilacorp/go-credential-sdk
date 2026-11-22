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
	"github.com/pilacorp/go-credential-sdk/credential/internal/cose"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

func coseVPContents(holderDID string) vp.PresentationContents {
	return vp.PresentationContents{
		Context: []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:      "urn:uuid:cose-vp-001",
		Types:   []string{"VerifiablePresentation"},
		Holder:  holderDID,
	}
}

func TestCOSEPresentation_ES256_RoundTrip(t *testing.T) {
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-vp-p256"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

	provider, err := signer.NewP256Provider(p256Key)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	pres, err := vp.NewCOSEPresentation(coseVPContents(did),
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new cose presentation: %v", err)
	}

	if err := pres.AddProofByProvider(provider); err != nil {
		t.Fatalf("add proof: %v", err)
	}

	if err := pres.Verify(vp.WithResolver(resolver)); err != nil {
		t.Fatalf("verify: %v", err)
	}

	if pres.GetType() != "COSE" {
		t.Fatalf("type = %q, want COSE", pres.GetType())
	}

	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	coseBytes, ok := serialized.([]byte)
	if !ok {
		t.Fatalf("serialized COSE presentation is %T, want []byte", serialized)
	}

	if len(coseBytes) < 2 || coseBytes[0] != 0xd2 {
		t.Fatalf("COSE bytes do not start with CBOR tag 18")
	}

	h, err := pres.Hash()
	if err != nil || len(h) != 64 {
		t.Fatalf("hash: %v (len %d)", err, len(h))
	}

	// Parse round trip
	parsed, err := vp.ParseCOSEPresentation(coseBytes)
	if err != nil {
		t.Fatalf("parse cose presentation: %v", err)
	}
	if err := parsed.Verify(vp.WithResolver(resolver)); err != nil {
		t.Fatalf("verify after parse: %v", err)
	}

	// ParsePresentation auto-detection
	autoParsed, err := vp.ParsePresentation(coseBytes, vp.WithResolver(resolver))
	if err != nil {
		t.Fatalf("ParsePresentation auto-detection: %v", err)
	}
	if autoParsed.GetType() != "COSE" {
		t.Fatalf("auto-detected type = %q, want COSE", autoParsed.GetType())
	}
}

func TestCOSEPresentation_ProtectedHeader(t *testing.T) {
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-vp-header"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

	provider, err := signer.NewP256Provider(p256Key)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	pres, err := vp.NewCOSEPresentation(coseVPContents(did),
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := pres.AddProofByProvider(provider); err != nil {
		t.Fatalf("sign: %v", err)
	}

	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	coseBytes := serialized.([]byte)

	prot, _, _, err := cose.Parse1(coseBytes)
	if err != nil {
		t.Fatalf("parse1: %v", err)
	}

	if prot.Alg != cose.AlgES256 {
		t.Errorf("alg = %d, want %d (ES256)", prot.Alg, cose.AlgES256)
	}
	if prot.ContentType != "application/vp" {
		t.Errorf("content_type = %q, want %q", prot.ContentType, "application/vp")
	}
	if prot.Typ != "application/vp+cose" {
		t.Errorf("typ = %q, want %q", prot.Typ, "application/vp+cose")
	}
	wantKid := did + "#key-1"
	if prot.Kid != wantKid {
		t.Errorf("kid = %q, want %q", prot.Kid, wantKid)
	}
}

func TestCOSEPresentation_EnvelopedCOSEVC(t *testing.T) {
	const (
		issuerDID = "did:example:cose-issuer"
		holderDID = "did:example:cose-holder"
	)

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen issuer P-256: %v", err)
	}
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen holder P-256: %v", err)
	}

	issuerVM := mustP256VM(t, issuerDID, "key-1", &issuerKey.PublicKey)
	holderVM := mustP256VM(t, holderDID, "key-1", &holderKey.PublicKey)

	resolver := vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(issuerDID, issuerVM),
		vmpkg.NewDIDDocument(holderDID, holderVM),
	)

	issuerProv, err := signer.NewP256Provider(issuerKey)
	if err != nil {
		t.Fatalf("issuer provider: %v", err)
	}
	holderProv, err := signer.NewP256Provider(holderKey)
	if err != nil {
		t.Fatalf("holder provider: %v", err)
	}

	// 1. Create and sign a COSECredential (vc+cose)
	cred, err := vc.NewCOSECredential(vc.CredentialContents{
		Context:   []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:        "urn:uuid:cose-vc-in-vp",
		Types:     []string{"VerifiableCredential", "MembershipCredential"},
		Issuer:    issuerDID,
		ValidFrom: time.Now().Add(-time.Hour),
		Subject: []vc.Subject{{
			ID:           "did:example:subject",
			CustomFields: map[string]interface{}{"memberId": "MEM-5678"},
		}},
	}, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new cose cred: %v", err)
	}
	if err := cred.AddProofByProvider(issuerProv); err != nil {
		t.Fatalf("sign cred: %v", err)
	}

	// 2. Create COSEPresentation embedding the COSE credential
	vpContents := vp.PresentationContents{
		Context:               []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:                    "urn:uuid:cose-vp-with-vc",
		Types:                 []string{"VerifiablePresentation"},
		Holder:                holderDID,
		VerifiableCredentials: []vc.Credential{cred},
	}
	pres, err := vp.NewCOSEPresentation(vpContents,
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new cose pres: %v", err)
	}
	if err := pres.AddProofByProvider(holderProv); err != nil {
		t.Fatalf("sign pres: %v", err)
	}

	// 3. Verify the presentation
	if err := pres.Verify(vp.WithResolver(resolver)); err != nil {
		t.Fatalf("verify cose presentation: %v", err)
	}

	// 4. Check enveloped format: data:application/vc+cose;base64,<b64>
	contentsJSON, err := pres.GetContents()
	if err != nil {
		t.Fatalf("get contents: %v", err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(contentsJSON, &body); err != nil {
		t.Fatalf("unmarshal contents: %v", err)
	}

	vcs, ok := body["verifiableCredential"].([]interface{})
	if !ok || len(vcs) != 1 {
		t.Fatalf("verifiableCredential missing or invalid: %v", body["verifiableCredential"])
	}
	envMap, ok := vcs[0].(map[string]interface{})
	if !ok {
		t.Fatalf("embedded credential is not map: %T", vcs[0])
	}
	idStr, _ := envMap["id"].(string)
	if !strings.HasPrefix(idStr, "data:application/vc+cose;base64,") {
		t.Fatalf("expected enveloped URI prefix 'data:application/vc+cose;base64,', got: %s", truncate(idStr, 80))
	}

	// 5. Decode the enveloped COSE VC and verify it
	b64Part := strings.TrimPrefix(idStr, "data:application/vc+cose;base64,")
	coseVCBytes, err := base64.StdEncoding.DecodeString(b64Part)
	if err != nil {
		t.Fatalf("decode enveloped base64: %v", err)
	}
	parsedVC, err := vc.ParseCOSECredential(coseVCBytes)
	if err != nil {
		t.Fatalf("parse enveloped COSE VC: %v", err)
	}
	if err := parsedVC.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify enveloped COSE VC: %v", err)
	}
	if got := parsedVC.ExtractField("credentialSubject.memberId"); got != "MEM-5678" {
		t.Errorf("memberId = %v, want %q", got, "MEM-5678")
	}

	// 6. Parse the full presentation via ParsePresentation auto-detection
	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	vpBytes := serialized.([]byte)
	autoParsed, err := vp.ParsePresentation(vpBytes)
	if err != nil {
		t.Fatalf("auto-parse: %v", err)
	}
	if autoParsed.GetType() != "COSE" {
		t.Fatalf("auto type = %q, want COSE", autoParsed.GetType())
	}
}

func TestCOSEPresentation_WrongKey_Rejected(t *testing.T) {
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen wrong P-256: %v", err)
	}

	did := "did:example:cose-vp-wrongkey"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	wrongVM := mustP256VM(t, did, "key-1", &wrongKey.PublicKey)
	sigResolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))
	wrongResolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, wrongVM))

	provider, err := signer.NewP256Provider(p256Key)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	pres, err := vp.NewCOSEPresentation(coseVPContents(did),
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(sigResolver))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := pres.AddProofByProvider(provider); err != nil {
		t.Fatalf("sign: %v", err)
	}

	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	vpBytes := serialized.([]byte)

	parsed, err := vp.ParseCOSEPresentation(vpBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := parsed.Verify(vp.WithResolver(wrongResolver)); err == nil {
		t.Fatal("expected verification to fail with wrong key")
	}
}

func TestCOSEPresentation_TamperedPayload_Rejected(t *testing.T) {
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-vp-tamper"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

	provider, err := signer.NewP256Provider(p256Key)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	pres, err := vp.NewCOSEPresentation(coseVPContents(did),
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := pres.AddProofByProvider(provider); err != nil {
		t.Fatalf("sign: %v", err)
	}

	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	vpBytes := serialized.([]byte)

	tampered := make([]byte, len(vpBytes))
	copy(tampered, vpBytes)
	mid := len(tampered) / 2
	tampered[mid] ^= 0xff

	parsed, err := vp.ParseCOSEPresentation(tampered)
	if err != nil {
		return // Tamper may break CBOR parsing, fine
	}
	if err := parsed.Verify(vp.WithResolver(resolver)); err == nil {
		t.Fatal("expected verification to fail on tampered COSE presentation")
	}
}

func TestCOSEPresentation_AuthOnlyKey_ForVP_Passes(t *testing.T) {
	// B1: a VP key listed only under authentication (not assertionMethod) must
	// be ACCEPTED because VP uses authentication purpose.
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-vp-auth"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	sigResolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

	provider, err := signer.NewP256Provider(p256Key)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	pres, err := vp.NewCOSEPresentation(coseVPContents(did),
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(sigResolver))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := pres.AddProofByProvider(provider); err != nil {
		t.Fatalf("sign: %v", err)
	}

	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	vpBytes := serialized.([]byte)

	// Verify with doc that has the key ONLY under authentication.
	authOnlyDoc := &vmpkg.DIDDocument{
		ID:                 did,
		VerificationMethod: []vmpkg.VerificationMethodEntry{vm},
		Authentication:     []string{vm.ID},
		AssertionMethod:    []string{}, // empty
	}
	authOnlyResolver := vmpkg.NewStaticResolver(authOnlyDoc)

	parsed, err := vp.ParseCOSEPresentation(vpBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := parsed.Verify(vp.WithResolver(authOnlyResolver)); err != nil {
		t.Fatalf("expected VP verification to pass with auth-only key, got: %v", err)
	}
}

func TestCOSEPresentation_AssertionOnlyKey_ForVP_Refused(t *testing.T) {
	// B1: a VP key listed only under assertionMethod (not authentication)
	// must be refused for a COSE VP.
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-vp-assert"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	sigResolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

	provider, err := signer.NewP256Provider(p256Key)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	pres, err := vp.NewCOSEPresentation(coseVPContents(did),
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(sigResolver))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := pres.AddProofByProvider(provider); err != nil {
		t.Fatalf("sign: %v", err)
	}

	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	vpBytes := serialized.([]byte)

	// Verify with doc that has the key ONLY under assertionMethod.
	assertOnlyDoc := &vmpkg.DIDDocument{
		ID:                 did,
		VerificationMethod: []vmpkg.VerificationMethodEntry{vm},
		AssertionMethod:    []string{vm.ID},
		Authentication:     []string{}, // empty
	}
	assertOnlyResolver := vmpkg.NewStaticResolver(assertOnlyDoc)

	parsed, err := vp.ParseCOSEPresentation(vpBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = parsed.Verify(vp.WithResolver(assertOnlyResolver))
	if err == nil {
		t.Fatal("expected verification to fail: key is not under authentication")
	}
	if !strings.Contains(err.Error(), "authentication") {
		t.Fatalf("expected authentication error, got: %v", err)
	}
}

func TestCOSEPresentation_HardRevoked_Refused(t *testing.T) {
	// B1: keyCompromise revocation on VP key must be refused.
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-vp-revoked"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	sigResolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

	provider, err := signer.NewP256Provider(p256Key)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	pres, err := vp.NewCOSEPresentation(coseVPContents(did),
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(sigResolver))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := pres.AddProofByProvider(provider); err != nil {
		t.Fatalf("sign: %v", err)
	}

	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	vpBytes := serialized.([]byte)

	revokedVM := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	revokedVM.RevocationReason = "keyCompromise"
	revokedDoc := &vmpkg.DIDDocument{
		ID:                 did,
		VerificationMethod: []vmpkg.VerificationMethodEntry{revokedVM},
		AssertionMethod:    []string{revokedVM.ID},
		Authentication:     []string{revokedVM.ID},
	}
	revokedResolver := vmpkg.NewStaticResolver(revokedDoc)

	parsed, err := vp.ParseCOSEPresentation(vpBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = parsed.Verify(vp.WithResolver(revokedResolver))
	if err == nil {
		t.Fatal("expected VP verification to fail: key is hard-revoked")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("expected revocation error, got: %v", err)
	}
}

func TestCOSEPresentation_WithVCValidation_TamperedInnerVC(t *testing.T) {
	// B2: a COSE VP carrying a tampered COSE VC must fail with WithVCValidation.
	const (
		issuerDID = "did:example:cose-b2-issuer"
		holderDID = "did:example:cose-b2-holder"
	)

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen issuer P-256: %v", err)
	}
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen holder P-256: %v", err)
	}

	issuerVM := mustP256VM(t, issuerDID, "key-1", &issuerKey.PublicKey)
	holderVM := mustP256VM(t, holderDID, "key-1", &holderKey.PublicKey)

	resolver := vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(issuerDID, issuerVM),
		vmpkg.NewDIDDocument(holderDID, holderVM),
	)

	issuerProv, err := signer.NewP256Provider(issuerKey)
	if err != nil {
		t.Fatalf("issuer provider: %v", err)
	}
	holderProv, err := signer.NewP256Provider(holderKey)
	if err != nil {
		t.Fatalf("holder provider: %v", err)
	}

	// Create and sign a COSE VC.
	cred, err := vc.NewCOSECredential(vc.CredentialContents{
		Context:   []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:        "urn:uuid:cose-b2-vc",
		Types:     []string{"VerifiableCredential"},
		Issuer:    issuerDID,
		ValidFrom: time.Now().Add(-time.Hour),
		Subject:   []vc.Subject{{ID: "did:example:subject"}},
	}, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new cred: %v", err)
	}
	if err := cred.AddProofByProvider(issuerProv); err != nil {
		t.Fatalf("sign cred: %v", err)
	}

	// Create VP with the good credential.
	vpWithVC := vp.PresentationContents{
		Context:               []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:                    "urn:uuid:cose-b2-vp-good",
		Types:                 []string{"VerifiablePresentation"},
		Holder:                holderDID,
		VerifiableCredentials: []vc.Credential{cred},
	}
	goodPres, err := vp.NewCOSEPresentation(vpWithVC,
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new good pres: %v", err)
	}
	if err := goodPres.AddProofByProvider(holderProv); err != nil {
		t.Fatalf("sign good pres: %v", err)
	}

	// Verify the VP proof (without VC validation) → should pass.
	goodBytes, _ := goodPres.Serialize()
	parsedGood, err := vp.ParseCOSEPresentation(goodBytes.([]byte))
	if err != nil {
		t.Fatalf("parse good: %v", err)
	}
	if err := parsedGood.Verify(vp.WithResolver(resolver)); err != nil {
		t.Fatalf("verify good VP (no VC validation): %v", err)
	}

	// Now verify with WithVCValidation but using a wrong resolver for the VC
	// (so inner VC verification fails).
	wrongIssuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongIssuerVM := mustP256VM(t, issuerDID, "key-1", &wrongIssuerKey.PublicKey)
	wrongResolver := vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(issuerDID, wrongIssuerVM),
		vmpkg.NewDIDDocument(holderDID, holderVM),
	)
	err = parsedGood.Verify(vp.WithResolver(wrongResolver), vp.WithVCValidation())
	if err == nil {
		t.Fatal("expected verification to fail: inner COSE VC should not verify with wrong issuer key")
	}

	// Also verify that WithVCValidation with correct resolver passes.
	parsedGood2, _ := vp.ParseCOSEPresentation(goodBytes.([]byte))
	if err := parsedGood2.Verify(vp.WithResolver(resolver), vp.WithVCValidation()); err != nil {
		t.Fatalf("expected VP+VC validation to pass with correct resolver, got: %v", err)
	}

}

func TestCOSEPresentation_WrongChallenge_Refused(t *testing.T) {
	// S2: wrong challenge must be refused.
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-vp-challenge"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

	provider, err := signer.NewP256Provider(p256Key)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	pres, err := vp.NewCOSEPresentation(coseVPContents(did),
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver),
		vp.WithChallenge("correct-nonce"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := pres.AddProofByProvider(provider); err != nil {
		t.Fatalf("sign: %v", err)
	}

	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	vpBytes := serialized.([]byte)

	parsed, err := vp.ParseCOSEPresentation(vpBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Verify with wrong challenge.
	err = parsed.Verify(vp.WithResolver(resolver), vp.WithExpectedChallenge("wrong-nonce"))
	if err == nil {
		t.Fatal("expected verification to fail: wrong challenge")
	}
	if !strings.Contains(err.Error(), "nonce") && !strings.Contains(err.Error(), "challenge") {
		t.Fatalf("expected nonce/challenge error, got: %v", err)
	}

	// Verify with correct challenge → passes.
	parsed2, _ := vp.ParseCOSEPresentation(vpBytes)
	if err := parsed2.Verify(vp.WithResolver(resolver), vp.WithExpectedChallenge("correct-nonce")); err != nil {
		t.Fatalf("expected verification to pass with correct challenge, got: %v", err)
	}
}

func TestCOSEPresentation_WrongDomain_Refused(t *testing.T) {
	// S2: wrong domain must be refused.
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-vp-domain"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

	provider, err := signer.NewP256Provider(p256Key)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	pres, err := vp.NewCOSEPresentation(coseVPContents(did),
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver),
		vp.WithDomain("correct-domain.example.com"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := pres.AddProofByProvider(provider); err != nil {
		t.Fatalf("sign: %v", err)
	}

	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	vpBytes := serialized.([]byte)

	parsed, err := vp.ParseCOSEPresentation(vpBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Verify with wrong domain.
	err = parsed.Verify(vp.WithResolver(resolver), vp.WithExpectedDomain("wrong-domain.example.com"))
	if err == nil {
		t.Fatal("expected verification to fail: wrong domain")
	}

	// Verify with correct domain → passes.
	parsed2, _ := vp.ParseCOSEPresentation(vpBytes)
	if err := parsed2.Verify(vp.WithResolver(resolver), vp.WithExpectedDomain("correct-domain.example.com")); err != nil {
		t.Fatalf("expected verification to pass with correct domain, got: %v", err)
	}
}

// --- Finding 1: kid resolution with iss (VC-JOSE-COSE §4.1.2) ---

// signP256COSE is a convenience sign function for COSE tests.
func signP256COSE(key *ecdsa.PrivateKey) func([]byte) ([]byte, error) {
	return func(digest []byte) ([]byte, error) {
		r, s, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			return nil, err
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig, nil
	}
}

func TestCOSEPresentation_RelativeKid_NoIss_Rejected(t *testing.T) {
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-vp-kid-noiss"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiablePresentation"},
		"id":       "urn:uuid:vp-kid-noiss-001",
		"holder":   did,
		"iat":      time.Now().Unix(),
	})
	prot := cose.Protected{
		Alg:         cose.AlgES256,
		ContentType: "application/vp",
		Kid:         "#key-1", // relative kid
		Typ:         "application/vp+cose",
	}
	coseBytes, err := cose.Sign1(prot, payloadJSON, signP256COSE(p256Key))
	if err != nil {
		t.Fatalf("sign1: %v", err)
	}

	parsed, err := vp.ParseCOSEPresentation(coseBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = parsed.Verify(vp.WithResolver(resolver))
	if err == nil {
		t.Fatal("expected rejection: relative kid without iss")
	}
	if !strings.Contains(err.Error(), "iss") {
		t.Fatalf("expected iss-related error, got: %v", err)
	}
}

func TestCOSEPresentation_RelativeKid_MatchingIss_Accepted(t *testing.T) {
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-vp-kid-iss"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiablePresentation"},
		"id":       "urn:uuid:vp-kid-iss-001",
		"holder":   did,
		"iss":      did, // iss matches holder
		"iat":      time.Now().Unix(),
	})
	prot := cose.Protected{
		Alg:         cose.AlgES256,
		ContentType: "application/vp",
		Kid:         "#key-1",
		Typ:         "application/vp+cose",
	}
	coseBytes, err := cose.Sign1(prot, payloadJSON, signP256COSE(p256Key))
	if err != nil {
		t.Fatalf("sign1: %v", err)
	}

	parsed, err := vp.ParseCOSEPresentation(coseBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := parsed.Verify(vp.WithResolver(resolver)); err != nil {
		t.Fatalf("expected acceptance: relative kid with matching iss, got: %v", err)
	}
}

func TestCOSEPresentation_AbsoluteKid_NoIss_Accepted(t *testing.T) {
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-vp-abs-kid"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiablePresentation"},
		"id":       "urn:uuid:vp-abs-kid-001",
		"holder":   did,
		"iat":      time.Now().Unix(),
	})
	prot := cose.Protected{
		Alg:         cose.AlgES256,
		ContentType: "application/vp",
		Kid:         did + "#key-1", // absolute kid
		Typ:         "application/vp+cose",
	}
	coseBytes, err := cose.Sign1(prot, payloadJSON, signP256COSE(p256Key))
	if err != nil {
		t.Fatalf("sign1: %v", err)
	}

	parsed, err := vp.ParseCOSEPresentation(coseBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := parsed.Verify(vp.WithResolver(resolver)); err != nil {
		t.Fatalf("expected acceptance: absolute kid, got: %v", err)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func TestCOSEPresentation_RelativeKid_IssNotHolder_Rejected(t *testing.T) {
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-vp-kid-iss-mismatch"
	other := "did:example:someone-else"
	vm := mustP256VM(t, other, "key-1", &p256Key.PublicKey)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiablePresentation"},
		"id":       "urn:uuid:vp-kid-iss-mismatch-001",
		"holder":   did,
		"iss":      other,
		"iat":      time.Now().Unix(),
	})
	prot := cose.Protected{
		Alg:         cose.AlgES256,
		ContentType: "application/vp",
		Kid:         "#key-1",
		Typ:         "application/vp+cose",
	}
	coseBytes, err := cose.Sign1(prot, payloadJSON, signP256COSE(p256Key))
	if err != nil {
		t.Fatalf("sign1: %v", err)
	}

	parsed, err := vp.ParseCOSEPresentation(coseBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = parsed.Verify(vp.WithResolver(resolver))
	if err == nil || !strings.Contains(err.Error(), "does not match holder") {
		t.Fatalf("Verify error = %v, want iss/holder mismatch", err)
	}
}
