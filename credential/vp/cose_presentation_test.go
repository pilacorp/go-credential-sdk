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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
