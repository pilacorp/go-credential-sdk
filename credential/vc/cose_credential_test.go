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

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/internal/cose"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

func coseContents(issuerDID string) vc.CredentialContents {
	return vc.CredentialContents{
		Context:   []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:        "urn:uuid:cose-test-001",
		Types:     []string{"VerifiableCredential", "AlumniCredential"},
		Issuer:    issuerDID,
		ValidFrom: time.Now().Add(-time.Hour),
		Subject: []vc.Subject{{
			ID:           "did:example:subject",
			CustomFields: map[string]interface{}{"name": "Nguyen Van B"},
		}},
	}
}

func TestCOSECredential_ES256_RoundTrip(t *testing.T) {
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-p256"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

	provider, err := signer.NewP256Provider(p256Key)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	cred, err := vc.NewCOSECredential(coseContents(did),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new cose credential: %v", err)
	}

	if err := cred.AddProofByProvider(provider); err != nil {
		t.Fatalf("add proof: %v", err)
	}

	if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Check type
	if cred.GetType() != "COSE" {
		t.Fatalf("type = %q, want COSE", cred.GetType())
	}

	// Serialize returns []byte
	serialized, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	coseBytes, ok := serialized.([]byte)
	if !ok {
		t.Fatalf("serialized COSE credential is %T, want []byte", serialized)
	}

	// COSE_Sign1 starts with tag 18 (0xd2)
	if len(coseBytes) < 2 || coseBytes[0] != 0xd2 {
		t.Fatalf("COSE bytes do not start with CBOR tag 18")
	}

	// Hash is 64 hex chars (SHA-256)
	h, err := cred.Hash()
	if err != nil || len(h) != 64 {
		t.Fatalf("hash: %v (len %d)", err, len(h))
	}

	// Parse round trip
	parsed, err := vc.ParseCOSECredential(coseBytes)
	if err != nil {
		t.Fatalf("parse cose credential: %v", err)
	}
	if err := parsed.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify after parse: %v", err)
	}
	if got := parsed.ExtractField("credentialSubject.name"); got != "Nguyen Van B" {
		t.Errorf("name = %v, want %q", got, "Nguyen Van B")
	}

	// ParseCredential auto-detection
	autoParsed, err := vc.ParseCredential(coseBytes, vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("ParseCredential auto-detection: %v", err)
	}
	if autoParsed.GetType() != "COSE" {
		t.Fatalf("auto-detected type = %q, want COSE", autoParsed.GetType())
	}
	if err := autoParsed.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("auto-detected verify: %v", err)
	}
}

func TestCOSECredential_ES256K_RoundTrip(t *testing.T) {
	const privHex = "57600b3f2b7e1054094e14cd85c72a40dc74c4ee062bb381cea604b55ce56aec"

	secpProvider, err := signer.NewDefaultProvider(privHex)
	if err != nil {
		t.Fatalf("secp provider: %v", err)
	}

	did := "did:example:cose-secp"
	vm := vmpkg.NewSecp256k1VM(did, "key-1", pubHex(t, privHex))
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

	cred, err := vc.NewCOSECredential(coseContents(did),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new cose credential: %v", err)
	}

	if err := cred.AddProofByProvider(secpProvider); err != nil {
		t.Fatalf("add proof: %v", err)
	}

	if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify: %v", err)
	}

	serialized, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	coseBytes := serialized.([]byte)

	// Parse and verify
	parsed, err := vc.ParseCOSECredential(coseBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := parsed.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify after parse: %v", err)
	}
}

func TestCOSECredential_TamperedPayload_Rejected(t *testing.T) {
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-tamper"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

	provider, err := signer.NewP256Provider(p256Key)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	cred, err := vc.NewCOSECredential(coseContents(did),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := cred.AddProofByProvider(provider); err != nil {
		t.Fatalf("add proof: %v", err)
	}

	serialized, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	coseBytes := serialized.([]byte)

	// Tamper: flip a byte in the middle of the payload area
	tampered := make([]byte, len(coseBytes))
	copy(tampered, coseBytes)
	mid := len(tampered) / 2
	tampered[mid] ^= 0xff

	parsed, err := vc.ParseCOSECredential(tampered)
	if err != nil {
		// Tamper might break CBOR parsing, which is also fine
		return
	}
	if err := parsed.Verify(vc.WithResolver(resolver)); err == nil {
		t.Fatal("expected verification to fail on tampered COSE credential")
	}
}

func TestCOSECredential_WrongKey_Rejected(t *testing.T) {
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen wrong P-256: %v", err)
	}

	did := "did:example:cose-wrongkey"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	wrongVM := mustP256VM(t, did, "key-1", &wrongKey.PublicKey)
	sigResolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))
	wrongResolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, wrongVM))

	provider, err := signer.NewP256Provider(p256Key)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	cred, err := vc.NewCOSECredential(coseContents(did),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(sigResolver))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := cred.AddProofByProvider(provider); err != nil {
		t.Fatalf("add proof: %v", err)
	}

	serialized, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	coseBytes := serialized.([]byte)

	parsed, err := vc.ParseCOSECredential(coseBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := parsed.Verify(vc.WithResolver(wrongResolver)); err == nil {
		t.Fatal("expected verification to fail with wrong key")
	}
}

func TestCOSECredential_ProtectedHeader(t *testing.T) {
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-header"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

	provider, err := signer.NewP256Provider(p256Key)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	cred, err := vc.NewCOSECredential(coseContents(did),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := cred.AddProofByProvider(provider); err != nil {
		t.Fatalf("add proof: %v", err)
	}

	serialized, err := cred.Serialize()
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
	if prot.ContentType != "application/vc" {
		t.Errorf("content_type = %q, want %q", prot.ContentType, "application/vc")
	}
	if prot.Typ != "application/vc+cose" {
		t.Errorf("typ = %q, want %q", prot.Typ, "application/vc+cose")
	}
	wantKid := did + "#key-1"
	if prot.Kid != wantKid {
		t.Errorf("kid = %q, want %q", prot.Kid, wantKid)
	}
}

func TestCOSECredential_DetectsCOSEInput(t *testing.T) {
	// IsCOSESign1 should detect COSE bytes correctly
	coseHeader := []byte{0xd2, 0x84} // tag 18 + 4-element array
	if !cose.IsCOSESign1(coseHeader) {
		t.Fatal("IsCOSESign1 should return true for 0xd2 0x84")
	}

	// Not COSE
	if cose.IsCOSESign1([]byte(`{"type": "VerifiableCredential"}`)) {
		t.Fatal("IsCOSESign1 should return false for JSON")
	}
	if cose.IsCOSESign1([]byte("eyJ")) {
		t.Fatal("IsCOSESign1 should return false for JWT prefix")
	}
}

func TestCOSECredential_EnvelopedInJSON(t *testing.T) {
	// A COSE credential enveloped in a JSON EnvelopedVerifiableCredential
	// should be parseable via ParseCredential.
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-envelope"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

	provider, err := signer.NewP256Provider(p256Key)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	cred, err := vc.NewCOSECredential(coseContents(did),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := cred.AddProofByProvider(provider); err != nil {
		t.Fatalf("add proof: %v", err)
	}

	serialized, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	coseBytes := serialized.([]byte)
	b64 := base64.StdEncoding.EncodeToString(coseBytes)

	envelope := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"EnvelopedVerifiableCredential"},
		"id":       "data:application/vc+cose;base64," + b64,
	}
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	parsed, err := vc.ParseCredential(envelopeJSON)
	if err != nil {
		t.Fatalf("ParseCredential from COSE envelope: %v", err)
	}
	if parsed.GetType() != "COSE" {
		t.Fatalf("type = %q, want COSE", parsed.GetType())
	}
	if err := parsed.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify enveloped COSE: %v", err)
	}
}

func TestCOSECredential_DisallowedAlg(t *testing.T) {
	// Verify that Parse1 with disallowed alg rejects
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	prot := cose.Protected{
		Alg:         cose.AlgES256,
		ContentType: "application/vc",
		Kid:         "did:example:test#key-1",
		Typ:         "application/vc+cose",
	}
	payload := []byte(`{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"]}`)

	signFn := func(digest []byte) ([]byte, error) {
		r, s, err := ecdsa.Sign(rand.Reader, p256Key, digest)
		if err != nil {
			return nil, err
		}
		rBytes := r.Bytes()
		sBytes := s.Bytes()
		sig := make([]byte, 64)
		copy(sig[32-len(rBytes):32], rBytes)
		copy(sig[64-len(sBytes):64], sBytes)
		return sig, nil
	}

	coseBytes, err := cose.Sign1(prot, payload, signFn)
	if err != nil {
		t.Fatalf("sign1: %v", err)
	}

	// Allow only ES256K (-47), not ES256 (-7) → should reject
	_, _, err = cose.Verify1(coseBytes, &p256Key.PublicKey, []int{cose.AlgES256K})
	if err == nil {
		t.Fatal("expected rejection for disallowed alg")
	}
	if !strings.Contains(err.Error(), "not in the allowed set") {
		t.Fatalf("unexpected error: %v", err)
	}
}
