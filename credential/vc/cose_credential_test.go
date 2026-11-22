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

func TestCOSECredential_AuthOnlyKey_Refused(t *testing.T) {
	// B1: a key listed only under authentication (not assertionMethod) must be
	// refused for a COSE VC.
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-authonly"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)

	// Sign with a resolver that has the key under both purposes.
	sigResolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

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

	// Verify against a resolver where the key is ONLY under authentication.
	authOnlyDoc := &vmpkg.DIDDocument{
		ID:                 did,
		VerificationMethod: []vmpkg.VerificationMethodEntry{vm},
		Authentication:     []string{vm.ID},
		AssertionMethod:    []string{}, // empty
	}
	authOnlyResolver := vmpkg.NewStaticResolver(authOnlyDoc)

	parsed, err := vc.ParseCOSECredential(coseBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = parsed.Verify(vc.WithResolver(authOnlyResolver))
	if err == nil {
		t.Fatal("expected verification to fail: key is not under assertionMethod")
	}
	if !strings.Contains(err.Error(), "assertionMethod") {
		t.Fatalf("expected assertionMethod error, got: %v", err)
	}
}

func TestCOSECredential_HardRevoked_Refused(t *testing.T) {
	// B1: keyCompromise revocation must be refused.
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-revoked"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)

	// Sign with a clean resolver.
	sigResolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

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

	// Verify against a resolver where the key is hard-revoked (keyCompromise).
	revokedVM := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	revokedVM.RevocationReason = "keyCompromise"
	revokedDoc := &vmpkg.DIDDocument{
		ID:                 did,
		VerificationMethod: []vmpkg.VerificationMethodEntry{revokedVM},
		AssertionMethod:    []string{revokedVM.ID},
		Authentication:     []string{revokedVM.ID},
	}
	revokedResolver := vmpkg.NewStaticResolver(revokedDoc)

	parsed, err := vc.ParseCOSECredential(coseBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = parsed.Verify(vc.WithResolver(revokedResolver))
	if err == nil {
		t.Fatal("expected verification to fail: key is hard-revoked")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("expected revocation error, got: %v", err)
	}
}

func TestCOSECredential_SoftRevoked_BeforeIAT_Accepted(t *testing.T) {
	// B1: soft-revoked after iat → accepted (credential was signed before revocation).
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-softrev"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)

	// Sign with a clean resolver.
	sigResolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

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

	// Verify against a resolver with soft revocation AFTER iat (iat = now, revoked = now+1h).
	softVM := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	future := time.Now().Add(time.Hour)
	softVM.Revoked = &future
	softDoc := &vmpkg.DIDDocument{
		ID:                 did,
		VerificationMethod: []vmpkg.VerificationMethodEntry{softVM},
		AssertionMethod:    []string{softVM.ID},
		Authentication:     []string{softVM.ID},
	}
	softResolver := vmpkg.NewStaticResolver(softDoc)

	parsed, err := vc.ParseCOSECredential(coseBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// iat is now, revoked in the future → accepted
	if err := parsed.Verify(vc.WithResolver(softResolver)); err != nil {
		t.Fatalf("expected acceptance (soft-revoked after iat), got: %v", err)
	}
}

func TestCOSECredential_SoftRevoked_AfterIAT_Refused(t *testing.T) {
	// B1: soft-revoked before iat → refused.
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-softrev-fail"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)

	// Sign with a clean resolver.
	sigResolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

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

	// Verify against a resolver with soft revocation BEFORE iat (iat = now, revoked = now-1h).
	softVM := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	past := time.Now().Add(-time.Hour)
	softVM.Revoked = &past
	softDoc := &vmpkg.DIDDocument{
		ID:                 did,
		VerificationMethod: []vmpkg.VerificationMethodEntry{softVM},
		AssertionMethod:    []string{softVM.ID},
		Authentication:     []string{softVM.ID},
	}
	softResolver := vmpkg.NewStaticResolver(softDoc)

	parsed, err := vc.ParseCOSECredential(coseBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = parsed.Verify(vc.WithResolver(softResolver))
	if err == nil {
		t.Fatal("expected verification to fail: soft-revoked before iat")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("expected revocation error, got: %v", err)
	}
}

func TestCOSECredential_IssuerBinding_KidMismatch_Refused(t *testing.T) {
	// B1: a COSE VC with issuer A but kid belonging to DID B must be refused.
	keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256 A: %v", err)
	}
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256 B: %v", err)
	}

	didA := "did:example:issuerA"
	didB := "did:example:issuerB"
	vmA := mustP256VM(t, didA, "key-1", &keyA.PublicKey)
	vmB := mustP256VM(t, didB, "key-1", &keyB.PublicKey)

	// Signing resolver: has didA's doc for key resolution at signing time.
	sigResolver := vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(didA, vmA),
		vmpkg.NewDIDDocument(didB, vmB),
	)

	// Verification resolver: has both docs, but B's key is used for signing
	// while A is the issuer in the payload.
	verifyResolver := vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(didA, vmA),
		vmpkg.NewDIDDocument(didB, vmB),
	)

	providerB, err := signer.NewP256Provider(keyB)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	// Create credential with issuer A but sign with B's key.
	// Use didB's VM for signing (kid will be didB#key-1) but payload says issuer didA.
	cred, err := vc.NewCOSECredential(coseContents(didB),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(sigResolver))
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	// Modify the payload to say issuer A (forgery attempt).
	// We need to sign, then tamper.
	if err := cred.AddProofByProvider(providerB); err != nil {
		t.Fatalf("add proof: %v", err)
	}

	// The kid is didB#key-1 and the issuer is didB — this should verify.
	// But if we build a credential with issuer A, resolve A's key for signing,
	// but the kid points to B, it should fail.
	// Let me construct this differently using the internal cose package directly.
	issuerA := coseContents(didA)
	credA, err := vc.NewCOSECredential(issuerA,
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(sigResolver))
	if err != nil {
		t.Fatalf("new credA: %v", err)
	}
	// Signing with provider A's key will work and kid will be didA#key-1
	providerA, err := signer.NewP256Provider(keyA)
	if err != nil {
		t.Fatalf("providerA: %v", err)
	}
	if err := credA.AddProofByProvider(providerA); err != nil {
		t.Fatalf("sign A: %v", err)
	}
	serialized, err := credA.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	coseBytes := serialized.([]byte)

	// Now verify with a resolver that returns B's key for A's DID.
	// This simulates kid = didA#key-1 but the DID doc for A has B's key.
	tamperDoc := &vmpkg.DIDDocument{
		ID:                 didA,
		VerificationMethod: []vmpkg.VerificationMethodEntry{vmB},
		AssertionMethod:    []string{vmB.ID},
	}
	// This won't work because vmB.ID is didB#key-1, not didA#key-1.
	// The resolution would fail on FindVerificationMethod.
	// What we actually want: verify with a correct resolver, the kid resolves,
	// but the key doesn't match → already covered by WrongKey test.
	// The real binding test: issuer in payload must match the DID part of kid.
	// Let's verify with the normal resolver — kid is didA#key-1 → resolves
	// against issuer didA → finds keyA → verifies. That's correct.
	// The dangerous case: kid is didB#key-1 (absolute) while issuer says didA.
	// The verifier should refuse because kid doesn't belong to the issuer's DID.
	_ = coseBytes
	_ = verifyResolver
	_ = tamperDoc

	// Use the internal cose package to construct a forged credential:
	// issuer = didA in payload, kid = didB#key-1 in protected header, signed with keyB.
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"@context":  []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":      []interface{}{"VerifiableCredential"},
		"id":        "urn:uuid:forged-001",
		"issuer":    didA,
		"validFrom": time.Now().Add(-time.Hour).Format(time.RFC3339),
		"iat":       time.Now().Unix(),
		"credentialSubject": map[string]interface{}{
			"id": "did:example:subject",
		},
	})
	prot := cose.Protected{
		Alg:         cose.AlgES256,
		ContentType: "application/vc",
		Kid:         didB + "#key-1", // kid of B, not A
		Typ:         "application/vc+cose",
	}
	signFn := func(digest []byte) ([]byte, error) {
		r, s, serr := ecdsa.Sign(rand.Reader, keyB, digest)
		if serr != nil {
			return nil, serr
		}
		rBytes := r.Bytes()
		sBytes := s.Bytes()
		sig := make([]byte, 64)
		copy(sig[32-len(rBytes):32], rBytes)
		copy(sig[64-len(sBytes):64], sBytes)
		return sig, nil
	}
	forgedBytes, err := cose.Sign1(prot, payloadJSON, signFn)
	if err != nil {
		t.Fatalf("sign1 forged: %v", err)
	}

	parsed, err := vc.ParseCOSECredential(forgedBytes)
	if err != nil {
		t.Fatalf("parse forged: %v", err)
	}
	// Verify with resolver that has both A and B.
	// kid is didB#key-1, issuer is didA. The verifier should refuse because
	// it resolves didA's doc but won't find didB#key-1 in it.
	err = parsed.Verify(vc.WithResolver(verifyResolver))
	if err == nil {
		t.Fatal("expected verification to fail: kid belongs to a different DID than issuer")
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

func TestCOSECredential_RelativeKid_NoIss_Rejected(t *testing.T) {
	// A COSE VC with a relative kid (#fragment) and no iss claim in the
	// payload must be rejected per VC-JOSE-COSE §4.1.2.
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-kid-noiss"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

	// Build a COSE_Sign1 with a relative kid (#key-1) and NO iss in payload.
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"@context":  []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":      []interface{}{"VerifiableCredential"},
		"id":        "urn:uuid:kid-noiss-001",
		"issuer":    did,
		"validFrom": time.Now().Add(-time.Hour).Format(time.RFC3339),
		"iat":       time.Now().Unix(),
		"credentialSubject": map[string]interface{}{
			"id": "did:example:subject",
		},
	})
	prot := cose.Protected{
		Alg:         cose.AlgES256,
		ContentType: "application/vc",
		Kid:         "#key-1", // relative kid
		Typ:         "application/vc+cose",
	}
	coseBytes, err := cose.Sign1(prot, payloadJSON, signP256COSE(p256Key))
	if err != nil {
		t.Fatalf("sign1: %v", err)
	}

	parsed, err := vc.ParseCOSECredential(coseBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = parsed.Verify(vc.WithResolver(resolver))
	if err == nil {
		t.Fatal("expected rejection: relative kid without iss")
	}
	if !strings.Contains(err.Error(), "iss") {
		t.Fatalf("expected iss-related error, got: %v", err)
	}
}

func TestCOSECredential_RelativeKid_MatchingIss_Accepted(t *testing.T) {
	// A COSE VC with a relative kid and an iss claim matching issuer must be
	// accepted.
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-kid-iss"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"@context":  []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":      []interface{}{"VerifiableCredential"},
		"id":        "urn:uuid:kid-iss-001",
		"issuer":    did,
		"iss":       did, // iss matches issuer
		"validFrom": time.Now().Add(-time.Hour).Format(time.RFC3339),
		"iat":       time.Now().Unix(),
		"credentialSubject": map[string]interface{}{
			"id": "did:example:subject",
		},
	})
	prot := cose.Protected{
		Alg:         cose.AlgES256,
		ContentType: "application/vc",
		Kid:         "#key-1", // relative kid
		Typ:         "application/vc+cose",
	}
	coseBytes, err := cose.Sign1(prot, payloadJSON, signP256COSE(p256Key))
	if err != nil {
		t.Fatalf("sign1: %v", err)
	}

	parsed, err := vc.ParseCOSECredential(coseBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := parsed.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("expected acceptance: relative kid with matching iss, got: %v", err)
	}
}

func TestCOSECredential_AbsoluteKid_NoIss_Accepted(t *testing.T) {
	// An absolute kid requires no iss — this is the standard case the SDK
	// produces, and already tested by the round-trip tests. This test makes
	// the expectation explicit.
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256: %v", err)
	}

	did := "did:example:cose-abs-kid"
	vm := mustP256VM(t, did, "key-1", &p256Key.PublicKey)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))

	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"@context":  []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":      []interface{}{"VerifiableCredential"},
		"id":        "urn:uuid:abs-kid-001",
		"issuer":    did,
		"validFrom": time.Now().Add(-time.Hour).Format(time.RFC3339),
		"iat":       time.Now().Unix(),
		"credentialSubject": map[string]interface{}{
			"id": "did:example:subject",
		},
	})
	prot := cose.Protected{
		Alg:         cose.AlgES256,
		ContentType: "application/vc",
		Kid:         did + "#key-1", // absolute kid
		Typ:         "application/vc+cose",
	}
	coseBytes, err := cose.Sign1(prot, payloadJSON, signP256COSE(p256Key))
	if err != nil {
		t.Fatalf("sign1: %v", err)
	}

	parsed, err := vc.ParseCOSECredential(coseBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// No iss in payload, but kid is absolute → fine
	if err := parsed.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("expected acceptance: absolute kid, got: %v", err)
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
