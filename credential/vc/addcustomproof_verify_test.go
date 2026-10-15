package vc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// externalProofFor runs the external signing flow against cred and returns the
// proof it produces: GetSigningInput → CreateProofSigning → sign →
// EncodeMultibaseKey. This is the proof shape AddCustomProof exists for.
func externalProofFor(t *testing.T, cred *vc.JSONCredential, priv *ecdsa.PrivateKey, vmURL string) *dto.Proof {
	t.Helper()

	proof := &dto.Proof{
		Type:               "DataIntegrityProof",
		Cryptosuite:        "ecdsa-rdfc-2019",
		Created:            "2026-01-01T00:00:00Z",
		VerificationMethod: vmURL,
		ProofPurpose:       "assertionMethod",
	}

	docHash, err := cred.GetSigningInput()
	if err != nil {
		t.Fatalf("GetSigningInput: %v", err)
	}
	proofHash, err := cred.CreateProofSigning(docHash, proof)
	if err != nil {
		t.Fatalf("CreateProofSigning: %v", err)
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, proofHash)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	proof.ProofValue = vmpkg.EncodeMultibaseKey(sig)

	return proof
}

// customProofCredential builds the document these tests attach a proof to. The
// data-integrity context is declared up front: the external flow never adds
// one, so the proof configuration would not canonicalize without it.
func customProofCredential(t *testing.T, issuerDID string) *vc.JSONCredential {
	t.Helper()
	validFrom, err := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("parse time: %v", err)
	}
	cred, err := vc.NewJSONCredential(vc.CredentialContents{
		Context: []interface{}{
			"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/data-integrity/v2",
		},
		ID:        "urn:uuid:addcustomproof-verify",
		Types:     []string{"VerifiableCredential"},
		Issuer:    issuerDID,
		ValidFrom: validFrom,
		Subject:   []vc.Subject{{ID: "did:example:subject"}},
	})
	if err != nil {
		t.Fatalf("NewJSONCredential: %v", err)
	}
	return cred
}

// proofOnDocument returns the credential's proof as it was serialized, or nil
// when nothing is attached.
func proofOnDocument(t *testing.T, cred *vc.JSONCredential) interface{} {
	t.Helper()
	raw, err := cred.GetContents()
	if err != nil {
		t.Fatalf("contents: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return doc["proof"]
}

func customProofDIDs(t *testing.T) (string, *ecdsa.PrivateKey, vmpkg.ResolverProvider) {
	t.Helper()
	const did = "did:example:addcustomproof"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	vm, err := vmpkg.NewP256MultikeyVM(did, "key-1", &priv.PublicKey)
	if err != nil {
		t.Fatalf("NewP256MultikeyVM: %v", err)
	}
	return did, priv, vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))
}

// With the option, a proof that checks out is attached and the credential
// verifies — the option must not stand in the way of a correct signature.
func TestAddCustomProof_VerifyProof_AttachesAValidProof(t *testing.T) {
	did, priv, resolver := customProofDIDs(t)
	cred := customProofCredential(t, did)

	proof := externalProofFor(t, cred, priv, did+"#key-1")

	if err := cred.AddCustomProof(proof, vc.WithVerifyProof(), vc.WithResolver(resolver)); err != nil {
		t.Fatalf("a valid external proof was refused: %v", err)
	}
	if proofOnDocument(t, cred) == nil {
		t.Fatal("the proof was not attached")
	}
	if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("the attached proof does not verify: %v", err)
	}
}

// A proof signed by a key the verification method does not name is refused, and
// the document is left as it was — no proof, nothing half-written.
//
// Without the option this proof attached in silence and failed at whoever
// received the credential, which is the gap this closes: the caller that made
// the proof is the one in a position to fix it.
func TestAddCustomProof_VerifyProof_RefusesAProofByAnotherKey(t *testing.T) {
	did, _, resolver := customProofDIDs(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	cred := customProofCredential(t, did)
	before := proofOnDocument(t, cred)

	proof := externalProofFor(t, cred, other, did+"#key-1")

	err = cred.AddCustomProof(proof, vc.WithVerifyProof(), vc.WithResolver(resolver))
	if err == nil {
		t.Fatal("a proof signed by another key was attached")
	}
	if !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("err = %v, want it to say the proof does not verify", err)
	}
	if after := proofOnDocument(t, cred); after != nil || before != nil {
		t.Errorf("the refused call changed the document: proof = %v", after)
	}
}

// Signing one document and attaching the proof to another is caught too: the
// document digest is half of what the signature commits to.
func TestAddCustomProof_VerifyProof_RefusesAProofOverAnotherDocument(t *testing.T) {
	did, priv, resolver := customProofDIDs(t)

	signedOver := customProofCredential(t, did)
	proof := externalProofFor(t, signedOver, priv, did+"#key-1")

	// Same issuer and key, different subject.
	validFrom, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	target, err := vc.NewJSONCredential(vc.CredentialContents{
		Context: []interface{}{
			"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/data-integrity/v2",
		},
		ID:        "urn:uuid:addcustomproof-verify",
		Types:     []string{"VerifiableCredential"},
		Issuer:    did,
		ValidFrom: validFrom,
		Subject:   []vc.Subject{{ID: "did:example:someone-else"}},
	})
	if err != nil {
		t.Fatalf("NewJSONCredential: %v", err)
	}

	if err := target.AddCustomProof(proof, vc.WithVerifyProof(), vc.WithResolver(resolver)); err == nil {
		t.Fatal("a proof made over another document was attached")
	}
	if p := proofOnDocument(t, target); p != nil {
		t.Errorf("the refused call left a proof: %v", p)
	}
}

// Without the option nothing is checked, exactly as before: a client that
// prefers to call Verify() afterwards, or not at all, is unaffected.
func TestAddCustomProof_WithoutTheOption_AttachesUnverified(t *testing.T) {
	did, _, resolver := customProofDIDs(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	cred := customProofCredential(t, did)

	proof := externalProofFor(t, cred, other, did+"#key-1")

	if err := cred.AddCustomProof(proof); err != nil {
		t.Fatalf("AddCustomProof without the option must attach as given: %v", err)
	}
	if proofOnDocument(t, cred) == nil {
		t.Fatal("the proof was not attached")
	}
	// And it is still a bad proof — the check was skipped, not passed.
	if err := cred.Verify(vc.WithResolver(resolver)); err == nil {
		t.Fatal("Verify accepted a proof signed by another key")
	}
}

// Only ecdsa-rdfc-2019 can be checked before attaching. The other suites bind
// to material the document does not carry yet, so they are refused with the
// option set rather than checked against bytes nobody signed — and the message
// says what to do instead.
func TestAddCustomProof_VerifyProof_RefusesOtherSuites(t *testing.T) {
	did, _, resolver := customProofDIDs(t)
	cred := customProofCredential(t, did)

	proof := &dto.Proof{
		Type:               "EcdsaSecp256k1Signature2019",
		Created:            "2026-01-01T00:00:00Z",
		VerificationMethod: did + "#key-1",
		ProofPurpose:       "assertionMethod",
		JWS:                "eyJhbGciOiJFUzI1NksifQ..AAAA",
	}

	err := cred.AddCustomProof(proof, vc.WithVerifyProof(), vc.WithResolver(resolver))
	if err == nil {
		t.Fatal("a suite that cannot be checked before attaching was checked anyway")
	}
	if !strings.Contains(err.Error(), "cannot be checked before it is attached") {
		t.Errorf("err = %v, want it to name the limitation", err)
	}
	if p := proofOnDocument(t, cred); p != nil {
		t.Errorf("the refused call left a proof: %v", p)
	}

	// Without the option it still attaches, so the refusal is about the check,
	// not about the suite being unsupported.
	if err := cred.AddCustomProof(proof); err != nil {
		t.Fatalf("the same proof without the option: %v", err)
	}
	if proofOnDocument(t, cred) == nil {
		t.Error("the proof was not attached without the option")
	}
}
