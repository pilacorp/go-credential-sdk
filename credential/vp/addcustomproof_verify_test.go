package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// customProofPresentation builds the document these tests attach a proof to.
// The data-integrity context is declared up front: the external flow never adds
// one, so the proof configuration would not canonicalize without it.
func customProofPresentation(t *testing.T, holderDID string) *vp.JSONPresentation {
	t.Helper()
	pres, err := vp.NewJSONPresentation(vp.PresentationContents{
		Context: []interface{}{
			"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/data-integrity/v2",
		},
		ID:     "urn:uuid:vp-addcustomproof-verify",
		Types:  []string{"VerifiablePresentation"},
		Holder: holderDID,
	})
	if err != nil {
		t.Fatalf("NewJSONPresentation: %v", err)
	}
	return pres
}

// externalVPProofFor runs the external signing flow and returns the proof,
// bound to the challenge and domain given.
func externalVPProofFor(t *testing.T, pres *vp.JSONPresentation, priv *ecdsa.PrivateKey,
	vmURL, challenge, domain string) *dto.Proof {
	t.Helper()

	proof := &dto.Proof{
		Type:               "DataIntegrityProof",
		Cryptosuite:        "ecdsa-rdfc-2019",
		Created:            "2026-01-01T00:00:00Z",
		VerificationMethod: vmURL,
		ProofPurpose:       "authentication",
		Challenge:          challenge,
		Domain:             dto.StringOrStrings{domain},
	}

	docHash, err := pres.GetSigningInput()
	if err != nil {
		t.Fatalf("GetSigningInput: %v", err)
	}
	proofHash, err := pres.CreateProofSigning(docHash, proof)
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

func customProofHolder(t *testing.T) (string, *ecdsa.PrivateKey, vmpkg.ResolverProvider) {
	t.Helper()
	const did = "did:example:vp-addcustomproof"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	vm, err := vmpkg.NewP256MultikeyVM(did, "key-1", &priv.PublicKey)
	if err != nil {
		t.Fatalf("NewP256MultikeyVM: %v", err)
	}
	doc := vmpkg.NewDIDDocument(did, vm)
	return did, priv, vmpkg.NewStaticResolver(doc)
}

func TestVPAddCustomProof_VerifyProof_AttachesAValidProof(t *testing.T) {
	did, priv, resolver := customProofHolder(t)
	pres := customProofPresentation(t, did)

	proof := externalVPProofFor(t, pres, priv, did+"#key-1", "nonce-123", "verifier.example")

	if err := pres.AddCustomProof(proof, vp.WithVerifyProof(), vp.WithResolver(resolver)); err != nil {
		t.Fatalf("a valid external proof was refused: %v", err)
	}
	if err := pres.Verify(vp.WithResolver(resolver),
		vp.WithExpectedChallenge("nonce-123"), vp.WithExpectedDomain("verifier.example")); err != nil {
		t.Fatalf("the attached proof does not verify: %v", err)
	}
}

// challenge and domain are part of the proof configuration the signature
// commits to, so editing either after signing must be caught here.
//
// This is the case worth having on the presentation side: a holder that reuses
// a proof under a different nonce is replaying it, and before this the swap was
// attached in silence and only surfaced at the verifier — by which point the
// holder is no longer the one who can explain it.
func TestVPAddCustomProof_VerifyProof_RefusesASwappedChallenge(t *testing.T) {
	did, priv, resolver := customProofHolder(t)
	pres := customProofPresentation(t, did)

	proof := externalVPProofFor(t, pres, priv, did+"#key-1", "nonce-123", "verifier.example")
	proof.Challenge = "nonce-999"

	err := pres.AddCustomProof(proof, vp.WithVerifyProof(), vp.WithResolver(resolver))
	if err == nil {
		t.Fatal("a proof whose challenge was changed after signing was attached")
	}
	if !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("err = %v, want it to say the proof does not verify", err)
	}
	if pres.ExtractField("proof") != nil {
		t.Errorf("the refused call left a proof: %v", pres.ExtractField("proof"))
	}

	// The same swap without the option still attaches, unchecked, as before.
	if err := pres.AddCustomProof(proof); err != nil {
		t.Fatalf("AddCustomProof without the option must attach as given: %v", err)
	}
	if pres.ExtractField("proof") == nil {
		t.Error("the proof was not attached without the option")
	}
}

// The same for domain, which travels beside challenge in the proof
// configuration.
func TestVPAddCustomProof_VerifyProof_RefusesASwappedDomain(t *testing.T) {
	did, priv, resolver := customProofHolder(t)
	pres := customProofPresentation(t, did)

	proof := externalVPProofFor(t, pres, priv, did+"#key-1", "nonce-123", "verifier.example")
	proof.Domain = dto.StringOrStrings{"attacker.example"}

	if err := pres.AddCustomProof(proof, vp.WithVerifyProof(), vp.WithResolver(resolver)); err == nil {
		t.Fatal("a proof whose domain was changed after signing was attached")
	}
	if pres.ExtractField("proof") != nil {
		t.Errorf("the refused call left a proof: %v", pres.ExtractField("proof"))
	}
}
