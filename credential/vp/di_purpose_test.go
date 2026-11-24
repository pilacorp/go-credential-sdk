package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// A presentation verifier expects authentication. A proof that instead says
// assertionMethod is a credential signature sitting on a presentation, which
// Data Integrity 1.0 §4.4 requires the verifier to refuse.
func TestVP_VerifyRefusesAProofPurposeItDidNotExpect(t *testing.T) {
	const did = "did:example:vp-purpose"

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	vm := mustP256VM(t, did, "key-1", &key.PublicKey)
	resolver := verificationmethod.NewStaticResolver(verificationmethod.NewDIDDocument(did, vm))

	pres, err := vp.NewJSONPresentation(vp.PresentationContents{
		Context: []interface{}{
			"https://www.w3.org/ns/credentials/v2",
		},
		ID:     "urn:uuid:vp-purpose",
		Types:  []string{"VerifiablePresentation"},
		Holder: did,
	})
	if err != nil {
		t.Fatalf("new presentation: %v", err)
	}
	proof := &dto.Proof{
		Type:               "DataIntegrityProof",
		Cryptosuite:        "ecdsa-rdfc-2019",
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: vm.ID,
		ProofPurpose:       "assertionMethod",
	}
	docHash, err := pres.GetSigningInput()
	if err != nil {
		t.Fatalf("signing input: %v", err)
	}
	digest, err := pres.CreateProofSigning(docHash, proof)
	if err != nil {
		t.Fatalf("proof digest: %v", err)
	}
	proof.ProofValue = verificationmethod.EncodeMultibaseKey(lowSSignature(t, key, digest))
	if err := pres.AddCustomProof(proof); err != nil {
		t.Fatalf("attach: %v", err)
	}

	err = pres.Verify(vp.WithResolver(resolver))
	if err == nil {
		t.Fatal("a VP whose proofPurpose is assertionMethod verified")
	}
	if !strings.Contains(err.Error(), "assertionMethod") || !strings.Contains(err.Error(), "authentication") {
		t.Fatalf("refused, but not for the proof purpose: %v", err)
	}
	if err := pres.Verify(vp.WithResolver(resolver), vp.WithExpectedProofPurpose("assertionMethod")); err != nil {
		t.Fatalf("a caller that asked for assertionMethod was refused: %v", err)
	}
}

func lowSSignature(t *testing.T, key *ecdsa.PrivateKey, digest []byte) []byte {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	halfN := new(big.Int).Rsh(key.Curve.Params().N, 1)
	if s.Cmp(halfN) > 0 {
		s = new(big.Int).Sub(key.Curve.Params().N, s)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig
}
