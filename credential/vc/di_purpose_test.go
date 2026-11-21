package vc_test

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
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// A login key signs a credential and writes proofPurpose authentication, which
// is the purpose that key actually has. Data Integrity 1.0 §4.4 requires the
// verifier to compare that field with the purpose it expects. A VC verifier
// expects assertionMethod.
func TestVC_VerifyRefusesAProofPurposeItDidNotExpect(t *testing.T) {
	const did = "did:example:vc-purpose"

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	vm := mustP256VM(t, did, "key-1", &key.PublicKey)
	resolver := verificationmethod.NewStaticResolver(verificationmethod.NewDIDDocument(did, vm))

	cred, err := vc.ParseJSONCredential(mkCredentialJSON(did))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	proof := &dto.Proof{
		Type:               "DataIntegrityProof",
		Cryptosuite:        "ecdsa-rdfc-2019",
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: vm.ID,
		ProofPurpose:       "authentication",
	}
	if err := signJSONCredential(t, cred, key, proof); err != nil {
		t.Fatalf("sign: %v", err)
	}

	err = cred.Verify(vc.WithResolver(resolver))
	if err == nil {
		t.Fatal("a VC whose proofPurpose is authentication verified")
	}
	if !strings.Contains(err.Error(), "authentication") || !strings.Contains(err.Error(), "assertionMethod") {
		t.Fatalf("refused, but not for the proof purpose: %v", err)
	}
	if err := cred.Verify(vc.WithResolver(resolver), vc.WithExpectedProofPurpose("authentication")); err != nil {
		t.Fatalf("a caller that asked for authentication was refused: %v", err)
	}
}

func signJSONCredential(t *testing.T, cred *vc.JSONCredential, key *ecdsa.PrivateKey, proof *dto.Proof) error {
	t.Helper()
	docHash, err := cred.GetSigningInput()
	if err != nil {
		return err
	}
	digest, err := cred.CreateProofSigning(docHash, proof)
	if err != nil {
		return err
	}
	proof.ProofValue = verificationmethod.EncodeMultibaseKey(lowSSignature(t, key, digest))
	return cred.AddCustomProof(proof)
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
