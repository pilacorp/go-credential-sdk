package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
	"github.com/stretchr/testify/assert"
)

func TestExternalSigningFlow_VP(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	presentationData := vp.PresentationContents{
		Context: []interface{}{
			"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/data-integrity/v2",
		},
		Types: []string{"VerifiablePresentation"},
	}
	presentation, err := vp.NewJSONPresentation(presentationData)
	assert.NoError(t, err)

	proof := &dto.Proof{
		Type:               "DataIntegrityProof",
		Cryptosuite:        "ecdsa-rdfc-2019",
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: "did:example:123#key-1",
		ProofPurpose:       "authentication",
		Challenge:          "12345-challenge",
		Domain:             dto.StringOrStrings{"example.com"},
	}

	docHash, err := presentation.GetSigningInput()
	assert.NoError(t, err)

	proofHash, err := presentation.CreateProofSigning(docHash, proof)
	assert.NoError(t, err)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, proofHash)
	assert.NoError(t, err)

	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sigBytes := make([]byte, 64)
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)

	proof.ProofValue = verificationmethod.EncodeMultibaseKey(sigBytes)

	err = presentation.AddCustomProof(proof)
	assert.NoError(t, err)

	output, err := presentation.Serialize()
	assert.NoError(t, err)
	outMap := output.(map[string]interface{})
	assert.NotNil(t, outMap["proof"])

	proofMap := outMap["proof"].(map[string]interface{})
	assert.Equal(t, "12345-challenge", proofMap["challenge"])
	assert.Equal(t, "example.com", proofMap["domain"])
	assert.Equal(t, "DataIntegrityProof", proofMap["type"])

	proofVal := proofMap["proofValue"].(string)
	assert.Equal(t, byte('z'), proofVal[0])
}
