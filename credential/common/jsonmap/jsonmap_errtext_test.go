package jsonmap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
)

// TestProofPurposeErrorBounded checks that a long proofPurpose from the
// document is cut in the mismatch error rather than copied whole.
func TestProofPurposeErrorBounded(t *testing.T) {
	err := proofPurposeDisagrees(&dto.Proof{Type: "DataIntegrityProof", ProofPurpose: strings.Repeat("p", 1<<20)}, "assertionMethod")
	if err == nil || len(err.Error()) > 1024 {
		t.Fatalf("error length = %d, want an error under 1024 bytes", len(err.Error()))
	}
}

// TestUnsupportedProofTypeErrorBounded checks that a long proof.type is cut in
// the error rather than copied whole.
func TestUnsupportedProofTypeErrorBounded(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := JSONMap{"proof": map[string]interface{}{"type": strings.Repeat("t", 1<<20), "verificationMethod": "did:example:issuer#key-1"}}
	_, err = m.VerifyProof(issuerResolver(t, &priv.PublicKey), "")
	if err == nil || len(err.Error()) > 1024 {
		t.Fatalf("error = %d bytes, want an error under 1024 bytes", len(fmt.Sprint(err)))
	}
}
