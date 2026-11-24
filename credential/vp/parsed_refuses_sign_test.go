package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/internal/jwttest"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// A parsed JWT or JOSE presentation has no resolved verification method, so
// signing it must fail: Accept cannot verify the signature against the key the
// header names. Regression test for #101.
func TestParsedPresentationRefusesSigning(t *testing.T) {
	const holder = "did:example:parsed-vp-holder"

	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderProv, err := signer.NewP256Provider(holderKey)
	if err != nil {
		t.Fatal(err)
	}
	otherProv, err := signer.NewP256Provider(otherKey)
	if err != nil {
		t.Fatal(err)
	}

	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(holder,
		mustP256VM(t, holder, "key-1", &holderKey.PublicKey)))

	contents := vp.PresentationContents{
		Context: []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:      "urn:uuid:parsed-refuse-sign-001",
		Types:   []string{"VerifiablePresentation"},
		Holder:  holder,
	}

	const wantErr = "no verification method is bound"

	// Build and sign a JWT presentation, then serialize it.
	jwtBuilt, err := vp.NewJWTPresentation(contents, vp.WithResolver(resolver))
	if err != nil {
		t.Fatal(err)
	}
	if err := jwtBuilt.AddProofByProvider(holderProv); err != nil {
		t.Fatal(err)
	}
	jwtSer, err := jwtBuilt.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	jwtToken := jwtSer.(string)

	// Build and sign a JOSE presentation, then serialize it.
	joseBuilt, err := vp.NewJOSEPresentation(contents, vp.WithResolver(resolver))
	if err != nil {
		t.Fatal(err)
	}
	if err := joseBuilt.AddProofByProvider(holderProv); err != nil {
		t.Fatal(err)
	}
	joseSer, err := joseBuilt.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	joseToken := joseSer.(string)

	// --- JWT ---

	t.Run("jwt/AddProofByProvider/other_key", func(t *testing.T) {
		parsed, err := vp.ParseJWTPresentation(jwtToken)
		if err != nil {
			t.Fatal(err)
		}
		serBefore, _ := parsed.Serialize()
		err = parsed.AddProofByProvider(otherProv, vp.WithReplaceProof(), vp.WithChallenge("n1"))
		assertVPSignRefused(t, err, wantErr)
		serAfter, _ := parsed.Serialize()
		if serBefore.(string) != serAfter.(string) {
			t.Fatal("Serialize changed after refused sign")
		}
	})

	t.Run("jwt/AddProofByProvider/right_key", func(t *testing.T) {
		parsed, err := vp.ParseJWTPresentation(jwtToken)
		if err != nil {
			t.Fatal(err)
		}
		err = parsed.AddProofByProvider(holderProv, vp.WithReplaceProof(), vp.WithChallenge("n1"))
		assertVPSignRefused(t, err, wantErr)
	})

	t.Run("jwt/AddCustomProof/other_key", func(t *testing.T) {
		parsed, err := vp.ParseJWTPresentation(jwtToken)
		if err != nil {
			t.Fatal(err)
		}
		input, _ := parsed.GetSigningInput()
		raw := jwttest.SignExternally(t, otherProv, string(input))
		err = parsed.AddCustomProof(&dto.Proof{Signature: raw}, vp.WithReplaceProof())
		assertVPSignRefused(t, err, wantErr)
	})

	t.Run("jwt/AddCustomProof/right_key", func(t *testing.T) {
		parsed, err := vp.ParseJWTPresentation(jwtToken)
		if err != nil {
			t.Fatal(err)
		}
		input, _ := parsed.GetSigningInput()
		raw := jwttest.SignExternally(t, holderProv, string(input))
		err = parsed.AddCustomProof(&dto.Proof{Signature: raw}, vp.WithReplaceProof())
		assertVPSignRefused(t, err, wantErr)
	})

	// --- JOSE ---

	t.Run("jose/AddProofByProvider/other_key", func(t *testing.T) {
		parsed, err := vp.ParseJOSEPresentation(joseToken)
		if err != nil {
			t.Fatal(err)
		}
		hashBefore, _ := parsed.Hash()
		err = parsed.AddProofByProvider(otherProv, vp.WithReplaceProof(), vp.WithChallenge("n1"))
		assertVPSignRefused(t, err, wantErr)
		hashAfter, _ := parsed.Hash()
		if hashBefore != hashAfter {
			t.Fatal("Hash changed after refused sign")
		}
	})

	t.Run("jose/AddProofByProvider/right_key", func(t *testing.T) {
		parsed, err := vp.ParseJOSEPresentation(joseToken)
		if err != nil {
			t.Fatal(err)
		}
		err = parsed.AddProofByProvider(holderProv, vp.WithReplaceProof(), vp.WithChallenge("n1"))
		assertVPSignRefused(t, err, wantErr)
	})

	t.Run("jose/AddCustomProof/other_key", func(t *testing.T) {
		parsed, err := vp.ParseJOSEPresentation(joseToken)
		if err != nil {
			t.Fatal(err)
		}
		input, _ := parsed.GetSigningInput()
		raw := jwttest.SignExternally(t, otherProv, string(input))
		err = parsed.AddCustomProof(&dto.Proof{Signature: raw}, vp.WithReplaceProof())
		assertVPSignRefused(t, err, wantErr)
	})

	t.Run("jose/AddCustomProof/right_key", func(t *testing.T) {
		parsed, err := vp.ParseJOSEPresentation(joseToken)
		if err != nil {
			t.Fatal(err)
		}
		input, _ := parsed.GetSigningInput()
		raw := jwttest.SignExternally(t, holderProv, string(input))
		err = parsed.AddCustomProof(&dto.Proof{Signature: raw}, vp.WithReplaceProof())
		assertVPSignRefused(t, err, wantErr)
	})
}

func assertVPSignRefused(t *testing.T, err error, wantErr string) {
	t.Helper()
	if err == nil {
		t.Fatal("signing a parsed token must fail, got nil")
	}
	if !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("error = %v, want substring %q", err, wantErr)
	}
}
