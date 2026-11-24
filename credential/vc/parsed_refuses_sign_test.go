package vc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/internal/jwttest"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// A parsed JWT or JOSE credential has no resolved verification method, so
// signing it must fail: Accept cannot verify the signature against the key the
// header names. Regression test for #101.
func TestParsedCredentialRefusesSigning(t *testing.T) {
	const issuer = "did:example:parsed-vc-issuer"

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerProv, err := signer.NewP256Provider(issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	otherProv, err := signer.NewP256Provider(otherKey)
	if err != nil {
		t.Fatal(err)
	}

	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(issuer,
		mustP256VM(t, issuer, "key-1", &issuerKey.PublicKey)))

	contents := vc.CredentialContents{
		Context:   []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:        "urn:uuid:parsed-refuse-sign-001",
		Types:     []string{"VerifiableCredential"},
		Issuer:    issuer,
		ValidFrom: time.Now().Add(-time.Hour),
		Subject:   []vc.Subject{{ID: "did:example:subject"}},
	}

	const wantErr = "no verification method is bound"

	// Build and sign a JWT credential, then serialize it.
	jwtBuilt, err := vc.NewJWTCredential(contents, vc.WithResolver(resolver))
	if err != nil {
		t.Fatal(err)
	}
	if err := jwtBuilt.AddProofByProvider(issuerProv); err != nil {
		t.Fatal(err)
	}
	jwtSer, err := jwtBuilt.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	jwtToken := jwtSer.(string)

	// Build and sign a JOSE credential, then serialize it.
	joseBuilt, err := vc.NewJOSECredential(contents, vc.WithResolver(resolver))
	if err != nil {
		t.Fatal(err)
	}
	if err := joseBuilt.AddProofByProvider(issuerProv); err != nil {
		t.Fatal(err)
	}
	joseSer, err := joseBuilt.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	joseToken := joseSer.(string)

	// --- JWT ---

	t.Run("jwt/AddProofByProvider/other_key", func(t *testing.T) {
		parsed, err := vc.ParseJWTCredential(jwtToken)
		if err != nil {
			t.Fatal(err)
		}
		hashBefore, _ := parsed.Hash()
		err = parsed.AddProofByProvider(otherProv, vc.WithReplaceProof())
		assertParsedSignRefused(t, err, wantErr)
		hashAfter, _ := parsed.Hash()
		if hashBefore != hashAfter {
			t.Fatal("Hash changed after refused sign")
		}
	})

	t.Run("jwt/AddProofByProvider/right_key", func(t *testing.T) {
		parsed, err := vc.ParseJWTCredential(jwtToken)
		if err != nil {
			t.Fatal(err)
		}
		err = parsed.AddProofByProvider(issuerProv, vc.WithReplaceProof())
		assertParsedSignRefused(t, err, wantErr)
	})

	t.Run("jwt/AddCustomProof/other_key", func(t *testing.T) {
		parsed, err := vc.ParseJWTCredential(jwtToken)
		if err != nil {
			t.Fatal(err)
		}
		input, _ := parsed.GetSigningInput()
		raw := jwttest.SignExternally(t, otherProv, string(input))
		err = parsed.AddCustomProof(&dto.Proof{Signature: raw}, vc.WithReplaceProof())
		assertParsedSignRefused(t, err, wantErr)
	})

	t.Run("jwt/AddCustomProof/right_key", func(t *testing.T) {
		parsed, err := vc.ParseJWTCredential(jwtToken)
		if err != nil {
			t.Fatal(err)
		}
		input, _ := parsed.GetSigningInput()
		raw := jwttest.SignExternally(t, issuerProv, string(input))
		err = parsed.AddCustomProof(&dto.Proof{Signature: raw}, vc.WithReplaceProof())
		assertParsedSignRefused(t, err, wantErr)
	})

	// --- JOSE ---

	t.Run("jose/AddProofByProvider/other_key", func(t *testing.T) {
		parsed, err := vc.ParseJOSECredential(joseToken)
		if err != nil {
			t.Fatal(err)
		}
		hashBefore, _ := parsed.Hash()
		err = parsed.AddProofByProvider(otherProv, vc.WithReplaceProof())
		assertParsedSignRefused(t, err, wantErr)
		hashAfter, _ := parsed.Hash()
		if hashBefore != hashAfter {
			t.Fatal("Hash changed after refused sign")
		}
	})

	t.Run("jose/AddProofByProvider/right_key", func(t *testing.T) {
		parsed, err := vc.ParseJOSECredential(joseToken)
		if err != nil {
			t.Fatal(err)
		}
		err = parsed.AddProofByProvider(issuerProv, vc.WithReplaceProof())
		assertParsedSignRefused(t, err, wantErr)
	})

	t.Run("jose/AddCustomProof/other_key", func(t *testing.T) {
		parsed, err := vc.ParseJOSECredential(joseToken)
		if err != nil {
			t.Fatal(err)
		}
		input, _ := parsed.GetSigningInput()
		raw := jwttest.SignExternally(t, otherProv, string(input))
		err = parsed.AddCustomProof(&dto.Proof{Signature: raw}, vc.WithReplaceProof())
		assertParsedSignRefused(t, err, wantErr)
	})

	t.Run("jose/AddCustomProof/right_key", func(t *testing.T) {
		parsed, err := vc.ParseJOSECredential(joseToken)
		if err != nil {
			t.Fatal(err)
		}
		input, _ := parsed.GetSigningInput()
		raw := jwttest.SignExternally(t, issuerProv, string(input))
		err = parsed.AddCustomProof(&dto.Proof{Signature: raw}, vc.WithReplaceProof())
		assertParsedSignRefused(t, err, wantErr)
	})
}

func assertParsedSignRefused(t *testing.T, err error, wantErr string) {
	t.Helper()
	if err == nil {
		t.Fatal("signing a parsed token must fail, got nil")
	}
	if !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("error = %v, want substring %q", err, wantErr)
	}
}
