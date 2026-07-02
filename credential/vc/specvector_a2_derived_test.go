package vc_test

import (
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/bbs"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// W3C VC Data Integrity BBS Cryptosuites v1.0, Appendix A.2.2 "Derived Proof"
// (https://www.w3.org/TR/vc-di-bbs/#test-vectors): verify the specification's
// published derived proof over the windsurfing revealed document.
const specA2DerivedProofValue = "u2V0DhVkCEJgxugaFJpT7ROtWzZ9mWBMw2Uk2caOtXtKGEMJVDFv9psrafLrzfprwyHOk7GgTv4V9U5VDvEW6E0n-MjO0RvbEYZDECqhFbZgxLtdTXDAD46d691Ltb37hYt9OOKJorYfMWhD_ONzGYzgQ4IrFqA2s_m597DymX7HauNGw2iK48mBAI4xwC4MQ3pLJwuwRiy3msMzccvvdMynM97xymCnoSS0KeW9uCRMYhPb90N-AKNXvjwXZqpgXhyWYxWQhUm2-XbQFhs0rg6RUZS9xY35XkXq9IvRbtn1I_OvfVGRnGuwuhF-H-HwdDrk02z-54jENSD1nEQtfZBJ4J4iOjNklnqePZoMYTKTnGEW4A9k6NVT0V3cW-Tm9NvJut0B3G9XDUkfvSrwrDnAXIabo7fYqY686Ay34lc3gbQsVyowadQckkRj50Jb8xaP5o57BqHDvYZ76avYf2Tt0uCskMX3vWfmB_I7CtWM9jrhxGxCFUre250hkhQP-zfUqwKduyokwY2EmLMR2e7uE6QTRp1I7wZ1nvFAceJSWFr72VHCwZ_gXWdmin5wndcCIikYXtXAY7OER5izYNltHg_vlO87IRr9yS93cGW_O0FxZw167c1rqmoPw5SM825-7j9LjsAfuf2nK_DfEmT3fx0fXeTtI6kghMVS0WSYMKdpt1B3pU5ozUoVa-jmLK6_UfQfXZaYAAgEEAgMDBwQGBQCOAAECBQYICQoODxAREhOGAwQFCAkKRBEzd6o"

func specA2DerivedSignedDocument() []byte {
	return []byte(`{
	  "@context": [
	    "https://www.w3.org/ns/credentials/v2",
	    {"@vocab": "https://windsurf.grotto-networking.com/selective#"}
	  ],
	  "type": ["VerifiableCredential"],
	  "issuer": "https://vc.example/windsurf/racecommittee",
	  "credentialSubject": {
	    "sailNumber": "Earth101",
	    "sails": [
	      {"size": 6.1, "sailName": "Lahaina", "year": 2023},
	      {"size": 7, "sailName": "Lahaina", "year": 2020}
	    ],
	    "boards": [
	      {"year": 2022, "boardName": "CompFoil170", "brand": "Wailea"},
	      {"boardName": "Kanaha Custom", "brand": "Wailea", "year": 2019}
	    ]
	  },
	  "proof": {
	    "type": "DataIntegrityProof",
	    "cryptosuite": "bbs-2023",
	    "created": "2023-08-15T23:36:38Z",
	    "verificationMethod": "` + specDerivedDID + `#zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ",
	    "proofPurpose": "assertionMethod",
	    "proofValue": "` + specA2DerivedProofValue + `"
	  }
	}`)
}

// TestSpecVectorA2DerivedProofVerify verifies the A.2 published derived proof.
func TestSpecVectorA2DerivedProofVerify(t *testing.T) {
	keyID := "zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ"
	resolver := verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument(
			specDerivedDID,
			verificationmethod.NewBLS12381G2VM(specDerivedDID, keyID, keyID),
		),
	)

	cred, err := vc.ParseBBSCredential(specA2DerivedSignedDocument())
	if err != nil {
		t.Fatalf("parse derived credential: %v", err)
	}
	if err := cred.Verify(vc.WithResolver(resolver), vc.WithBBSEngine(bbs.NewZKryptiumEngine())); err != nil {
		t.Fatalf("verify A.2 derived proof: %v", err)
	}
}
