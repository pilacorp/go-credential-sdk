package vc_test

import (
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/bbs"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// W3C VC Data Integrity BBS Cryptosuites v1.0 test vectors, Appendix A.1.2
// "Derived Proof" (https://www.w3.org/TR/vc-di-bbs/#test-vectors). A BBS derived
// proof is produced with random scalars, so it cannot be reproduced byte for
// byte; instead we verify the specification's published derived proof against
// its revealed document. This pins our reveal-document canonicalization, label
// map handling and disclosed-message ordering to the specification.
const (
	specDerivedDID         = "did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ"
	specDerivedProofValue  = "u2V0DhVkC0JasX_e4m_LYsPPMUcVH8aIrAeJOJGV50hI2LN9r8Pq-GL4MnR-EyQS7TGxhP9Dsq7etkuYVNB2pekWpGHIWJsyFnEVbRzo245VyVh1fxIPGN0JHF6Q9z_s7Ew2P4R-IqIAvOyMe_iRE-LR_7e0LYh49XNIss-wj68T23KdFtcHOL0KnELklEKcSJafTngDgwm2i-uJCzfFU6T3kIBcnC5kCP-lbQsQqRhouqxngSqRIOa85qnH4MBYstCSlqgrMBG3H57i9_HPPNkHHau63-7Vs2TZ3YFDb1jK_f8gNM8Yh3GuDcYSt5hljD3K9Jdiupia6mU0Vpl3vGw3IrwnFSgz15bVNGxsoBHqi2_Y4Bf7JUzurRtEjScpH39g_8wRUztrNI9pOuaPr4ZjICsGZLiogP_z0avqjSCpjt7AAM98aLaNh1gChz9UTm-AQyjAuCCr37jSl_z0kzHBi9X-jbUeEbt1SGeWb1DhXa_9wm_15INa62DZ7D-jHSTGO-HJr7anB2Qlb7XOOT9HDgzOif08gcaIahjZxtD_lIfc3REvoZeiHy_M8qjkib7gBMANyHjfG2UmGe--6HIt79kG9ZHhRrZKu09qRr1LxfQWKn3TrMHRDBMBYE4QL5qUo9UzVoktzri9C3sG_wuE1T7BhqWwN86uW3cmtqWy4glcczLiXdPzwMm4ciyuHzEz06vvXVjJRiRnL5Yqfhq3hKw9picCIbjWNgBuZsd0yx-blamU8DiZKhLUdLSNnnHXigkUa87yqbxnse8OqYD_sh9taV9QpYeKQfYmaj9XRzhfd6Kdc0RkklM2TsRLad3TCuy9nn1tLQE2r5IXXigF7K-geX_i6z5DV8ksug6tBafj1XKb3AxQfkVZau-x0RebPRmP140uRiCg9V87fNsWGsYoTC4NlJDa_aGJnPd7r2a79wvv8l93oDjZINJHENXzNL8Ex-6IAAAEChAAEBQeGAAEHERITRBEzd6o"
)

func specDerivedSignedDocument() []byte {
	return []byte(`{
	  "@context": [
	    "https://www.w3.org/ns/credentials/v2",
	    "https://w3id.org/citizenship/v4rc1"
	  ],
	  "type": ["VerifiableCredential", "PermanentResidentCardCredential"],
	  "issuer": {
	    "id": "did:key:zDnaeTHxNEBZoKaEo6PdA83fq98ebiFvo3X273Ydu4YmV96rg",
	    "image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2P4z/DiPwAG0ALnwgz64QAAAABJRU5ErkJggg=="
	  },
	  "validFrom": "2024-12-16T00:00:00Z",
	  "validUntil": "2025-12-16T23:59:59Z",
	  "credentialSubject": {
	    "type": ["PermanentResident", "Person"],
	    "birthCountry": "Arcadia"
	  },
	  "proof": {
	    "type": "DataIntegrityProof",
	    "cryptosuite": "bbs-2023",
	    "created": "2023-08-15T23:36:38Z",
	    "verificationMethod": "` + specDerivedDID + `#zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ",
	    "proofPurpose": "assertionMethod",
	    "proofValue": "` + specDerivedProofValue + `"
	  }
	}`)
}

// TestSpecVectorA1DerivedProofVerify verifies the specification's published BBS
// derived proof against its revealed document.
func TestSpecVectorA1DerivedProofVerify(t *testing.T) {
	keyID := "zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ"
	resolver := verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument(
			specDerivedDID,
			verificationmethod.NewBLS12381G2VM(specDerivedDID, keyID, keyID),
		),
	)

	cred, err := vc.ParseBBSCredential(specDerivedSignedDocument())
	if err != nil {
		t.Fatalf("parse derived credential: %v", err)
	}
	if err := cred.Verify(vc.WithResolver(resolver), vc.WithBBSEngine(bbs.NewZKryptiumEngine())); err != nil {
		t.Fatalf("verify spec derived proof: %v", err)
	}
}
