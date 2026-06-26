package bbs

import (
	"encoding/hex"
	"encoding/json"
	"testing"
)

// W3C VC Data Integrity BBS Cryptosuites v1.0 test vectors, Appendix A.2
// "Baseline Enhanced Example" (https://www.w3.org/TR/vc-di-bbs/#test-vectors).
// Same key pair and HMAC key as A.1, but a document with nested arrays and
// floating-point values, and mandatory pointers that address array elements.
const (
	specA2MandatoryHash  = "555de05f898817e31301bac187d0c3ff2b03e2cbdb4adb4d568c17de961f9a18"
	specA2BBSSignature   = "8331f55ad458fe5c322420b2cb806f9a20ea6b2b8a29d51710026d71ace5da080064b488818efc75a439525bd031450822a6a332da781926e19360b90166431124efcf3d060fbc750c6122c714c07f71"
	specA2BaseProofValue = "u2V0ChVhQgzH1WtRY_lwyJCCyy4BvmiDqayuKKdUXEAJtcazl2ggAZLSIgY78daQ5UlvQMUUIIqajMtp4GSbhk2C5AWZDESTvzz0GD7x1DGEixxTAf3FYQDpbvyXTTZCxjDXNI1e-am9CMB6U_J5S936Tt3PFYUvfVV3gX4mIF-MTAbrBh9DD_ysD4svbSttNVowX3pYfmhhYYKTvGvo9pXVJbxIrm3i4wkdhUxqKCTIGrnxFuAdZwWi6T3omD5wzZ7bAGbRneEEQSxBmXtvnC6Pr59nPv_v3HrAW9wq_uxYzF_NyaX3GPv0h_FV2T2OSao8C6uoyWiqIj1ggABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v-FZy9pc3N1ZXJ4HS9jcmVkZW50aWFsU3ViamVjdC9zYWlsTnVtYmVyeBovY3JlZGVudGlhbFN1YmplY3Qvc2FpbHMvMXggL2NyZWRlbnRpYWxTdWJqZWN0L2JvYXJkcy8wL3llYXJ4Gi9jcmVkZW50aWFsU3ViamVjdC9zYWlscy8y"
)

func specEnhancedDocument() map[string]interface{} {
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(`{
	  "@context": [
	    "https://www.w3.org/ns/credentials/v2",
	    {"@vocab": "https://windsurf.grotto-networking.com/selective#"}
	  ],
	  "type": ["VerifiableCredential"],
	  "issuer": "https://vc.example/windsurf/racecommittee",
	  "credentialSubject": {
	    "sailNumber": "Earth101",
	    "sails": [
	      {"size": 5.5, "sailName": "Kihei", "year": 2023},
	      {"size": 6.1, "sailName": "Lahaina", "year": 2023},
	      {"size": 7.0, "sailName": "Lahaina", "year": 2020},
	      {"size": 7.8, "sailName": "Lahaina", "year": 2023}
	    ],
	    "boards": [
	      {"boardName": "CompFoil170", "brand": "Wailea", "year": 2022},
	      {"boardName": "Kanaha Custom", "brand": "Wailea", "year": 2019}
	    ]
	  }
	}`), &doc); err != nil {
		panic(err)
	}
	return doc
}

func specEnhancedMandatoryPointers() []string {
	return []string{
		"/issuer",
		"/credentialSubject/sailNumber",
		"/credentialSubject/sails/1",
		"/credentialSubject/boards/0/year",
		"/credentialSubject/sails/2",
	}
}

// TestSpecVectorA2BaseProof reproduces the A.2 base proof byte-for-byte.
func TestSpecVectorA2BaseProof(t *testing.T) {
	signer, err := NewZKryptiumSignerFromPrivateKeyHex(specPrivateKeyHex)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	hmacKey, err := hex.DecodeString(specHMACKeyHex)
	if err != nil {
		t.Fatalf("hmac key: %v", err)
	}

	proofValue, err := createBaseProofWithHMACKey(
		specEnhancedDocument(),
		specBaselineProofConfig(),
		specEnhancedMandatoryPointers(),
		signer,
		hmacKey,
	)
	if err != nil {
		t.Fatalf("create base proof: %v", err)
	}

	if proofValue != specA2BaseProofValue {
		t.Fatalf("base proof value mismatch\n got: %s\nwant: %s", proofValue, specA2BaseProofValue)
	}

	bp, err := parseBaseProofValue(proofValue)
	if err != nil {
		t.Fatalf("parse base proof: %v", err)
	}
	if got := hex.EncodeToString(bp.BBSSignature); got != specA2BBSSignature {
		t.Fatalf("bbs signature mismatch\n got: %s\nwant: %s", got, specA2BBSSignature)
	}
	if got := hex.EncodeToString(bp.BBSHeader[:32]); got != specProofHash {
		t.Fatalf("proof hash mismatch\n got: %s\nwant: %s", got, specProofHash)
	}
	if got := hex.EncodeToString(bp.BBSHeader[32:]); got != specA2MandatoryHash {
		t.Fatalf("mandatory hash mismatch\n got: %s\nwant: %s", got, specA2MandatoryHash)
	}
}
