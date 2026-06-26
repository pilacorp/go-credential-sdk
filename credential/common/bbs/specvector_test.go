package bbs

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/sd"
)

// Official W3C VC Data Integrity BBS Cryptosuites v1.0 test vectors,
// Appendix A.1 "Baseline Basic Example" (https://www.w3.org/TR/vc-di-bbs/#test-vectors).
// These are byte-exact: with the spec's fixed private key and fixed HMAC key,
// the base proof is fully deterministic, so the produced proof value MUST equal
// the published one. This pins our canonicalization, label replacement, grouping,
// hashing and signing to the specification.
const (
	specPrivateKeyHex = "66d36e118832af4c5e28b2dfe1b9577857e57b042a33e06bdea37b811ed09ee0"
	specPublicKeyHex  = "a4ef1afa3da575496f122b9b78b8c24761531a8a093206ae7c45b80759c168ba4f7a260f9c3367b6c019b4677841104b10665edbe70ba3ebe7d9cfbffbf71eb016f70abfbb163317f372697dc63efd21fc55764f63926a8f02eaea325a2a888f"
	specHMACKeyHex    = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"

	specProofHash     = "3a5bbf25d34d90b18c35cd2357be6a6f42301e94fc9e52f77e93b773c5614bdf"
	specMandatoryHash = "8e7cc22c318dd2094e02d0bf06c5d73a5dba717611a40f6d1bedc5ea7c300fd6"
	specBBSSignature  = "86168dd2b5d0c7c6a56a30f4212ed116a53def05d0d6708207d483c7ff2053aefa22d24ba7659d60852694f8d85be0fa2adc3974c7dc4cc68b3db17b2423975047104162c24502b41591879ac24f1bb1"

	specBaseProofValue = "u2V0ChVhQhhaN0rXQx8alajD0IS7RFqU97wXQ1nCCB9SDx_8gU676ItJLp2WdYIUmlPjYW-D6Ktw5dMfcTMaLPbF7JCOXUEcQQWLCRQK0FZGHmsJPG7FYQDpbvyXTTZCxjDXNI1e-am9CMB6U_J5S936Tt3PFYUvfjnzCLDGN0glOAtC_BsXXOl26cXYRpA9tG-3F6nwwD9ZYYKTvGvo9pXVJbxIrm3i4wkdhUxqKCTIGrnxFuAdZwWi6T3omD5wzZ7bAGbRneEEQSxBmXtvnC6Pr59nPv_v3HrAW9wq_uxYzF_NyaX3GPv0h_FV2T2OSao8C6uoyWiqIj1ggABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v-BZy9pc3N1ZXI"
)

// specBaselineDocument is the Appendix A.1 unsecured document. Note: the spec's
// displayed document (Example 8) shows a different "description" than the value
// the published signature was actually generated over (Example 13 "Add Base
// Transformation"); this uses the value that was signed so the vector reproduces.
func specBaselineDocument() map[string]interface{} {
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(`{
	  "@context": [
	    "https://www.w3.org/ns/credentials/v2",
	    "https://w3id.org/citizenship/v4rc1"
	  ],
	  "type": ["VerifiableCredential", "PermanentResidentCardCredential"],
	  "issuer": {
	    "id": "did:key:zDnaeTHxNEBZoKaEo6PdA83fq98ebiFvo3X273Ydu4YmV96rg",
	    "image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2P4z/DiPwAG0ALnwgz64QAAAABJRU5ErkJggg=="
	  },
	  "name": "Permanent Resident Card",
	  "description": "Permanent Resident Card from Government of Utopia.",
	  "credentialSubject": {
	    "type": ["PermanentResident", "Person"],
	    "givenName": "JANE",
	    "familyName": "SMITH",
	    "gender": "Female",
	    "image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2P4v43hPwAHIgK1v4tX6wAAAABJRU5ErkJggg==",
	    "residentSince": "2015-01-01",
	    "commuterClassification": "C1",
	    "birthCountry": "Arcadia",
	    "birthDate": "1978-07-17",
	    "permanentResidentCard": {
	      "type": ["PermanentResidentCard"],
	      "identifier": "83627465",
	      "lprCategory": "C09",
	      "lprNumber": "999-999-999"
	    }
	  },
	  "validFrom": "2024-12-16T00:00:00Z",
	  "validUntil": "2025-12-16T23:59:59Z"
	}`), &doc); err != nil {
		panic(err)
	}
	return doc
}

func specBaselineProofConfig() map[string]interface{} {
	return map[string]interface{}{
		"type":               "DataIntegrityProof",
		"cryptosuite":        Cryptosuite,
		"created":            "2023-08-15T23:36:38Z",
		"verificationMethod": "did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ#zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ",
		"proofPurpose":       "assertionMethod",
	}
}

// TestSpecVectorVerifySpecSignature checks whether our engine verifies the
// specification's published base signature against the messages our pipeline
// reconstructs. If this passes, our canonicalization, grouping, labels, header
// and messages are spec-correct and any byte difference is purely in the BBS
// Sign primitive (a different but valid signature), not our transform.
func TestSpecVectorVerifySpecSignature(t *testing.T) {
	hmacKey, err := hex.DecodeString(specHMACKeyHex)
	if err != nil {
		t.Fatalf("hmac key: %v", err)
	}
	grouped, err := sd.CanonicalizeAndGroup(
		specBaselineDocument(),
		hmacKey,
		map[string][]string{"mandatory": {"/issuer"}},
	)
	if err != nil {
		t.Fatalf("group: %v", err)
	}
	grouped = normalizeGroupedCanonLabels(grouped)
	mg := grouped.Groups["mandatory"]

	if got := hex.EncodeToString(sd.HashMandatory(mg.Matching)); got != specMandatoryHash {
		t.Fatalf("mandatory hash mismatch\n got: %s\nwant: %s", got, specMandatoryHash)
	}

	proofHash, _ := hex.DecodeString(specProofHash)
	mandatoryHash, _ := hex.DecodeString(specMandatoryHash)
	header := append(append([]byte{}, proofHash...), mandatoryHash...)

	nonMandatory := sd.OrderedValues(mg.NonMatching)
	messages := make([][]byte, len(nonMandatory))
	for i, nq := range nonMandatory {
		messages[i] = []byte(nq)
	}

	pub, _ := hex.DecodeString(specPublicKeyHex)
	sig, _ := hex.DecodeString(specBBSSignature)
	if err := NewZKryptiumEngine().Verify(pub, sig, header, messages); err != nil {
		t.Fatalf("spec signature did NOT verify against our messages: %v", err)
	}
}

// TestSpecVectorA1BaseProof reproduces the W3C base proof byte-for-byte using
// the specification's fixed key pair and HMAC key.
func TestSpecVectorA1BaseProof(t *testing.T) {
	signer, err := NewZKryptiumSignerFromPrivateKeyHex(specPrivateKeyHex)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	if got := hex.EncodeToString(signer.PublicKey()); got != specPublicKeyHex {
		t.Fatalf("public key mismatch\n got: %s\nwant: %s", got, specPublicKeyHex)
	}

	hmacKey, err := hex.DecodeString(specHMACKeyHex)
	if err != nil {
		t.Fatalf("hmac key: %v", err)
	}

	proofValue, err := createBaseProofWithHMACKey(
		specBaselineDocument(),
		specBaselineProofConfig(),
		[]string{"/issuer"},
		signer,
		hmacKey,
	)
	if err != nil {
		t.Fatalf("create base proof: %v", err)
	}

	if proofValue != specBaseProofValue {
		t.Fatalf("base proof value mismatch\n got: %s\nwant: %s", proofValue, specBaseProofValue)
	}

	bp, err := parseBaseProofValue(proofValue)
	if err != nil {
		t.Fatalf("parse base proof: %v", err)
	}
	if got := hex.EncodeToString(bp.BBSSignature); got != specBBSSignature {
		t.Fatalf("bbs signature mismatch\n got: %s\nwant: %s", got, specBBSSignature)
	}
	if len(bp.BBSHeader) != 64 {
		t.Fatalf("bbs header length = %d, want 64", len(bp.BBSHeader))
	}
	if got := hex.EncodeToString(bp.BBSHeader[:32]); got != specProofHash {
		t.Fatalf("proof hash mismatch\n got: %s\nwant: %s", got, specProofHash)
	}
	if got := hex.EncodeToString(bp.BBSHeader[32:]); got != specMandatoryHash {
		t.Fatalf("mandatory hash mismatch\n got: %s\nwant: %s", got, specMandatoryHash)
	}
}
