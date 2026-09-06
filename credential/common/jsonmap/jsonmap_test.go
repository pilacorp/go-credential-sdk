package jsonmap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

type testSigner struct {
	sig []byte
}

func (s *testSigner) Sign(hashPayload []byte) ([]byte, error) {
	if len(hashPayload) != 32 {
		return nil, fmt.Errorf("hash payload must be 32 bytes, got %d", len(hashPayload))
	}
	return s.sig, nil
}

// testCredential returns a minimal but real JSON-LD credential. The @context is
// required: the signing path canonicalizes the proof config against it.
func testCredential() JSONMap {
	return JSONMap{
		"@context": []interface{}{
			"https://www.w3.org/2018/credentials/v1",
			map[string]interface{}{
				"age":  "https://schema.org/age",
				"name": "https://schema.org/name",
			},
		},
		"id":           "urn:uuid:0f7c2d1e-3b4a-4c5d-8e9f-0a1b2c3d4e5f",
		"type":         []interface{}{"VerifiableCredential"},
		"issuer":       "did:example:issuer",
		"issuanceDate": "2024-01-01T00:00:00Z",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
			"age":  30,
		},
	}
}

func proofObject(t *testing.T, m JSONMap) map[string]interface{} {
	t.Helper()
	obj, ok := m["proof"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected proof to be a map, got %T", m["proof"])
	}
	return obj
}

func TestJSONMap_AddECDSAProof_Accepts64ByteSignature(t *testing.T) {
	m := testCredential()

	sig64 := make([]byte, 64)
	for i := range sig64 {
		sig64[i] = 0xAB
	}

	if err := (&m).AddECDSAProof(&testSigner{sig: sig64}, "did:example:issuer#key-1", "assertionMethod"); err != nil {
		t.Fatalf("AddECDSAProof error: %v", err)
	}

	pv, _ := proofObject(t, m)["proofValue"].(string)
	raw, err := verificationmethod.DecodeMultibaseKey(pv)
	if err != nil {
		t.Fatalf("proofValue is not multibase base58btc: %v", err)
	}
	if len(raw) != 64 {
		t.Fatalf("decoded proofValue length = %d, want 64", len(raw))
	}
}

func TestJSONMap_AddECDSAProof_Accepts65ByteSignature(t *testing.T) {
	m := testCredential()

	sig65 := make([]byte, 65)
	for i := range sig65 {
		sig65[i] = 0xCD
	}

	if err := (&m).AddECDSAProof(&testSigner{sig: sig65}, "did:example:issuer#key-1", "assertionMethod"); err != nil {
		t.Fatalf("AddECDSAProof error: %v", err)
	}

	pv, _ := proofObject(t, m)["proofValue"].(string)
	raw, err := verificationmethod.DecodeMultibaseKey(pv)
	if err != nil {
		t.Fatalf("proofValue is not multibase base58btc: %v", err)
	}
	if len(raw) != 65 {
		t.Fatalf("decoded proofValue length = %d, want 65", len(raw))
	}
}

// A non-secp256k1-shaped signature (e.g. an RSA signer mis-routed to a
// secp256k1 VM) must be rejected at signing time, not stored silently.
func TestJSONMap_AddECDSAProof_RejectsNonECDSASignature(t *testing.T) {
	m := testCredential()

	err := (&m).AddECDSAProof(&testSigner{sig: make([]byte, 256)}, "did:example:issuer#key-1", "assertionMethod")
	if err == nil {
		t.Fatalf("expected error for non-64/65-byte signature")
	}
}

// ===== ecdsa-rdfc-2019, Data Integrity ECDSA Cryptosuites v1.0 section 3.2 =====

const testPrivHex = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"

func testKeyPair(t *testing.T) (signer.SignerProvider, string) {
	t.Helper()
	priv, err := ethcrypto.HexToECDSA(testPrivHex)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	sp, err := signer.NewDefaultProvider(testPrivHex)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return sp, hex.EncodeToString(ethcrypto.FromECDSAPub(&priv.PublicKey))
}

func TestJSONMap_AddECDSAProof_RoundTripsThroughSpecConformantBranch(t *testing.T) {
	sp, pubHex := testKeyPair(t)
	m := testCredential()

	if err := (&m).AddECDSAProof(sp, "did:example:issuer#key-1", "assertionMethod"); err != nil {
		t.Fatalf("AddECDSAProof error: %v", err)
	}

	proof, err := ParseRawToProof(m.getFirstProof())
	if err != nil {
		t.Fatalf("parse proof: %v", err)
	}
	if !strings.HasPrefix(proof.ProofValue, multibaseBase58BTCPrefix) {
		t.Fatalf("proofValue is not multibase base58btc: %s", proof.ProofValue)
	}

	ok, err := m.verifyECDSA(pubHex, &proof)
	if err != nil {
		t.Fatalf("verifyECDSA error: %v", err)
	}
	if !ok {
		t.Fatalf("freshly signed proof failed to verify")
	}
}

// Proof options are now inside the signature, so editing one invalidates it.
// proof.created matters most: strictPurposeCheck compares it to the key's
// revocation timestamp.
func TestJSONMap_VerifyECDSA_RejectsTamperedProofOptions(t *testing.T) {
	sp, pubHex := testKeyPair(t)

	for _, field := range []string{"created", "proofPurpose", "verificationMethod", "cryptosuite", "type"} {
		t.Run(field, func(t *testing.T) {
			m := testCredential()
			if err := (&m).AddECDSAProof(sp, "did:example:issuer#key-1", "assertionMethod"); err != nil {
				t.Fatalf("AddECDSAProof error: %v", err)
			}

			proof, err := ParseRawToProof(m.getFirstProof())
			if err != nil {
				t.Fatalf("parse proof: %v", err)
			}
			switch field {
			case "created":
				proof.Created = "2000-01-01T00:00:00Z"
			case "proofPurpose":
				proof.ProofPurpose = "authentication"
			case "verificationMethod":
				proof.VerificationMethod = "did:example:issuer#key-2"
			case "cryptosuite":
				proof.Cryptosuite = "ecdsa-jcs-2019"
			case "type":
				proof.Type = "SomeOtherProof"
			}

			ok, err := m.verifyECDSA(pubHex, &proof)
			if err == nil && ok {
				t.Fatalf("tampered %s verified successfully", field)
			}
		})
	}
}

// Editing the credential body must still invalidate the signature.
func TestJSONMap_VerifyECDSA_RejectsTamperedBody(t *testing.T) {
	sp, pubHex := testKeyPair(t)
	m := testCredential()

	if err := (&m).AddECDSAProof(sp, "did:example:issuer#key-1", "assertionMethod"); err != nil {
		t.Fatalf("AddECDSAProof error: %v", err)
	}
	proof, err := ParseRawToProof(m.getFirstProof())
	if err != nil {
		t.Fatalf("parse proof: %v", err)
	}
	m["credentialSubject"].(map[string]interface{})["name"] = "Mallory"

	ok, err := m.verifyECDSA(pubHex, &proof)
	if err == nil && ok {
		t.Fatalf("tampered body verified successfully")
	}
}

// The signature now commits to the JSON type of numeric claims: 30 and "30" no
// longer hash to the same bytes.
func TestJSONMap_CanonicalizeNative_CommitsToNumericType(t *testing.T) {
	numeric := testCredential()
	stringy := testCredential()
	stringy["credentialSubject"].(map[string]interface{})["age"] = "30"

	numericHash, err := numeric.canonicalizeNative()
	if err != nil {
		t.Fatalf("canonicalizeNative(numeric): %v", err)
	}
	stringHash, err := stringy.canonicalizeNative()
	if err != nil {
		t.Fatalf("canonicalizeNative(string): %v", err)
	}
	if hex.EncodeToString(numericHash) == hex.EncodeToString(stringHash) {
		t.Fatalf(`"age": 30 and "age": "30" produced the same digest`)
	}

	// The legacy path coerces both to xsd:string and cannot tell them apart.
	legacyNumeric, err := numeric.Canonicalize()
	if err != nil {
		t.Fatalf("Canonicalize(numeric): %v", err)
	}
	legacyString, err := stringy.Canonicalize()
	if err != nil {
		t.Fatalf("Canonicalize(string): %v", err)
	}
	if hex.EncodeToString(legacyNumeric) != hex.EncodeToString(legacyString) {
		t.Fatalf("legacy Canonicalize unexpectedly distinguishes 30 from \"30\"; this test documents the behaviour the new path fixes")
	}
}

// Oracle: hand-written canonical N-Quads must be exactly what the signer hashes.
func TestJSONMap_CanonicalizeNative_MatchesExpectedNQuads(t *testing.T) {
	const wantNQuads = `<did:example:subject> <https://schema.org/age> "30"^^<http://www.w3.org/2001/XMLSchema#integer> .
<did:example:subject> <https://schema.org/name> "Alice" .
<urn:uuid:0f7c2d1e-3b4a-4c5d-8e9f-0a1b2c3d4e5f> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<urn:uuid:0f7c2d1e-3b4a-4c5d-8e9f-0a1b2c3d4e5f> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:subject> .
<urn:uuid:0f7c2d1e-3b4a-4c5d-8e9f-0a1b2c3d4e5f> <https://www.w3.org/2018/credentials#issuanceDate> "2024-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<urn:uuid:0f7c2d1e-3b4a-4c5d-8e9f-0a1b2c3d4e5f> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer> .
`

	m := testCredential()
	got, err := m.canonicalizeNative()
	if err != nil {
		t.Fatalf("canonicalizeNative: %v", err)
	}
	want := sha256.Sum256([]byte(wantNQuads))
	if hex.EncodeToString(got) != hex.EncodeToString(want[:]) {
		body, _ := m.bodyWithoutProof()
		nq, _, cErr := processor.CanonicalizeWithIdMap(body)
		t.Fatalf("transformedDocumentHash mismatch\n got: %s\nwant: %s\nactual N-Quads (%v):\n%s",
			hex.EncodeToString(got), hex.EncodeToString(want[:]), cErr, strings.Join(nq, ""))
	}
}

// Oracle: hashData is proofConfigHash || transformedDocumentHash, each SHA-256
// of independently reconstructed canonical N-Quads.
func TestJSONMap_ECDSAHashData_MatchesExpectedConcatenation(t *testing.T) {
	const wantProofConfigNQuads = `_:c14n0 <http://purl.org/dc/terms/created> "2024-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:c14n0 <https://w3id.org/security#cryptosuite> "ecdsa-rdfc-2019"^^<https://w3id.org/security#cryptosuiteString> .
_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:c14n0 <https://w3id.org/security#verificationMethod> <did:example:issuer#key-1> .
`

	m := testCredential()
	m.ensureDataIntegrityContext()

	proof := &dto.Proof{
		Type:               DataIntegrityProof,
		Cryptosuite:        ECDSARDFC2019,
		Created:            "2024-01-01T00:00:00Z",
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "assertionMethod",
	}

	hashData, err := m.ecdsaHashData(proof)
	if err != nil {
		t.Fatalf("ecdsaHashData: %v", err)
	}
	if len(hashData) != 64 {
		t.Fatalf("hashData length = %d, want 64", len(hashData))
	}

	docHash, err := m.canonicalizeNative()
	if err != nil {
		t.Fatalf("canonicalizeNative: %v", err)
	}
	if hex.EncodeToString(hashData[32:]) != hex.EncodeToString(docHash) {
		t.Fatalf("hashData[32:] is not transformedDocumentHash")
	}

	// A missing statement here is a proof option that fell outside the signature.
	cfg, err := m.ecdsaProofConfig(proof)
	if err != nil {
		t.Fatalf("ecdsaProofConfig: %v", err)
	}
	nq, _, err := processor.CanonicalizeWithIdMap(cfg)
	if err != nil {
		t.Fatalf("canonicalize proof config: %v", err)
	}
	if joined := strings.Join(nq, ""); joined != wantProofConfigNQuads {
		t.Fatalf("proof config N-Quads mismatch\n got:\n%s\nwant:\n%s", joined, wantProofConfigNQuads)
	}

	cfgHash := sha256.Sum256([]byte(wantProofConfigNQuads))
	if hex.EncodeToString(hashData[:32]) != hex.EncodeToString(cfgHash[:]) {
		t.Fatalf("hashData[:32] is not proofConfigHash")
	}
}

// A "z" proofValue that carries no usable signature must error, not fall
// through to the legacy branch.
func TestJSONMap_VerifyECDSA_RejectsMalformedMultibaseProofValue(t *testing.T) {
	_, pubHex := testKeyPair(t)

	cases := map[string]string{
		// 0, O, I and l are not in the base58 alphabet.
		"undecodable": "z0OIl",
		// Decodes cleanly, but is not a 64/65-byte secp256k1 signature.
		"wrong length": verificationmethod.EncodeMultibaseKey(make([]byte, 32)),
	}

	for name, proofValue := range cases {
		t.Run(name, func(t *testing.T) {
			m := testCredential()
			proof := &dto.Proof{
				Type:               DataIntegrityProof,
				Cryptosuite:        ECDSARDFC2019,
				Created:            "2024-01-01T00:00:00Z",
				VerificationMethod: "did:example:issuer#key-1",
				ProofPurpose:       "assertionMethod",
				ProofValue:         proofValue,
			}

			if _, err := m.verifyECDSA(pubHex, proof); err == nil {
				t.Fatalf("expected an error for proofValue %q", proofValue)
			}
		})
	}
}
