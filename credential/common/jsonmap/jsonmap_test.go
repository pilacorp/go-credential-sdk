package jsonmap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
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
func nativeBodyHash(t *testing.T, m JSONMap) []byte {
	t.Helper()
	body, err := m.bodyWithoutProof()
	if err != nil {
		t.Fatalf("bodyWithoutProof: %v", err)
	}
	canonical, err := canonicalizeNative(body)
	if err != nil {
		t.Fatalf("canonicalizeNative: %v", err)
	}
	h := sha256.Sum256(canonical)
	return h[:]
}

func TestJSONMap_CanonicalizeNative_CommitsToNumericType(t *testing.T) {
	numeric := testCredential()
	stringy := testCredential()
	stringy["credentialSubject"].(map[string]interface{})["age"] = "30"

	numericHash := nativeBodyHash(t, numeric)
	stringHash := nativeBodyHash(t, stringy)
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
	body, err := m.bodyWithoutProof()
	if err != nil {
		t.Fatalf("bodyWithoutProof: %v", err)
	}
	got, err := canonicalizeNative(body)
	if err != nil {
		t.Fatalf("canonicalizeNative: %v", err)
	}
	if string(got) != wantNQuads {
		t.Fatalf("canonical N-Quads mismatch\n got:\n%s\nwant:\n%s", got, wantNQuads)
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

	docHash := nativeBodyHash(t, m)
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

// ===== proof configuration (section 3.2.5) =====

const proofConfigTestContext = "https://www.w3.org/ns/credentials/v2"

func testProof() *dto.Proof {
	return &dto.Proof{
		Type:               DataIntegrityProof,
		Created:            "2024-01-01T00:00:00Z",
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "assertionMethod",
		Cryptosuite:        ECDSARDFC2019,
	}
}

// TestECDSAProofConfig_ContainsExactlyTheSignedOptions pins the option set that
// ends up in the signature. Adding or removing a key here changes hashData, so
// this test failing means every previously issued credential stops verifying —
// update it only alongside a deliberate spec change.
func TestJSONMap_ECDSAProofConfig_ContainsExactlyTheSignedOptions(t *testing.T) {
	m := JSONMap{"@context": proofConfigTestContext}

	cfg, err := m.ecdsaProofConfig(testProof())
	if err != nil {
		t.Fatalf("ecdsaProofConfig: %v", err)
	}

	gotKeys := make([]string, 0, len(cfg))
	for k := range cfg {
		gotKeys = append(gotKeys, k)
	}
	sort.Strings(gotKeys)

	wantKeys := []string{"@context", "created", "cryptosuite", "proofPurpose", "type", "verificationMethod"}
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Errorf("keys = %v, want %v", gotKeys, wantKeys)
	}

	want := map[string]interface{}{
		"type":               DataIntegrityProof,
		"created":            "2024-01-01T00:00:00Z",
		"verificationMethod": "did:example:issuer#key-1",
		"proofPurpose":       "assertionMethod",
		"cryptosuite":        ECDSARDFC2019,
		"@context":           proofConfigTestContext,
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("cfg = %#v, want %#v", cfg, want)
	}
}

// TestECDSAProofConfig_ExcludesProofValue guards section 3.2.5: the signature
// cannot cover itself, so proofValue must never reach the proof config.
func TestJSONMap_ECDSAProofConfig_ExcludesProofValue(t *testing.T) {
	m := JSONMap{"@context": proofConfigTestContext}

	proof := testProof()
	proof.ProofValue = "zSignatureThatMustNotBeHashed"
	proof.JWS = "header..signature"

	cfg, err := m.ecdsaProofConfig(proof)
	if err != nil {
		t.Fatalf("ecdsaProofConfig: %v", err)
	}

	for _, k := range []string{"proofValue", "jws"} {
		if _, present := cfg[k]; present {
			t.Errorf("%q must not appear in the proof config: %#v", k, cfg)
		}
	}
}

// TestECDSAProofConfig_RequiresContext covers the guard that keeps a document
// without @context from hashing to sha256("") — the proof options only expand
// into N-Quads when a context defines their terms.
func TestJSONMap_ECDSAProofConfig_RequiresContext(t *testing.T) {
	tests := []struct {
		name string
		doc  JSONMap
	}{
		{"key absent", JSONMap{}},
		{"explicit nil", JSONMap{"@context": nil}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.doc.ecdsaProofConfig(testProof()); err == nil {
				t.Fatal("expected an error for a document without @context, got nil")
			}
		})
	}
}

func TestJSONMap_ECDSAProofConfig_RejectsNilProof(t *testing.T) {
	m := JSONMap{"@context": proofConfigTestContext}

	if _, err := m.ecdsaProofConfig(nil); err == nil {
		t.Fatal("expected an error for a nil proof, got nil")
	}
}

// TestECDSAProofConfig_DoesNotAliasTheDocument pins the reason for the ToMap
// round trip: the config is handed to json-gold, and a write through the shared
// @context would corrupt the credential that is about to be signed.
func TestJSONMap_ECDSAProofConfig_DoesNotAliasTheDocument(t *testing.T) {
	const original = proofConfigTestContext
	m := JSONMap{"@context": []interface{}{original}}

	cfg, err := m.ecdsaProofConfig(testProof())
	if err != nil {
		t.Fatalf("ecdsaProofConfig: %v", err)
	}

	cfg["@context"].([]interface{})[0] = "https://attacker.example/context"

	if got := m["@context"].([]interface{})[0]; got != original {
		t.Errorf("writing to the config changed the document's @context: got %q, want %q", got, original)
	}
}

// TestECDSAProofConfig_NormalizesContextTypes covers the other half of the round
// trip: json-gold only understands the types encoding/json produces, and rejects
// a []string @context with "invalid local context".
func TestJSONMap_ECDSAProofConfig_NormalizesContextTypes(t *testing.T) {
	m := JSONMap{"@context": []string{proofConfigTestContext}}

	cfg, err := m.ecdsaProofConfig(testProof())
	if err != nil {
		t.Fatalf("ecdsaProofConfig: %v", err)
	}

	got, ok := cfg["@context"].([]interface{})
	if !ok {
		t.Fatalf("@context = %T, want []interface{}", cfg["@context"])
	}
	if len(got) != 1 || got[0] != proofConfigTestContext {
		t.Errorf("@context = %#v, want [%q]", got, proofConfigTestContext)
	}
}

// TestECDSAProofConfig_MatchesSDOptionSet pins the shared-source guarantee in the
// doc comment: both cryptosuites hash the same option set because both read it
// from proofConfigMapFor. A divergence here means an ecdsa-sd-2023 proof and an
// ecdsa-rdfc-2019 proof no longer commit to the same options.
func TestJSONMap_ECDSAProofConfig_MatchesSDOptionSet(t *testing.T) {
	m := JSONMap{"@context": proofConfigTestContext}
	proof := testProof()

	cfg, err := m.ecdsaProofConfig(proof)
	if err != nil {
		t.Fatalf("ecdsaProofConfig: %v", err)
	}
	delete(cfg, "@context") // the SD path attaches the context further down

	if want := proofConfigMapFor(*proof); !reflect.DeepEqual(cfg, want) {
		t.Errorf("proof config = %#v, want the shared option set %#v", cfg, want)
	}
}

// ===== @context preparation =====

const (
	testContextV1 = "https://www.w3.org/2018/credentials/v1"
	testContextV2 = "https://www.w3.org/ns/credentials/v2"
)

// TestEnsureDataIntegrityContext covers every shape of @context the signing
// path can encounter. The Data Integrity terms must end up defined exactly
// once: the proof config is canonicalized against this @context, so a missing
// term drops the proof options from the hash and a duplicate changes nothing
// but bloats the credential.
func TestJSONMap_EnsureDataIntegrityContext(t *testing.T) {
	tests := []struct {
		name    string
		context interface{} // nil means the key is absent entirely
		setKey  bool
		want    interface{}
	}{
		{
			name:   "absent key gets the data integrity context",
			setKey: false,
			want:   []interface{}{dataIntegrityV2Context},
		},
		{
			name:    "explicit nil is treated as absent",
			context: nil,
			setKey:  true,
			want:    []interface{}{dataIntegrityV2Context},
		},
		{
			name:    "string credentials v2 already covers it",
			context: testContextV2,
			setKey:  true,
			want:    testContextV2,
		},
		{
			name:    "string data integrity context already covers it",
			context: dataIntegrityV2Context,
			setKey:  true,
			want:    dataIntegrityV2Context,
		},
		{
			name:    "uncovered string is promoted to a slice",
			context: testContextV1,
			setKey:  true,
			want:    []interface{}{testContextV1, dataIntegrityV2Context},
		},
		{
			name:    "slice containing credentials v2 is left alone",
			context: []interface{}{testContextV2},
			setKey:  true,
			want:    []interface{}{testContextV2},
		},
		{
			name:    "slice containing the data integrity context is left alone",
			context: []interface{}{testContextV1, dataIntegrityV2Context},
			setKey:  true,
			want:    []interface{}{testContextV1, dataIntegrityV2Context},
		},
		{
			name:    "uncovered slice gets the context appended last",
			context: []interface{}{testContextV1},
			setKey:  true,
			want:    []interface{}{testContextV1, dataIntegrityV2Context},
		},
		{
			name:    "empty slice gets the context",
			context: []interface{}{},
			setKey:  true,
			want:    []interface{}{dataIntegrityV2Context},
		},
		{
			name:    "inline context object is preserved and the context appended",
			context: []interface{}{testContextV1, map[string]interface{}{"foo": "https://example.com/foo"}},
			setKey:  true,
			want: []interface{}{
				testContextV1,
				map[string]interface{}{"foo": "https://example.com/foo"},
				dataIntegrityV2Context,
			},
		},
		{
			name:    "non-string entries do not satisfy the coverage check",
			context: []interface{}{float64(42)},
			setKey:  true,
			want:    []interface{}{float64(42), dataIntegrityV2Context},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := JSONMap{}
			if tc.setKey {
				m["@context"] = tc.context
			}

			m.ensureDataIntegrityContext()

			if got := m["@context"]; !reflect.DeepEqual(got, tc.want) {
				t.Errorf("@context = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// TestEnsureDataIntegrityContext_Idempotent guards the signing path: a
// credential can be re-signed (or carry a second proof), and each pass must not
// append another copy of the context.
func TestJSONMap_EnsureDataIntegrityContext_Idempotent(t *testing.T) {
	for _, start := range []interface{}{
		nil,
		testContextV1,
		testContextV2,
		[]interface{}{testContextV1},
		[]interface{}{testContextV2},
	} {
		m := JSONMap{"@context": start}

		m.ensureDataIntegrityContext()
		afterFirst := m["@context"]

		m.ensureDataIntegrityContext()
		afterSecond := m["@context"]

		if !reflect.DeepEqual(afterFirst, afterSecond) {
			t.Errorf("start %#v: second call changed @context: %#v -> %#v", start, afterFirst, afterSecond)
		}
	}
}

// TestEnsureDataIntegrityContext_DoesNotWriteThroughSharedBacking pins the
// reason the slice branch copies before appending: appending straight onto the
// caller's slice would write into spare capacity it still shares with another
// slice, corrupting a document the caller never handed over.
func TestJSONMap_EnsureDataIntegrityContext_DoesNotWriteThroughSharedBacking(t *testing.T) {
	const sentinel = "https://example.com/untouched"

	shared := []interface{}{testContextV1, sentinel}
	m := JSONMap{"@context": shared[:1]} // len 1, cap 2 — spare slot holds sentinel

	m.ensureDataIntegrityContext()

	if shared[1] != sentinel {
		t.Errorf("spare capacity was overwritten: shared[1] = %#v, want %q", shared[1], sentinel)
	}
	want := []interface{}{testContextV1, dataIntegrityV2Context}
	if got := m["@context"]; !reflect.DeepEqual(got, want) {
		t.Errorf("@context = %#v, want %#v", got, want)
	}
}

// TestEnsureDataIntegrityContext_UnhandledTypesAreLeftAlone documents the
// current gap: the type switch handles nil, string and []interface{} only, so a
// bare inline object or a []string @context passes through untouched and the
// Data Integrity terms are never added.
func TestJSONMap_EnsureDataIntegrityContext_UnhandledTypesAreLeftAlone(t *testing.T) {
	for _, ctx := range []interface{}{
		map[string]interface{}{"foo": "https://example.com/foo"},
		[]string{testContextV1},
	} {
		m := JSONMap{"@context": ctx}

		m.ensureDataIntegrityContext()

		if got := m["@context"]; !reflect.DeepEqual(got, ctx) {
			t.Errorf("@context = %#v, want it unchanged as %#v", got, ctx)
		}
	}
}
