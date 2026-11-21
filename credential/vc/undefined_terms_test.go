package vc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// undefinedTermsV2 is the VCDM 2.0 §5.2 catch-all context.
const undefinedTermsV2 = "https://www.w3.org/ns/credentials/undefined-terms/v2"

// --- Fixed keys for reproducible fixtures ---

const (
	fixtureP256D   = "c9c3e9a9a2a6b3f1d2e4c5b6a7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
	fixtureSecpKey = "4c0883a69102937d6231471b5dbb6204fe512961708279f03a37b1df5a287b08"
	fixtureIssuer  = "did:nda:testnet:fixture-168"
)

// fixtureP256Key builds the fixed P-256 private key from fixtureP256D.
func fixtureP256Key() *ecdsa.PrivateKey {
	d := new(big.Int)
	d.SetString(fixtureP256D, 16)
	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}
}

// --- Backward-compatibility fixtures: signed on main with examples/v2 ---
// These bytes must not change. A credential signed with examples/v2 on main
// must parse, verify, and produce the same Hash() on this branch.

const fixtureP256JSON = `{"@context":["https://www.w3.org/ns/credentials/v2","https://www.w3.org/ns/credentials/examples/v2"],"credentialSubject":{"age":30,"department":"Engineering","id":"did:nda:testnet:fixture-subject","name":"Fixture Test"},"id":"urn:uuid:fixture-168-p256","issuer":"did:nda:testnet:fixture-168","proof":{"created":"2026-11-21T09:55:35Z","cryptosuite":"ecdsa-rdfc-2019","proofPurpose":"assertionMethod","proofValue":"z2C7vPhPWXouR2TfqCWR4SJxpahHfDBjFJCnw3AYErWkgvp4Ppk94JGynTHEomQzscgbnf4Dc2WeZmq8mHa1LZGny","type":"DataIntegrityProof","verificationMethod":"did:nda:testnet:fixture-168#key-p256"},"type":"VerifiableCredential","validFrom":"2024-01-01T00:00:00Z","validUntil":"2099-12-31T23:59:59Z"}`

const fixtureP256Hash = "a24f8fb3293438aa1d43bb6caa66f6c4a2a4b313d4e67569dc3b6f00e4db53f2"

const fixtureSecpJSON = `{"@context":["https://www.w3.org/ns/credentials/v2","https://www.w3.org/ns/credentials/examples/v2","https://w3id.org/security/suites/secp256k1-2019/v1"],"credentialSubject":{"age":30,"department":"Engineering","id":"did:nda:testnet:fixture-subject","name":"Fixture Test"},"id":"urn:uuid:fixture-168-secp","issuer":"did:nda:testnet:fixture-168","proof":{"created":"2026-11-21T09:55:35Z","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..FMC-JWm5hBCT6QXS0KVn1VPe6h4XihiJ9OEOfUB17l0DCGdLr7LfDCYyFaF2DnaOhDlv2WaKo-wzS8H8ioeJag","proofPurpose":"assertionMethod","type":"EcdsaSecp256k1Signature2019","verificationMethod":"did:nda:testnet:fixture-168#key-secp"},"type":"VerifiableCredential","validFrom":"2024-01-01T00:00:00Z","validUntil":"2099-12-31T23:59:59Z"}`

const fixtureSecpHash = "54bfdfca80db5af847edae509beb12921445bc876a221ed8c458e6b068700527"

// failTransport refuses every request, proving no network is used.
type failTransport struct{}

func (failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("network access is forbidden: all contexts must be served from bundled data")
}

// withNoNetwork sets the process-wide document loader HTTP client to one that
// fails on every request, runs fn, then restores the default. The test proves
// that signing and verification use only bundled contexts.
func withNoNetwork(t *testing.T, fn func()) {
	t.Helper()
	processor.SetDocumentLoaderHTTPClient(&http.Client{Transport: failTransport{}})
	defer processor.SetDocumentLoaderHTTPClient(nil)
	fn()
}

// fixtureP256Resolver returns a static resolver for the P-256 fixture key.
func fixtureP256Resolver(t *testing.T) *verificationmethod.StaticResolver {
	t.Helper()
	priv := fixtureP256Key()
	vm, err := verificationmethod.NewP256VM(fixtureIssuer, "key-p256", &priv.PublicKey)
	if err != nil {
		t.Fatalf("p256 vm: %v", err)
	}
	return verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument(fixtureIssuer, vm))
}

// fixtureSecpResolver returns a static resolver for the secp256k1 fixture key.
func fixtureSecpResolver(t *testing.T) *verificationmethod.StaticResolver {
	t.Helper()
	priv, err := ethcrypto.HexToECDSA(fixtureSecpKey)
	if err != nil {
		t.Fatalf("secp key: %v", err)
	}
	pubHex := hex.EncodeToString(ethcrypto.FromECDSAPub(&priv.PublicKey))
	return verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument(fixtureIssuer,
			verificationmethod.NewSecp256k1VM(fixtureIssuer, "key-secp", pubHex)))
}

// --- Backward compatibility: credentials signed with examples/v2 on main ---

func TestFixture_P256_ExamplesV2_ParseVerifyHash(t *testing.T) {
	cred, err := ParseJSONCredential([]byte(fixtureP256JSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	resolver := fixtureP256Resolver(t)
	if err := cred.Verify(WithResolver(resolver)); err != nil {
		t.Fatalf("verify: %v", err)
	}

	hash, err := cred.Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if hash != fixtureP256Hash {
		t.Fatalf("hash mismatch: got %s, want %s", hash, fixtureP256Hash)
	}

	// Round-trip: serialize and compare bytes.
	raw, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	got, _ := json.Marshal(raw)
	if string(got) != fixtureP256JSON {
		t.Fatalf("round-trip bytes differ:\ngot:  %s\nwant: %s", got, fixtureP256JSON)
	}
}

func TestFixture_Secp256k1_ExamplesV2_ParseVerifyHash(t *testing.T) {
	cred, err := ParseJSONCredential([]byte(fixtureSecpJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	resolver := fixtureSecpResolver(t)
	if err := cred.Verify(WithResolver(resolver)); err != nil {
		t.Fatalf("verify: %v", err)
	}

	hash, err := cred.Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if hash != fixtureSecpHash {
		t.Fatalf("hash mismatch: got %s, want %s", hash, fixtureSecpHash)
	}

	raw, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	got, _ := json.Marshal(raw)
	if string(got) != fixtureSecpJSON {
		t.Fatalf("round-trip bytes differ:\ngot:  %s\nwant: %s", got, fixtureSecpJSON)
	}
}

// --- Offline sign-and-verify with undefined-terms/v2 ---

func TestUndefinedTermsV2_P256_SignVerify_NoNetwork(t *testing.T) {
	priv := fixtureP256Key()
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}
	resolver := fixtureP256Resolver(t)

	vcc := CredentialContents{
		Context: []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			undefinedTermsV2,
		},
		ID:     "urn:uuid:test-undefined-terms-p256",
		Types:  []string{"VerifiableCredential"},
		Issuer: fixtureIssuer,
		ValidFrom: func() time.Time {
			t, _ := time.Parse(time.RFC3339, "2024-01-01T00:00:00Z")
			return t
		}(),
		ValidUntil: func() time.Time {
			t, _ := time.Parse(time.RFC3339, "2099-12-31T23:59:59Z")
			return t
		}(),
		Subject: []Subject{{
			ID:           "did:nda:testnet:test-subject",
			CustomFields: map[string]interface{}{"name": "Test", "score": 42},
		}},
	}

	withNoNetwork(t, func() {
		cred, err := NewJSONCredential(vcc)
		if err != nil {
			t.Fatalf("new credential: %v", err)
		}

		err = cred.AddProofByProvider(prov,
			WithVerificationMethodKey("key-p256"),
			WithResolver(resolver))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}

		raw, err := cred.Serialize()
		if err != nil {
			t.Fatalf("serialize: %v", err)
		}
		rawBytes, _ := json.Marshal(raw)

		// Parse and verify the signed credential.
		parsed, err := ParseJSONCredential(rawBytes)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := parsed.Verify(WithResolver(resolver)); err != nil {
			t.Fatalf("verify: %v", err)
		}

		if _, err := parsed.Hash(); err != nil {
			t.Fatalf("hash: %v", err)
		}

		// Confirm undefined-terms/v2 is still the last context.
		ctx := extractContextStrings(t, parsed)
		if len(ctx) == 0 {
			t.Fatal("empty context")
		}
		if ctx[len(ctx)-1] != undefinedTermsV2 {
			t.Fatalf("last context = %v, want %s", ctx[len(ctx)-1], undefinedTermsV2)
		}
	})
}

func TestUndefinedTermsV2_Secp256k1_SignVerify_NoNetwork(t *testing.T) {
	secpPriv, err := ethcrypto.HexToECDSA(fixtureSecpKey)
	if err != nil {
		t.Fatalf("secp key: %v", err)
	}
	_ = secpPriv

	prov, err := signer.NewDefaultProvider(fixtureSecpKey)
	if err != nil {
		t.Fatalf("secp provider: %v", err)
	}
	resolver := fixtureSecpResolver(t)

	vcc := CredentialContents{
		Context: []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			undefinedTermsV2,
		},
		ID:     "urn:uuid:test-undefined-terms-secp",
		Types:  []string{"VerifiableCredential"},
		Issuer: fixtureIssuer,
		ValidFrom: func() time.Time {
			t, _ := time.Parse(time.RFC3339, "2024-01-01T00:00:00Z")
			return t
		}(),
		ValidUntil: func() time.Time {
			t, _ := time.Parse(time.RFC3339, "2099-12-31T23:59:59Z")
			return t
		}(),
		Subject: []Subject{{
			ID:           "did:nda:testnet:test-subject",
			CustomFields: map[string]interface{}{"name": "Test", "score": 42},
		}},
	}

	withNoNetwork(t, func() {
		cred, err := NewJSONCredential(vcc)
		if err != nil {
			t.Fatalf("new credential: %v", err)
		}

		err = cred.AddProofByProvider(prov,
			WithVerificationMethodKey("key-secp"),
			WithResolver(resolver))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}

		raw, err := cred.Serialize()
		if err != nil {
			t.Fatalf("serialize: %v", err)
		}
		rawBytes, _ := json.Marshal(raw)

		parsed, err := ParseJSONCredential(rawBytes)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := parsed.Verify(WithResolver(resolver)); err != nil {
			t.Fatalf("verify: %v", err)
		}

		if _, err := parsed.Hash(); err != nil {
			t.Fatalf("hash: %v", err)
		}

		// The secp256k1 suite context must be inserted before undefined-terms/v2.
		ctx := extractContextStrings(t, parsed)
		if len(ctx) < 3 {
			t.Fatalf("expected at least 3 context entries, got %d: %v", len(ctx), ctx)
		}
		if ctx[len(ctx)-1] != undefinedTermsV2 {
			t.Fatalf("last context = %v, want %s", ctx[len(ctx)-1], undefinedTermsV2)
		}
		if ctx[len(ctx)-2] != "https://w3id.org/security/suites/secp256k1-2019/v1" {
			t.Fatalf("second-to-last context = %v, want secp256k1 suite context", ctx[len(ctx)-2])
		}
	})
}

// --- VP tests with undefined-terms/v2 ---

func TestUndefinedTermsV2_VP_P256_SignVerify_NoNetwork(t *testing.T) {
	// VP tests live in the vp package; this test verifies a credential with
	// undefined-terms/v2 round-trips through the VC sign path with P-256 and
	// no network, which also exercises the Data Integrity context insertion.
	// A full VP signing test is in the vp package's test file.

	prov, err := signer.NewP256Provider(fixtureP256Key())
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}
	resolver := fixtureP256Resolver(t)

	vcc := CredentialContents{
		Context: []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			undefinedTermsV2,
		},
		ID:     "urn:uuid:test-undefined-terms-vp-p256",
		Types:  []string{"VerifiableCredential"},
		Issuer: fixtureIssuer,
		ValidFrom: func() time.Time {
			t, _ := time.Parse(time.RFC3339, "2024-01-01T00:00:00Z")
			return t
		}(),
		ValidUntil: func() time.Time {
			t, _ := time.Parse(time.RFC3339, "2099-12-31T23:59:59Z")
			return t
		}(),
		Subject: []Subject{{
			ID:           "did:nda:testnet:test-subject",
			CustomFields: map[string]interface{}{"name": "Test"},
		}},
	}

	withNoNetwork(t, func() {
		cred, err := NewJSONCredential(vcc)
		if err != nil {
			t.Fatalf("new credential: %v", err)
		}
		err = cred.AddProofByProvider(prov,
			WithVerificationMethodKey("key-p256"),
			WithResolver(resolver))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if err := cred.Verify(WithResolver(resolver)); err != nil {
			t.Fatalf("verify: %v", err)
		}
	})
}

// extractContextStrings reads @context from the credential's serialized form
// and returns its string entries in order.
func extractContextStrings(t *testing.T, cred *JSONCredential) []string {
	t.Helper()
	raw, err := cred.GetContents()
	if err != nil {
		t.Fatalf("GetContents: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	arr, ok := m["@context"].([]interface{})
	if !ok {
		t.Fatalf("@context is not an array: %T", m["@context"])
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
