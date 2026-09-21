package vc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// A fixed secp256k1 scalar keeps these tests deterministic.
const suiteSecpPriv = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

// mkVC11CredentialJSON builds a VC 1.1 document, the shape the
// EcdsaSecp256k1Signature2019 suite belongs to.
func mkVC11CredentialJSON(issuerDID string) []byte {
	return []byte(fmt.Sprintf(`{
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        {"@vocab": "https://example.org/vocab#"}
      ],
      "id": "urn:uuid:secp-suite-vc-001",
      "type": ["VerifiableCredential", "IdentityCredential"],
      "issuer": %q,
      "issuanceDate": "2026-01-01T00:00:00Z",
      "credentialSubject": {
        "id": "did:example:subject",
        "name": "Nguyen Van A"
      }
    }`, issuerDID))
}

// proofOf returns the credential's single proof object.
func proofOf(t *testing.T, cred vc.Credential) map[string]interface{} {
	t.Helper()
	raw, err := cred.GetContents()
	if err != nil {
		t.Fatalf("contents: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	switch p := doc["proof"].(type) {
	case map[string]interface{}:
		return p
	case []interface{}:
		if len(p) != 1 {
			t.Fatalf("want exactly one proof, got %d", len(p))
		}
		m, ok := p[0].(map[string]interface{})
		if !ok {
			t.Fatalf("proof[0] is %T, want object", p[0])
		}
		return m
	default:
		t.Fatalf("proof is %T, want object or array", doc["proof"])
		return nil
	}
}

func secpResolver(t *testing.T, did string) vmpkg.ResolverProvider {
	t.Helper()
	return vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(did, vmpkg.NewSecp256k1VM(did, "key-1", pubHex(t, suiteSecpPriv))))
}

func secpProvider(t *testing.T) signer.SignerProvider {
	t.Helper()
	p, err := signer.NewDefaultProvider(suiteSecpPriv)
	if err != nil {
		t.Fatalf("secp provider: %v", err)
	}
	return p
}

// TestSecp256k1Suite_IssueVerify is the round trip the whole suite exists for:
// a secp256k1 issuer key signs a VC 1.1 credential and the SDK verifies it.
func TestSecp256k1Suite_IssueVerify(t *testing.T) {
	const did = "did:example:secp-suite-vc"
	resolver := secpResolver(t, did)

	cred, err := vc.ParseJSONCredential(mkVC11CredentialJSON(did))
	if err != nil {
		t.Fatalf("parse credential: %v", err)
	}
	if err := cred.AddProofByProvider(
		secpProvider(t),
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(resolver),
	); err != nil {
		t.Fatalf("add proof: %v", err)
	}

	if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestSecp256k1Suite_ProofShape pins the wire format against
// https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/: type, a detached JWS in
// `jws` with alg ES256K / b64:false / crit:[b64], and no proofValue.
func TestSecp256k1Suite_ProofShape(t *testing.T) {
	const did = "did:example:secp-suite-shape"
	resolver := secpResolver(t, did)

	cred, err := vc.ParseJSONCredential(mkVC11CredentialJSON(did))
	if err != nil {
		t.Fatalf("parse credential: %v", err)
	}
	if err := cred.AddProofByProvider(
		secpProvider(t),
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(resolver),
	); err != nil {
		t.Fatalf("add proof: %v", err)
	}

	proof := proofOf(t, cred)

	if got := proof["type"]; got != "EcdsaSecp256k1Signature2019" {
		t.Errorf("proof.type = %v, want EcdsaSecp256k1Signature2019", got)
	}
	if _, ok := proof["proofValue"]; ok {
		t.Error("proof carries proofValue; the suite signs into jws")
	}
	if got := proof["cryptosuite"]; got != nil {
		t.Errorf("proof.cryptosuite = %v, want absent (not a Data Integrity proof)", got)
	}

	jws, ok := proof["jws"].(string)
	if !ok || jws == "" {
		t.Fatalf("proof.jws = %v, want a detached JWS string", proof["jws"])
	}
	// Detached JWS: header..signature, with an empty payload segment.
	parts := strings.Split(jws, ".")
	if len(parts) != 3 || parts[1] != "" {
		t.Fatalf("jws = %q, want a detached JWS (header..signature)", jws)
	}
	// The spec's header, byte for byte:
	// {"alg":"ES256K","b64":false,"crit":["b64"]}
	const wantHeader = "eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ"
	if parts[0] != wantHeader {
		t.Errorf("jws header = %q, want %q", parts[0], wantHeader)
	}
}

// TestSecp256k1Suite_ContextLeftAlone checks a VC 1.1 document keeps the
// @context it was issued with. credentials/v1 already defines the suite, and
// its terms are @protected, so layering another security context on top is a
// redefinition the canonicalizer rejects outright.
func TestSecp256k1Suite_ContextLeftAlone(t *testing.T) {
	const did = "did:example:secp-suite-ctx"
	resolver := secpResolver(t, did)

	cred, err := vc.ParseJSONCredential(mkVC11CredentialJSON(did))
	if err != nil {
		t.Fatalf("parse credential: %v", err)
	}
	if err := cred.AddProofByProvider(
		secpProvider(t),
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(resolver),
	); err != nil {
		t.Fatalf("add proof: %v", err)
	}

	raw, err := cred.GetContents()
	if err != nil {
		t.Fatalf("contents: %v", err)
	}
	if strings.Contains(string(raw), "https://w3id.org/security/v2") {
		t.Errorf("suite context was added to a VC 1.1 document that already defines the suite:\n%s", raw)
	}
	if !strings.Contains(string(raw), "https://www.w3.org/2018/credentials/v1") {
		t.Errorf("document lost its own @context:\n%s", raw)
	}
}

// TestSecp256k1Suite_SuiteFollowsTheKey checks the suite is never named by the
// caller:
// on a VC 1.1 document the suite follows the verification method's key, because
// the key is what decides which suites apply at all. The data model cannot
// decide it — a 1.1 document takes either suite.
func TestSecp256k1Suite_SuiteFollowsTheKey(t *testing.T) {
	p256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	p256VM := mustP256VM(t, "did:example:suite-by-key", "key-p256", &p256Priv.PublicKey)
	secpVM := vmpkg.NewSecp256k1VM("did:example:suite-by-key", "key-secp", pubHex(t, suiteSecpPriv))
	resolver := vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument("did:example:suite-by-key", p256VM, secpVM))

	cases := []struct {
		name      string
		kid       string
		provider  func(t *testing.T) signer.SignerProvider
		wantType  string
		wantSuite string // cryptosuite, empty when the suite has none
	}{
		{
			name:     "secp256k1 key",
			kid:      "key-secp",
			provider: secpProvider,
			wantType: "EcdsaSecp256k1Signature2019",
		},
		{
			name: "P-256 key on the same VC 1.1 document",
			kid:  "key-p256",
			provider: func(t *testing.T) signer.SignerProvider {
				p, err := signer.NewP256Provider(p256Priv)
				if err != nil {
					t.Fatalf("p256 provider: %v", err)
				}
				return p
			},
			wantType:  "DataIntegrityProof",
			wantSuite: "ecdsa-rdfc-2019",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := vc.ParseJSONCredential(mkVC11CredentialJSON("did:example:suite-by-key"))
			if err != nil {
				t.Fatalf("parse credential: %v", err)
			}
			// The caller names no suite — only the key and the document.
			if err := cred.AddProofByProvider(tc.provider(t),
				vc.WithVerificationMethodKey(tc.kid),
				vc.WithResolver(resolver)); err != nil {
				t.Fatalf("add proof: %v", err)
			}

			proof := proofOf(t, cred)
			if got := proof["type"]; got != tc.wantType {
				t.Errorf("proof.type = %v, want %s", got, tc.wantType)
			}
			if got, _ := proof["cryptosuite"].(string); got != tc.wantSuite {
				t.Errorf("proof.cryptosuite = %q, want %q", got, tc.wantSuite)
			}
			if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
				t.Fatalf("verify: %v", err)
			}
		})
	}
}

// TestSecp256k1Suite_RejectsVC2Document is the spec boundary: the suite belongs
// to VC Data Model 1.1, and the 2.0 Data Integrity cryptosuites cover P-256 and
// P-384 only. Signing a 2.0 document with it must fail loudly rather than have
// the SDK bolt a security context on and produce a combination no
// specification covers.
func TestSecp256k1Suite_RejectsVC2Document(t *testing.T) {
	const did = "did:example:secp-suite-vc2"
	resolver := secpResolver(t, did)

	cred, err := vc.ParseJSONCredential(mkCredentialJSON(did)) // VC 2.0 context
	if err != nil {
		t.Fatalf("parse credential: %v", err)
	}
	err = cred.AddProofByProvider(
		secpProvider(t),
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(resolver),
	)
	if err == nil {
		t.Fatal("signed a VC 2.0 document with a VC 1.1 suite")
	}
	for _, want := range []string{"VC Data Model 1.1", "WithDataModel11"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q, so it does not tell the caller what to do: %v", want, err)
		}
	}
}

// TestSecp256k1Suite_DataModel11Builder covers the path a caller actually takes:
// build the credential as VC 1.1 from CredentialContents, then sign it with the
// suite — no hand-written JSON.
func TestSecp256k1Suite_DataModel11Builder(t *testing.T) {
	const did = "did:example:secp-suite-builder"
	resolver := secpResolver(t, did)

	cred, err := vc.NewJSONCredential(vc.CredentialContents{
		// No @context: the data model supplies credentials/v1.
		ID:         "urn:uuid:builder-001",
		Types:      []string{"VerifiableCredential"},
		Issuer:     did,
		ValidFrom:  time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC),
		ValidUntil: time.Date(2027, 9, 21, 0, 0, 0, 0, time.UTC),
		Subject:    []vc.Subject{{ID: "did:example:subject"}},
	}, vc.WithDataModel11())
	if err != nil {
		t.Fatalf("new credential: %v", err)
	}

	raw, err := cred.GetContents()
	if err != nil {
		t.Fatalf("contents: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// VC 1.1 names the validity period issuanceDate / expirationDate.
	if got := doc["issuanceDate"]; got != "2026-09-21T00:00:00Z" {
		t.Errorf("issuanceDate = %v, want the validFrom value", got)
	}
	if got := doc["expirationDate"]; got != "2027-09-21T00:00:00Z" {
		t.Errorf("expirationDate = %v, want the validUntil value", got)
	}
	if _, ok := doc["validFrom"]; ok {
		t.Error("document carries validFrom, a VC 2.0 property")
	}
	if !strings.Contains(string(raw), "https://www.w3.org/2018/credentials/v1") {
		t.Errorf("@context is not the VC 1.1 base context:\n%s", raw)
	}

	if err := cred.AddProofByProvider(
		secpProvider(t),
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(resolver),
	); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestSecp256k1Suite_DataModelContextMismatch checks the builder refuses to put
// a 2.0 base context on a 1.1 document. Rewriting it instead would leave
// credentialStatus.type, credentialSchema.type and any 2.0-only property
// declaring a data model the document no longer claims.
func TestSecp256k1Suite_DataModelContextMismatch(t *testing.T) {
	_, err := vc.NewJSONCredential(vc.CredentialContents{
		Context: []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:      "urn:uuid:mismatch-001",
		Types:   []string{"VerifiableCredential"},
		Issuer:  "did:example:issuer",
		Subject: []vc.Subject{{ID: "did:example:subject"}},
	}, vc.WithDataModel11())
	if err == nil {
		t.Fatal("built a VC 1.1 credential on the VC 2.0 base context")
	}
	if !strings.Contains(err.Error(), "VC Data Model 1.1") {
		t.Errorf("error does not name the mismatch: %v", err)
	}
}

// TestSecp256k1Suite_LegacyHexProofStillVerifies guards the compatibility
// boundary: the same proof type name was used by the pre-v1.8.0 in-house
// format, which carries a hex proofValue instead of a jws. Credentials already
// issued that way must keep verifying.
func TestSecp256k1Suite_LegacyHexProofStillVerifies(t *testing.T) {
	const did = "did:example:secp-suite-legacy"
	resolver := secpResolver(t, did)

	legacy := []byte(`{
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      "id": "urn:uuid:legacy-hex-001",
      "type": ["VerifiableCredential"],
      "issuer": "did:example:secp-suite-legacy",
      "issuanceDate": "2026-01-01T00:00:00Z",
      "credentialSubject": {"id": "did:example:subject"},
      "proof": {
        "type": "EcdsaSecp256k1Signature2019",
        "created": "2026-01-01T00:00:00Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "deadbeef",
        "proofValue": "00"
      }
    }`)

	cred, err := vc.ParseJSONCredential(legacy)
	if err != nil {
		t.Fatalf("parse credential: %v", err)
	}
	// The signature is not valid, so this must fail — but it must fail inside
	// the legacy verifier, not by being routed to the new suite verifier or by
	// being rejected as an unknown proof type.
	err = cred.Verify(vc.WithResolver(resolver))
	if err == nil {
		t.Fatal("expected the bogus legacy signature to fail")
	}
	for _, wrong := range []string{"malformed detached JWS", "unsupported proof type", "does not hold a secp256k1 key"} {
		if strings.Contains(err.Error(), wrong) {
			t.Fatalf("legacy hex proof was routed to the new suite verifier: %v", err)
		}
	}
}

// TestSecp256k1Suite_TamperedProofOptions checks the signature covers the proof
// configuration, not just the document body: rewriting created after issuance
// must fail verification.
func TestSecp256k1Suite_TamperedProofOptions(t *testing.T) {
	const did = "did:example:secp-suite-tamper"
	resolver := secpResolver(t, did)

	cred, err := vc.ParseJSONCredential(mkVC11CredentialJSON(did))
	if err != nil {
		t.Fatalf("parse credential: %v", err)
	}
	if err := cred.AddProofByProvider(
		secpProvider(t),
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(resolver),
	); err != nil {
		t.Fatalf("add proof: %v", err)
	}

	raw, err := cred.GetContents()
	if err != nil {
		t.Fatalf("contents: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	proof, ok := doc["proof"].(map[string]interface{})
	if !ok {
		list, isList := doc["proof"].([]interface{})
		if !isList || len(list) == 0 {
			t.Fatalf("unexpected proof shape %T", doc["proof"])
		}
		proof = list[0].(map[string]interface{})
	}
	proof["created"] = "2001-01-01T00:00:00Z"

	tampered, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	reparsed, err := vc.ParseJSONCredential(tampered)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if err := reparsed.Verify(vc.WithResolver(resolver)); err == nil {
		t.Fatal("verify accepted a credential whose proof.created was rewritten after signing")
	}
}

// TestSecp256k1Suite_WrongCurveSigner checks the curve is enforced, not just
// the key: a P-256 signer bound to a secp256k1 verification method picks the
// right suite for that VM but cannot produce a signature it verifies against.
// Without the self-check this would leave the issuer holding a credential that
// only fails at somebody else's verifier.
func TestSecp256k1Suite_WrongCurveSigner(t *testing.T) {
	const did = "did:example:secp-suite-curve"

	p256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	p256Prov, err := signer.NewP256Provider(p256Priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	// The DID publishes a secp256k1 key; the signer holds a P-256 one.
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did,
		vmpkg.NewSecp256k1VM(did, "key-1", pubHex(t, suiteSecpPriv))))

	cred, err := vc.ParseJSONCredential(mkVC11CredentialJSON(did))
	if err != nil {
		t.Fatalf("parse credential: %v", err)
	}
	err = cred.AddProofByProvider(p256Prov,
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(resolver))
	if err == nil || !strings.Contains(err.Error(), "does not verify against verification method") {
		t.Fatalf("add proof err = %v, want the wrong-key rejection", err)
	}
}

// TestSecp256k1Suite_WrongSignerRejected checks a signer that does not hold the
// bound verification method's key fails at signing time rather than at the
// verifier.
func TestSecp256k1Suite_WrongSignerRejected(t *testing.T) {
	const did = "did:example:secp-suite-wrong-signer"
	const otherPriv = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"

	resolver := secpResolver(t, did) // publishes suiteSecpPriv's public key

	other, err := signer.NewDefaultProvider(otherPriv)
	if err != nil {
		t.Fatalf("other provider: %v", err)
	}

	cred, err := vc.ParseJSONCredential(mkVC11CredentialJSON(did))
	if err != nil {
		t.Fatalf("parse credential: %v", err)
	}
	err = cred.AddProofByProvider(other,
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(resolver))
	if err == nil || !strings.Contains(err.Error(), "does not verify against verification method") {
		t.Fatalf("add proof err = %v, want the wrong-signer rejection", err)
	}
}
