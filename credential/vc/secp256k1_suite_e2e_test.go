package vc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsoncanonicalizer"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// A fixed secp256k1 scalar keeps these tests deterministic.
const suiteSecpPriv = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

// mkSuiteCredentialJSON builds the VC 2.0 document these tests sign. @vocab
// keeps the custom credentialSubject terms defined so canonicalization stays
// in SafeMode.
func mkSuiteCredentialJSON(issuerDID string) []byte {
	return []byte(fmt.Sprintf(`{
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        {"@vocab": "https://example.org/vocab#"}
      ],
      "id": "urn:uuid:secp-suite-vc-001",
      "type": ["VerifiableCredential", "IdentityCredential"],
      "issuer": %q,
      "validFrom": "2026-01-01T00:00:00Z",
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
// a secp256k1 issuer key signs a credential and the SDK verifies it.
func TestSecp256k1Suite_IssueVerify(t *testing.T) {
	const did = "did:example:secp-suite-vc"
	resolver := secpResolver(t, did)

	cred, err := vc.ParseJSONCredential(mkSuiteCredentialJSON(did))
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

	cred, err := vc.ParseJSONCredential(mkSuiteCredentialJSON(did))
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

// TestSecp256k1Suite_ContextLeftAlone checks the SDK adds the suite context
// only when the document does not already define the suite. A caller who put
// security/v2 on the document themselves keeps exactly that: adding a second
// definition of the same @protected terms is a redefinition the canonicalizer
// rejects outright.
func TestSecp256k1Suite_ContextLeftAlone(t *testing.T) {
	const did = "did:example:secp-suite-ctx"
	resolver := secpResolver(t, did)

	raw := []byte(fmt.Sprintf(`{
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://w3id.org/security/v2"
      ],
      "id": "urn:uuid:secp-suite-ctx-001",
      "type": ["VerifiableCredential"],
      "issuer": %q,
      "validFrom": "2026-01-01T00:00:00Z",
      "credentialSubject": {"id": "did:example:subject"}
    }`, did))

	cred, err := vc.ParseJSONCredential(raw)
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

	contents, err := cred.GetContents()
	if err != nil {
		t.Fatalf("contents: %v", err)
	}
	if strings.Contains(string(contents), "https://w3id.org/security/suites/secp256k1-2019/v1") {
		t.Errorf("a second suite context was added to a document that already defines the suite:\n%s", contents)
	}
	if !strings.Contains(string(contents), "https://w3id.org/security/v2") {
		t.Errorf("document lost the context it was built with:\n%s", contents)
	}
}

// TestSecp256k1Suite_SuiteFollowsTheKey checks the suite is never named by the
// caller:
// on a document the suite follows the verification method's key, because
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
			name: "P-256 key on the same document",
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
			cred, err := vc.ParseJSONCredential(mkSuiteCredentialJSON("did:example:suite-by-key"))
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

// TestSecp256k1Suite_SignsVC2Document is the point of the whole change: the
// deployment's keys are secp256k1 and its documents are VC 2.0. credentials/v2
// defines Data Integrity only, so the SDK adds the suite's own context, and
// the 2.0 properties the deployment depends on — BitstringStatusListEntry
// above all — survive it.
func TestSecp256k1Suite_SignsVC2Document(t *testing.T) {
	const did = "did:example:secp-suite-vc2"
	resolver := secpResolver(t, did)

	raw := []byte(fmt.Sprintf(`{
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      "id": "urn:uuid:secp-suite-vc2-001",
      "type": ["VerifiableCredential"],
      "issuer": %q,
      "validFrom": "2026-01-01T00:00:00Z",
      "credentialStatus": {
        "id": "https://example.org/status/1#94567",
        "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation",
        "statusListIndex": "94567",
        "statusListCredential": "https://example.org/status/1"
      },
      "credentialSubject": {"id": "did:example:subject"}
    }`, did))

	cred, err := vc.ParseJSONCredential(raw)
	if err != nil {
		t.Fatalf("parse credential: %v", err)
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

	proof := proofOf(t, cred)
	if proof["type"] != "EcdsaSecp256k1Signature2019" {
		t.Fatalf("proof type = %v, want EcdsaSecp256k1Signature2019", proof["type"])
	}
	if _, ok := proof["jws"].(string); !ok {
		t.Fatalf("proof carries no jws: %v", proof)
	}
	if _, ok := proof["cryptosuite"]; ok {
		t.Fatalf("this suite names itself in type; cryptosuite must be absent: %v", proof)
	}

	contents, err := cred.GetContents()
	if err != nil {
		t.Fatalf("contents: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(contents, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	ctx, ok := doc["@context"].([]interface{})
	if !ok {
		t.Fatalf("@context is %T, want an array", doc["@context"])
	}
	if ctx[0] != "https://www.w3.org/ns/credentials/v2" {
		t.Fatalf("the base context must stay first, got %v", ctx)
	}
	var hasSuite bool
	for _, c := range ctx {
		if c == "https://w3id.org/security/suites/secp256k1-2019/v1" {
			hasSuite = true
		}
	}
	if !hasSuite {
		t.Fatalf("@context does not carry the suite context: %v", ctx)
	}
	status, ok := doc["credentialStatus"].(map[string]interface{})
	if !ok || status["type"] != "BitstringStatusListEntry" {
		t.Fatalf("the 2.0 status entry did not survive: %v", doc["credentialStatus"])
	}
}

// TestSecp256k1Suite_ProofCarryingItsOwnKeyIsRefused covers #89. A proof whose
// verificationMethod holds a raw public key instead of a DID URL used to reach
// a verifier that checked the signature against that very key, so a document
// nobody with a published key had signed verified. The refusal now happens
// before any signature math, in didForProof: a verificationMethod that is not a
// DID URL names no key in anybody's DID document.
func TestSecp256k1Suite_ProofCarryingItsOwnKeyIsRefused(t *testing.T) {
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
	err = cred.Verify(vc.WithResolver(resolver))
	if err == nil {
		t.Fatal("a proof carrying its own public key must not verify")
	}
	if !strings.Contains(err.Error(), "is not a DID URL") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// A second secp256k1 scalar, standing in for an attacker's own key. It is not
// in any DID document these tests resolve.
const attackerSecpPriv = "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"

// TestSecp256k1Suite_DowngradeToTheLegacyShapeIsRefused is step 3 of #89's
// reproduction, and the reason that issue was raised against a released
// version: the forgery does not need to break the new suite's signature, only
// to drop it.
//
// An attacker takes a credential genuinely signed with this suite, deletes jws,
// edits the subject, and attaches a hex proofValue signed with their own key
// plus that key in verificationMethod. The proof type never changes. Under the
// old routing the missing jws sent the document to the legacy verifier, which
// took the key from the proof — so the edited credential verified.
func TestSecp256k1Suite_DowngradeToTheLegacyShapeIsRefused(t *testing.T) {
	const did = "did:example:secp-suite-downgrade"
	resolver := secpResolver(t, did)

	cred, err := vc.ParseJSONCredential(mkSuiteCredentialJSON(did))
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
		t.Fatalf("the genuine credential must verify: %v", err)
	}

	raw, err := cred.GetContents()
	if err != nil {
		t.Fatalf("contents: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// The body the attacker wants signed: jws gone, subject edited.
	delete(doc, "proof")
	subject, ok := doc["credentialSubject"].(map[string]interface{})
	if !ok {
		t.Fatalf("credentialSubject is %T, want object", doc["credentialSubject"])
	}
	subject["name"] = "Attacker"

	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	// The legacy verifier hashed the JCS form of the body, so that is what the
	// attacker signs.
	canonical, err := jsoncanonicalizer.Transform(body)
	if err != nil {
		t.Fatalf("canonicalize body: %v", err)
	}
	privBytes, err := hex.DecodeString(attackerSecpPriv)
	if err != nil {
		t.Fatalf("decode attacker key: %v", err)
	}
	proofValue, err := crypto.SignMessage(privBytes, canonical)
	if err != nil {
		t.Fatalf("attacker sign: %v", err)
	}
	attackerPriv, err := ethcrypto.ToECDSA(privBytes)
	if err != nil {
		t.Fatalf("parse attacker key: %v", err)
	}
	attackerPubHex := "0x" + hex.EncodeToString(
		ethcrypto.CompressPubkey(&attackerPriv.PublicKey))

	// Self-check: the forgery is well formed, so a refusal below comes from the
	// SDK's routing and not from a fixture that never signed anything. Reinstate
	// the legacy branch and this same document verifies.
	sigBytes, err := hex.DecodeString(proofValue)
	if err != nil {
		t.Fatalf("decode attacker signature: %v", err)
	}
	pubBytes, err := crypto.KeyToBytes(attackerPubHex)
	if err != nil {
		t.Fatalf("attacker key to bytes: %v", err)
	}
	if !crypto.VerifyJSONSignature(pubBytes, body, sigBytes) {
		t.Fatal("the forged legacy signature does not check out against the attacker key; fix the fixture")
	}

	doc["proof"] = map[string]interface{}{
		"type":               "EcdsaSecp256k1Signature2019",
		"created":            "2026-01-01T00:00:00Z",
		"proofPurpose":       "assertionMethod",
		"verificationMethod": attackerPubHex,
		"proofValue":         proofValue,
	}
	forged, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal forged credential: %v", err)
	}

	downgraded, err := vc.ParseJSONCredential(forged)
	if err != nil {
		t.Fatalf("parse forged credential: %v", err)
	}
	if err := downgraded.Verify(vc.WithResolver(resolver)); err == nil {
		t.Fatal("the downgraded credential verified: the issuer's suite can be stripped and replaced")
	}
}

// TestSecp256k1Suite_TamperedProofOptions checks the signature covers the proof
// configuration, not just the document body: rewriting created after issuance
// must fail verification.
func TestSecp256k1Suite_TamperedProofOptions(t *testing.T) {
	const did = "did:example:secp-suite-tamper"
	resolver := secpResolver(t, did)

	cred, err := vc.ParseJSONCredential(mkSuiteCredentialJSON(did))
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

	cred, err := vc.ParseJSONCredential(mkSuiteCredentialJSON(did))
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

	cred, err := vc.ParseJSONCredential(mkSuiteCredentialJSON(did))
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

// The suite signs with secp256k1, so a proof of this type pointing at a P-256
// verification method is refused on the curve, before the signature is even
// checked. Without that check the failure would still happen, but it would
// read as a bad signature and send the reader looking in the wrong place.
func TestSecp256k1Suite_ProofMustPointAtASecp256k1Method(t *testing.T) {
	const did = "did:example:secp-suite-mixed"

	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("p256 key: %v", err)
	}
	p256VM, err := vmpkg.NewP256VM(did, "key-2", &p256Key.PublicKey)
	if err != nil {
		t.Fatalf("p256 vm: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did,
		vmpkg.NewSecp256k1VM(did, "key-1", pubHex(t, suiteSecpPriv)), p256VM))

	cred, err := vc.ParseJSONCredential(mkSuiteCredentialJSON(did))
	if err != nil {
		t.Fatalf("parse credential: %v", err)
	}
	if err := cred.AddProofByProvider(secpProvider(t),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Repoint the signed proof at the P-256 method on the same document.
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
		t.Fatalf("proof is %T, want one object", doc["proof"])
	}
	proof["verificationMethod"] = did + "#key-2"
	repointed, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	parsed, err := vc.ParseJSONCredential(repointed, vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("parse repointed: %v", err)
	}
	err = parsed.Verify(vc.WithResolver(resolver))
	if err == nil {
		t.Fatal("verify accepted an EcdsaSecp256k1Signature2019 proof on a P-256 method")
	}
	if !strings.Contains(err.Error(), "does not hold a secp256k1 key") {
		t.Fatalf("err = %v, want the curve named", err)
	}
}

// The signature covers the whole proof except the field that holds it. A third
// party adding proofValue — the slot the other suite signs into — must break
// the signature, not sit in the document unnoticed while Verify stays green.
func TestSecp256k1Suite_ProofValueIsCoveredBySignature(t *testing.T) {
	const did = "did:example:secp-suite-slot"
	resolver := secpResolver(t, did)

	cred, err := vc.ParseJSONCredential(mkSuiteCredentialJSON(did))
	if err != nil {
		t.Fatalf("parse credential: %v", err)
	}
	if err := cred.AddProofByProvider(secpProvider(t),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, ok := proofOf(t, cred)["proofValue"]; ok {
		t.Fatal("this suite signs into jws; it must not write proofValue")
	}

	raw, err := cred.GetContents()
	if err != nil {
		t.Fatalf("contents: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	doc["proof"].(map[string]interface{})["proofValue"] = "z3FXQdeadbeef"
	tampered, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	parsed, err := vc.ParseJSONCredential(tampered)
	if err != nil {
		t.Fatalf("parse tampered: %v", err)
	}
	if err := parsed.Verify(vc.WithResolver(resolver)); err == nil {
		t.Fatal("verify accepted a proof with a second signature slot filled in")
	}
}

// RFC 7797 signs the header that travels with the proof, so changing it after
// issuance breaks the signature.
func TestSecp256k1Suite_JWSHeaderIsCoveredBySignature(t *testing.T) {
	const did = "did:example:secp-suite-header"
	resolver := secpResolver(t, did)

	cred, err := vc.ParseJSONCredential(mkSuiteCredentialJSON(did))
	if err != nil {
		t.Fatalf("parse credential: %v", err)
	}
	if err := cred.AddProofByProvider(secpProvider(t),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign: %v", err)
	}

	raw, err := cred.GetContents()
	if err != nil {
		t.Fatalf("contents: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	proof := doc["proof"].(map[string]interface{})
	parts := strings.SplitN(proof["jws"].(string), "..", 2)
	if len(parts) != 2 {
		t.Fatalf("jws is not detached: %v", proof["jws"])
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var h map[string]interface{}
	if err := json.Unmarshal(header, &h); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	h["kid"] = did + "#key-1"
	rebuilt, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	proof["jws"] = base64.RawURLEncoding.EncodeToString(rebuilt) + ".." + parts[1]

	tampered, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := vc.ParseJSONCredential(tampered)
	if err != nil {
		t.Fatalf("parse tampered: %v", err)
	}
	if err := parsed.Verify(vc.WithResolver(resolver)); err == nil {
		t.Fatal("verify accepted a jws whose header changed after signing")
	}
}

// RFC 7518 fixes an ES256K signature at 64 bytes. A 65th byte is a byte nobody
// signed, so accepting it would give one credential many byte forms that all
// verify, and many different hashes.
func TestSecp256k1Suite_JWSSignatureMustBe64Bytes(t *testing.T) {
	const did = "did:example:secp-suite-siglen"
	resolver := secpResolver(t, did)

	cred, err := vc.ParseJSONCredential(mkSuiteCredentialJSON(did))
	if err != nil {
		t.Fatalf("parse credential: %v", err)
	}
	if err := cred.AddProofByProvider(secpProvider(t),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign: %v", err)
	}

	raw, err := cred.GetContents()
	if err != nil {
		t.Fatalf("contents: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	proof := doc["proof"].(map[string]interface{})
	parts := strings.SplitN(proof["jws"].(string), "..", 2)
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(signature) != 64 {
		t.Fatalf("issued signature is %d bytes, want 64", len(signature))
	}

	for _, extra := range []byte{0x00, 0x1b, 0xff} {
		padded := append(append([]byte{}, signature...), extra)
		proof["jws"] = parts[0] + ".." + base64.RawURLEncoding.EncodeToString(padded)
		tampered, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		parsed, err := vc.ParseJSONCredential(tampered)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := parsed.Verify(vc.WithResolver(resolver)); err == nil {
			t.Fatalf("verify accepted a 65-byte signature ending in %#x", extra)
		}
	}
}

// The suite's context defines proof at the document root, while credentials/v2
// scopes that term to the credential. A document using its own term of that
// name would therefore be signed with a different meaning than it was built
// with, so signing is refused and the document is left untouched.
func TestSecp256k1Suite_RefusesWhenTheContextWouldChangeMeaning(t *testing.T) {
	const did = "did:example:secp-suite-collide"
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did,
		vmpkg.NewSecp256k1VM(did, "key-1", pubHex(t, suiteSecpPriv))))

	raw := []byte(fmt.Sprintf(`{
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        {"@vocab": "https://example.org/vocab#"}
      ],
      "id": "urn:uuid:secp-suite-collide-001",
      "type": ["VerifiableCredential"],
      "issuer": %q,
      "validFrom": "2026-01-01T00:00:00Z",
      "credentialSubject": {
        "id": "did:example:subject",
        "proof": "https://notary.example/record/1"
      }
    }`, did))

	cred, err := vc.ParseJSONCredential(raw)
	if err != nil {
		t.Fatalf("parse credential: %v", err)
	}
	err = cred.AddProofByProvider(secpProvider(t),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err == nil {
		t.Fatal("signed a document whose own proof term the suite context redefines")
	}
	if !strings.Contains(err.Error(), "changed what the document says") {
		t.Fatalf("err = %v, want the collision named", err)
	}
	if cred.ExtractField("proof") != nil {
		t.Fatal("a refused signature must not be attached")
	}

	// The document must come back exactly as the caller built it.
	after, err := cred.GetContents()
	if err != nil {
		t.Fatalf("contents: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(after, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	ctx, ok := doc["@context"].([]interface{})
	if !ok || len(ctx) != 2 {
		t.Fatalf("@context was left modified: %v", doc["@context"])
	}
}

// A signer that does not hold the method's key is refused, and the suite
// context added along the way must not survive that refusal — the next signing
// attempt, possibly under another suite, has to start from the document the
// caller built.
func TestSecp256k1Suite_FailedSigningLeavesNoContextBehind(t *testing.T) {
	const did = "did:example:secp-suite-rollback"
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("p256 key: %v", err)
	}
	p256VM, err := vmpkg.NewP256VM(did, "key-2", &p256Key.PublicKey)
	if err != nil {
		t.Fatalf("p256 vm: %v", err)
	}
	// key-1 is a secp256k1 method whose key the signer below does not hold.
	other, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("other key: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did,
		vmpkg.NewSecp256k1VM(did, "key-1", hex.EncodeToString(ethcrypto.CompressPubkey(&other.PublicKey))),
		p256VM))

	cred, err := vc.ParseJSONCredential(mkSuiteCredentialJSON(did))
	if err != nil {
		t.Fatalf("parse credential: %v", err)
	}
	if err := cred.AddProofByProvider(secpProvider(t),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver)); err == nil {
		t.Fatal("expected the wrong signer to be refused")
	}

	p256Signer, err := signer.NewP256Provider(p256Key)
	if err != nil {
		t.Fatalf("p256 signer: %v", err)
	}
	if err := cred.AddProofByProvider(p256Signer,
		vc.WithVerificationMethodKey("key-2"), vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign with P-256: %v", err)
	}

	raw, err := cred.GetContents()
	if err != nil {
		t.Fatalf("contents: %v", err)
	}
	if strings.Contains(string(raw), "secp256k1-2019") {
		t.Fatalf("a failed secp256k1 signing left its context on an ecdsa-rdfc-2019 credential:\n%s", raw)
	}
}
