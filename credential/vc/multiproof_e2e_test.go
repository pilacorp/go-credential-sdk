package vc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

const mpIssuerDID = "did:example:mp-issuer"

func genP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("p256 keygen: %v", err)
	}
	return k
}

// mpDIDDoc publishes two issuer keys: key-1 P-256 (for ecdsa-rdfc-2019) and
// key-2 RSA (for JsonWebSignature2020).
func mpDIDDoc(t *testing.T, p256Pub *ecdsa.PublicKey, rsaPub *rsa.PublicKey) *verificationmethod.DIDDocument {
	t.Helper()
	k1 := mpIssuerDID + "#key-1"
	k2 := mpIssuerDID + "#key-2"
	return &verificationmethod.DIDDocument{
		ID: mpIssuerDID,
		VerificationMethod: []verificationmethod.VerificationMethodEntry{
			verificationmethod.NewP256VM(mpIssuerDID, "key-1", p256Pub),
			{ID: k2, Type: "JsonWebKey2020", Controller: mpIssuerDID, PublicKeyJwk: &verificationmethod.JWK{
				Kty: "RSA",
				N:   base64.RawURLEncoding.EncodeToString(rsaPub.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPub.E)).Bytes()),
			}},
		},
		AssertionMethod: []string{k1, k2},
		Authentication:  []string{k1, k2},
	}
}

func mpCredentialJSON() []byte {
	return []byte(fmt.Sprintf(`{
      "@context": ["https://www.w3.org/ns/credentials/v2", {"@vocab": "https://example.org/vocab#"}],
      "id": "urn:uuid:mp-001",
      "type": ["VerifiableCredential", "IdentityCredential"],
      "issuer": %q,
      "validFrom": "2026-01-01T00:00:00Z",
      "credentialSubject": {"id": "did:example:subject", "name": "Nguyen Van A"}
    }`, mpIssuerDID))
}

// addJWSProof attaches a JsonWebSignature2020 proof through jsonmap: vc issues
// ecdsa-rdfc-2019 with a P-256 key only, so JWS is verify-only there.
func addJWSProof(t *testing.T, cred *vc.JSONCredential, prov signer.SignerProvider, vmURL string) *vc.JSONCredential {
	t.Helper()
	// GetContents, not Serialize: the credential may not have a proof yet.
	b, err := cred.GetContents()
	if err != nil {
		t.Fatalf("get contents: %v", err)
	}
	var m jsonmap.JSONMap
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := m.AddJWSProof(prov, vmURL, "assertionMethod"); err != nil {
		t.Fatalf("add jws proof (%s): %v", vmURL, err)
	}
	b2, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal signed: %v", err)
	}
	parsed, err := vc.ParseJSONCredential(b2)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	return parsed
}

// signTwoProofs attaches an ecdsa-rdfc-2019 proof (key-1) and a
// JsonWebSignature2020 proof (key-2) to one credential.
func signTwoProofs(t *testing.T, resolver *memResolver, p256Priv *ecdsa.PrivateKey, rsaPriv *rsa.PrivateKey) *vc.JSONCredential {
	t.Helper()
	cred, err := vc.ParseJSONCredential(mpCredentialJSON())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	ecdsaSigner, err := signer.NewP256Provider(p256Priv)
	if err != nil {
		t.Fatalf("ecdsa signer: %v", err)
	}
	if err := cred.AddProofByProvider(ecdsaSigner,
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver)); err != nil {
		t.Fatalf("add ecdsa proof: %v", err)
	}

	rsaProvider, err := signer.NewRSAProvider(rsaPriv)
	if err != nil {
		t.Fatalf("rsa provider: %v", err)
	}
	return addJWSProof(t, cred, rsaProvider, mpIssuerDID+"#key-2")
}

func TestMultiProof_IssueVerify(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	p256Priv := genP256(t)
	resolver := &memResolver{docs: map[string]*verificationmethod.DIDDocument{
		mpIssuerDID: mpDIDDoc(t, &p256Priv.PublicKey, &rsaPriv.PublicKey),
	}}

	cred := signTwoProofs(t, resolver, p256Priv, rsaPriv)

	serialized, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	b, _ := json.Marshal(serialized)

	var doc map[string]interface{}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	proofs, ok := doc["proof"].([]interface{})
	if !ok || len(proofs) != 2 {
		t.Fatalf("expected 2 proofs, got %T %v", doc["proof"], doc["proof"])
	}

	parsed, err := vc.ParseJSONCredential(b)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if err := parsed.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify multi-proof: %v", err)
	}
}

func TestMultiProof_TamperRejected(t *testing.T) {
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	p256Priv := genP256(t)
	resolver := &memResolver{docs: map[string]*verificationmethod.DIDDocument{
		mpIssuerDID: mpDIDDoc(t, &p256Priv.PublicKey, &rsaPriv.PublicKey),
	}}
	cred := signTwoProofs(t, resolver, p256Priv, rsaPriv)
	serialized, _ := cred.Serialize()
	b, _ := json.Marshal(serialized)

	var doc map[string]interface{}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cs, ok := doc["credentialSubject"].(map[string]interface{}); ok {
		cs["name"] = "Someone Else"
	}
	tampered, _ := json.Marshal(doc)

	parsed, err := vc.ParseJSONCredential(tampered)
	if err != nil {
		t.Fatalf("parse tampered: %v", err)
	}
	if err := parsed.Verify(vc.WithResolver(resolver)); err == nil {
		t.Fatal("tampered multi-proof credential must not verify")
	}
}

func TestMultiProof_OneWrongKeyRejected(t *testing.T) {
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	p256Priv := genP256(t)
	resolver := &memResolver{docs: map[string]*verificationmethod.DIDDocument{
		mpIssuerDID: mpDIDDoc(t, &p256Priv.PublicKey, &rsaPriv.PublicKey),
	}}
	cred := signTwoProofs(t, resolver, p256Priv, rsaPriv)
	serialized, _ := cred.Serialize()
	b, _ := json.Marshal(serialized)

	// Resolver advertises a different RSA key for key-2 → the JWS proof fails,
	// so the whole credential must fail (AND semantics).
	otherRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
	badResolver := &memResolver{docs: map[string]*verificationmethod.DIDDocument{
		mpIssuerDID: mpDIDDoc(t, &p256Priv.PublicKey, &otherRSA.PublicKey),
	}}
	parsed, err := vc.ParseJSONCredential(b)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if err := parsed.Verify(vc.WithResolver(badResolver)); err == nil {
		t.Fatal("credential with one invalid proof must not verify (AND semantics)")
	}
}

// These tests mock DID resolution with verificationmethod.StaticResolver so
// they exercise key types (RSA, P-256) the production DID resolver does not yet
// publish. authen-service tests can reuse the same StaticResolver + NewXxxVM
// builders.

func mp2CredJSON(issuerDID string) []byte {
	return []byte(fmt.Sprintf(`{
      "@context": ["https://www.w3.org/ns/credentials/v2", {"@vocab": "https://example.org/vocab#"}],
      "id": "urn:uuid:mp2-001",
      "type": ["VerifiableCredential", "IdentityCredential"],
      "issuer": %q,
      "validFrom": "2026-01-01T00:00:00Z",
      "credentialSubject": {"id": "did:example:subject", "name": "Tran Thi B"}
    }`, issuerDID))
}

type signSpec struct {
	provider signer.SignerProvider
	key      string
	jws      bool // sign through jsonmap; key must then be a full VM URL
}

func signProofs(t *testing.T, cred *vc.JSONCredential, resolver verificationmethod.ResolverProvider, specs ...signSpec) *vc.JSONCredential {
	t.Helper()
	for _, s := range specs {
		if s.jws {
			cred = addJWSProof(t, cred, s.provider, s.key)
			continue
		}
		if err := cred.AddProofByProvider(s.provider,
			vc.WithVerificationMethodKey(s.key), vc.WithResolver(resolver)); err != nil {
			t.Fatalf("add proof (%s): %v", s.key, err)
		}
	}
	return cred
}

func assertProofCount(t *testing.T, cred *vc.JSONCredential, want int) {
	t.Helper()
	serialized, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	b, _ := json.Marshal(serialized)
	var doc map[string]interface{}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got := 1
	if arr, ok := doc["proof"].([]interface{}); ok {
		got = len(arr)
	}
	if got != want {
		t.Fatalf("proof count = %d, want %d", got, want)
	}
}

func reparse(t *testing.T, cred *vc.JSONCredential) *vc.JSONCredential {
	t.Helper()
	serialized, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	b, _ := json.Marshal(serialized)
	parsed, err := vc.ParseJSONCredential(b)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	return parsed
}

func genRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	return k
}

// Three proofs of mixed key types/cryptosuites: P-256 ecdsa-rdfc-2019, RSA
// RS256 JsonWebSignature2020, RSA PS256 JsonWebSignature2020.
func TestMultiProof_MixedKeyTypes(t *testing.T) {
	did := "did:example:mp2-mixed"
	p256Priv := genP256(t)
	rsaRS := genRSA(t)
	rsaPS := genRSA(t)
	resolver := verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument(did,
			verificationmethod.NewP256VM(did, "key-1", &p256Priv.PublicKey),
			verificationmethod.NewRSAVM(did, "key-2", &rsaRS.PublicKey),
			verificationmethod.NewRSAVM(did, "key-3", &rsaPS.PublicKey),
		),
	)

	cred, err := vc.ParseJSONCredential(mp2CredJSON(did))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	p256, _ := signer.NewP256Provider(p256Priv)
	rs, _ := signer.NewRSAProvider(rsaRS, "RS256")
	ps, _ := signer.NewRSAProvider(rsaPS, "PS256")
	cred = signProofs(t, cred, resolver,
		signSpec{provider: p256, key: "key-1"},
		signSpec{provider: rs, key: did + "#key-2", jws: true},
		signSpec{provider: ps, key: did + "#key-3", jws: true},
	)

	assertProofCount(t, cred, 3)
	if err := reparse(t, cred).Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify mixed proof set: %v", err)
	}
}

// Proof set whose proofs reference verification methods in two different DID
// documents — each proof is resolved against its own DID.
func TestMultiProof_CrossDIDVerificationMethods(t *testing.T) {
	issuerDID := "did:example:mp2-issuer"
	delegateDID := "did:example:mp2-delegate"
	p256Priv := genP256(t)
	rsaKey := genRSA(t)
	resolver := verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument(issuerDID,
			verificationmethod.NewP256VM(issuerDID, "key-1", &p256Priv.PublicKey)),
		verificationmethod.NewDIDDocument(delegateDID,
			verificationmethod.NewRSAVM(delegateDID, "key-1", &rsaKey.PublicKey)),
	)

	cred, err := vc.ParseJSONCredential(mp2CredJSON(issuerDID))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	p256, _ := signer.NewP256Provider(p256Priv)
	rsaProv, _ := signer.NewRSAProvider(rsaKey)
	cred = signProofs(t, cred, resolver,
		signSpec{provider: p256, key: "key-1"},                              // VM under the issuer DID
		signSpec{provider: rsaProv, key: delegateDID + "#key-1", jws: true}, // VM under the delegate DID
	)

	assertProofCount(t, cred, 2)
	if err := reparse(t, cred).Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify cross-DID proof set: %v", err)
	}
}

// AND semantics across three proofs: if the resolver advertises a wrong key for
// just one proof, the whole credential must fail.
func TestMultiProof_PartialFailureRejected(t *testing.T) {
	did := "did:example:mp2-partial"
	p256Priv := genP256(t)
	rsaA := genRSA(t)
	rsaB := genRSA(t)
	resolver := verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument(did,
			verificationmethod.NewP256VM(did, "key-1", &p256Priv.PublicKey),
			verificationmethod.NewRSAVM(did, "key-2", &rsaA.PublicKey),
			verificationmethod.NewRSAVM(did, "key-3", &rsaB.PublicKey),
		),
	)

	cred, err := vc.ParseJSONCredential(mp2CredJSON(did))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	p256, _ := signer.NewP256Provider(p256Priv)
	pa, _ := signer.NewRSAProvider(rsaA)
	pb, _ := signer.NewRSAProvider(rsaB)
	cred = signProofs(t, cred, resolver,
		signSpec{provider: p256, key: "key-1"},
		signSpec{provider: pa, key: did + "#key-2", jws: true},
		signSpec{provider: pb, key: did + "#key-3", jws: true},
	)

	// Bad resolver: key-3 advertises a different RSA key; the other two stay valid.
	other := genRSA(t)
	badResolver := verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument(did,
			verificationmethod.NewP256VM(did, "key-1", &p256Priv.PublicKey),
			verificationmethod.NewRSAVM(did, "key-2", &rsaA.PublicKey),
			verificationmethod.NewRSAVM(did, "key-3", &other.PublicKey),
		),
	)
	if err := reparse(t, cred).Verify(vc.WithResolver(badResolver)); err == nil {
		t.Fatal("proof set with one invalid proof must not verify (AND semantics)")
	}
}

// One JsonWebSignature2020 proof per RSA JOSE algorithm, all in one proof set.
func TestMultiProof_VariousJWSAlgs(t *testing.T) {
	did := "did:example:mp2-algs"
	algs := []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}

	keys := make([]*rsa.PrivateKey, len(algs))
	vms := make([]verificationmethod.VerificationMethodEntry, len(algs))
	for i := range algs {
		keys[i] = genRSA(t)
		vms[i] = verificationmethod.NewRSAVM(did, fmt.Sprintf("key-%d", i+1), &keys[i].PublicKey)
	}
	resolver := verificationmethod.NewStaticResolver(verificationmethod.NewDIDDocument(did, vms...))

	cred, err := vc.ParseJSONCredential(mp2CredJSON(did))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for i, alg := range algs {
		prov, err := signer.NewRSAProvider(keys[i], alg)
		if err != nil {
			t.Fatalf("rsa provider %s: %v", alg, err)
		}
		cred = addJWSProof(t, cred, prov, fmt.Sprintf("%s#key-%d", did, i+1))
	}

	assertProofCount(t, cred, len(algs))
	if err := reparse(t, cred).Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify multi-alg proof set: %v", err)
	}
}

// NOTE: auto-select no longer filters by the signer's key type (a SignerProvider
// has no key kind). On a DID holding several keys of different types, pin the VM
// with WithVerificationMethodKey; otherwise the latest active VM for the purpose
// is used and its key type decides the cryptosuite.
