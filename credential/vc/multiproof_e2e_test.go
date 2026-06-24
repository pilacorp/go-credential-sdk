package vc_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

const (
	mpIssuerDID = "did:example:mp-issuer"
	mpSecpPriv  = "57600b3f2b7e1054094e14cd85c72a40dc74c4ee062bb381cea604b55ce56aec"
)

// mpDIDDoc publishes two issuer keys: key-1 secp256k1 (for ecdsa-rdfc-2019) and
// key-2 RSA (for JsonWebSignature2020).
func mpDIDDoc(t *testing.T, secpPrivHex string, rsaPub *rsa.PublicKey) *verificationmethod.DIDDocument {
	t.Helper()
	k1 := mpIssuerDID + "#key-1"
	k2 := mpIssuerDID + "#key-2"
	return &verificationmethod.DIDDocument{
		ID: mpIssuerDID,
		VerificationMethod: []verificationmethod.VerificationMethodEntry{
			{ID: k1, Type: "EcdsaSecp256k1VerificationKey2019", Controller: mpIssuerDID, PublicKeyHex: pubHex(t, secpPrivHex)},
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

// signTwoProofs attaches an ecdsa-rdfc-2019 proof (key-1) and a
// JsonWebSignature2020 proof (key-2) to one credential.
func signTwoProofs(t *testing.T, resolver *memResolver, rsaPriv *rsa.PrivateKey) *vc.JSONCredential {
	t.Helper()
	cred, err := vc.ParseJSONCredential(mpCredentialJSON())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	ecdsaSigner, err := signer.NewDefaultProvider(mpSecpPriv)
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
	if err := cred.AddProofByProvider(rsaProvider,
		vc.WithVerificationMethodKey("key-2"), vc.WithResolver(resolver)); err != nil {
		t.Fatalf("add jws proof: %v", err)
	}
	return cred
}

func TestMultiProof_IssueVerify(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	resolver := &memResolver{docs: map[string]*verificationmethod.DIDDocument{
		mpIssuerDID: mpDIDDoc(t, mpSecpPriv, &rsaPriv.PublicKey),
	}}

	cred := signTwoProofs(t, resolver, rsaPriv)

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
	resolver := &memResolver{docs: map[string]*verificationmethod.DIDDocument{
		mpIssuerDID: mpDIDDoc(t, mpSecpPriv, &rsaPriv.PublicKey),
	}}
	cred := signTwoProofs(t, resolver, rsaPriv)
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
	resolver := &memResolver{docs: map[string]*verificationmethod.DIDDocument{
		mpIssuerDID: mpDIDDoc(t, mpSecpPriv, &rsaPriv.PublicKey),
	}}
	cred := signTwoProofs(t, resolver, rsaPriv)
	serialized, _ := cred.Serialize()
	b, _ := json.Marshal(serialized)

	// Resolver advertises a different RSA key for key-2 → the JWS proof fails,
	// so the whole credential must fail (AND semantics).
	otherRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
	badResolver := &memResolver{docs: map[string]*verificationmethod.DIDDocument{
		mpIssuerDID: mpDIDDoc(t, mpSecpPriv, &otherRSA.PublicKey),
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
}

func signProofs(t *testing.T, cred *vc.JSONCredential, resolver verificationmethod.ResolverProvider, specs ...signSpec) {
	t.Helper()
	for _, s := range specs {
		if err := cred.AddProofByProvider(s.provider,
			vc.WithVerificationMethodKey(s.key), vc.WithResolver(resolver)); err != nil {
			t.Fatalf("add proof (%s): %v", s.key, err)
		}
	}
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

// Three proofs of mixed key types/cryptosuites: secp256k1 ecdsa-rdfc-2019, RSA
// RS256 JsonWebSignature2020, RSA PS256 JsonWebSignature2020.
func TestMultiProof_MixedKeyTypes(t *testing.T) {
	did := "did:example:mp2-mixed"
	rsaRS := genRSA(t)
	rsaPS := genRSA(t)
	resolver := verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument(did,
			verificationmethod.NewSecp256k1VM(did, "key-1", pubHex(t, mpSecpPriv)),
			verificationmethod.NewRSAVM(did, "key-2", &rsaRS.PublicKey),
			verificationmethod.NewRSAVM(did, "key-3", &rsaPS.PublicKey),
		),
	)

	cred, err := vc.ParseJSONCredential(mp2CredJSON(did))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	secp, _ := signer.NewDefaultProvider(mpSecpPriv)
	rs, _ := signer.NewRSAProvider(rsaRS, "RS256")
	ps, _ := signer.NewRSAProvider(rsaPS, "PS256")
	signProofs(t, cred, resolver,
		signSpec{secp, "key-1"},
		signSpec{rs, "key-2"},
		signSpec{ps, "key-3"},
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
	rsaKey := genRSA(t)
	resolver := verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument(issuerDID,
			verificationmethod.NewSecp256k1VM(issuerDID, "key-1", pubHex(t, mpSecpPriv))),
		verificationmethod.NewDIDDocument(delegateDID,
			verificationmethod.NewRSAVM(delegateDID, "key-1", &rsaKey.PublicKey)),
	)

	cred, err := vc.ParseJSONCredential(mp2CredJSON(issuerDID))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	secp, _ := signer.NewDefaultProvider(mpSecpPriv)
	rsaProv, _ := signer.NewRSAProvider(rsaKey)
	signProofs(t, cred, resolver,
		signSpec{secp, "key-1"},                   // VM under the issuer DID
		signSpec{rsaProv, delegateDID + "#key-1"}, // VM under the delegate DID
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
	rsaA := genRSA(t)
	rsaB := genRSA(t)
	resolver := verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument(did,
			verificationmethod.NewSecp256k1VM(did, "key-1", pubHex(t, mpSecpPriv)),
			verificationmethod.NewRSAVM(did, "key-2", &rsaA.PublicKey),
			verificationmethod.NewRSAVM(did, "key-3", &rsaB.PublicKey),
		),
	)

	cred, err := vc.ParseJSONCredential(mp2CredJSON(did))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	secp, _ := signer.NewDefaultProvider(mpSecpPriv)
	pa, _ := signer.NewRSAProvider(rsaA)
	pb, _ := signer.NewRSAProvider(rsaB)
	signProofs(t, cred, resolver,
		signSpec{secp, "key-1"},
		signSpec{pa, "key-2"},
		signSpec{pb, "key-3"},
	)

	// Bad resolver: key-3 advertises a different RSA key; the other two stay valid.
	other := genRSA(t)
	badResolver := verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument(did,
			verificationmethod.NewSecp256k1VM(did, "key-1", pubHex(t, mpSecpPriv)),
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
		if err := cred.AddProofByProvider(prov,
			vc.WithVerificationMethodKey(fmt.Sprintf("key-%d", i+1)),
			vc.WithResolver(resolver)); err != nil {
			t.Fatalf("add %s proof: %v", alg, err)
		}
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
