package did

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mr-tron/base58"
)

const (
	testDID    = "did:nda:0xabc"
	testIssuer = "did:nda:0xissuer"

	// W3C ecdsa-rdfc-2019 P-256 worked example, also in credential/.../w3c-rdfc-p256.
	w3cP256SecretMultibase = "z42twTcNeSYcnqg1FLuSFs2bsGH3ZqbRHFmvS9XMsYhjxvHN"
	w3cP256PublicMultibase = "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP"
)

func TestNewSecp256k1VM(t *testing.T) {
	vm := NewSecp256k1VM(testDID, "#key-1", "0x02aa")

	if vm.Id != testDID+"#key-1" {
		t.Fatalf("id not built from did + fragment: %q", vm.Id)
	}
	if vm.Controller != testDID {
		t.Fatalf("controller not set: %q", vm.Controller)
	}
	if vm.Type != secp256k1VMType {
		t.Fatalf("expected type %s, got %s", secp256k1VMType, vm.Type)
	}
	if vm.PublicKeyHex != "0x02aa" {
		t.Fatalf("public key not set: %q", vm.PublicKeyHex)
	}
	if vm.PublicKeyMultibase != "" {
		t.Fatalf("secp256k1 keys are published as hex, got multibase %q", vm.PublicKeyMultibase)
	}
}

func TestNewP256MultikeyVM(t *testing.T) {
	t.Run("w3c vector", func(t *testing.T) {
		vm, err := NewP256MultikeyVM(testDID, "#sign", p256PubFromSecretMultibase(t, w3cP256SecretMultibase))
		if err != nil {
			t.Fatalf("NewP256MultikeyVM: %v", err)
		}

		if vm.PublicKeyMultibase != w3cP256PublicMultibase {
			t.Fatalf("multibase mismatch:\n got: %s\nwant: %s", vm.PublicKeyMultibase, w3cP256PublicMultibase)
		}
		if vm.Id != testDID+"#sign" {
			t.Fatalf("id not built from did + fragment: %q", vm.Id)
		}
		if vm.Controller != testDID {
			t.Fatalf("controller not set: %q", vm.Controller)
		}
		if vm.Type != multikeyVMType {
			t.Fatalf("expected type %s, got %s", multikeyVMType, vm.Type)
		}
		if vm.PublicKeyHex != "" {
			t.Fatalf("Multikey publishes multibase only, got hex %q", vm.PublicKeyHex)
		}
	})

	t.Run("rejects secp256k1", func(t *testing.T) {
		secp, err := crypto.GenerateKey()
		if err != nil {
			t.Fatalf("generate secp256k1 key: %v", err)
		}
		if _, err := NewP256MultikeyVM(testDID, "#key-2", &secp.PublicKey); err == nil {
			t.Fatal("expected a secp256k1 key to be rejected")
		}
	})

	t.Run("rejects nil", func(t *testing.T) {
		if _, err := NewP256MultikeyVM(testDID, "#key-2", nil); err == nil {
			t.Fatal("expected a nil key to be rejected")
		}
	})
}

func TestNewVerificationMethods(t *testing.T) {
	key1 := NewSecp256k1VM(testDID, "#key-1", "0x02aa")
	sign := testP256VM(t, testDID, "#sign")
	auth := testP256VM(t, testDID, "#auth")

	t.Run("keeps order and ids", func(t *testing.T) {
		vms, _, _ := NewVerificationMethods(NewSpec(key1), NewSpec(sign), NewSpec(auth))

		want := []string{testDID + "#key-1", testDID + "#sign", testDID + "#auth"}
		for i, id := range want {
			if vms[i].Id != id {
				t.Fatalf("vm %d: expected %s, got %s", i, id, vms[i].Id)
			}
		}
	})

	t.Run("routes purposes", func(t *testing.T) {
		_, authentication, assertionMethod := NewVerificationMethods(
			NewSpec(key1),
			NewSpec(sign, PurposeAssertionMethod),
			NewSpec(auth, PurposeAuthentication),
		)

		// key-1 lists no purpose, so it joins both arrays.
		if want := []string{testDID + "#key-1", testDID + "#auth"}; !slices.Equal(authentication, want) {
			t.Fatalf("authentication: got %v, want %v", authentication, want)
		}
		if want := []string{testDID + "#key-1", testDID + "#sign"}; !slices.Equal(assertionMethod, want) {
			t.Fatalf("assertionMethod: got %v, want %v", assertionMethod, want)
		}
	})

	t.Run("arrays do not share memory", func(t *testing.T) {
		_, authentication, assertionMethod := NewVerificationMethods(NewSpec(key1))

		authentication[0] = "mutated"
		if assertionMethod[0] == "mutated" {
			t.Fatal("authentication and assertionMethod share a backing array")
		}
	})

	t.Run("empty", func(t *testing.T) {
		vms, authentication, assertionMethod := NewVerificationMethods()

		if len(vms) != 0 || len(authentication) != 0 || len(assertionMethod) != 0 {
			t.Fatalf("expected empty results, got %v / %v / %v", vms, authentication, assertionMethod)
		}
	})
}

// A single-VM document feeds DocHash: its serialization must not drift.
const singleVMDocumentJSON = `{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/v1"],"id":"did:nda:0xabc","controller":"did:nda:0xissuer","verificationMethod":[{"id":"did:nda:0xabc#key-1","type":"EcdsaSecp256k1VerificationKey2019","controller":"did:nda:0xabc","publicKeyHex":"0x02aa"}],"authentication":["did:nda:0xabc#key-1"],"assertionMethod":["did:nda:0xabc#key-1"],"didDocumentMetadata":{"type":"people"}}`

// DID Core 1.0 §6.1: a JSON-LD DID document's @context MUST list
// https://www.w3.org/ns/did/v1 first.
func TestDocumentContext_DIDCoreFirst(t *testing.T) {
	secp := NewSecp256k1VM(testDID, "#key-1", "0x02aa")
	p256, err := NewP256MultikeyVM(testDID, "#key-2", p256PubFromSecretMultibase(t, w3cP256SecretMultibase))
	if err != nil {
		t.Fatalf("p256 vm: %v", err)
	}

	tests := []struct {
		name string
		vms  []VerificationMethod
		want []string
	}{
		{"secp256k1 only", []VerificationMethod{secp},
			[]string{"https://www.w3.org/ns/did/v1", "https://w3id.org/security/v1"}},
		{"with multikey adds cid", []VerificationMethod{secp, p256},
			[]string{"https://www.w3.org/ns/did/v1", "https://w3id.org/security/v1", cidContext}},
		{"no vms", nil,
			[]string{"https://www.w3.org/ns/did/v1", "https://w3id.org/security/v1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := documentContext(tt.vms)
			if !slices.Equal(got, tt.want) {
				t.Errorf("documentContext = %q, want %q", got, tt.want)
			}
			if got[0] != "https://www.w3.org/ns/did/v1" {
				t.Errorf("@context[0] = %q, DID Core requires did/v1 first", got[0])
			}
		})
	}
}

func TestGenerateDIDDocument_SingleVMSerializationUnchanged(t *testing.T) {
	doc := GenerateDIDDocument("0x02aa", testDID, "", testIssuer, DIDTypePeople, nil)

	got, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(got) != singleVMDocumentJSON {
		t.Fatalf("document serialization changed:\n got: %s\nwant: %s", got, singleVMDocumentJSON)
	}
}

func TestGenerateDIDDocument_TwoVMs(t *testing.T) {
	doc := GenerateDIDDocument("0x02aa", testDID, "", testIssuer, DIDTypePeople, nil,
		NewSpec(testP256VM(t, testDID, "#key-2"), PurposeAssertionMethod))

	if len(doc.VerificationMethod) != 2 {
		t.Fatalf("expected 2 verification methods, got %d", len(doc.VerificationMethod))
	}
	if !slices.Contains(doc.Context, cidContext) {
		t.Fatalf("CID context missing: %v", doc.Context)
	}
	if slices.Contains(doc.Authentication, testDID+"#key-2") {
		t.Fatalf("assertionMethod-only VM leaked into authentication: %v", doc.Authentication)
	}
	if !slices.Contains(doc.AssertionMethod, testDID+"#key-2") {
		t.Fatalf("VM missing from assertionMethod: %v", doc.AssertionMethod)
	}
}

func TestGenerateDualCurveKeyPair(t *testing.T) {
	kp, err := GenerateDualCurveKeyPair()
	if err != nil {
		t.Fatalf("GenerateDualCurveKeyPair: %v", err)
	}

	if kp.PrivateKey.Curve != crypto.S256() {
		t.Fatal("PrivateKey must stay a secp256k1 key so the existing helpers keep working")
	}
	if kp.P256PublicKey == nil || kp.P256PublicKey.Curve != elliptic.P256() {
		t.Fatal("P256PublicKey must be on P-256")
	}
	if kp.GetAddress() == "" || kp.GetPublicKeyHex() == "" || kp.GetPrivateKeyHex() == "" {
		t.Fatal("secp256k1 helpers must still work on a dual-curve key pair")
	}

	// Both public keys must come from the same scalar.
	scalar := make([]byte, 32)
	kp.PrivateKey.D.FillBytes(scalar)
	want := p256PubFromScalar(t, scalar)
	if kp.P256PublicKey.X.Cmp(want.X) != 0 || kp.P256PublicKey.Y.Cmp(want.Y) != 0 {
		t.Fatal("P256PublicKey was not derived from the secp256k1 private scalar")
	}

	vm, err := NewP256MultikeyVM(testDID, "#key-2", kp.P256PublicKey)
	if err != nil {
		t.Fatalf("NewP256MultikeyVM: %v", err)
	}
	if !strings.HasPrefix(vm.PublicKeyMultibase, "zDn") {
		t.Fatalf("expected a p256-pub multikey, got %s", vm.PublicKeyMultibase)
	}
}

// TestPrintDIDDocument is an eyeball check: go test ./did/ -run PrintDIDDocument -v
func TestPrintDIDDocument(t *testing.T) {
	kp, err := GenerateDualCurveKeyPair()
	if err != nil {
		t.Fatalf("GenerateDualCurveKeyPair: %v", err)
	}

	didID := ToDID("did:nda", kp.GetAddress())
	p256VM, err := NewP256MultikeyVM(didID, "#key-2", kp.P256PublicKey)
	if err != nil {
		t.Fatalf("NewP256MultikeyVM: %v", err)
	}

	doc := GenerateDIDDocument(kp.GetPublicKeyHex(), didID, "", ToDID("did:nda", "0xissuer"),
		DIDTypePeople, map[string]any{"name": "Dinh"},
		NewSpec(p256VM, PurposeAssertionMethod))

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	hash, err := doc.Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	t.Logf("\n%s\n\ndocHash: %s\nprivate key (dev only): %s\n", out, hash, kp.GetPrivateKeyHex())
}

// p256PubFromSecretMultibase decodes a p256-priv Multikey and returns its public key.
func p256PubFromSecretMultibase(t *testing.T, s string) *ecdsa.PublicKey {
	t.Helper()

	raw, err := base58.Decode(s[1:])
	if err != nil {
		t.Fatalf("decode secret multibase: %v", err)
	}
	if len(raw) != 34 || raw[0] != 0x86 || raw[1] != 0x26 {
		t.Fatalf("unexpected p256-priv multikey: len=%d prefix=%x", len(raw), raw[:2])
	}

	return p256PubFromScalar(t, raw[2:])
}

// p256PubFromScalar returns the P-256 public key for a 32-byte scalar.
func p256PubFromScalar(t *testing.T, scalar []byte) *ecdsa.PublicKey {
	t.Helper()

	priv, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatalf("load P-256 private key: %v", err)
	}

	point := priv.PublicKey().Bytes() // 0x04 || X || Y
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(point[1:33]),
		Y:     new(big.Int).SetBytes(point[33:]),
	}
}

// testP256VM builds a Multikey VM from the W3C vector key.
func testP256VM(t *testing.T, did, fragment string) VerificationMethod {
	t.Helper()

	vm, err := NewP256MultikeyVM(did, fragment, p256PubFromSecretMultibase(t, w3cP256SecretMultibase))
	if err != nil {
		t.Fatalf("NewP256MultikeyVM: %v", err)
	}

	return vm
}
