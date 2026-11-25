package verificationmethod

import (
	"context"
	"testing"
	"time"
)

// threeKeyDoc builds the typical upcoming DID document:
//
//	#key-1  EcdsaSecp256k1VerificationKey2019  publicKeyHex (secp256k1)
//	#key-2  Multikey                            publicKeyMultibase (P-256)
//	#key-3  JsonWebKey                          publicKeyJwk (secp256k1 JWK)
//
// All three are listed in both authentication and assertionMethod.
func threeKeyDoc() *DIDDocument {
	const did = "did:pila:three-key"
	return &DIDDocument{
		ID: did,
		VerificationMethod: []VerificationMethodEntry{
			{
				ID:           did + "#key-1",
				Type:         "EcdsaSecp256k1VerificationKey2019",
				Controller:   did,
				PublicKeyHex: "02ba5734d8f7091719471e7f7ed6b9df170dc70cc661ca05e688601ad984f068b0",
			},
			{
				ID:                 did + "#key-2",
				Type:               "Multikey",
				Controller:         did,
				PublicKeyMultibase: "zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
			},
			{
				ID:         did + "#key-3",
				Type:       "JsonWebKey",
				Controller: did,
				PublicKeyJwk: &JWK{
					Kty: "EC",
					Crv: "secp256k1",
					X:   "ulc02PcJFxlHHn9-1rnfFw3HDMZhygXmiGAa2YTwaLA",
					Y:   "1nNR5fBgcwkkmTNqsIOe-KUhr9M05TgHIF-i8I7sdPQ",
				},
			},
		},
		Authentication:  []string{did + "#key-1", did + "#key-2", did + "#key-3"},
		AssertionMethod: []string{did + "#key-1", did + "#key-2", did + "#key-3"},
	}
}

// --- SelectDefaultSigningVM tests ---

func TestSelectDefaultSigningVM_SkipsJsonWebKey(t *testing.T) {
	doc := threeKeyDoc()
	const did = "did:pila:three-key"

	for _, purpose := range []string{"authentication", "assertionMethod"} {
		t.Run(purpose, func(t *testing.T) {
			vm, err := SelectDefaultSigningVM(doc, purpose)
			if err != nil {
				t.Fatalf("SelectDefaultSigningVM: %v", err)
			}
			if vm.ID != did+"#key-2" {
				t.Errorf("got %q, want %q (should skip #key-3 JsonWebKey)", vm.ID, did+"#key-2")
			}
		})
	}
}

func TestSelectDefaultSigningVM_Key2Revoked_ReturnsKey1(t *testing.T) {
	doc := threeKeyDoc()
	const did = "did:pila:three-key"

	revoked := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	doc.VerificationMethod[1].Revoked = &revoked // revoke #key-2

	vm, err := SelectDefaultSigningVM(doc, "assertionMethod")
	if err != nil {
		t.Fatalf("SelectDefaultSigningVM: %v", err)
	}
	// #key-2 is revoked, #key-3 is JsonWebKey — should fall back to #key-1
	if vm.ID != did+"#key-1" {
		t.Errorf("got %q, want %q (key-2 revoked, key-3 is JsonWebKey)", vm.ID, did+"#key-1")
	}
}

func TestSelectDefaultSigningVM_OnlyJsonWebKey_FallsBack(t *testing.T) {
	const did = "did:pila:only-jwk"
	doc := &DIDDocument{
		ID: did,
		VerificationMethod: []VerificationMethodEntry{
			{
				ID:         did + "#key-3",
				Type:       "JsonWebKey",
				Controller: did,
				PublicKeyJwk: &JWK{
					Kty: "EC",
					Crv: "secp256k1",
					X:   "ulc02PcJFxlHHn9-1rnfFw3HDMZhygXmiGAa2YTwaLA",
					Y:   "1nNR5fBgcwkkmTNqsIOe-KUhr9M05TgHIF-i8I7sdPQ",
				},
			},
		},
		Authentication:  []string{did + "#key-3"},
		AssertionMethod: []string{did + "#key-3"},
	}

	// Single VM: single-VM branch returns it directly.
	vm, err := SelectDefaultSigningVM(doc, "assertionMethod")
	if err != nil {
		t.Fatalf("SelectDefaultSigningVM: %v", err)
	}
	if vm.ID != did+"#key-3" {
		t.Errorf("got %q, want %q (only VM)", vm.ID, did+"#key-3")
	}
}

func TestSelectDefaultSigningVM_Key1RevokedKey3Active_FallsBackToJsonWebKey(t *testing.T) {
	const did = "did:pila:fallback-jwk"
	revoked := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	doc := &DIDDocument{
		ID: did,
		VerificationMethod: []VerificationMethodEntry{
			{
				ID:           did + "#key-1",
				Type:         "EcdsaSecp256k1VerificationKey2019",
				Controller:   did,
				PublicKeyHex: "02ba5734d8f7091719471e7f7ed6b9df170dc70cc661ca05e688601ad984f068b0",
				Revoked:      &revoked,
			},
			{
				ID:         did + "#key-3",
				Type:       "JsonWebKey",
				Controller: did,
				PublicKeyJwk: &JWK{
					Kty: "EC",
					Crv: "secp256k1",
					X:   "ulc02PcJFxlHHn9-1rnfFw3HDMZhygXmiGAa2YTwaLA",
					Y:   "1nNR5fBgcwkkmTNqsIOe-KUhr9M05TgHIF-i8I7sdPQ",
				},
			},
		},
		Authentication:  []string{did + "#key-1", did + "#key-3"},
		AssertionMethod: []string{did + "#key-1", did + "#key-3"},
	}

	vm, err := SelectDefaultSigningVM(doc, "assertionMethod")
	if err != nil {
		t.Fatalf("SelectDefaultSigningVM: %v", err)
	}
	// #key-1 is revoked, only #key-3 (JsonWebKey) remains — must fall back to it.
	if vm.ID != did+"#key-3" {
		t.Errorf("got %q, want %q (only usable VM is JsonWebKey)", vm.ID, did+"#key-3")
	}
}

// --- SelectLatestActiveVMForPurpose unchanged ---

func TestSelectLatestActiveVMForPurpose_StillReturnsJsonWebKey(t *testing.T) {
	doc := threeKeyDoc()
	const did = "did:pila:three-key"

	vm, err := SelectLatestActiveVMForPurpose(doc, "assertionMethod")
	if err != nil {
		t.Fatalf("SelectLatestActiveVMForPurpose: %v", err)
	}
	// Verifiers use this; it must still return #key-3 (highest index).
	if vm.ID != did+"#key-3" {
		t.Errorf("got %q, want %q (unchanged behaviour)", vm.ID, did+"#key-3")
	}
}

// --- SelectLatestActiveSigningVMForPurpose directly ---

func TestSelectLatestActiveSigningVMForPurpose_SkipsJsonWebKey(t *testing.T) {
	doc := threeKeyDoc()
	const did = "did:pila:three-key"

	vm, err := SelectLatestActiveSigningVMForPurpose(doc, "assertionMethod")
	if err != nil {
		t.Fatalf("SelectLatestActiveSigningVMForPurpose: %v", err)
	}
	if vm.ID != did+"#key-2" {
		t.Errorf("got %q, want %q", vm.ID, did+"#key-2")
	}
}

func TestSelectLatestActiveSigningVMForPurpose_FallbackToJsonWebKey(t *testing.T) {
	const did = "did:pila:only-jwk-multi"
	doc := &DIDDocument{
		ID: did,
		VerificationMethod: []VerificationMethodEntry{
			{
				ID:         did + "#key-3",
				Type:       "JsonWebKey",
				Controller: did,
				PublicKeyJwk: &JWK{
					Kty: "EC",
					Crv: "secp256k1",
					X:   "ulc02PcJFxlHHn9-1rnfFw3HDMZhygXmiGAa2YTwaLA",
					Y:   "1nNR5fBgcwkkmTNqsIOe-KUhr9M05TgHIF-i8I7sdPQ",
				},
			},
			{
				ID:         did + "#key-4",
				Type:       "JsonWebKey",
				Controller: did,
				PublicKeyJwk: &JWK{
					Kty: "EC",
					Crv: "secp256k1",
					X:   "ulc02PcJFxlHHn9-1rnfFw3HDMZhygXmiGAa2YTwaLA",
					Y:   "1nNR5fBgcwkkmTNqsIOe-KUhr9M05TgHIF-i8I7sdPQ",
				},
			},
		},
		Authentication:  []string{did + "#key-3", did + "#key-4"},
		AssertionMethod: []string{did + "#key-3", did + "#key-4"},
	}

	// All VMs are JsonWebKey: must fall back and pick the highest (#key-4).
	vm, err := SelectLatestActiveSigningVMForPurpose(doc, "assertionMethod")
	if err != nil {
		t.Fatalf("SelectLatestActiveSigningVMForPurpose: %v", err)
	}
	if vm.ID != did+"#key-4" {
		t.Errorf("got %q, want %q (fallback picks highest JsonWebKey)", vm.ID, did+"#key-4")
	}
}

// --- ResolveSigningVM integration (un-pinned path uses SelectDefaultSigningVM) ---

func TestResolveSigningVM_UnpinnedSkipsJsonWebKey(t *testing.T) {
	doc := threeKeyDoc()
	const did = "did:pila:three-key"

	resolver := &stubResolver{doc: doc}
	vm, url, err := ResolveSigningVM(context.Background(), did, "assertionMethod", "", resolver)
	if err != nil {
		t.Fatalf("ResolveSigningVM: %v", err)
	}
	if url != did+"#key-2" || vm.ID != url {
		t.Errorf("got %q, want %q (un-pinned should skip JsonWebKey)", url, did+"#key-2")
	}
}

func TestResolveSigningVM_PinnedJsonWebKeyAllowed(t *testing.T) {
	doc := threeKeyDoc()
	const did = "did:pila:three-key"

	resolver := &stubResolver{doc: doc}
	vm, url, err := ResolveSigningVM(context.Background(), did, "assertionMethod", "key-3", resolver)
	if err != nil {
		t.Fatalf("ResolveSigningVM: %v", err)
	}
	if url != did+"#key-3" || vm.ID != url {
		t.Errorf("got %q, want %q (pinned kid must be honoured)", url, did+"#key-3")
	}
}
