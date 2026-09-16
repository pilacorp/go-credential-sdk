package did

import (
	"strings"
	"testing"
)

func TestDIDDocument_Validate(t *testing.T) {
	vm := func(fragment string) VerificationMethod { return NewSecp256k1VM(testDID, fragment, "0x02aa") }

	tests := []struct {
		name    string
		doc     *DIDDocument
		wantErr string // empty means valid
	}{
		{"nil document", nil, "nil"},
		{"empty document", &DIDDocument{}, ""},
		{"single vm with both purposes",
			&DIDDocument{
				VerificationMethod: []VerificationMethod{vm("#key-1")},
				Authentication:     []string{testDID + "#key-1"},
				AssertionMethod:    []string{testDID + "#key-1"},
			}, ""},
		{"two distinct vms",
			&DIDDocument{
				VerificationMethod: []VerificationMethod{vm("#key-1"), vm("#key-2")},
				Authentication:     []string{testDID + "#key-1", testDID + "#key-2"},
			}, ""},
		{"empty vm id",
			&DIDDocument{VerificationMethod: []VerificationMethod{{Type: "EcdsaSecp256k1VerificationKey2019"}}},
			"verificationMethod[0]: id is empty"},
		{"duplicate vm id",
			&DIDDocument{VerificationMethod: []VerificationMethod{vm("#key-1"), vm("#key-1")}},
			"duplicate id " + testDID + "#key-1"},
		{"authentication references unknown vm",
			&DIDDocument{
				VerificationMethod: []VerificationMethod{vm("#key-1")},
				Authentication:     []string{testDID + "#ghost"},
			}, `authentication references unknown verification method "` + testDID + `#ghost"`},
		{"assertionMethod references unknown vm",
			&DIDDocument{
				VerificationMethod: []VerificationMethod{vm("#key-1")},
				AssertionMethod:    []string{testDID + "#ghost"},
			}, `assertionMethod references unknown verification method "` + testDID + `#ghost"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.doc.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate: unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate: expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate: error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

// GenerateDIDDocument still builds whatever it is given — Validate is what
// catches an extra VM colliding with the generator's own #key-1 / #key-2.
func TestGenerateDIDDocument_ValidateCatchesReservedFragment(t *testing.T) {
	for _, fragment := range []string{"#key-1", "#key-2"} {
		t.Run(fragment, func(t *testing.T) {
			extra := NewSpec(NewSecp256k1VM(testDID, fragment, "0x03bb"))
			p256, err := NewP256MultikeyVM(testDID, "#key-2", p256PubFromSecretMultibase(t, w3cP256SecretMultibase))
			if err != nil {
				t.Fatalf("p256 vm: %v", err)
			}
			// Mirror GenerateDID: caller extras first, then the generator's P-256 VM.
			doc := GenerateDIDDocument("0x02aa", testDID, "", testIssuer, DIDTypePeople, nil, extra, NewSpec(p256))

			err = doc.Validate()
			if err == nil {
				t.Fatalf("expected duplicate %s to be rejected, got valid document with %d VMs", fragment, len(doc.VerificationMethod))
			}
			if !strings.Contains(err.Error(), "duplicate id "+testDID+fragment) {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestGenerateDIDDocument_DefaultIsValid(t *testing.T) {
	p256, err := NewP256MultikeyVM(testDID, "#key-2", p256PubFromSecretMultibase(t, w3cP256SecretMultibase))
	if err != nil {
		t.Fatalf("p256 vm: %v", err)
	}
	doc := GenerateDIDDocument("0x02aa", testDID, "", testIssuer, DIDTypePeople, nil, NewSpec(p256))
	if err := doc.Validate(); err != nil {
		t.Fatalf("default generator document should validate: %v", err)
	}
}
