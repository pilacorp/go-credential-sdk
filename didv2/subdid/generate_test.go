package subdid

import (
	"encoding/json"
	"testing"

	"github.com/pilacorp/go-credential-sdk/didv2/did"
)

func TestGenerateSubDID_Vectors(t *testing.T) {
	tests := []struct {
		name, subID, document, signature string
		metadata                         map[string]any
	}{
		{"Sub-DID document", subIDS1, createSubDIDJSON, createSignature, nil},
		{"subId, type and rootConsent set by GenerateSubDID", subIDS1, createSubDIDJSON, createSignature,
			map[string]any{"subId": "NV-00123", "type": "item", "rootConsent": "0x00"}},
	}
	for _, tt := range tests {
		res, err := GenerateSubDID(rootR1, tt.subID, row1PublicKeyHex, did.DIDTypePeople, tt.metadata,
			provider(t, rootR1PrivateKeyHex), provider(t, row1PrivateKeyHex))
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}

		stored, err := json.Marshal(res.Document)
		if err != nil {
			t.Fatal(err)
		}
		if string(stored) != tt.document {
			t.Errorf("%s: document = %s, want the vector", tt.name, stored)
		}
		if res.Signature != tt.signature || res.DID != row1SubDID || res.Type != "people" {
			t.Errorf("%s: got DID %s, type %s, signature %s", tt.name, res.DID, res.Type, res.Signature)
		}
	}
}

func TestGenerateSubDID_Refuses(t *testing.T) {
	if _, err := GenerateSubDID(rootR1, subIDS1, row1PublicKeyHex, did.DIDTypePeople, nil,
		provider(t, row1PrivateKeyHex), provider(t, row1PrivateKeyHex)); err == nil {
		t.Error("a root signer without the root's primary key was accepted")
	}
	if _, err := GenerateSubDID(rootR1, subIDS1, row1PublicKeyHex, did.DIDTypePeople, nil,
		provider(t, rootR1PrivateKeyHex), provider(t, rootR1PrivateKeyHex)); err == nil {
		t.Error("a Sub-DID signer without the Sub-DID key was accepted")
	}
	if _, err := GenerateSubDID(rootR1, "", row1PublicKeyHex, did.DIDTypePeople, nil,
		provider(t, rootR1PrivateKeyHex), provider(t, row1PrivateKeyHex)); err == nil {
		t.Error("an empty subID was accepted")
	}
}
