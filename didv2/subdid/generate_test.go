package subdid

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/pilacorp/go-credential-sdk/didv2/did"
	"github.com/pilacorp/go-credential-sdk/didv2/signer"
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

func ExampleGenerateSubDID() {
	rootDID := "did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
	rootPrivateKeyHex := "1111111111111111111111111111111111111111111111111111111111111111"
	subID := "0b8e6f3c-5a1d-4c27-9f40-3e2a7d91c6b5"

	rootSigner, err := signer.NewDefaultProvider(rootPrivateKeyHex)
	if err != nil {
		panic(err)
	}

	subKey, err := DeriveSubDIDKey(rootPrivateKeyHex, subID)
	if err != nil {
		panic(err)
	}
	subSigner, err := signer.NewDefaultProvider(subKey.GetPrivateKeyHex())
	if err != nil {
		panic(err)
	}

	res, err := GenerateSubDID(rootDID, subID, subKey.GetPublicKeyHex(), did.DIDTypePeople, nil, rootSigner, subSigner)
	if err != nil {
		panic(err)
	}

	body, err := json.Marshal(map[string]any{"document": res.Document, "type": res.Type, "signature": res.Signature})
	if err != nil {
		panic(err)
	}

	fmt.Println(res.DID)
	fmt.Println(len(body) > 0)
	// Output:
	// did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071
	// true
}
