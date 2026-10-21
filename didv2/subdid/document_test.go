package subdid

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/pilacorp/go-credential-sdk/didv2/did"
)

const (
	rootR1 = "did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
	rootR2 = "did:nda:0x681248d5c48008ce14e5aebab76ce15476ad2509"
	rootR3 = "did:nda:0x80c0dbf239224071c59dd8970ab9d542e3414ab2"

	subIDS1 = "0b8e6f3c-5a1d-4c27-9f40-3e2a7d91c6b5"
	subIDS2 = "NV-00123"
	subIDS3 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-"

	row1PublicKeyHex  = "0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7"
	row1SubDID        = "did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071"
	row1PrivateKeyHex = "46c9a6cf35b07f7d3f5d37f75bf671cc1251d9399a2db28e35b0942765cde8e8"
	row2PublicKeyHex  = "0x03eea1acf8f417b7825a00be2bf446ef87da146f58e664f36f85f91e74d4f79dc1"
	row2SubDID        = "did:nda:0x97c19e066bdaa1bc4788e3c2e6c35c7e7bfc73af"

	rootR1PrivateKeyHex = "1111111111111111111111111111111111111111111111111111111111111111"
)

var kdfRows = []struct {
	rootDID, subID, publicKeyHex, subDID string
}{
	{rootR1, subIDS1, row1PublicKeyHex, row1SubDID},
	{rootR1, subIDS2, row2PublicKeyHex, row2SubDID},
	{rootR1, subIDS3, "0x02840520aa2a2dc89c1df1bc0a46d061c50303092f6b0c0af9f1f9bb0effaa537a", "did:nda:0x6fcfdfd07a2ca1cf57707527d81ef16ce8c18459"},
	{rootR2, subIDS1, "0x0217f00b15ac4464640c524b43c672d9b90df8bd5081d1d3c1e9ad54a7b959d941", "did:nda:0x586f05f19b0a7f5029383f68f8427eb754e9d77d"},
	{rootR2, subIDS2, "0x0211d8a137a79b618a8a386872dfb23b2dd6a05a05c88f67b4c3acbe5f8c423984", "did:nda:0x4ed51c44fac55637bf6b5a7b8c74f9ad7bf2c3b7"},
	{rootR2, subIDS3, "0x02d15aad4f5842fa3294ab77d843550a00846b349fe81bf773c4deb84a926bd8c6", "did:nda:0xc976ae5221b4f835936ea16811eaf8e838257829"},
	{rootR3, subIDS1, "0x02a480005b1046011aed89aaac3d3abf1da4a1262477b6cec1bad9c5d26a96fb32", "did:nda:0xe86ae62aa9110070ae77143c21b466d0527f2015"},
	{rootR3, subIDS2, "0x031a0971e17b99787b28e2072385a25cd8b1e9b299836db9814243ea169346c648", "did:nda:0xe548a92366b0840bfb6a5c371e989ee385db3d1c"},
	{rootR3, subIDS3, "0x0274b7a2505ee29545559d1ac097d840b4fedf253ed2a84702bc25733d5fe2ee13", "did:nda:0x428196c195b3fca1d70d9397c4d3bf45a94f28fc"},
}

func publicKey(t *testing.T, publicKeyHex string) *ecdsa.PublicKey {
	t.Helper()

	pub, err := crypto.DecompressPubkey(common.FromHex(publicKeyHex))
	if err != nil {
		t.Fatalf("decompress %s: %v", publicKeyHex, err)
	}

	return pub
}

func TestSubDIDFor_KDFRows(t *testing.T) {
	for _, row := range kdfRows {
		got, err := SubDIDFor(row.rootDID, publicKey(t, row.publicKeyHex))
		if err != nil {
			t.Fatalf("%s / %s: %v", row.rootDID, row.subID, err)
		}
		if got != row.subDID {
			t.Errorf("%s / %s: SubDIDFor = %s, want %s", row.rootDID, row.subID, got, row.subDID)
		}
	}
}

func TestParseSubID_Refuses(t *testing.T) {
	for name, subID := range map[string]string{
		"7 bytes":          "NV-0012",
		"65 bytes":         subIDS3 + "a",
		"space":            "NV 00123",
		"dot":              "NV.00123",
		"non-ASCII":        "NV-00123é",
		"trailing newline": "NV-00123\n",
		"empty":            "",
	} {
		if _, err := ParseSubID(subID); err == nil {
			t.Errorf("%s: ParseSubID(%q) accepted", name, subID)
		}
	}
}

func row1Document(t *testing.T, publicKeyHex string, metadata map[string]any, extraVMs ...did.VerificationMethodSpec) *did.DIDDocument {
	t.Helper()

	doc := did.GenerateDIDDocument(publicKeyHex, row1SubDID, "", rootR1, did.DIDTypePeople, metadata, extraVMs...)
	if doc == nil {
		t.Fatal("GenerateDIDDocument returned nil")
	}

	return doc
}

func TestValidateSubDID(t *testing.T) {
	secondKey := did.NewSpec(did.NewSecp256k1VM(row1SubDID, "#key-2", row2PublicKeyHex))

	tests := []struct {
		name    string
		doc     func() *did.DIDDocument
		rootDID string
		wantErr bool
	}{
		{"CreateSubDID document", func() *did.DIDDocument {
			return row1Document(t, row1PublicKeyHex, map[string]any{"subId": subIDS1})
		}, rootR1, false},
		{"second secp256k1 key", func() *did.DIDDocument {
			return row1Document(t, row1PublicKeyHex, nil, secondKey)
		}, rootR1, false},
		{"controller is not the root", func() *did.DIDDocument {
			doc := row1Document(t, row1PublicKeyHex, nil)
			doc.Controller = rootR2
			return doc
		}, rootR1, true},
		{"#key-1 on another address", func() *did.DIDDocument {
			return row1Document(t, row2PublicKeyHex, nil)
		}, rootR1, true},
		{"a fragment-only id shadowing #key-1", func() *did.DIDDocument {
			doc := row1Document(t, row2PublicKeyHex, nil)
			shadow := did.NewSecp256k1VM(row1SubDID, "#key-1", row1PublicKeyHex)
			shadow.Id = "#key-1"
			doc.VerificationMethod = append([]did.VerificationMethod{shadow}, doc.VerificationMethod...)
			return doc
		}, rootR1, true},
		{"mainnet Sub-DID under a testnet root", func() *did.DIDDocument {
			doc := row1Document(t, row1PublicKeyHex, nil)
			doc.Controller = "did:nda:testnet:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
			return doc
		}, "did:nda:testnet:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a", true},
	}
	for _, tt := range tests {
		err := ValidateSubDID(tt.doc(), tt.rootDID)
		if tt.wantErr && err == nil {
			t.Errorf("%s: want error", tt.name)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("%s: %v", tt.name, err)
		}
	}
}

const (
	rootConsentR1 = "0x45b815352a92764deec8dd6bd5f8842332f3e5548f75f803602ec99086537fb63bfa08f1ed32a03d3d33e7f455d4d78cb00877f4c8689c28f41b69dca8a5fa511c"

	createSubDIDJSON    = `{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/v1"],"id":"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071","controller":"did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a","verificationMethod":[{"id":"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1","type":"EcdsaSecp256k1VerificationKey2019","controller":"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071","publicKeyHex":"0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7"}],"authentication":["did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1"],"assertionMethod":["did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1"],"didDocumentMetadata":{"rootConsent":"0x45b815352a92764deec8dd6bd5f8842332f3e5548f75f803602ec99086537fb63bfa08f1ed32a03d3d33e7f455d4d78cb00877f4c8689c28f41b69dca8a5fa511c","subId":"0b8e6f3c-5a1d-4c27-9f40-3e2a7d91c6b5","type":"people"}}`
	createSubDIDDocHash = "0xd40e8cdf47ef809607d4be35edfc75aa9cbc3bda443ab93c706956ecdba3d8a8"

	registerSubDIDJSON    = `{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/v1"],"id":"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071","controller":"did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a","verificationMethod":[{"id":"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1","type":"EcdsaSecp256k1VerificationKey2019","controller":"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071","publicKeyHex":"0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7"}],"authentication":["did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1"],"assertionMethod":["did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1"],"didDocumentMetadata":{"rootConsent":"0x45b815352a92764deec8dd6bd5f8842332f3e5548f75f803602ec99086537fb63bfa08f1ed32a03d3d33e7f455d4d78cb00877f4c8689c28f41b69dca8a5fa511c","type":"people"}}`
	registerSubDIDDocHash = "0x0d19356dd2d8688182a95aa166b7eb0b1f5516821f06b147d50c70e3bd743eec"
)

func decodeFixture(t *testing.T, raw string) *did.DIDDocument {
	t.Helper()

	var doc did.DIDDocument
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	return &doc
}

// The docHash literals are reproduced outside Go with, for example:
//
//	pip install rfc8785 pycryptodome
//	python3 -c 'import json,sys,rfc8785; from Crypto.Hash import keccak;
//	  print(keccak.new(digest_bits=256, data=rfc8785.dumps(json.load(sys.stdin))).hexdigest())' < create.json
func TestDocHash_Vectors(t *testing.T) {
	tests := []struct {
		name, raw, docHash string
		metadata           map[string]any
	}{
		{"CreateSubDID", createSubDIDJSON, createSubDIDDocHash, map[string]any{"subId": subIDS1, "rootConsent": rootConsentR1}},
		{"RegisterSubDID", registerSubDIDJSON, registerSubDIDDocHash, map[string]any{"rootConsent": rootConsentR1}},
	}
	for _, tt := range tests {
		doc := decodeFixture(t, tt.raw)
		h, err := DocHash(doc)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if got := "0x" + hex.EncodeToString(h[:]); got != tt.docHash {
			t.Errorf("%s: docHash = %s, want %s", tt.name, got, tt.docHash)
		}

		generated := did.GenerateDIDDocument(row1PublicKeyHex, row1SubDID, "", rootR1, did.DIDTypePeople, tt.metadata)
		if stored, err := json.Marshal(generated); err != nil || string(stored) != tt.raw {
			t.Errorf("%s: json.Marshal(GenerateDIDDocument) = %s (%v), want the vector", tt.name, stored, err)
		}
	}
}

func TestDocHash_StructDifferenceBreaksTheSignature(t *testing.T) {
	edits := map[string][2]string{
		"controller null":         {`"controller":"did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"`, `"controller":null`},
		"assertionMethod missing": {`"assertionMethod":["did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1"],`, ``},
	}
	for name, edit := range edits {
		raw := strings.Replace(createSubDIDJSON, edit[0], edit[1], 1)
		if raw == createSubDIDJSON {
			t.Fatalf("%s: fixture edit did not apply", name)
		}

		doc := decodeFixture(t, raw)
		h, err := DocHash(doc)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := "0x" + hex.EncodeToString(h[:]); got == createSubDIDDocHash {
			t.Errorf("%s: docHash unchanged", name)
		}
		if err := VerifyDocumentSignature(doc, common.FromHex(createSignature)); !errors.Is(err, ErrPossessionInvalid) {
			t.Errorf("%s: err = %v, want ErrPossessionInvalid", name, err)
		}
	}
}
