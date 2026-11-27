package attribute_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/didv2"
	"github.com/pilacorp/go-credential-sdk/didv2/attribute"
	"github.com/pilacorp/go-credential-sdk/didv2/did"
	"github.com/pilacorp/go-credential-sdk/didv2/signer"
)

// platformDocument is what the platform creates: secp256k1 #key-1 for both
// purposes, P-256 Multikey #key-2 for assertion.
func platformDocument(t *testing.T) *did.DIDDocument {
	t.Helper()

	kp, err := did.GenerateECDSAKeyPair()
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	issuerSigner, err := signer.NewDefaultProvider(kp.GetPrivateKeyHex())
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	g, err := didv2.NewDIDGenerator(didv2.WithIssuerSignerProvider(issuerSigner))
	if err != nil {
		t.Fatalf("generator: %v", err)
	}

	res, err := g.GenerateDID(t.Context(), did.DIDTypePeople, "", nil, didv2.WithP256VerificationMethod())
	if err != nil {
		t.Fatalf("GenerateDID: %v", err)
	}

	return res.Document
}

func freshSecpKey(t *testing.T) string {
	t.Helper()

	kp, err := did.GenerateECDSAKeyPair()
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	return kp.GetPublicKeyHex()
}

// requireUpdate checks what every update owes did-registrar: the hash is the new
// document's, and the document passed in is left as it was.
func requireUpdate(t *testing.T, before string, doc *did.DIDDocument, u *attribute.Update) {
	t.Helper()

	got, err := u.Document.Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if got != u.DocHash {
		t.Errorf("DocHash %s, the document hashes to %s", u.DocHash, got)
	}

	after, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(after) != before {
		t.Error("the input document was modified")
	}
}

func snapshot(t *testing.T, doc *did.DIDDocument) string {
	t.Helper()

	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	return string(raw)
}

func record(t *testing.T, u *attribute.Update) *attribute.Record {
	t.Helper()

	rec, err := attribute.DecodeRecord(u.Value)
	if err != nil {
		t.Fatalf("decode %s: %v", u.Value, err)
	}

	return rec
}

func TestAddingAMethodPublishesItsKeyN(t *testing.T) {
	doc := platformDocument(t)
	before := snapshot(t, doc)
	key := freshSecpKey(t)

	u, err := attribute.AddVerificationMethod(doc, did.VerificationMethod{PublicKeyHex: key},
		[]did.VerificationPurpose{did.PurposeAuthentication})
	if err != nil {
		t.Fatalf("AddVerificationMethod: %v", err)
	}

	requireUpdate(t, before, doc, u)

	if u.Name != "key/3" || len(u.Document.VerificationMethod) != 3 {
		t.Fatalf("name %s, %d methods", u.Name, len(u.Document.VerificationMethod))
	}

	rec := record(t, u)
	if rec.PublicKey != key || !slices.Equal(rec.Purposes, []string{attribute.PurposeAuth}) || rec.KeyType != "" || rec.Revoked != nil {
		t.Errorf("record %+v", rec)
	}
}

// did-registrar refuses a revocation whose record has no revoked block: the key
// would stay valid on chain while the document says it is revoked.
func TestRevokingAMethodPublishesTheRevocation(t *testing.T) {
	doc := platformDocument(t)
	before := snapshot(t, doc)
	at := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)

	u, err := attribute.RevokeVerificationMethod(doc, "#key-2", "keyCompromise", at)
	if err != nil {
		t.Fatalf("RevokeVerificationMethod: %v", err)
	}

	requireUpdate(t, before, doc, u)

	if u.Name != "key/2" {
		t.Fatalf("name %s", u.Name)
	}

	if !strings.Contains(string(u.Value), `"kt":"Multikey","revoked":{"t":"2026-11-27T00:00:00Z","reason":"keyCompromise"}`) {
		t.Errorf("value %s", u.Value)
	}

	if vm := u.Document.FindVerificationMethod("#key-2"); vm == nil || vm.Revoked == nil {
		t.Error("#key-2 is not revoked in the new document")
	}
}

func TestChangingPurposesPublishesTheMethodsNewPurposes(t *testing.T) {
	doc := platformDocument(t)
	before := snapshot(t, doc)

	added, err := attribute.AddVerificationMethodPurposes(doc, "#key-2", []did.VerificationPurpose{did.PurposeAuthentication})
	if err != nil {
		t.Fatalf("AddVerificationMethodPurposes: %v", err)
	}

	requireUpdate(t, before, doc, added)

	if rec := record(t, added); added.Name != "key/2" || !slices.Equal(rec.Purposes, []string{attribute.PurposeAssert, attribute.PurposeAuth}) {
		t.Errorf("%s %+v", added.Name, rec)
	}

	removed, err := attribute.RemoveVerificationMethodPurposes(doc, "#key-1", []did.VerificationPurpose{did.PurposeAuthentication})
	if err != nil {
		t.Fatalf("RemoveVerificationMethodPurposes: %v", err)
	}

	requireUpdate(t, before, doc, removed)

	if rec := record(t, removed); removed.Name != "key/1" || !slices.Equal(rec.Purposes, []string{attribute.PurposeAssert}) {
		t.Errorf("%s %+v", removed.Name, rec)
	}
}

// A rotation changes two methods, the new one and the revoked one; a key/N
// would write only one, so the attribute is the bundle, and it names every
// method of the new document.
func TestRotatingAMethodPublishesTheWholeSet(t *testing.T) {
	doc := platformDocument(t)
	before := snapshot(t, doc)

	u, err := attribute.RotateVerificationMethod(doc, "#key-1",
		did.VerificationMethod{PublicKeyHex: freshSecpKey(t)}, "superseded", time.Time{})
	if err != nil {
		t.Fatalf("RotateVerificationMethod: %v", err)
	}

	requireUpdate(t, before, doc, u)

	if u.Name != attribute.VMBundleAttributeName {
		t.Fatalf("name %s", u.Name)
	}

	records, err := attribute.DecodeVMBundle(u.Value)
	if err != nil {
		t.Fatalf("DecodeVMBundle: %v", err)
	}

	if len(records) != len(u.Document.VerificationMethod) || len(records) != 3 {
		t.Fatalf("%d records for %d methods", len(records), len(u.Document.VerificationMethod))
	}

	if records[0].ID != "#key-1" || records[0].Revoked == nil || records[2].ID != "#key-3" || records[2].Revoked != nil {
		t.Errorf("bundle %s", u.Value)
	}
}

// A failed operation leaves nothing behind: the input is untouched and no
// update is returned to sign.
func TestAFailedOperationReturnsNoUpdate(t *testing.T) {
	doc := platformDocument(t)
	before := snapshot(t, doc)

	if u, err := attribute.RevokeVerificationMethod(doc, "#key-9", "keyCompromise", time.Time{}); err == nil || u != nil {
		t.Fatalf("revoked a method the document does not have: %v", u)
	}

	if snapshot(t, doc) != before {
		t.Error("the input document was modified")
	}
}

func TestNameForMapsAMethodIDToItsAttribute(t *testing.T) {
	for kid, want := range map[string]string{
		"did:nda:testnet:0xab#key-3": "key/3",
		"#key-12":                    "key/12",
		"key-1":                      "key/1",
	} {
		if got, err := attribute.NameFor(kid); err != nil || got != want {
			t.Errorf("NameFor(%q) = %q, %v; want %q", kid, got, err, want)
		}
	}

	for _, kid := range []string{"#key-0", "#key-x", "#owner", ""} {
		if _, err := attribute.NameFor(kid); err == nil {
			t.Errorf("NameFor(%q) accepted", kid)
		}
	}
}
