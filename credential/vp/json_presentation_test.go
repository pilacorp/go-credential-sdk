package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// The VC Data Model allows holder as either a URL string or an object with an
// id. The verifier already accepted both; signing must too, or a presentation
// another implementation produced cannot be signed by this SDK.
func TestVP_HolderObject_SignAndVerify(t *testing.T) {
	const holder = "did:example:vp-holder-object"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("p256: %v", err)
	}
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(holder,
		mustP256VM(t, holder, "key-1", &priv.PublicKey)))

	doc := []byte(`{
		"@context": ["https://www.w3.org/ns/credentials/v2"],
		"id": "urn:uuid:vp-holder-object",
		"type": ["VerifiablePresentation"],
		"holder": {"id": "` + holder + `", "name": "Alice"},
		"verifiableCredential": []
	}`)

	pres, err := vp.ParseJSONPresentation(doc)
	if err != nil {
		t.Fatalf("parse vp: %v", err)
	}
	if err := pres.AddProofByProvider(prov, vp.WithResolver(resolver)); err != nil {
		t.Fatalf("sign vp with object holder: %v", err)
	}
	if err := pres.Verify(vp.WithResolver(resolver)); err != nil {
		t.Fatalf("verify vp with object holder: %v", err)
	}

	// Signing resolves the DID from holder.id but must leave the object
	// itself untouched — it is part of the signed document.
	if got := pres.ExtractField("holder.id"); got != holder {
		t.Errorf("raw holder.id = %q, want %q; the object form must not be flattened", got, holder)
	}
}

// An object holder without an id carries no DID to resolve a signing key from.
func TestVP_HolderObjectWithoutID_RejectedAtSigning(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	prov, _ := signer.NewP256Provider(priv)

	pres, err := vp.ParseJSONPresentation([]byte(`{
		"@context": ["https://www.w3.org/ns/credentials/v2"],
		"type": ["VerifiablePresentation"],
		"holder": {"name": "Alice"},
		"verifiableCredential": []
	}`))
	if err != nil {
		t.Fatalf("parse vp: %v", err)
	}
	if err := pres.AddProofByProvider(prov); err == nil {
		t.Fatal("expected signing to fail when holder has no id")
	}
}
