package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"

	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// AddProof takes a P-256 private key hex, matching the P-256-only VM
// requirement of AddProofByProvider.
func TestVP_AddProof_P256Hex(t *testing.T) {
	const did = "did:example:vp-addproof"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d := make([]byte, 32)
	priv.D.FillBytes(d)
	resolver := vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(did, mustP256VM(t, did, "key-1", &priv.PublicKey)))

	pres, err := vp.ParseJSONPresentation(vpDoc(did))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := pres.AddProof(hex.EncodeToString(d), vp.WithResolver(resolver)); err != nil {
		t.Fatalf("add proof: %v", err)
	}
	if err := pres.Verify(vp.WithResolver(resolver)); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
