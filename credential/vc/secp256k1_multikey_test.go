package vc_test

import (
	"encoding/hex"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// A secp256k1 key published as a Multikey must carry a credential end to end:
// the signer picks EcdsaSecp256k1Signature2019 from the bound VM's key type,
// and the verifier reads the key back out of publicKeyMultibase.
//
// publicKeyHex, which these documents used to carry, is not a property DID Core
// defines — a resolver written against the specification finds no key material
// in it and treats the verification method as holding none, so a credential we
// issue cannot be verified outside this system (#91).
func TestSecp256k1Suite_MultikeyVerificationMethod(t *testing.T) {
	const did = "did:example:secp-multikey"

	privBytes, err := hex.DecodeString(suiteSecpPriv)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	priv, err := ethcrypto.ToECDSA(privBytes)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	mkVM, err := vmpkg.NewSecp256k1MultikeyVM(did, "key-1", &priv.PublicKey)
	if err != nil {
		t.Fatalf("NewSecp256k1MultikeyVM: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, mkVM))

	cred, err := vc.ParseJSONCredential(mkSuiteCredentialJSON(did))
	if err != nil {
		t.Fatalf("parse credential: %v", err)
	}
	if err := cred.AddProofByProvider(
		secpProvider(t),
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(resolver),
	); err != nil {
		t.Fatalf("add proof: %v", err)
	}

	// The suite is chosen from the key the VM holds, so a Multikey must route to
	// the same suite publicKeyHex did.
	proof := proofOf(t, cred)
	if proof["type"] != "EcdsaSecp256k1Signature2019" {
		t.Errorf("proof type = %v, want EcdsaSecp256k1Signature2019", proof["type"])
	}
	if proof["jws"] == nil {
		t.Error("proof carries no jws")
	}

	if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify against a Multikey verification method: %v", err)
	}
}
