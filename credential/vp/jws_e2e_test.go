package vp_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vm "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

const (
	jwsHolderDID   = "did:example:vp-holder"
	holderSecpPriv = "57600b3f2b7e1054094e14cd85c72a40dc74c4ee062bb381cea604b55ce56aec"
	wrongSecpPriv  = "1111111111111111111111111111111111111111111111111111111111111111"
)

func secpPubHex(t *testing.T, privHex string) string {
	t.Helper()
	priv, err := ethcrypto.HexToECDSA(privHex)
	if err != nil {
		t.Fatalf("priv: %v", err)
	}
	return hex.EncodeToString(ethcrypto.FromECDSAPub(&priv.PublicKey))
}

func vpDoc(holder string) []byte {
	return []byte(`{
		"@context": ["https://www.w3.org/ns/credentials/v2"],
		"id": "urn:uuid:vp-jws-001",
		"type": ["VerifiablePresentation"],
		"holder": "` + holder + `",
		"verifiableCredential": []
	}`)
}

// VP can be signed with an RSA provider (JsonWebSignature2020), resolved to the
// holder's RSA verification method.
func TestVP_AddProofByProvider_RSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	resolver := vm.NewStaticResolver(vm.NewDIDDocument(jwsHolderDID,
		vm.NewRSAVM(jwsHolderDID, "key-1", &rsaKey.PublicKey),
	))

	pres, err := vp.ParseJSONPresentation(vpDoc(jwsHolderDID))
	if err != nil {
		t.Fatalf("parse vp: %v", err)
	}

	rsaProv, _ := signer.NewRSAProvider(rsaKey)
	if err := pres.AddProofByProvider(rsaProv, vp.WithResolver(resolver)); err != nil {
		t.Fatalf("sign vp with rsa: %v", err)
	}
	if err := pres.Verify(vp.WithResolver(resolver)); err != nil {
		t.Fatalf("verify vp (rsa proof): %v", err)
	}
}

// WithProofVerificationMethod verifies a single chosen proof: a VP carrying a
// valid RSA proof (key-1) and a secp256k1 proof whose key the resolver mis-
// advertises (key-2) fails full verification but passes when restricted to key-1.
func TestVP_VerifySpecificProof(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}

	pres, err := vp.ParseJSONPresentation(vpDoc(jwsHolderDID))
	if err != nil {
		t.Fatalf("parse vp: %v", err)
	}

	// Resolver advertises a WRONG secp256k1 key for key-2. The key types are
	// correct, so signing routes by VM key type; the wrong key value only makes
	// the key-2 proof fail verification.
	resolver := vm.NewStaticResolver(vm.NewDIDDocument(jwsHolderDID,
		vm.NewRSAVM(jwsHolderDID, "key-1", &rsaKey.PublicKey),
		vm.NewSecp256k1VM(jwsHolderDID, "key-2", secpPubHex(t, wrongSecpPriv)),
	))

	rsaProv, _ := signer.NewRSAProvider(rsaKey)
	secp, _ := signer.NewDefaultProvider(holderSecpPriv)
	if err := pres.AddProofByProvider(rsaProv, vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver)); err != nil {
		t.Fatalf("sign rsa proof: %v", err)
	}
	if err := pres.AddProofByProvider(secp, vp.WithVerificationMethodKey("key-2"), vp.WithResolver(resolver)); err != nil {
		t.Fatalf("sign secp proof: %v", err)
	}

	// Full verification fails because the key-2 proof does not match.
	if err := pres.Verify(vp.WithResolver(resolver)); err == nil {
		t.Fatal("expected full verify to fail (key-2 advertised wrong key)")
	}

	// Restricting to the valid RSA proof passes.
	if err := pres.Verify(vp.WithResolver(resolver),
		vp.WithProofVerificationMethod(jwsHolderDID+"#key-1")); err != nil {
		t.Fatalf("verify single (key-1) proof: %v", err)
	}
}
