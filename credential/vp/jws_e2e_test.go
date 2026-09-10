package vp_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
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

// signVPLegacy signs a presentation through jsonmap. vp issues ecdsa-rdfc-2019
// with a P-256 VM only, so secp256k1 and JsonWebSignature2020 presentations —
// which verification still accepts — can only be produced this way.
func signVPLegacy(t *testing.T, pres vp.Presentation, prov signer.SignerProvider, vmURL string, useJWS bool) *vp.JSONPresentation {
	t.Helper()
	raw, err := pres.GetContents()
	if err != nil {
		t.Fatalf("get contents: %v", err)
	}
	var m jsonmap.JSONMap
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal presentation: %v", err)
	}

	if useJWS {
		err = m.AddJWSProof(prov, vmURL, "authentication")
	} else {
		err = m.AddECDSAProof(prov, vmURL, "authentication")
	}
	if err != nil {
		t.Fatalf("add proof (%s): %v", vmURL, err)
	}

	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal presentation: %v", err)
	}
	signed, err := vp.ParseJSONPresentation(b)
	if err != nil {
		t.Fatalf("re-parse presentation: %v", err)
	}
	return signed
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

// A JsonWebSignature2020 presentation still verifies against the holder's RSA
// verification method.
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
	signed := signVPLegacy(t, pres, rsaProv, jwsHolderDID+"#key-1", true)
	if err := signed.Verify(vp.WithResolver(resolver)); err != nil {
		t.Fatalf("verify vp (rsa proof): %v", err)
	}
}

// WithProofVerificationMethod verifies a single chosen proof: a VP carrying a
// valid RSA proof (key-1) and a secp256k1 proof (key-2) whose key the verifier's
// resolver mis-advertises fails full verification but passes when restricted to
// key-1.
func TestVP_VerifySpecificProof(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}

	pres, err := vp.ParseJSONPresentation(vpDoc(jwsHolderDID))
	if err != nil {
		t.Fatalf("parse vp: %v", err)
	}

	// The verifier resolves a WRONG secp256k1 key for key-2, so only that proof fails.
	verifyResolver := vm.NewStaticResolver(vm.NewDIDDocument(jwsHolderDID,
		vm.NewRSAVM(jwsHolderDID, "key-1", &rsaKey.PublicKey),
		vm.NewSecp256k1VM(jwsHolderDID, "key-2", secpPubHex(t, wrongSecpPriv)),
	))

	rsaProv, _ := signer.NewRSAProvider(rsaKey)
	secp, _ := signer.NewDefaultProvider(holderSecpPriv)
	signed := signVPLegacy(t, pres, rsaProv, jwsHolderDID+"#key-1", true)
	signed = signVPLegacy(t, signed, secp, jwsHolderDID+"#key-2", false)

	// Full verification fails because the key-2 proof does not match.
	if err := signed.Verify(vp.WithResolver(verifyResolver)); err == nil {
		t.Fatal("expected full verify to fail (key-2 advertised wrong key)")
	}

	// Restricting to the valid RSA proof passes.
	if err := signed.Verify(vp.WithResolver(verifyResolver),
		vp.WithProofVerificationMethod(jwsHolderDID+"#key-1")); err != nil {
		t.Fatalf("verify single (key-1) proof: %v", err)
	}
}
