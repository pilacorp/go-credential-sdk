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
	holderP256Priv = "57600b3f2b7e1054094e14cd85c72a40dc74c4ee062bb381cea604b55ce56aec"
	wrongP256Priv  = "1111111111111111111111111111111111111111111111111111111111111111"
)

func secpPubHex(t *testing.T, privHex string) string {
	t.Helper()
	priv, err := ethcrypto.HexToECDSA(privHex)
	if err != nil {
		t.Fatalf("priv: %v", err)
	}
	return hex.EncodeToString(ethcrypto.FromECDSAPub(&priv.PublicKey))
}

// signVPViaJSONMap signs a presentation through jsonmap, bypassing vp's VM
// selection, so JsonWebSignature2020 (RSA) presentations and rdfc proofs pinned
// to an explicit VM — which verification still accepts — can be produced.
// ecdsa-rdfc-2019 proofs must come from a P-256 signer. The proofs are
// current-format (multibase); see legacy_hex_test.go for pre-multibase hex
// artifacts.
func signVPViaJSONMap(t *testing.T, pres vp.Presentation, prov signer.SignerProvider, vmURL string, useJWS bool) *vp.JSONPresentation {
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
	signed := signVPViaJSONMap(t, pres, rsaProv, jwsHolderDID+"#key-1", true)
	if err := signed.Verify(vp.WithResolver(resolver)); err != nil {
		t.Fatalf("verify vp (rsa proof): %v", err)
	}
}

// WithProofVerificationMethod verifies a single chosen proof: a VP carrying a
// valid RSA proof (key-1) and a P-256 ecdsa-rdfc-2019 proof (key-2) whose key
// the verifier's resolver mis-advertises fails full verification but passes
// when restricted to key-1.
func TestVP_VerifySpecificProof(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	p256Prov, err := signer.NewP256ProviderFromHex(holderP256Priv)
	if err != nil {
		t.Fatalf("p256: %v", err)
	}
	wrongP256, err := signer.NewP256ProviderFromHex(wrongP256Priv)
	if err != nil {
		t.Fatalf("wrong p256: %v", err)
	}

	pres, err := vp.ParseJSONPresentation(vpDoc(jwsHolderDID))
	if err != nil {
		t.Fatalf("parse vp: %v", err)
	}

	// The verifier resolves a WRONG P-256 key for key-2, so only that proof fails.
	verifyResolver := vm.NewStaticResolver(vm.NewDIDDocument(jwsHolderDID,
		vm.NewRSAVM(jwsHolderDID, "key-1", &rsaKey.PublicKey),
		mustP256VM(t, jwsHolderDID, "key-2", wrongP256.Public()),
	))

	rsaProv, _ := signer.NewRSAProvider(rsaKey)
	signed := signVPViaJSONMap(t, pres, rsaProv, jwsHolderDID+"#key-1", true)
	signed = signVPViaJSONMap(t, signed, p256Prov, jwsHolderDID+"#key-2", false)

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
