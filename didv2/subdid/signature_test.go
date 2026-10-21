package subdid

import (
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/pilacorp/go-credential-sdk/didv2/signer"
)

const (
	rootConsentDigestR1 = "0xe0fd998a09ff6c4c91a950fa22016dcd57d0f232fe71843aa64a3e805cf0e021"
	rootConsentHighS    = "0x45b815352a92764deec8dd6bd5f8842332f3e5548f75f803602ec99086537fb6c405f70e12cd5fc2c2cc180baa2b28720aa664f1e6e00412cbb6f4b0279046f01b"

	createSignatureDigest = "0xf0ee42e49a17f4d587b62a78432609fbc1de53153c9d72edd8f2f895eb3ea6ca"
	createSignature       = "0x73ffc216c50a9cbdf28d8eac72954f337974e390e83427abe79d3ed5bea8ee7e602b23159cf8ce401bf7e5fc2de553568e9c3a9359267fc393e5033f7fa59ce61b"

	registerSignatureDigest = "0xa8a5a9567d77c2c495d98f3b353eec639fa36b1c4e6aa4b2a72a7b2dc2ce88d7"
	registerSignature       = "0xb9131a83b97882708749b2dedd49b19777f44d36c0b7d6debdda895cb15e6ad37f5e752ceb3f8556e4e6c8f25f2ebe2da8b11bf5706a44ed69d95433f77de4311b"
)

func provider(t *testing.T, privateKeyHex string) signer.SignerProvider {
	t.Helper()

	p, err := signer.NewDefaultProvider(privateKeyHex)
	if err != nil {
		t.Fatal(err)
	}

	return p
}

func TestVerifyRootConsent(t *testing.T) {
	doc := decodeFixture(t, createSubDIDJSON)
	if err := VerifyRootConsent(doc, rootR1); err != nil {
		t.Errorf("R1: %v", err)
	}
	if err := VerifyRootConsent(doc, rootR2); !errors.Is(err, ErrConsentInvalid) {
		t.Errorf("R2: err = %v, want ErrConsentInvalid", err)
	}

	doc.DocumentMetadata[rootConsentKey] = rootConsentHighS
	if err := VerifyRootConsent(doc, rootR1); !errors.Is(err, ErrConsentInvalid) {
		t.Errorf("high-s consent: err = %v, want ErrConsentInvalid", err)
	}
}

func TestVerifyDocumentSignature(t *testing.T) {
	for name, tt := range map[string]struct{ raw, signature string }{
		"CreateSubDID":   {createSubDIDJSON, createSignature},
		"RegisterSubDID": {registerSubDIDJSON, registerSignature},
	} {
		doc := decodeFixture(t, tt.raw)
		sig := common.FromHex(tt.signature)
		if err := VerifyDocumentSignature(doc, sig); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		sig[64] -= 27
		if err := VerifyDocumentSignature(doc, sig); err != nil {
			t.Errorf("%s with v in {0,1}: %v", name, err)
		}
	}

	register := decodeFixture(t, registerSubDIDJSON)
	if err := VerifyDocumentSignature(register, common.FromHex(createSignature)); !errors.Is(err, ErrPossessionInvalid) {
		t.Errorf("CreateSubDID signature on the RegisterSubDID document: err = %v, want ErrPossessionInvalid", err)
	}
}
