package ecdsasd

import (
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// #191. The base proof parses N-Quads text back into a dataset, and a parse that
// decoded escapes one after another turned a backslash before n, r or t into a
// control character, so the base signature covered a changed value and a
// derived proof revealing it did not verify. A literal holding such text keeps
// it through every proof, revealed here. A backslash is not a URI character
// (RFC 3986 §2), so an id holding one is refused when the base proof is made,
// not signed changed.
func TestDerivedProof_ValueWithEscapedText(t *testing.T) {
	exp := w3cLoadExpected(t)
	keys := w3cLoadKeys(t)
	issuerPriv, err := verificationmethod.DecodeP256PrivMultibase(keys.BaseKeyPair.SecretKeyMultibase)
	if err != nil {
		t.Fatalf("issuer priv: %v", err)
	}
	issuerSigner, err := signer.NewP256Provider(issuerPriv)
	if err != nil {
		t.Fatalf("issuer signer: %v", err)
	}
	issuerPub, err := verificationmethod.ECPubFromMultibase(keys.BaseKeyPair.PublicKeyMultibase)
	if err != nil {
		t.Fatalf("issuer pub: %v", err)
	}

	for _, value := range []string{`C:\new`, `C:\rest`, `C:\temp`, `say \"hi\"`, `a\\b`} {
		t.Run(value, func(t *testing.T) {
			cred := w3cCred(t)
			cred["description"] = value
			config := w3cProofConfig(exp, cred["@context"])

			baseProof, err := CreateBaseProof(cred, config, []string{"/issuer"}, issuerSigner)
			if err != nil {
				t.Fatalf("CreateBaseProof: %v", err)
			}
			if err := VerifyProof(cred, config, baseProof, issuerPub); err != nil {
				t.Fatalf("verify base proof: %v", err)
			}
			revealed, derivedProof, err := DeriveProof(cred, baseProof, append(append([]string{}, exp.Derived.SelectivePointers...), "/description"))
			if err != nil {
				t.Fatalf("DeriveProof: %v", err)
			}
			if err := VerifyProof(revealed, w3cProofConfig(exp, revealed["@context"]), derivedProof, issuerPub); err != nil {
				t.Fatalf("verify derived proof: %v", err)
			}
		})
	}

	t.Run("IRI with a backslash", func(t *testing.T) {
		cred := w3cCred(t)
		cred["credentialSubject"].(map[string]interface{})["id"] = `urn:s:a\nb`
		if _, err := CreateBaseProof(cred, w3cProofConfig(exp, cred["@context"]), []string{"/issuer"}, issuerSigner); err == nil {
			t.Fatal("CreateBaseProof signed an id that is not an IRI")
		}
	})
}
