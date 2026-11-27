package ecdsasd

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// #183: a pointer without a leading "/" was read as the root pointer "", so a
// holder who wrote "credentialSubject" disclosed every statement, and one who
// wrote "x/validFrom" disclosed /validFrom. RFC 6901 §3 starts every reference
// token with "/", so a caller's pointer without one is an error.
func TestCheckPointersRefusesAPointerWithoutLeadingSlash(t *testing.T) {
	cred := w3cCred(t)
	for _, pointer := range []string{"credentialSubject", "credentialSubject/sailNumber", "x/validFrom"} {
		err := checkPointers(cred, []string{"/issuer", pointer})
		if err == nil || !strings.Contains(err.Error(), "must start with /") {
			t.Errorf("%q: error = %v, want a leading-slash error", pointer, err)
		}
	}
}

// VC-DI-ECDSA §3.4.12: a pointer that matches nothing is an error, whatever its
// place next to the root pointer.
func TestCheckPointersRefusesAPointerThatDoesNotMatch(t *testing.T) {
	document := map[string]interface{}{"name": "Alice"}
	for _, pointers := range [][]string{{"", "/missing"}, {"/missing", ""}} {
		err := checkPointers(document, pointers)
		if err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Errorf("%q: error = %v, want a missing pointer error", pointers, err)
		}
	}
	if err := checkPointers(document, []string{"", "/name"}); err != nil {
		t.Errorf(`["", "/name"]: error = %v, want nil`, err)
	}
}

// The two entry points that take pointers from a caller refuse one without a
// leading "/" before anything is disclosed or signed.
func TestProofsRefuseAPointerWithoutLeadingSlash(t *testing.T) {
	cred := w3cCred(t)
	exp := w3cLoadExpected(t)

	if _, _, err := DeriveProof(cred, exp.BaseProofValue, []string{"credentialSubject"}); err == nil ||
		!strings.Contains(err.Error(), "must start with /") {
		t.Errorf("DeriveProof: error = %v, want a leading-slash error", err)
	}

	proofConfig := w3cProofConfig(exp, cred["@context"])
	if _, err := CreateBaseProof(cred, proofConfig, []string{"credentialSubject"}, unreachableSigner{}); err == nil ||
		!strings.Contains(err.Error(), "must start with /") {
		t.Errorf("CreateBaseProof: error = %v, want a leading-slash error", err)
	}
}

// A caller's pointer that matches nothing is refused, even next to the root
// pointer: in the issuer's mandatory pointers, or in the holder's selective
// pointers when the stored mandatory pointers hold "".
func TestProofsRefuseAPointerThatDoesNotMatch(t *testing.T) {
	cred := w3cCred(t)
	exp := w3cLoadExpected(t)
	proofConfig := w3cProofConfig(exp, cred["@context"])

	if _, err := CreateBaseProof(cred, proofConfig, []string{"", "/missing"}, unreachableSigner{}); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Errorf("CreateBaseProof: error = %v, want a missing pointer error", err)
	}

	issuerSigner, _ := w3cIssuer(t)
	basePV, err := CreateBaseProof(cred, proofConfig, []string{""}, issuerSigner)
	if err != nil {
		t.Fatalf("CreateBaseProof: %v", err)
	}
	if _, _, err := DeriveProof(cred, basePV, []string{"/missing"}); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Errorf("DeriveProof: error = %v, want a missing pointer error", err)
	}
}

// Versions up to v1.15.0 signed mandatory pointers without checking them, and
// so does the di-sd-primitives reference. A stored pointer keeps the reference's
// rule of dropping the text before its first "/", so these base proofs still
// verify and derive. Reading
// "credentialSubject" as the root discloses nothing extra: it already made every
// statement mandatory.
func TestBaseProofsWithUncheckedMandatoryPointersStillVerifyAndDerive(t *testing.T) {
	cred := w3cCred(t)
	exp := w3cLoadExpected(t)
	issuerSigner, issuerPub := w3cIssuer(t)

	for _, mandatory := range [][]string{{"credentialSubject"}, {"x/validFrom"}, {"", "/missing"}} {
		// createBaseProof signs what it is given, as released versions did.
		basePV, err := createBaseProof(cred, w3cProofConfig(exp, cred["@context"]), mandatory, issuerSigner, nil)
		if err != nil {
			t.Fatalf("%q: createBaseProof: %v", mandatory, err)
		}
		if err := VerifyBaseProof(cred, w3cProofConfig(exp, cred["@context"]), basePV, issuerPub); err != nil {
			t.Errorf("%q: verify base: %v", mandatory, err)
		}

		revealDoc, derivedPV, err := DeriveProof(cred, basePV, []string{"/issuer"})
		if err != nil {
			t.Errorf("%q: derive: %v", mandatory, err)
			continue
		}
		if err := VerifyProof(revealDoc, w3cProofConfig(exp, revealDoc["@context"]), derivedPV, issuerPub); err != nil {
			t.Errorf("%q: verify derived: %v", mandatory, err)
		}
	}
}

func w3cIssuer(t *testing.T) (signer.SignerProvider, *ecdsa.PublicKey) {
	t.Helper()
	keys := w3cLoadKeys(t)
	issuerPriv, err := verificationmethod.DecodeP256PrivMultibase(keys.BaseKeyPair.SecretKeyMultibase)
	if err != nil {
		t.Fatalf("issuer priv: %v", err)
	}
	issuerSigner, err := signer.NewP256Provider(issuerPriv)
	if err != nil {
		t.Fatalf("issuer signer: %v", err)
	}
	return issuerSigner, &issuerPriv.PublicKey
}

// unreachableSigner fails the test's expectation if signing is reached.
type unreachableSigner struct{}

func (unreachableSigner) Sign([]byte) ([]byte, error) {
	return nil, errors.New("signing reached: the pointer was not refused first")
}

// Densifying removes the holes the selection leaves in an array. A null the
// document holds is data and stays.
func TestSelectJsonLdKeepsNullArrayItems(t *testing.T) {
	document := map[string]interface{}{"list": []interface{}{"a", nil, "b"}}
	cases := map[string]interface{}{
		"/list":   []interface{}{"a", nil, "b"},
		"/list/1": []interface{}{nil},
		"/list/2": []interface{}{"b"},
	}
	for pointer, want := range cases {
		got, err := selectJsonLd(document, []string{pointer})
		if err != nil {
			t.Fatalf("%s: %v", pointer, err)
		}
		if !reflect.DeepEqual(got["list"], want) {
			t.Errorf("%s: list = %#v, want %#v", pointer, got["list"], want)
		}
	}
}

// A later pointer can fill a hole an earlier one left: /a/1/x first leaves a
// hole at /a/0, which /a/0/y then fills. Treating the hole as a selected value
// drops /a/0/y without an error.
func TestSelectJsonLdFillsAHoleALaterPointerReaches(t *testing.T) {
	document := map[string]interface{}{"a": []interface{}{
		map[string]interface{}{"y": "Y0", "secret": "s0"},
		map[string]interface{}{"x": "X1", "secret": "s1"},
	}}
	want := []interface{}{map[string]interface{}{"y": "Y0"}, map[string]interface{}{"x": "X1"}}

	for _, pointers := range [][]string{{"/a/0/y", "/a/1/x"}, {"/a/1/x", "/a/0/y"}} {
		got, err := selectJsonLd(document, pointers)
		if err != nil {
			t.Fatalf("%q: %v", pointers, err)
		}
		if !reflect.DeepEqual(got["a"], want) {
			t.Errorf("%q: a = %#v, want %#v", pointers, got["a"], want)
		}
	}
}

// A pointer can come from a base proof, so an error quotes only its start: a
// 1 MB pointer must not make a 1 MB error.
func TestPointerErrorsQuoteOnlyTheStartOfAPointer(t *testing.T) {
	long := strings.Repeat("a", 1<<20)
	document := map[string]interface{}{"a": map[string]interface{}{}}
	for name, check := range map[string]func() error{
		"no leading slash":         func() error { return checkPointers(document, []string{long}) },
		"missing next to the root": func() error { return checkPointers(document, []string{"", "/" + long}) },
		"missing member": func() error {
			_, err := selectJsonLd(document, []string{"/" + long})
			return err
		},
		"missing under selected one": func() error {
			_, err := selectJsonLd(document, []string{"/a", "/a/" + long})
			return err
		},
	} {
		err := check()
		if err == nil || len(err.Error()) > 1024 {
			t.Errorf("%s: error = %.80v (%d bytes), want an error of at most 1024 bytes", name, err, len(fmt.Sprint(err)))
		}
	}
}
