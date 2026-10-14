package vc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// unreachableSigner stands in for a signer that is configured correctly but
// cannot answer — an HSM or a KMS behind a network. It fails at the one step
// every signing path has to take, after everything else the call does.
type unreachableSigner struct{}

func (unreachableSigner) Sign([]byte) ([]byte, error) {
	return nil, errors.New("signer unreachable")
}

// vc11DocumentJSON is a VC 1.1 document: its @context defines neither the Data
// Integrity terms nor credentials/v2, so a Data Integrity signing call has to
// add a context before it can canonicalize the proof configuration.
const vc11DocumentJSON = `{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "id": "urn:uuid:signing-atomicity-001",
  "type": ["VerifiableCredential"],
  "issuer": "did:example:signing-atomicity",
  "issuanceDate": "2026-01-01T00:00:00Z",
  "credentialSubject": {"id": "did:example:subject"}
}`

func atomicityKey(t *testing.T) (string, *ecdsa.PublicKey, signer.SignerProvider, vmpkg.ResolverProvider) {
	t.Helper()
	const did = "did:example:signing-atomicity"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, mustP256VM(t, did, "key-1", &priv.PublicKey)))
	return did, &priv.PublicKey, prov, resolver
}

// A Data Integrity signing call adds the data-integrity context to a VC 1.1
// document so the proof configuration can be canonicalized. The context is a
// means to a signature: if no signature comes out, it must not stay behind.
func TestSigning_FailedSigningLeavesNoContextBehind(t *testing.T) {
	_, _, _, resolver := atomicityKey(t)

	cred, err := vc.ParseJSONCredential([]byte(vc11DocumentJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	before, err := cred.GetContents()
	if err != nil {
		t.Fatalf("contents: %v", err)
	}

	err = cred.AddProofByProvider(unreachableSigner{},
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err == nil {
		t.Fatal("an unreachable signer must fail")
	}

	after, err := cred.GetContents()
	if err != nil {
		t.Fatalf("contents: %v", err)
	}
	if string(after) != string(before) {
		t.Errorf("document after a failed signing =\n%s\nwant\n%s", after, before)
	}
}

// The same rule for the ecdsa-sd-2023 base proof, which reaches the context
// through its own path.
func TestSigning_FailedSDBaseProofLeavesNoContextBehind(t *testing.T) {
	did, pub, _, _ := atomicityKey(t)

	var m jsonmap.JSONMap
	if err := json.Unmarshal([]byte(vc11DocumentJSON), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	before, _ := json.Marshal(m)

	err := m.AddECDSASDBaseProof(unreachableSigner{}, did+"#key-1", "assertionMethod",
		[]string{"/issuer"}, jsonmap.WithVMPublicKey(pub))
	if err == nil {
		t.Fatal("an unreachable signer must fail")
	}

	if after, _ := json.Marshal(m); string(after) != string(before) {
		t.Errorf("document after a failed base proof =\n%s\nwant\n%s", after, before)
	}
}

// AddECDSASDBaseProof writes the proof set rather than appending to it, so a
// proof already on the document was dropped without a word. It refuses now.
func TestSigning_SDBaseProofRefusesAnExistingProof(t *testing.T) {
	did, pub, prov, _ := atomicityKey(t)

	var m jsonmap.JSONMap
	if err := json.Unmarshal([]byte(vc11DocumentJSON), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := m.AddECDSAProof(prov, did+"#key-1", "assertionMethod", jsonmap.WithVMPublicKey(pub)); err != nil {
		t.Fatalf("add rdfc-2019 proof: %v", err)
	}
	before, _ := json.Marshal(m)

	err := m.AddECDSASDBaseProof(prov, did+"#key-1", "assertionMethod",
		[]string{"/issuer"}, jsonmap.WithVMPublicKey(pub))
	if err == nil {
		t.Fatal("a base proof must not silently replace an existing proof")
	}
	if !strings.Contains(err.Error(), "already carries a proof") {
		t.Errorf("err = %v, want it to name the existing proof", err)
	}
	if after, _ := json.Marshal(m); string(after) != string(before) {
		t.Errorf("the refused call changed the document")
	}
}

// jwtShapedCredential is what both JWT credential types have in common.
type jwtShapedCredential interface {
	AddProofByProvider(signer.SignerProvider, ...vc.CredentialOpt) error
	Verify(...vc.CredentialOpt) error
	Hash() (string, error)
}

// A JWT holds one signature, so signing an already-signed credential replaces
// it. Signing with a key the header does not name already failed. What went
// through in silence was signing again with the RIGHT key: it succeeded and
// Hash() changed, because ECDSA draws a fresh nonce per signature. Hash() is an
// anchoring key, so one credential became two. VC 1.1 JWT and vc+jwt follow the
// same rule.
func TestSigning_RefusesToReplaceASignature(t *testing.T) {
	did, _, prov, resolver := atomicityKey(t)
	contents := joseContents(did)

	kinds := []struct {
		name  string
		build func(t *testing.T) jwtShapedCredential
	}{
		{"VC 1.1 JWT", func(t *testing.T) jwtShapedCredential {
			c, err := vc.NewJWTCredential(contents, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
			if err != nil {
				t.Fatalf("NewJWTCredential: %v", err)
			}
			return c
		}},
		{"vc+jwt", func(t *testing.T) jwtShapedCredential {
			c, err := vc.NewJOSECredential(contents, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
			if err != nil {
				t.Fatalf("NewJOSECredential: %v", err)
			}
			return c
		}},
	}

	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) {
			cred := k.build(t)
			if err := cred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
				t.Fatalf("sign: %v", err)
			}
			first, err := cred.Hash()
			if err != nil {
				t.Fatalf("hash: %v", err)
			}

			// The right key, the same claims: the case that used to pass in silence.
			err = cred.AddProofByProvider(prov, vc.WithResolver(resolver))
			if err == nil {
				t.Fatal("signing an already-signed credential must be refused")
			}
			if !strings.Contains(err.Error(), "already signed") {
				t.Errorf("err = %v, want it to say the credential is already signed", err)
			}
			if refused, _ := cred.Hash(); refused != first {
				t.Errorf("the refused call changed Hash(): %s -> %s", first, refused)
			}

			// Asked for, it goes through — and the hash moves, which is why the
			// caller has to ask.
			if err := cred.AddProofByProvider(prov, vc.WithResolver(resolver), vc.WithReplaceProof()); err != nil {
				t.Fatalf("WithReplaceProof must allow re-signing: %v", err)
			}
			if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
				t.Fatalf("the replacement signature must verify: %v", err)
			}
			if replaced, _ := cred.Hash(); replaced == first {
				t.Error("re-signing produced the same Hash(); this test no longer shows why the option exists")
			}
		})
	}
}
