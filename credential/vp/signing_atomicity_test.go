package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// unreachableSigner stands in for a signer that is configured correctly but
// cannot answer — an HSM or a KMS behind a network. It fails at the one step
// every signing path has to take, after everything else the call does.
type unreachableSigner struct{}

func (unreachableSigner) Sign([]byte) ([]byte, error) {
	return nil, errors.New("signer unreachable")
}

// jwtShapedPresentation is what both JWT presentation types have in common.
type jwtShapedPresentation interface {
	AddProofByProvider(signer.SignerProvider, ...vp.PresentationOpt) error
	Verify(...vp.PresentationOpt) error
	Serialize() (interface{}, error)
}

// presentationKinds builds each JWT-shaped presentation, signed once with
// challenge "nonce-AAA". VC 1.1 JWT and vp+jwt carry one signature each and
// must follow the same rules.
func presentationKinds(t *testing.T) []struct {
	name     string
	build    func(t *testing.T) jwtShapedPresentation
	resolver vmpkg.ResolverProvider
	signer   signer.SignerProvider
} {
	t.Helper()
	const holder = "did:example:vp-atomicity"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(holder,
		mustP256VM(t, holder, "key-1", &priv.PublicKey)))

	contents := vp.PresentationContents{
		Context: []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:      "urn:uuid:vp-atomicity",
		Types:   []string{"VerifiablePresentation"},
		Holder:  holder,
	}

	type kind = struct {
		name     string
		build    func(t *testing.T) jwtShapedPresentation
		resolver vmpkg.ResolverProvider
		signer   signer.SignerProvider
	}
	return []kind{
		{"VC 1.1 JWT", func(t *testing.T) jwtShapedPresentation {
			p, err := vp.NewJWTPresentation(contents, vp.WithResolver(resolver),
				vp.WithVerificationMethodKey("key-1"), vp.WithChallenge("nonce-AAA"))
			if err != nil {
				t.Fatalf("NewJWTPresentation: %v", err)
			}
			if err := p.AddProofByProvider(prov, vp.WithResolver(resolver)); err != nil {
				t.Fatalf("sign: %v", err)
			}
			return p
		}, resolver, prov},
		{"vp+jwt", func(t *testing.T) jwtShapedPresentation {
			p, err := vp.NewJOSEPresentation(contents, vp.WithResolver(resolver),
				vp.WithVerificationMethodKey("key-1"), vp.WithChallenge("nonce-AAA"))
			if err != nil {
				t.Fatalf("NewJOSEPresentation: %v", err)
			}
			if err := p.AddProofByProvider(prov, vp.WithResolver(resolver)); err != nil {
				t.Fatalf("sign: %v", err)
			}
			return p
		}, resolver, prov},
	}
}

func tokenOf(t *testing.T, pres jwtShapedPresentation) string {
	t.Helper()
	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	token, ok := serialized.(string)
	if !ok {
		t.Fatalf("serialized presentation is %T, want string", serialized)
	}
	return token
}

// A verifier hands out a fresh challenge, the holder re-signs, and the signer
// fails. The call reports the failure; the presentation must be what it was.
//
// On the VC 1.1 JWT path it was not: the new nonce was written and the old
// signature cleared before signing, so a presentation that verified a moment
// earlier came back with the new nonce and no signature, from a call that
// returned an error. vp+jwt already got this right; the table pins both.
func TestSigning_FailedResignLeavesThePresentationSigned(t *testing.T) {
	for _, k := range presentationKinds(t) {
		t.Run(k.name, func(t *testing.T) {
			pres := k.build(t)
			before := tokenOf(t, pres)

			err := pres.AddProofByProvider(unreachableSigner{}, vp.WithResolver(k.resolver),
				vp.WithChallenge("nonce-BBB"), vp.WithReplaceProof())
			if err == nil {
				t.Fatal("an unreachable signer must fail")
			}

			if after := tokenOf(t, pres); after != before {
				t.Errorf("the failed call changed the token:\n%s\nwant\n%s", after, before)
			}
			if err := pres.Verify(vp.WithResolver(k.resolver), vp.WithExpectedChallenge("nonce-AAA")); err != nil {
				t.Errorf("the presentation stopped verifying with the challenge it was signed with: %v", err)
			}
		})
	}
}

// Re-signing under a new challenge is a real need and must still work.
func TestSigning_ResignWithANewChallengeStillWorks(t *testing.T) {
	for _, k := range presentationKinds(t) {
		t.Run(k.name, func(t *testing.T) {
			pres := k.build(t)

			if err := pres.AddProofByProvider(k.signer, vp.WithResolver(k.resolver),
				vp.WithChallenge("nonce-BBB"), vp.WithReplaceProof()); err != nil {
				t.Fatalf("re-sign: %v", err)
			}
			if err := pres.Verify(vp.WithResolver(k.resolver), vp.WithExpectedChallenge("nonce-BBB")); err != nil {
				t.Fatalf("verify with the new challenge: %v", err)
			}
			if err := pres.Verify(vp.WithResolver(k.resolver), vp.WithExpectedChallenge("nonce-AAA")); err == nil {
				t.Fatal("the old challenge must no longer verify")
			}
		})
	}
}

// Signing an already-signed presentation replaces its signature, because a JWT
// holds one. That stays possible, but only when the caller asks.
func TestSigning_RefusesToReplaceASignature(t *testing.T) {
	for _, k := range presentationKinds(t) {
		t.Run(k.name, func(t *testing.T) {
			pres := k.build(t)
			before := tokenOf(t, pres)

			err := pres.AddProofByProvider(k.signer, vp.WithResolver(k.resolver))
			if err == nil {
				t.Fatal("signing an already-signed presentation must be refused")
			}
			if !strings.Contains(err.Error(), "already signed") {
				t.Errorf("err = %v, want it to say the presentation is already signed", err)
			}
			if after := tokenOf(t, pres); after != before {
				t.Errorf("the refused call changed the token")
			}

			if err := pres.AddProofByProvider(k.signer, vp.WithResolver(k.resolver), vp.WithReplaceProof()); err != nil {
				t.Fatalf("WithReplaceProof must allow re-signing: %v", err)
			}
			if err := pres.Verify(vp.WithResolver(k.resolver)); err != nil {
				t.Fatalf("the replacement signature must verify: %v", err)
			}
		})
	}
}

// JSON-LD presentations append to the proof set, so WithReplaceProof cannot mean
// what it says there. Both JSON-LD signing paths refuse it instead of ignoring
// it, before touching the presentation.
func TestSigning_JSONLDRefusesReplaceProof(t *testing.T) {
	const holder = "did:example:vp-jsonld-replace"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(holder,
		mustP256VM(t, holder, "key-1", &priv.PublicKey)))
	contents := vp.PresentationContents{
		Context: []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:      "urn:uuid:vp-jsonld-replace",
		Types:   []string{"VerifiablePresentation"},
		Holder:  holder,
	}

	paths := []struct {
		name string
		call func(p *vp.JSONPresentation) error
	}{
		{"AddProofByProvider", func(p *vp.JSONPresentation) error {
			return p.AddProofByProvider(prov, vp.WithResolver(resolver), vp.WithReplaceProof())
		}},
		{"AddCustomProof", func(p *vp.JSONPresentation) error {
			proof := &dto.Proof{Type: "DataIntegrityProof", Cryptosuite: "ecdsa-rdfc-2019",
				VerificationMethod: holder + "#key-1", ProofPurpose: "authentication", ProofValue: "z1111"}
			return p.AddCustomProof(proof, vp.WithReplaceProof())
		}},
	}

	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			pres, err := vp.NewJSONPresentation(contents)
			if err != nil {
				t.Fatalf("NewJSONPresentation: %v", err)
			}
			err = path.call(pres)
			if err == nil {
				t.Fatal("WithReplaceProof on a JSON-LD signing call must be refused, not ignored")
			}
			if !strings.Contains(err.Error(), "does not apply to JSON-LD") {
				t.Errorf("err = %v, want it to say the option does not apply to JSON-LD", err)
			}
			if pres.ExtractField("proof") != nil {
				t.Errorf("the refused call attached a proof: %v", pres.ExtractField("proof"))
			}
		})
	}
}
