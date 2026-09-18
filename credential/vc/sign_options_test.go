package vc_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/internal/jwttest"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// signPath signs contents one way and returns what was built, so the test can
// check it afterwards: verify runs the SDK's own Verify, attached reports
// whether a signature or proof ended up on the credential.
type signPath struct {
	name string
	sign func(t *testing.T, contents vc.CredentialContents, s signer.SignerProvider, opts ...vc.CredentialOpt) (verify func() error, attached func() bool, err error)
}

func signPaths(resolver vmpkg.ResolverProvider) []signPath {
	return []signPath{
		{"JWT AddProofByProvider", func(t *testing.T, c vc.CredentialContents, s signer.SignerProvider, opts ...vc.CredentialOpt) (func() error, func() bool, error) {
			cred, err := vc.NewJWTCredential(c, vc.WithResolver(resolver))
			if err != nil {
				t.Fatalf("new jwt credential: %v", err)
			}
			err = cred.AddProofByProvider(s, opts...)
			return func() error { return cred.Verify(vc.WithResolver(resolver)) },
				func() bool { _, herr := cred.Hash(); return herr == nil }, err
		}},
		{"JWT AddCustomProof", func(t *testing.T, c vc.CredentialContents, s signer.SignerProvider, opts ...vc.CredentialOpt) (func() error, func() bool, error) {
			cred, err := vc.NewJWTCredential(c, vc.WithResolver(resolver))
			if err != nil {
				t.Fatalf("new jwt credential: %v", err)
			}
			input, err := cred.GetSigningInput()
			if err != nil {
				t.Fatalf("signing input: %v", err)
			}
			err = cred.AddCustomProof(&dto.Proof{Signature: jwttest.SignExternally(t, s, string(input))}, opts...)
			return func() error { return cred.Verify(vc.WithResolver(resolver)) },
				func() bool { _, herr := cred.Hash(); return herr == nil }, err
		}},
		{"JSON AddProofByProvider", func(t *testing.T, c vc.CredentialContents, s signer.SignerProvider, opts ...vc.CredentialOpt) (func() error, func() bool, error) {
			cred, err := vc.NewJSONCredential(c)
			if err != nil {
				t.Fatalf("new json credential: %v", err)
			}
			err = cred.AddProofByProvider(s, append([]vc.CredentialOpt{vc.WithResolver(resolver)}, opts...)...)
			return func() error { return cred.Verify(vc.WithResolver(resolver)) },
				func() bool { _, serr := cred.Serialize(); return serr == nil }, err
		}},
		{"JSON AddCustomProof", func(t *testing.T, c vc.CredentialContents, s signer.SignerProvider, opts ...vc.CredentialOpt) (func() error, func() bool, error) {
			cred, err := vc.NewJSONCredential(c)
			if err != nil {
				t.Fatalf("new json credential: %v", err)
			}
			err = cred.AddCustomProof(externalJSONProof(t, c, s, resolver), opts...)
			return func() error { return cred.Verify(vc.WithResolver(resolver)) },
				func() bool { return cred.ExtractField("proof") != nil }, err
		}},
		{"ECDSA-SD AddProofByProvider", func(t *testing.T, c vc.CredentialContents, s signer.SignerProvider, opts ...vc.CredentialOpt) (func() error, func() bool, error) {
			cred, err := vc.NewECDSASDCredential(c)
			if err != nil {
				t.Fatalf("new ecdsa-sd credential: %v", err)
			}
			err = cred.AddProofByProvider(s, nil, append([]vc.CredentialOpt{vc.WithResolver(resolver)}, opts...)...)
			attached := func() bool { _, derr := cred.Derive([]string{"credentialSubject.name"}); return derr == nil }
			verify := func() error {
				derived, derr := cred.Derive([]string{"credentialSubject.name"})
				if derr != nil {
					return derr
				}
				return derived.Verify(vc.WithResolver(resolver))
			}
			return verify, attached, err
		}},
	}
}

// WithVerifyProof is a verification option. At signing time there is no
// signature to verify yet, and the signing paths already check the fresh
// signature against the verification method's key, so it must not stop a
// correct signature from being attached.
func TestSign_VerifyOptionDoesNotBlockACorrectSignature(t *testing.T) {
	const did = "did:example:sign-opts"
	resolver, _, p256 := dualCurveDID(t, did)

	for _, path := range signPaths(resolver) {
		t.Run(path.name, func(t *testing.T) {
			verify, _, err := path.sign(t, jwtMultikeyContents(did), p256,
				vc.WithVerifyProof(), vc.WithResolver(resolver))
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if err := verify(); err != nil {
				t.Fatalf("verify: %v", err)
			}
		})
	}
}

// Content options (here WithCheckExpiration) run before signing: a credential
// that fails them is never handed to the signer and nothing is attached.
func TestSign_ContentOptionsRunBeforeSigning(t *testing.T) {
	const did = "did:example:sign-opts"
	resolver, _, p256 := dualCurveDID(t, did)

	notYetValid := jwtMultikeyContents(did)
	notYetValid.ValidFrom = time.Now().Add(time.Hour)

	for _, path := range signPaths(resolver) {
		wantCalls := 0
		if strings.HasSuffix(path.name, "AddCustomProof") {
			wantCalls = 1 // the test signs outside the SDK before the call
		}
		t.Run(path.name, func(t *testing.T) {
			s := &jwttest.Counting{SignerProvider: p256}
			_, attached, err := path.sign(t, notYetValid, s, vc.WithCheckExpiration())
			if err == nil || !strings.Contains(err.Error(), "not valid yet") {
				t.Fatalf("sign err = %v, want the expiration check to fail", err)
			}
			if s.Calls != wantCalls {
				t.Fatalf("signer was called %d time(s), want %d: a credential that fails its options must not be signed", s.Calls, wantCalls)
			}
			if attached() {
				t.Fatal("nothing must be attached")
			}
		})
	}
}

// externalJSONProof signs a copy of the credential with the SDK and returns the
// proof, as a client signing outside would hand it to AddCustomProof.
func externalJSONProof(t *testing.T, c vc.CredentialContents, s signer.SignerProvider, resolver vmpkg.ResolverProvider) *dto.Proof {
	t.Helper()
	signed, err := vc.NewJSONCredential(c)
	if err != nil {
		t.Fatalf("new json credential: %v", err)
	}
	if err := signed.AddProofByProvider(s, vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign the copy: %v", err)
	}
	raw, err := json.Marshal(signed.ExtractField("proof"))
	if err != nil {
		t.Fatalf("marshal proof: %v", err)
	}
	var proof dto.Proof
	if err := json.Unmarshal(raw, &proof); err != nil {
		t.Fatalf("unmarshal proof: %v", err)
	}
	return &proof
}

// The header's kid and the SD-JWT disclosures are fixed by NewJWTCredential; a
// signing call refuses the options that set them instead of dropping them,
// before the signer is called, and attaches nothing.
func TestJWT_SigningRefusesBuildTimeOptions(t *testing.T) {
	const (
		did    = "did:example:sign-opts"
		wantVM = "WithVerificationMethodKey cannot be applied when signing a JWT"
		wantSD = "SD-JWT options cannot be applied when signing"
	)
	resolver, _, p256 := dualCurveDID(t, did)

	options := []struct {
		name string
		opt  vc.CredentialOpt
		want string
	}{
		// key-2 is the header's own key: refused even when it would change nothing.
		{"WithVerificationMethodKey", vc.WithVerificationMethodKey("key-2"), wantVM},
		{"WithSDSelectivePaths", vc.WithSDSelectivePaths([]string{"credentialSubject.name"}), wantSD},
		{"WithSDDisclosures", vc.WithSDDisclosures([]string{"WyJzYWx0IiwibmFtZSIsIkEiXQ"}), wantSD},
		{"WithSDHashAlgorithm", vc.WithSDHashAlgorithm("sha-256"), wantSD},
		{"WithSDShuffle", vc.WithSDShuffle(true), wantSD},
		{"WithSDDecoyDigests", vc.WithSDDecoyDigests([]vc.Decoy{{}}), wantSD},
	}
	for _, path := range signPaths(resolver) {
		if !strings.HasPrefix(path.name, "JWT") {
			continue
		}
		wantCalls := 0
		if path.name == "JWT AddCustomProof" {
			wantCalls = 1 // the test signs outside the SDK before the call
		}
		for _, o := range options {
			t.Run(path.name+"/"+o.name, func(t *testing.T) {
				s := &jwttest.Counting{SignerProvider: p256}
				_, attached, err := path.sign(t, jwtMultikeyContents(did), s, o.opt)
				if err == nil || !strings.Contains(err.Error(), o.want) {
					t.Fatalf("sign err = %v, want a refusal containing %q", err, o.want)
				}
				if s.Calls != wantCalls {
					t.Fatalf("signer called %d time(s), want %d: refuse before signing", s.Calls, wantCalls)
				}
				if attached() {
					t.Fatal("nothing must be attached")
				}
			})
		}
	}
}

// A JSON-LD proof arrives at AddCustomProof already signed, verificationMethod
// included; an option naming another method is refused, not dropped.
func TestJSON_AddCustomProofRefusesVerificationMethodOption(t *testing.T) {
	const did = "did:example:sign-opts"
	proof := func() *dto.Proof {
		return &dto.Proof{Type: "DataIntegrityProof", Cryptosuite: "ecdsa-rdfc-2019", ProofPurpose: "assertionMethod",
			VerificationMethod: did + "#key-2", ProofValue: "z3FXQ", Created: "2026-09-19T00:00:00Z"}
	}

	cred, err := vc.NewJSONCredential(jwtMultikeyContents(did))
	if err != nil {
		t.Fatalf("new json credential: %v", err)
	}
	err = cred.AddCustomProof(proof(), vc.WithVerificationMethodKey("key-1"))
	if err == nil || !strings.Contains(err.Error(), "proof.VerificationMethod") {
		t.Fatalf("err = %v, want a refusal pointing at proof.VerificationMethod", err)
	}
	if cred.ExtractField("proof") != nil {
		t.Fatal("a refused proof must not be attached")
	}

	// The same proof without the option is attached: the refusal is about the option.
	if err := cred.AddCustomProof(proof()); err != nil {
		t.Fatalf("plain AddCustomProof: %v", err)
	}
	if cred.ExtractField("proof") == nil {
		t.Fatal("proof should be attached")
	}
}
