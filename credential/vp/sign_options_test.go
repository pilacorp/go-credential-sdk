package vp_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/internal/jwttest"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// signPath signs contents one way and returns what was built: verify runs the
// SDK's own Verify, attached reports whether a signature or proof ended up on
// the presentation.
type signPath struct {
	name string
	sign func(t *testing.T, contents vp.PresentationContents, s signer.SignerProvider, opts ...vp.PresentationOpt) (verify func() error, attached func() bool, err error)
}

func signPaths(resolver vmpkg.ResolverProvider) []signPath {
	jwtAttached := func(p *vp.JWTPresentation) func() bool {
		return func() bool { s, _ := p.Serialize(); return strings.Count(s.(string), ".") == 2 }
	}
	return []signPath{
		{"JWT AddProofByProvider", func(t *testing.T, c vp.PresentationContents, s signer.SignerProvider, opts ...vp.PresentationOpt) (func() error, func() bool, error) {
			p, err := vp.NewJWTPresentation(c, vp.WithResolver(resolver))
			if err != nil {
				t.Fatalf("NewJWTPresentation: %v", err)
			}
			err = p.AddProofByProvider(s, opts...)
			return func() error { return p.Verify(vp.WithResolver(resolver)) }, jwtAttached(p), err
		}},
		{"JWT AddCustomProof", func(t *testing.T, c vp.PresentationContents, s signer.SignerProvider, opts ...vp.PresentationOpt) (func() error, func() bool, error) {
			p, err := vp.NewJWTPresentation(c, vp.WithResolver(resolver))
			if err != nil {
				t.Fatalf("NewJWTPresentation: %v", err)
			}
			input, err := p.GetSigningInput()
			if err != nil {
				t.Fatalf("GetSigningInput: %v", err)
			}
			err = p.AddCustomProof(&dto.Proof{Signature: jwttest.SignExternally(t, s, string(input))}, opts...)
			return func() error { return p.Verify(vp.WithResolver(resolver)) }, jwtAttached(p), err
		}},
		{"JSON AddCustomProof", func(t *testing.T, c vp.PresentationContents, s signer.SignerProvider, opts ...vp.PresentationOpt) (func() error, func() bool, error) {
			p, err := vp.NewJSONPresentation(c)
			if err != nil {
				t.Fatalf("NewJSONPresentation: %v", err)
			}
			err = p.AddCustomProof(externalJSONProof(t, c, s, resolver), opts...)
			return func() error { return p.Verify(vp.WithResolver(resolver)) },
				func() bool { return p.ExtractField("proof") != nil }, err
		}},
		{"JSON AddProofByProvider", func(t *testing.T, c vp.PresentationContents, s signer.SignerProvider, opts ...vp.PresentationOpt) (func() error, func() bool, error) {
			p, err := vp.NewJSONPresentation(c)
			if err != nil {
				t.Fatalf("NewJSONPresentation: %v", err)
			}
			err = p.AddProofByProvider(s, append([]vp.PresentationOpt{vp.WithResolver(resolver)}, opts...)...)
			return func() error { return p.Verify(vp.WithResolver(resolver)) },
				func() bool { _, serr := p.Serialize(); return serr == nil }, err
		}},
	}
}

func signOptionsContents() vp.PresentationContents {
	return vp.PresentationContents{
		Context: []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:      "urn:uuid:sign-options-test",
		Types:   []string{"VerifiablePresentation"},
		Holder:  testDID,
	}
}

// WithVerifyProof is a verification option. At signing time there is no
// signature to verify yet, and the signing paths already check the fresh
// signature against the verification method's key, so it must not stop a
// correct signature from being attached.
func TestSign_VerifyOptionDoesNotBlockACorrectSignature(t *testing.T) {
	resolver := testResolver(t)
	for _, path := range signPaths(resolver) {
		t.Run(path.name, func(t *testing.T) {
			verify, _, err := path.sign(t, signOptionsContents(), mustP256Signer(t),
				vp.WithVerifyProof(), vp.WithResolver(resolver))
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if err := verify(); err != nil {
				t.Fatalf("verify: %v", err)
			}
		})
	}
}

// Content options (here WithCheckExpiration) run before signing: a
// presentation that fails them is never handed to the signer and nothing is
// attached.
func TestSign_ContentOptionsRunBeforeSigning(t *testing.T) {
	resolver := testResolver(t)
	notYetValid := signOptionsContents()
	notYetValid.ValidFrom = time.Now().Add(time.Hour)

	for _, path := range signPaths(resolver) {
		wantCalls := 0
		if strings.HasSuffix(path.name, "AddCustomProof") {
			wantCalls = 1 // the test signs outside the SDK before the call
		}
		t.Run(path.name, func(t *testing.T) {
			s := &jwttest.Counting{SignerProvider: mustP256Signer(t)}
			_, attached, err := path.sign(t, notYetValid, s, vp.WithCheckExpiration())
			if err == nil || !strings.Contains(err.Error(), "not valid yet") {
				t.Fatalf("sign err = %v, want the expiration check to fail", err)
			}
			if s.Calls != wantCalls {
				t.Fatalf("signer was called %d time(s), want %d: a presentation that fails its options must not be signed", s.Calls, wantCalls)
			}
			if attached() {
				t.Fatal("nothing must be attached")
			}
		})
	}
}

// externalJSONProof signs a copy of the presentation with the SDK and returns
// the proof, as a client signing outside would hand it to AddCustomProof.
func externalJSONProof(t *testing.T, c vp.PresentationContents, s signer.SignerProvider, resolver vmpkg.ResolverProvider) *dto.Proof {
	t.Helper()
	// The v2 context defines no validFrom/validUntil on a presentation, so a copy
	// carrying them cannot be canonicalized; the proof only has to reach the
	// option checks, which read the target presentation, not this copy.
	c.ValidFrom, c.ValidUntil = time.Time{}, time.Time{}
	signed, err := vp.NewJSONPresentation(c)
	if err != nil {
		t.Fatalf("NewJSONPresentation: %v", err)
	}
	if err := signed.AddProofByProvider(s, vp.WithResolver(resolver)); err != nil {
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

// A JWT presentation's kid is fixed by NewJWTPresentation, and an external
// signature already covers nonce/aud; the signing calls refuse the options that
// would set them instead of dropping them, and attach nothing.
func TestJWTPresentation_SigningRefusesBuildTimeOptions(t *testing.T) {
	const (
		wantVM        = "WithVerificationMethodKey cannot be applied when signing a JWT"
		wantChallenge = "pass them to NewJWTPresentation before GetSigningInput"
	)
	resolver := testResolver(t)
	p256 := mustP256Signer(t)

	cases := []struct {
		name  string
		opt   vp.PresentationOpt
		paths []string // JWT signing paths that must refuse it
		want  string
	}{
		{"WithVerificationMethodKey", vp.WithVerificationMethodKey("key-2"), []string{"JWT AddProofByProvider", "JWT AddCustomProof"}, wantVM},
		{"WithChallenge", vp.WithChallenge("my-nonce"), []string{"JWT AddCustomProof"}, wantChallenge},
		{"WithDomain", vp.WithDomain("https://verifier.example"), []string{"JWT AddCustomProof"}, wantChallenge},
	}
	for _, path := range signPaths(resolver) {
		for _, tc := range cases {
			refused := false
			for _, p := range tc.paths {
				refused = refused || p == path.name
			}
			if !refused {
				continue
			}
			wantCalls := 0
			if path.name == "JWT AddCustomProof" {
				wantCalls = 1 // the test signs outside the SDK before the call
			}
			t.Run(path.name+"/"+tc.name, func(t *testing.T) {
				s := &jwttest.Counting{SignerProvider: p256}
				_, attached, err := path.sign(t, jwtVPContents(), s, tc.opt)
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("err = %v, want a refusal containing %q", err, tc.want)
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

	// The refusal comes before applyChallengeDomain: a refused call leaves the
	// payload untouched even when WithChallenge is passed alongside.
	t.Run("AddProofByProvider leaves the payload untouched", func(t *testing.T) {
		p, err := vp.NewJWTPresentation(jwtVPContents(), vp.WithResolver(resolver))
		if err != nil {
			t.Fatalf("new: %v", err)
		}
		before, _ := p.GetSigningInput()
		err = p.AddProofByProvider(p256, vp.WithVerificationMethodKey("key-2"), vp.WithChallenge("n"))
		if err == nil || !strings.Contains(err.Error(), wantVM) {
			t.Fatalf("err = %v, want %q", err, wantVM)
		}
		if after, _ := p.Serialize(); after.(string) != string(before) {
			t.Fatal("a refused call must leave the presentation unsigned and its payload unchanged")
		}
	})

	// The same external signature without the option is accepted and verifies:
	// the refusal is about the option, not the signature.
	t.Run("plain AddCustomProof still verifies", func(t *testing.T) {
		p, err := vp.NewJWTPresentation(jwtVPContents(), vp.WithResolver(resolver))
		if err != nil {
			t.Fatalf("new: %v", err)
		}
		input, _ := p.GetSigningInput()
		if err := p.AddCustomProof(&dto.Proof{Signature: jwttest.SignExternally(t, p256, string(input))}); err != nil {
			t.Fatalf("plain AddCustomProof: %v", err)
		}
		if err := p.Verify(vp.WithResolver(resolver)); err != nil {
			t.Fatalf("verify: %v", err)
		}
	})
}

// A JSON-LD proof arrives at AddCustomProof already signed, with challenge,
// domain and verificationMethod inside the signed proof configuration; options
// naming them are refused, not dropped.
func TestJSONPresentation_AddCustomProofRefusesProofOptions(t *testing.T) {
	proof := func() *dto.Proof {
		return &dto.Proof{Type: "DataIntegrityProof", Cryptosuite: "ecdsa-rdfc-2019", ProofPurpose: "authentication",
			VerificationMethod: testDID + "#key-2", ProofValue: "z3FXQ", Created: "2026-09-19T00:00:00Z"}
	}
	for _, tc := range []struct {
		name string
		opt  vp.PresentationOpt
	}{
		{"WithChallenge", vp.WithChallenge("my-nonce")},
		{"WithDomain", vp.WithDomain("https://verifier.example")},
		{"WithVerificationMethodKey", vp.WithVerificationMethodKey("key-1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := vp.NewJSONPresentation(jwtVPContents())
			if err != nil {
				t.Fatalf("new: %v", err)
			}
			err = p.AddCustomProof(proof(), tc.opt)
			if err == nil || !strings.Contains(err.Error(), "on the proof you sign") {
				t.Fatalf("err = %v, want a refusal pointing at the proof fields", err)
			}
			if p.ExtractField("proof") != nil {
				t.Fatal("a refused proof must not be attached")
			}
		})
	}

	p, err := vp.NewJSONPresentation(jwtVPContents())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := p.AddCustomProof(proof()); err != nil {
		t.Fatalf("plain AddCustomProof: %v", err)
	}
	if p.ExtractField("proof") == nil {
		t.Fatal("proof should be attached")
	}
}
