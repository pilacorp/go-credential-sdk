package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// A presentation signed with a challenge/domain verifies only against the same
// expected values: the verifier-issued nonce cannot be swapped or dropped.
func TestVP_ChallengeDomain_SignAndVerify(t *testing.T) {
	const holder = "did:example:vp-challenge"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("p256: %v", err)
	}
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(holder,
		vmpkg.NewP256VM(holder, "key-1", &priv.PublicKey)))

	pres, err := vp.ParseJSONPresentation(vpDoc(holder))
	if err != nil {
		t.Fatalf("parse vp: %v", err)
	}
	err = pres.AddProofByProvider(prov, vp.WithResolver(resolver),
		vp.WithChallenge("nonce-123"), vp.WithDomain("verifier.example"))
	if err != nil {
		t.Fatalf("sign vp: %v", err)
	}

	if pres.ExtractField("proof.challenge") != "nonce-123" || pres.ExtractField("proof.domain") != "verifier.example" {
		t.Fatalf("proof lacks challenge/domain: %v", pres.ExtractField("proof"))
	}

	cases := []struct {
		name    string
		opts    []vp.PresentationOpt
		wantErr string
	}{
		{"matching challenge and domain", []vp.PresentationOpt{vp.WithExpectedChallenge("nonce-123"), vp.WithExpectedDomain("verifier.example")}, ""},
		{"no expectation", nil, ""},
		{"wrong challenge", []vp.PresentationOpt{vp.WithExpectedChallenge("nonce-999")}, "challenge"},
		{"wrong domain", []vp.PresentationOpt{vp.WithExpectedDomain("attacker.example")}, "domain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := pres.Verify(append([]vp.PresentationOpt{vp.WithResolver(resolver)}, tc.opts...)...)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("verify: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("verify err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}

	// Round-trip through JSON keeps the signed options and the signature valid.
	raw, err := pres.GetContents()
	if err != nil {
		t.Fatalf("contents: %v", err)
	}
	reparsed, err := vp.ParseJSONPresentation(raw)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if err := reparsed.Verify(vp.WithResolver(resolver), vp.WithExpectedChallenge("nonce-123")); err != nil {
		t.Fatalf("verify re-parsed: %v", err)
	}
}

// A presentation signed WITHOUT a challenge must fail when the verifier expects
// one — silently accepting it would defeat the replay protection.
func TestVP_ChallengeDomain_MissingChallengeRejected(t *testing.T) {
	const holder = "did:example:vp-nochallenge"
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	prov, _ := signer.NewP256Provider(priv)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(holder,
		vmpkg.NewP256VM(holder, "key-1", &priv.PublicKey)))

	pres, err := vp.ParseJSONPresentation(vpDoc(holder))
	if err != nil {
		t.Fatalf("parse vp: %v", err)
	}
	if err := pres.AddProofByProvider(prov, vp.WithResolver(resolver)); err != nil {
		t.Fatalf("sign vp: %v", err)
	}
	if err := pres.Verify(vp.WithResolver(resolver), vp.WithExpectedChallenge("nonce-123")); err == nil {
		t.Fatal("expected verification to fail without a challenge in the proof")
	}
}
