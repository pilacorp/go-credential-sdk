package vp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// vpWithBigVC returns a signed presentation embedding one signed credential
// whose credentialSubject has nExtra dummy claims. The VP itself is small,
// but the embedded VC can be made arbitrarily large.
func vpWithBigVC(t *testing.T, nExtra int) (Presentation, *vmpkg.StaticResolver) {
	t.Helper()
	const issuer = "did:example:lim-issuer"
	const holder = "did:example:lim-holder"

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerProv, err := signer.NewP256Provider(issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	holderProv, err := signer.NewP256Provider(holderKey)
	if err != nil {
		t.Fatal(err)
	}
	resolver := vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(issuer, mustP256VM(t, issuer, "key-1", &issuerKey.PublicKey)),
		vmpkg.NewDIDDocument(holder, mustP256VM(t, holder, "key-1", &holderKey.PublicKey)),
	)

	// Build subject with nExtra claims.
	subject := map[string]interface{}{
		"id":   "did:example:subject",
		"name": "Nguyen Van A",
	}
	for i := 0; i < nExtra; i++ {
		subject[fmt.Sprintf("extra%d", i)] = fmt.Sprintf("value%d", i)
	}

	credDoc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{"@vocab": "https://example.org/vocab#"},
		},
		"id":                "urn:uuid:lim-vc-001",
		"type":              []interface{}{"VerifiableCredential"},
		"issuer":            issuer,
		"validFrom":         "2026-01-01T00:00:00Z",
		"credentialSubject": subject,
	}
	credRaw, err := json.Marshal(credDoc)
	if err != nil {
		t.Fatal(err)
	}

	cred, err := vc.ParseJSONCredential(credRaw)
	if err != nil {
		t.Fatalf("parse vc: %v", err)
	}
	if err := cred.AddProofByProvider(issuerProv,
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign vc: %v", err)
	}
	serialized, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize vc: %v", err)
	}
	vcMap, ok := serialized.(map[string]interface{})
	if !ok {
		t.Fatalf("serialized vc is %T, want map", serialized)
	}

	vpDoc, err := json.Marshal(map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               holder,
		"verifiableCredential": []interface{}{vcMap},
	})
	if err != nil {
		t.Fatal(err)
	}
	pres, err := ParseJSONPresentation(vpDoc)
	if err != nil {
		t.Fatalf("parse vp: %v", err)
	}
	if err := pres.AddProofByProvider(holderProv, WithResolver(resolver)); err != nil {
		t.Fatalf("sign vp: %v", err)
	}
	return pres, resolver
}

// TestWithJSONLDLimits_VP_EmbeddedVC_OverLimit verifies that a VP carrying an
// embedded VC whose total value count exceeds MaxValues is refused with
// ErrTooManyValues when WithVCValidation + WithJSONLDLimits are both set.
// This exercises the limit forwarding in verifyCredentials.
func TestWithJSONLDLimits_VP_EmbeddedVC_OverLimit(t *testing.T) {
	pres, resolver := vpWithBigVC(t, 200) // big VC, small VP

	err := pres.Verify(
		WithResolver(resolver),
		WithVCValidation(),
		WithJSONLDLimits(processor.JSONLDLimits{MaxValues: 50}),
	)
	if err == nil {
		t.Fatal("VP with over-limit embedded VC should be refused")
	}
	if !errors.Is(err, processor.ErrTooManyValues) {
		t.Fatalf("expected ErrTooManyValues (forwarded to embedded VC), got %v", err)
	}
}

// The presentation's own document is checked before any DID is resolved.
func TestWithJSONLDLimits_VP_OwnLimitExceeded(t *testing.T) {
	pres, _ := vpWithBigVC(t, 200)
	err := pres.Verify(WithResolver(failingResolver{t}), WithJSONLDLimits(processor.JSONLDLimits{MaxValues: 50}))
	if !errors.Is(err, processor.ErrTooManyValues) {
		t.Fatalf("err = %v, want ErrTooManyValues", err)
	}
}

// Without the presentation's proof check, the limits still reach each
// embedded credential.
func TestWithJSONLDLimits_VP_ForwardedToEmbeddedVC(t *testing.T) {
	pres, resolver := vpWithBigVC(t, 200)
	raw, err := pres.GetContents()
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseJSONPresentation(raw, WithResolver(resolver), WithVCValidation(),
		WithJSONLDLimits(processor.JSONLDLimits{MaxValues: 50}))
	if !errors.Is(err, processor.ErrTooManyValues) {
		t.Fatalf("err = %v, want ErrTooManyValues", err)
	}
}

// failingResolver fails the test when a DID is resolved.
type failingResolver struct{ t *testing.T }

func (r failingResolver) ResolveDocument(context.Context, string) (*vmpkg.DIDDocument, error) {
	r.t.Fatal("DID resolved before the value limit was checked")
	return nil, errors.New("unreachable")
}
