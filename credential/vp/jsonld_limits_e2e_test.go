package vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

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

	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holderKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerProv, _ := signer.NewP256Provider(issuerKey)
	holderProv, _ := signer.NewP256Provider(holderKey)
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
	credRaw, _ := json.Marshal(credDoc)

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

	vpDoc, _ := json.Marshal(map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               holder,
		"verifiableCredential": []interface{}{vcMap},
	})
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

// TestWithJSONLDLimits_VP_OwnLimitExceeded verifies that a VP itself is
// refused when its total value count exceeds MaxValues, before the VP proof
// is checked. A timing bound confirms json-gold is not reached.
func TestWithJSONLDLimits_VP_OwnLimitExceeded(t *testing.T) {
	pres, resolver := vpWithBigVC(t, 200) // VP contains a big VC embedded

	// Set a limit so low that the VP document itself exceeds it (the
	// embedded VC's values are part of the VP document).
	start := time.Now()
	err := pres.Verify(
		WithResolver(resolver),
		WithJSONLDLimits(processor.JSONLDLimits{MaxValues: 10}),
	)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("VP over its own limit should be refused")
	}
	if !errors.Is(err, processor.ErrTooManyValues) {
		t.Fatalf("expected ErrTooManyValues for VP itself, got %v", err)
	}
	// Pre-scan takes microseconds; proof verification takes >10ms.
	if elapsed > 5*time.Millisecond {
		t.Fatalf("VP check took %v, expected < 5ms (proof should not have been checked)", elapsed)
	}
	t.Logf("over-limit VP refused in %v", elapsed)
}

// TestWithJSONLDLimits_VP_UnderLimit verifies that a VP and its embedded VC
// under the limit pass verification normally.
func TestWithJSONLDLimits_VP_UnderLimit(t *testing.T) {
	pres, resolver := vpWithBigVC(t, 5) // small VC

	err := pres.Verify(
		WithResolver(resolver),
		WithVCValidation(),
		WithJSONLDLimits(processor.JSONLDLimits{MaxValues: 5000}),
	)
	if err != nil {
		t.Fatalf("under-limit VP should verify: %v", err)
	}
}

// TestWithJSONLDLimits_VP_NoOption verifies that without WithJSONLDLimits the
// VP verifies as on main (no limit imposed).
func TestWithJSONLDLimits_VP_NoOption(t *testing.T) {
	pres, resolver := vpWithBigVC(t, 200)

	err := pres.Verify(
		WithResolver(resolver),
		WithVCValidation(),
	)
	if err != nil {
		t.Fatalf("no-option VP should verify as on main: %v", err)
	}
}
