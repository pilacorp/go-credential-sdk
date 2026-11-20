package vc_test

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

// signedVC issues a P-256-signed VC with nExtra dummy credentialSubject claims,
// returning the parsed credential and a resolver that can verify it.
func signedVC(t *testing.T, nExtra int) (*vc.JSONCredential, vmpkg.ResolverProvider) {
	t.Helper()
	const issuerDID = "did:example:limits-issuer"

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}
	vm, err := vmpkg.NewP256VM(issuerDID, "key-1", &priv.PublicKey)
	if err != nil {
		t.Fatalf("p256 vm: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(issuerDID, vm))

	// Build the subject with nExtra claims.
	subject := map[string]interface{}{
		"id":   "did:example:subject",
		"name": "Nguyen Van A",
	}
	for i := 0; i < nExtra; i++ {
		subject[fmt.Sprintf("extra%d", i)] = fmt.Sprintf("value%d", i)
	}

	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{"@vocab": "https://example.org/vocab#"},
		},
		"id":                "urn:uuid:limits-vc-001",
		"type":              []interface{}{"VerifiableCredential"},
		"issuer":            issuerDID,
		"validFrom":         "2026-01-01T00:00:00Z",
		"credentialSubject": subject,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	cred, err := vc.ParseJSONCredential(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := cred.AddProofByProvider(prov, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return cred, resolver
}

// TestWithJSONLDLimits_VC_OverLimit verifies that a signed VC whose total value
// count exceeds MaxValues is refused with ErrTooManyValues, and that json-gold
// is not reached (pre-scan takes microseconds; proof verification takes
// milliseconds).
func TestWithJSONLDLimits_VC_OverLimit(t *testing.T) {
	cred, resolver := signedVC(t, 200) // 200 extra claims → total >> 50

	start := time.Now()
	err := cred.Verify(
		vc.WithResolver(resolver),
		vc.WithJSONLDLimits(processor.JSONLDLimits{MaxValues: 50}),
	)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("over-limit VC should be refused")
	}
	if !errors.Is(err, processor.ErrTooManyValues) {
		t.Fatalf("expected ErrTooManyValues, got %v", err)
	}
	// Pre-scan should refuse in microseconds; proof verification takes >10ms.
	// A 5ms bound confirms json-gold was not reached.
	if elapsed > 5*time.Millisecond {
		t.Fatalf("check took %v, expected < 5ms (json-gold should not have run)", elapsed)
	}
	t.Logf("over-limit VC refused in %v", elapsed)
}

// TestWithJSONLDLimits_VC_UnderLimit verifies that a signed VC under the limit
// passes verification normally.
func TestWithJSONLDLimits_VC_UnderLimit(t *testing.T) {
	cred, resolver := signedVC(t, 5) // small credential

	err := cred.Verify(
		vc.WithResolver(resolver),
		vc.WithJSONLDLimits(processor.JSONLDLimits{MaxValues: 500}),
	)
	if err != nil {
		t.Fatalf("under-limit VC should verify successfully: %v", err)
	}
}

// TestWithJSONLDLimits_VC_NoOption verifies that without WithJSONLDLimits the
// credential verifies as on main (no limit imposed).
func TestWithJSONLDLimits_VC_NoOption(t *testing.T) {
	cred, resolver := signedVC(t, 200)

	// No WithJSONLDLimits: should verify (json-gold runs, but the doc is valid).
	err := cred.Verify(vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("no-option VC should verify as on main: %v", err)
	}
}

// TestWithJSONLDLimits_VC_ParseCredential_OverLimit exercises the
// ParseCredential → executeOptions path with WithVerifyProof + WithJSONLDLimits.
func TestWithJSONLDLimits_VC_ParseCredential_OverLimit(t *testing.T) {
	cred, resolver := signedVC(t, 200)
	serialized, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	raw, err := json.Marshal(serialized)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	_, err = vc.ParseCredential(raw,
		vc.WithVerifyProof(),
		vc.WithResolver(resolver),
		vc.WithJSONLDLimits(processor.JSONLDLimits{MaxValues: 50}),
	)
	if err == nil {
		t.Fatal("ParseCredential with over-limit VC should fail")
	}
	if !errors.Is(err, processor.ErrTooManyValues) {
		t.Fatalf("expected ErrTooManyValues via ParseCredential, got %v", err)
	}
}

// TestWithJSONLDLimits_ECDSASD_OverLimit verifies that an ecdsa-sd derived
// credential is refused when it exceeds MaxValues.
func TestWithJSONLDLimits_ECDSASD_OverLimit(t *testing.T) {
	s := newE2E(t)
	baseBytes := issueBase(t, s)

	derivedBytes := deriveAndSerialize(t, baseBytes,
		[]string{"credentialSubject.name", "credentialSubject.dob"})

	derived, err := vc.ParseJSONCredential(derivedBytes)
	if err != nil {
		t.Fatalf("parse derived: %v", err)
	}

	// Set a very low limit that the derived credential will exceed.
	err = derived.Verify(
		vc.WithResolver(s.resolver),
		vc.WithJSONLDLimits(processor.JSONLDLimits{MaxValues: 5}),
	)
	if err == nil {
		t.Fatal("ecdsa-sd derived credential over limit should be refused")
	}
	if !errors.Is(err, processor.ErrTooManyValues) {
		t.Fatalf("expected ErrTooManyValues for ecdsa-sd derived, got %v", err)
	}
}
