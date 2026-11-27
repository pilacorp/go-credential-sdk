package vc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
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
	cred, _ := signedVC(t, 200) // 200 extra claims → total >> 50

	// The value limit is checked before the proof's DID is resolved.
	err := cred.Verify(
		vc.WithResolver(failingResolver{t}),
		vc.WithJSONLDLimits(processor.JSONLDLimits{MaxValues: 50}),
	)
	if !errors.Is(err, processor.ErrTooManyValues) {
		t.Fatalf("expected ErrTooManyValues, got %v", err)
	}
}

// failingResolver fails the test when a DID is resolved.
type failingResolver struct{ t *testing.T }

func (r failingResolver) ResolveDocument(context.Context, string) (*vmpkg.DIDDocument, error) {
	r.t.Fatal("DID resolved before the value limit was checked")
	return nil, errors.New("unreachable")
}

// scopedVC signs a credential whose subject holds 30 objects under p, a term
// with a scoped context.
func scopedVC(t *testing.T) (*vc.JSONCredential, vmpkg.ResolverProvider) {
	t.Helper()
	const issuerDID = "did:example:limits-issuer"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}
	vm, err := vmpkg.NewP256VM(issuerDID, "key-1", &priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(issuerDID, vm))
	items := make([]interface{}, 30)
	for i := range items {
		items[i] = map[string]interface{}{"q": "v"}
	}
	raw, err := json.Marshal(map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2", map[string]interface{}{
			"@vocab": "https://example.org/vocab#",
			"p":      map[string]interface{}{"@id": "https://example.org/vocab#p", "@context": map[string]interface{}{"q": "https://example.org/vocab#q"}},
		}},
		"type": []interface{}{"VerifiableCredential"}, "issuer": issuerDID, "validFrom": "2026-01-01T00:00:00Z",
		"credentialSubject": map[string]interface{}{"id": "did:example:subject", "p": items},
	})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := vc.ParseJSONCredential(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := cred.AddProofByProvider(prov, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return cred, resolver
}

// The proof's canonicalization takes the limit: a credential whose signature
// does not hold is refused for the limit, before the signature is checked.
func TestWithJSONLDLimits_VC_ScopedContextUses(t *testing.T) {
	cred, resolver := scopedVC(t)
	raw, err := cred.GetContents()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	proof := doc["proof"].(map[string]interface{})
	pv := proof["proofValue"].(string)
	last := "2"
	if pv[len(pv)-1] == '2' {
		last = "3"
	}
	proof["proofValue"] = pv[:len(pv)-1] + last // still base58btc, signature broken
	tampered, _ := json.Marshal(doc)
	forged, err := vc.ParseJSONCredential(tampered)
	if err != nil {
		t.Fatal(err)
	}
	err = forged.Verify(vc.WithResolver(resolver), vc.WithJSONLDLimits(processor.JSONLDLimits{MaxScopedContextUses: 20}))
	if !errors.Is(err, processor.ErrTooManyScopedContextUses) {
		t.Fatalf("err = %v, want ErrTooManyScopedContextUses", err)
	}
	if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("no limit: %v", err)
	}
}

// The compacted-form check takes the limit: the holder writes the key as p's
// IRI, which keeps the proof and applies no scoped context in expansion, but
// compaction selects p and applies it.
func TestWithJSONLDLimits_VC_ScopedContextUsesInCompaction(t *testing.T) {
	cred, resolver := scopedVC(t)
	raw, err := cred.GetContents()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	subject := doc["credentialSubject"].(map[string]interface{})
	subject["https://example.org/vocab#p"] = subject["p"]
	delete(subject, "p")
	raw, _ = json.Marshal(doc)
	rewritten, err := vc.ParseJSONCredential(raw)
	if err != nil {
		t.Fatal(err)
	}
	err = rewritten.Verify(vc.WithResolver(resolver), vc.WithJSONLDLimits(processor.JSONLDLimits{MaxScopedContextUses: 20}))
	if !errors.Is(err, processor.ErrTooManyScopedContextUses) {
		t.Fatalf("err = %v, want ErrTooManyScopedContextUses", err)
	}
}

// VerifyDetachedProof takes the limits as VerifyProof does.
func TestWithJSONLDLimits_DetachedProof(t *testing.T) {
	cred, resolver := scopedVC(t)
	ser, err := cred.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	body := jsonmap.JSONMap(ser.(map[string]interface{}))
	pb, _ := json.Marshal(body["proof"])
	var proof dto.Proof
	if err := json.Unmarshal(pb, &proof); err != nil {
		t.Fatal(err)
	}
	delete(body, "proof")
	err = body.VerifyDetachedProof(resolver, &proof, jsonmap.WithJSONLDLimits(processor.JSONLDLimits{MaxScopedContextUses: 20}))
	if !errors.Is(err, processor.ErrTooManyScopedContextUses) {
		t.Fatalf("err = %v, want ErrTooManyScopedContextUses", err)
	}
}
