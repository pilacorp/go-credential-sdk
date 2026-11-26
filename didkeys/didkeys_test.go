package didkeys

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
)

const testDID = "did:example:issuer"

func p256VM(did, fragment string) verificationmethod.VerificationMethodEntry {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	priv.X.FillBytes(xb)
	priv.Y.FillBytes(yb)
	return verificationmethod.VerificationMethodEntry{
		ID:         did + "#" + fragment,
		Type:       "JsonWebKey2020",
		Controller: did,
		PublicKeyJwk: &verificationmethod.JWK{
			Kty: "EC",
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(xb),
			Y:   base64.RawURLEncoding.EncodeToString(yb),
		},
	}
}

type staticResolver struct {
	docs map[string]*verificationmethod.DIDDocument
	err  error
}

func (s *staticResolver) ResolveDocument(_ context.Context, did string) (*verificationmethod.DIDDocument, error) {
	if s.err != nil {
		return nil, s.err
	}
	doc, ok := s.docs[did]
	if !ok {
		return nil, verificationmethod.ErrDIDNotFound
	}
	return doc, nil
}

func newDoc(did string, vms []verificationmethod.VerificationMethodEntry, assertionRefs []string) *verificationmethod.DIDDocument {
	return &verificationmethod.DIDDocument{
		ID:                 did,
		VerificationMethod: vms,
		AssertionMethod:    assertionRefs,
	}
}

// TC4: active key is returned.
func TestActiveKeyReturned(t *testing.T) {
	vm := p256VM(testDID, "key-1")
	doc := newDoc(testDID, []verificationmethod.VerificationMethodEntry{vm}, []string{testDID + "#key-1"})
	r, err := NewResolver(&staticResolver{docs: map[string]*verificationmethod.DIDDocument{testDID: doc}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := r.Keys(context.Background(), testDID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys; want 1", len(keys))
	}
	if keys[0].KID != testDID+"#key-1" {
		t.Errorf("KID = %q; want %q", keys[0].KID, testDID+"#key-1")
	}
}

// TC5: hard-revoked key (keyCompromise) is excluded.
func TestHardRevokedKeyExcluded(t *testing.T) {
	vm := p256VM(testDID, "key-1")
	past := time.Now().Add(-time.Hour)
	vm.Revoked = &past
	vm.RevocationReason = "keyCompromise"
	doc := newDoc(testDID, []verificationmethod.VerificationMethodEntry{vm}, []string{testDID + "#key-1"})
	r, err := NewResolver(&staticResolver{docs: map[string]*verificationmethod.DIDDocument{testDID: doc}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := r.Keys(context.Background(), testDID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("got %d keys; want 0 (hard-revoked)", len(keys))
	}
}

// TC6: soft-revoked key (superseded) is included.
func TestSoftRevokedKeyIncluded(t *testing.T) {
	vm := p256VM(testDID, "key-1")
	past := time.Now().Add(-time.Hour)
	vm.Revoked = &past
	vm.RevocationReason = "superseded"
	doc := newDoc(testDID, []verificationmethod.VerificationMethodEntry{vm}, []string{testDID + "#key-1"})
	r, err := NewResolver(&staticResolver{docs: map[string]*verificationmethod.DIDDocument{testDID: doc}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := r.Keys(context.Background(), testDID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys; want 1 (soft-revoked, included)", len(keys))
	}
}

// Unified rule: a key revoked with no stated reason is also included
// (soft-revoked). Only keyCompromise is hard.
func TestNoReasonRevokedKeyIncluded(t *testing.T) {
	vm := p256VM(testDID, "key-1")
	past := time.Now().Add(-time.Hour)
	vm.Revoked = &past
	vm.RevocationReason = "" // no reason
	doc := newDoc(testDID, []verificationmethod.VerificationMethodEntry{vm}, []string{testDID + "#key-1"})
	r, err := NewResolver(&staticResolver{docs: map[string]*verificationmethod.DIDDocument{testDID: doc}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := r.Keys(context.Background(), testDID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys; want 1 (no-reason revocation is soft)", len(keys))
	}
}

// TC7: expired key is excluded.
func TestExpiredKeyExcluded(t *testing.T) {
	vm := p256VM(testDID, "key-1")
	past := time.Now().Add(-time.Hour)
	vm.Expires = &past
	doc := newDoc(testDID, []verificationmethod.VerificationMethodEntry{vm}, []string{testDID + "#key-1"})
	r, err := NewResolver(&staticResolver{docs: map[string]*verificationmethod.DIDDocument{testDID: doc}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := r.Keys(context.Background(), testDID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("got %d keys; want 0 (expired)", len(keys))
	}
}

// ErrIssuerNotSupported for non-DID iss.
func TestNonDIDIssReturnsErrIssuerNotSupported(t *testing.T) {
	r, err := NewResolver(&staticResolver{docs: map[string]*verificationmethod.DIDDocument{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, iss := range []string{
		"",
		"https://issuer.example",
		"did:",
		"did:example",
		"did:Example:123",
		"did:example:a/b",
	} {
		_, err := r.Keys(context.Background(), iss)
		if !errors.Is(err, issuerkey.ErrIssuerNotSupported) {
			t.Errorf("iss=%q: err = %v; want ErrIssuerNotSupported", iss, err)
		}
	}
}

// TC3: ErrDIDNotFound from provider maps to ErrNoUsableKey.
func TestDIDNotFoundMapsToErrNoUsableKey(t *testing.T) {
	r, err := NewResolver(&staticResolver{docs: map[string]*verificationmethod.DIDDocument{}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Keys(context.Background(), "did:example:unknown")
	if !errors.Is(err, issuerkey.ErrNoUsableKey) {
		t.Errorf("err = %v; want ErrNoUsableKey", err)
	}
	// Also check the original cause is accessible.
	if !errors.Is(err, verificationmethod.ErrDIDNotFound) {
		t.Errorf("err = %v; want ErrDIDNotFound in chain", err)
	}
}

// A document with an embedded object in assertionMethod (instead of a string
// reference) will not decode into DIDDocument.AssertionMethod ([]string).
// When the provider wraps that as ErrInvalidDocument, the adapter returns
// ErrNoUsableKey, not a transport error.
func TestEmbeddedAssertionMethodNotDecoded(t *testing.T) {
	decodeErr := fmt.Errorf("%w: cannot unmarshal object into Go struct field "+
		"DIDDocument.assertionMethod of type string", verificationmethod.ErrInvalidDocument)
	r, err := NewResolver(&staticResolver{err: decodeErr})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Keys(context.Background(), "did:example:embedded")
	if !errors.Is(err, issuerkey.ErrNoUsableKey) {
		t.Errorf("err = %v; want ErrNoUsableKey for embedded assertionMethod", err)
	}
}

// ErrInvalidDocument from provider maps to ErrNoUsableKey.
func TestInvalidDocumentMapsToErrNoUsableKey(t *testing.T) {
	decodeErr := fmt.Errorf("%w: unexpected end of JSON input", verificationmethod.ErrInvalidDocument)
	r, err := NewResolver(&staticResolver{err: decodeErr})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Keys(context.Background(), "did:example:badformat")
	if !errors.Is(err, issuerkey.ErrNoUsableKey) {
		t.Errorf("err = %v; want ErrNoUsableKey", err)
	}
	if !errors.Is(err, verificationmethod.ErrInvalidDocument) {
		t.Errorf("err = %v; want ErrInvalidDocument in chain", err)
	}
}

// A transport error passes through without wrapping as ErrNoUsableKey.
func TestTransportErrorPassesThrough(t *testing.T) {
	transportErr := errors.New("connection refused")
	r, err := NewResolver(&staticResolver{err: transportErr})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Keys(context.Background(), "did:example:123")
	if errors.Is(err, issuerkey.ErrNoUsableKey) {
		t.Error("transport error should not be ErrNoUsableKey")
	}
	if errors.Is(err, issuerkey.ErrIssuerNotSupported) {
		t.Error("transport error should not be ErrIssuerNotSupported")
	}
	if !errors.Is(err, transportErr) {
		t.Errorf("err = %v; want transportErr in chain", err)
	}
}

// A key not in assertionMethod is excluded.
func TestKeyNotInAssertionMethodExcluded(t *testing.T) {
	vm := p256VM(testDID, "key-1")
	doc := newDoc(testDID, []verificationmethod.VerificationMethodEntry{vm}, nil)
	r, err := NewResolver(&staticResolver{docs: map[string]*verificationmethod.DIDDocument{testDID: doc}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := r.Keys(context.Background(), testDID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("got %d keys; want 0 (not in assertionMethod)", len(keys))
	}
}

// A key controlled by another DID is excluded.
func TestForeignControllerExcluded(t *testing.T) {
	vm := p256VM(testDID, "key-1")
	vm.Controller = "did:example:other"
	doc := newDoc(testDID, []verificationmethod.VerificationMethodEntry{vm}, []string{testDID + "#key-1"})
	r, err := NewResolver(&staticResolver{docs: map[string]*verificationmethod.DIDDocument{testDID: doc}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := r.Keys(context.Background(), testDID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("got %d keys; want 0 (foreign controller)", len(keys))
	}
}

// A key with a relative id in assertionMethod is resolved.
func TestRelativeAssertionMethodRef(t *testing.T) {
	vm := p256VM(testDID, "key-1")
	doc := newDoc(testDID, []verificationmethod.VerificationMethodEntry{vm}, []string{"#key-1"})
	r, err := NewResolver(&staticResolver{docs: map[string]*verificationmethod.DIDDocument{testDID: doc}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := r.Keys(context.Background(), testDID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys; want 1 (relative ref resolved)", len(keys))
	}
}

// A document that writes the method id as "#key-1" (relative DID URL)
// is handled: the adapter resolves it against the DID before comparing.
func TestRelativeMethodIDInDocument(t *testing.T) {
	vm := p256VM(testDID, "key-1")
	vm.ID = "#key-1" // relative form in the document
	doc := newDoc(testDID, []verificationmethod.VerificationMethodEntry{vm}, []string{"#key-1"})
	r, err := NewResolver(&staticResolver{docs: map[string]*verificationmethod.DIDDocument{testDID: doc}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := r.Keys(context.Background(), testDID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys; want 1 (relative method id resolved)", len(keys))
	}
	if keys[0].KID != testDID+"#key-1" {
		t.Errorf("KID = %q; want %q", keys[0].KID, testDID+"#key-1")
	}
}

// NewResolver rejects nil provider.
func TestNewResolverNilProvider(t *testing.T) {
	_, err := NewResolver(nil)
	if err == nil {
		t.Error("want error for nil provider")
	}
}

// KeyFilter can exclude specific curves.
func TestKeyFilter(t *testing.T) {
	vm := p256VM(testDID, "key-1")
	doc := newDoc(testDID, []verificationmethod.VerificationMethodEntry{vm}, []string{testDID + "#key-1"})
	r, err := NewResolverWithConfig(Config{
		Provider: &staticResolver{docs: map[string]*verificationmethod.DIDDocument{testDID: doc}},
		KeyFilter: func(pub crypto.PublicKey) bool {
			return false // reject everything
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := r.Keys(context.Background(), testDID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("got %d keys; want 0 (KeyFilter rejects all)", len(keys))
	}
}

// The DC path verifies with module jose, which takes ES256 and ES256K only.
// A P-384 key is not returned by default: handed to jws it fails as a policy
// error rather than as "no usable key". authen-service's adapter dropped such
// keys the same way.
func TestKeyJOSECannotUseExcludedByDefault(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xb := make([]byte, 48)
	yb := make([]byte, 48)
	priv.X.FillBytes(xb)
	priv.Y.FillBytes(yb)
	p384 := verificationmethod.VerificationMethodEntry{
		ID:         testDID + "#key-384",
		Type:       "JsonWebKey2020",
		Controller: testDID,
		PublicKeyJwk: &verificationmethod.JWK{
			Kty: "EC",
			Crv: "P-384",
			X:   base64.RawURLEncoding.EncodeToString(xb),
			Y:   base64.RawURLEncoding.EncodeToString(yb),
		},
	}
	p256 := p256VM(testDID, "key-1")
	doc := newDoc(testDID, []verificationmethod.VerificationMethodEntry{p384, p256},
		[]string{testDID + "#key-384", testDID + "#key-1"})
	r, err := NewResolver(&staticResolver{docs: map[string]*verificationmethod.DIDDocument{testDID: doc}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := r.Keys(context.Background(), testDID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].KID != testDID+"#key-1" {
		t.Fatalf("keys = %+v, want only the P-256 key", keys)
	}
}

// Multiple keys: rotation scenario with one superseded and one active.
func TestRotationScenario(t *testing.T) {
	old := p256VM(testDID, "key-1")
	past := time.Now().Add(-time.Hour)
	old.Revoked = &past
	old.RevocationReason = "superseded"

	stolen := p256VM(testDID, "key-2")
	stolen.Revoked = &past
	stolen.RevocationReason = "keyCompromise"

	fresh := p256VM(testDID, "key-3")

	doc := newDoc(testDID,
		[]verificationmethod.VerificationMethodEntry{old, stolen, fresh},
		[]string{testDID + "#key-1", testDID + "#key-2", testDID + "#key-3"},
	)
	r, err := NewResolver(&staticResolver{docs: map[string]*verificationmethod.DIDDocument{testDID: doc}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := r.Keys(context.Background(), testDID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys; want 2 (old superseded + fresh)", len(keys))
	}
	if keys[0].KID != testDID+"#key-1" {
		t.Errorf("keys[0].KID = %q; want #key-1", keys[0].KID)
	}
	if keys[1].KID != testDID+"#key-3" {
		t.Errorf("keys[1].KID = %q; want #key-3", keys[1].KID)
	}
}
