package verificationmethod

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNormalizeVerificationMethodURL(t *testing.T) {
	const did = "did:pila:abc123"

	tests := []struct {
		name string
		did  string
		kid  string
		want string
	}{
		{
			name: "empty kid returns empty",
			did:  did,
			kid:  "",
			want: "",
		},
		{
			name: "full URL same DID returned as-is",
			did:  did,
			kid:  "did:pila:abc123#key-1",
			want: "did:pila:abc123#key-1",
		},
		{
			name: "full URL different DID returned as-is (caller's responsibility)",
			did:  did,
			kid:  "did:pila:other999#key-7",
			want: "did:pila:other999#key-7",
		},
		{
			name: "fragment-only prefixed with hash",
			did:  did,
			kid:  "#key-1",
			want: "did:pila:abc123#key-1",
		},
		{
			name: "bare fragment gets did and hash prepended",
			did:  did,
			kid:  "key-1",
			want: "did:pila:abc123#key-1",
		},
		{
			name: "bare fragment with numeric suffix",
			did:  did,
			kid:  "key-42",
			want: "did:pila:abc123#key-42",
		},
		{
			name: "did with web method",
			did:  "did:web:example.com:users:alice",
			kid:  "auth-key",
			want: "did:web:example.com:users:alice#auth-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeVerificationMethodURL(tt.did, tt.kid)
			if got != tt.want {
				t.Errorf("NormalizeVerificationMethodURL(%q, %q) = %q, want %q", tt.did, tt.kid, got, tt.want)
			}
		})
	}
}

// stubResolver is a minimal ResolverProvider for tests. doc or err is
// returned verbatim from ResolveDocument.
type stubResolver struct {
	doc *DIDDocument
	err error
}

func (s *stubResolver) ResolveDocument(_ context.Context, _ string) (*DIDDocument, error) {
	return s.doc, s.err
}

func TestResolveVerificationMethodURL(t *testing.T) {
	const did = "did:pila:abc123"

	revoked := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	docWithAuthAndAssertion := &DIDDocument{
		ID: did,
		VerificationMethod: []VerificationMethodEntry{
			{ID: did + "#key-1", Type: "EcdsaSecp256k1VerificationKey2019", Controller: did},
			{ID: did + "#key-2", Type: "EcdsaSecp256k1VerificationKey2019", Controller: did},
		},
		Authentication:  []string{did + "#key-1", did + "#key-2"},
		AssertionMethod: []string{did + "#key-1"},
	}

	docWithRevokedLatest := &DIDDocument{
		ID: did,
		VerificationMethod: []VerificationMethodEntry{
			{ID: did + "#key-1", Type: "EcdsaSecp256k1VerificationKey2019", Controller: did},
			{ID: did + "#key-2", Type: "EcdsaSecp256k1VerificationKey2019", Controller: did, Revoked: &revoked, RevocationReason: "keyCompromise"},
		},
		Authentication: []string{did + "#key-1", did + "#key-2"},
	}

	docEmptyPurpose := &DIDDocument{
		ID:                 did,
		VerificationMethod: []VerificationMethodEntry{{ID: did + "#key-1", Type: "EcdsaSecp256k1VerificationKey2019", Controller: did}},
		Authentication:     []string{did + "#key-1"},
		// AssertionMethod intentionally empty
	}

	tests := []struct {
		name     string
		did      string
		purpose  string
		resolver ResolverProvider
		want     string
		wantErr  bool
	}{
		{
			name:     "nil resolver returns error",
			did:      did,
			purpose:  "authentication",
			resolver: nil,
			wantErr:  true,
		},
		{
			name:     "resolver error propagates",
			did:      did,
			purpose:  "authentication",
			resolver: &stubResolver{err: errors.New("network down")},
			wantErr:  true,
		},
		{
			name:     "picks highest key-N for authentication",
			did:      did,
			purpose:  "authentication",
			resolver: &stubResolver{doc: docWithAuthAndAssertion},
			want:     did + "#key-2",
		},
		{
			name:     "picks key-1 for assertionMethod (only one listed)",
			did:      did,
			purpose:  "assertionMethod",
			resolver: &stubResolver{doc: docWithAuthAndAssertion},
			want:     did + "#key-1",
		},
		{
			name:     "skips revoked latest, picks earlier active key",
			did:      did,
			purpose:  "authentication",
			resolver: &stubResolver{doc: docWithRevokedLatest},
			want:     did + "#key-1",
		},
		{
			name:     "empty purpose array returns error",
			did:      did,
			purpose:  "assertionMethod",
			resolver: &stubResolver{doc: docEmptyPurpose},
			wantErr:  true,
		},
		{
			name:     "unsupported purpose returns error",
			did:      did,
			purpose:  "keyAgreement",
			resolver: &stubResolver{doc: docWithAuthAndAssertion},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveVerificationMethodURL(context.Background(), tt.did, tt.purpose, tt.resolver)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ResolveVerificationMethodURL() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ResolveVerificationMethodURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
