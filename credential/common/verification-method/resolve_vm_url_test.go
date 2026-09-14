package verificationmethod

import (
	"context"
	"strings"
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

// Signing must refuse a revoked key even when the caller pins it: the verifier
// rejects anything created at or after the revocation.
func TestResolveSigningVM_RevokedKey(t *testing.T) {
	const did = "did:pila:abc123"
	revoked := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	secpVM := func(fragment string, revokedAt *time.Time) VerificationMethodEntry {
		return VerificationMethodEntry{
			ID:           did + "#" + fragment,
			Type:         "EcdsaSecp256k1VerificationKey2019",
			Controller:   did,
			PublicKeyHex: "0x04aa",
			Revoked:      revokedAt,
		}
	}

	doc := &DIDDocument{
		ID:                 did,
		VerificationMethod: []VerificationMethodEntry{secpVM("key-1", &revoked), secpVM("key-2", nil)},
		AssertionMethod:    []string{did + "#key-1", did + "#key-2"},
	}
	resolver := &stubResolver{doc: doc}

	t.Run("revoked kid rejected", func(t *testing.T) {
		_, _, err := ResolveSigningVM(context.Background(), did, "assertionMethod", "key-1", resolver)
		if err == nil || !strings.Contains(err.Error(), "was revoked at") {
			t.Fatalf("err = %v, want a revoked-key error", err)
		}
	})

	t.Run("active kid accepted", func(t *testing.T) {
		vm, url, err := ResolveSigningVM(context.Background(), did, "assertionMethod", "key-2", resolver)
		if err != nil {
			t.Fatalf("ResolveSigningVM: %v", err)
		}
		if url != did+"#key-2" || vm.ID != url {
			t.Errorf("resolved %q, want %q", url, did+"#key-2")
		}
	})
}

// Selection must skip VMs whose key is of another kind, so a signer never binds
// its proof to a VM it cannot verify against.
func TestResolveVerificationMethodURLForKey_KindFilter(t *testing.T) {
	const did = "did:pila:abc123"

	doc := &DIDDocument{
		ID: did,
		VerificationMethod: []VerificationMethodEntry{
			{ID: did + "#key-1", Type: "EcdsaSecp256k1VerificationKey2019", Controller: did, PublicKeyHex: "04aa"},
			{ID: did + "#key-2", Type: "JsonWebKey2020", Controller: did, PublicKeyJwk: &JWK{Kty: "EC", Crv: "P-256"}},
		},
		AssertionMethod: []string{did + "#key-1", did + "#key-2"},
	}

	tests := []struct {
		name     string
		kind     KeyKind
		resolver ResolverProvider
		want     string
		wantErr  bool
	}{
		{
			name:     "picks latest active VM matching the key kind",
			kind:     KeyP256,
			resolver: &stubResolver{doc: doc},
			want:     did + "#key-2",
		},
		{
			name:     "skips VMs of other kinds",
			kind:     KeySecp256k1,
			resolver: &stubResolver{doc: doc},
			want:     did + "#key-1",
		},
		{
			name:     "no matching kind returns error",
			kind:     KeyRSA,
			resolver: &stubResolver{doc: doc},
			wantErr:  true,
		},
		{
			name:     "nil resolver returns error",
			kind:     KeyP256,
			resolver: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveVerificationMethodURLForKey(context.Background(), did, "assertionMethod", tt.kind, tt.resolver)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ResolveVerificationMethodURLForKey() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ResolveVerificationMethodURLForKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

// With no kid pinned, signing uses the only VM when there is one, otherwise the
// latest active VM for the purpose.
func TestResolveSigningVM_DefaultSelection(t *testing.T) {
	const did = "did:pila:def"
	revoked := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	vm := func(fragment string, revokedAt *time.Time) VerificationMethodEntry {
		return VerificationMethodEntry{
			ID: did + "#" + fragment, Type: "EcdsaSecp256k1VerificationKey2019",
			Controller: did, PublicKeyHex: "0x04aa", Revoked: revokedAt,
		}
	}
	resolve := func(doc *DIDDocument) (string, error) {
		_, url, err := ResolveSigningVM(context.Background(), did, "assertionMethod", "", &stubResolver{doc: doc})
		return url, err
	}

	t.Run("single VM is used", func(t *testing.T) {
		url, err := resolve(&DIDDocument{
			ID:                 did,
			VerificationMethod: []VerificationMethodEntry{vm("signing", nil)},
			AssertionMethod:    []string{did + "#signing"},
		})
		if err != nil || url != did+"#signing" {
			t.Fatalf("got %q, %v; want %q", url, err, did+"#signing")
		}
	})

	t.Run("latest active for purpose wins", func(t *testing.T) {
		url, err := resolve(&DIDDocument{
			ID:                 did,
			VerificationMethod: []VerificationMethodEntry{vm("key-3", nil), vm("key-1", nil), vm("key-2", nil)},
			AssertionMethod:    []string{did + "#key-1", did + "#key-2"},
			Authentication:     []string{did + "#key-3"},
		})
		if err != nil || url != did+"#key-2" {
			t.Fatalf("got %q, %v; want %q", url, err, did+"#key-2")
		}
	})

	t.Run("revoked latest is skipped", func(t *testing.T) {
		url, err := resolve(&DIDDocument{
			ID:                 did,
			VerificationMethod: []VerificationMethodEntry{vm("key-1", nil), vm("key-2", &revoked)},
			AssertionMethod:    []string{did + "#key-1", did + "#key-2"},
		})
		if err != nil || url != did+"#key-1" {
			t.Fatalf("got %q, %v; want %q", url, err, did+"#key-1")
		}
	})

	t.Run("all revoked", func(t *testing.T) {
		_, err := resolve(&DIDDocument{
			ID:                 did,
			VerificationMethod: []VerificationMethodEntry{vm("key-1", &revoked), vm("key-2", &revoked)},
			AssertionMethod:    []string{did + "#key-1", did + "#key-2"},
		})
		if err == nil || !strings.Contains(err.Error(), "no active verification method") {
			t.Fatalf("err = %v, want no-active-VM error", err)
		}
	})

	t.Run("single VM still checked for revocation and purpose", func(t *testing.T) {
		if _, err := resolve(&DIDDocument{
			ID:                 did,
			VerificationMethod: []VerificationMethodEntry{vm("key-1", &revoked)},
			AssertionMethod:    []string{did + "#key-1"},
		}); err == nil || !strings.Contains(err.Error(), "was revoked at") {
			t.Fatalf("err = %v, want a revoked-key error", err)
		}
		if _, err := resolve(&DIDDocument{
			ID:                 did,
			VerificationMethod: []VerificationMethodEntry{vm("key-1", nil)},
			Authentication:     []string{did + "#key-1"},
		}); err == nil {
			t.Fatal("want an error when the only VM is not granted assertionMethod")
		}
	})
}
