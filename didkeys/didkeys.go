// Package didkeys bridges the root module's ResolverProvider (which resolves
// DID documents) to the digitalcredential module's issuerkey.Resolver (which
// returns keys for SD-JWT VC verification). A consumer that already has a
// ResolverProvider, such as authen-service's gRPC resolver, gets an
// issuerkey.Resolver from the SDK without writing its own adapter.
//
// The adapter applies the unified key rule of the SDK:
//
//   - Only keys listed under assertionMethod that belong to this document
//     (controller == document id) are considered.
//   - A key past its expires time is excluded.
//   - A key revoked as keyCompromise (IsHardRevocationReason) is excluded.
//   - A key revoked for any other reason, or with no stated reason, is
//     included: the signing-time comparison, when needed, is the verifier's
//     responsibility — the adapter does not know when a credential was signed.
//   - A key module jose cannot verify with (P-384, RSA) is excluded, so the
//     DC verifier reports no usable key instead of a policy error. A KeyFilter
//     narrows this further.
//
// A caller can tell "DID not found / deactivated" from "resolver unreachable":
// an error from ResolverProvider that wraps verificationmethod.ErrDIDNotFound
// is mapped to issuerkey.ErrNoUsableKey; any other error passes through so the
// caller sees the transport cause.
package didkeys

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"strings"
	"time"

	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
	"github.com/pilacorp/go-credential-sdk/jose/jwk"
)

// KeyFilter decides whether a public key extracted from a verification method
// should be returned. It runs after the default check that module jose can
// verify with the key, so it can only narrow the set.
type KeyFilter func(pub crypto.PublicKey) bool

// Config configures an Adapter.
type Config struct {
	// Provider resolves DID documents. Required.
	Provider verificationmethod.ResolverProvider

	// KeyFilter, when non-nil, is called for each key the adapter would
	// return. Only keys for which it returns true are included.
	KeyFilter KeyFilter
}

// resolver implements issuerkey.Resolver.
type resolver struct {
	provider  verificationmethod.ResolverProvider
	keyFilter KeyFilter
}

var _ issuerkey.Resolver = (*resolver)(nil)

// NewResolver returns an issuerkey.Resolver backed by provider. It applies the
// unified key rule described in the package doc.
func NewResolver(provider verificationmethod.ResolverProvider) (issuerkey.Resolver, error) {
	return NewResolverWithConfig(Config{Provider: provider})
}

// NewResolverWithConfig returns an issuerkey.Resolver with full configuration.
func NewResolverWithConfig(cfg Config) (issuerkey.Resolver, error) {
	if cfg.Provider == nil {
		return nil, errors.New("didkeys: provider is nil")
	}
	return &resolver{
		provider:  cfg.Provider,
		keyFilter: cfg.KeyFilter,
	}, nil
}

// Keys returns the keys the DID document of iss lists under assertionMethod.
// Its outcomes follow issuerkey.Resolver:
//
//   - an error wrapping issuerkey.ErrIssuerNotSupported: iss is empty or not a
//     conformant DID;
//   - an error wrapping issuerkey.ErrNoUsableKey: the DID does not exist or is
//     deactivated (the ResolverProvider returned ErrDIDNotFound), or the
//     document has no usable key;
//   - any other error: the document could not be fetched.
//
// A document whose keys are all excluded gives an empty slice and no error,
// as issuerkey.Resolver allows; issuerkey.Select reports that case.
func (r *resolver) Keys(ctx context.Context, iss string) ([]issuerkey.PublicKey, error) {
	if iss == "" {
		return nil, fmt.Errorf("%w: didkeys: credential has no iss", issuerkey.ErrIssuerNotSupported)
	}
	if !strings.HasPrefix(iss, "did:") {
		return nil, fmt.Errorf("%w: didkeys: iss is not a DID", issuerkey.ErrIssuerNotSupported)
	}
	if !conformantDID(iss) {
		return nil, fmt.Errorf("%w: didkeys: iss is not a valid DID", issuerkey.ErrIssuerNotSupported)
	}

	doc, err := r.provider.ResolveDocument(ctx, iss)
	if err != nil {
		if errors.Is(err, verificationmethod.ErrDIDNotFound) {
			return nil, fmt.Errorf("%w: %w", issuerkey.ErrNoUsableKey, err)
		}
		return nil, fmt.Errorf("didkeys: resolver failed: %w", err)
	}

	if doc == nil {
		return nil, fmt.Errorf("%w: didkeys: resolver returned nil document", issuerkey.ErrNoUsableKey)
	}

	return r.assertionKeys(doc, iss)
}

// assertionKeys walks assertionMethod and returns eligible keys.
func (r *resolver) assertionKeys(doc *verificationmethod.DIDDocument, did string) ([]issuerkey.PublicKey, error) {
	now := time.Now()
	keys := make([]issuerkey.PublicKey, 0)

	for _, ref := range doc.AssertionMethod {
		vmID := absoluteID(ref, did)
		vm := findVM(doc, vmID)
		if vm == nil {
			continue
		}
		if vm.Controller != did {
			continue
		}
		if vm.Expires != nil && !now.Before(*vm.Expires) {
			continue
		}
		if verificationmethod.IsHardRevocationReason(vm.RevocationReason) {
			continue
		}
		pub, err := verificationmethod.ECPubFromVM(vm)
		if err != nil {
			continue
		}
		// jwk.FromPublicKey applies the key check jws.Verify does.
		if _, err := jwk.FromPublicKey(pub); err != nil {
			continue
		}
		if r.keyFilter != nil && !r.keyFilter(pub) {
			continue
		}
		keys = append(keys, issuerkey.PublicKey{
			KID:    absoluteID(vm.ID, did),
			Public: pub,
		})
	}
	return keys, nil
}

// findVM looks up a verification method by absolute ID.
func findVM(doc *verificationmethod.DIDDocument, id string) *verificationmethod.VerificationMethodEntry {
	for i := range doc.VerificationMethod {
		vm := &doc.VerificationMethod[i]
		if vm.ID == id {
			return vm
		}
	}
	return nil
}

// absoluteID resolves a relative DID URL "#fragment" against the document;
// an absolute one stays as it is.
func absoluteID(id, did string) string {
	if strings.HasPrefix(id, "#") {
		return did + id
	}
	return id
}

// conformantDID reports whether s matches the did rule of DID Core 1.0 §3.1:
// did = "did:" method-name ":" method-specific-id. No "/" "?" or "#".
func conformantDID(s string) bool {
	method, id, ok := strings.Cut(strings.TrimPrefix(s, "did:"), ":")
	if !ok || method == "" || id == "" || id[len(id)-1] == ':' {
		return false
	}
	for i := 0; i < len(method); i++ {
		if c := method[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case isAlnum(c), c == '.', c == '-', c == '_', c == ':':
		case c == '%' && i+2 < len(id) && isHex(id[i+1]) && isHex(id[i+2]):
			i += 2
		default:
			return false
		}
	}
	return true
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
