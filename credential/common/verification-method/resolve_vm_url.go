package verificationmethod

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ResolveVerificationMethodURLForKey is like ResolveVerificationMethodURL but
// picks the latest active VM whose key matches kind, so the resolved VM is
// compatible with the signer's cryptosuite.
func ResolveVerificationMethodURLForKey(ctx context.Context, did, purpose string, kind KeyKind, resolver ResolverProvider) (string, error) {
	if resolver == nil {
		return "", fmt.Errorf("document resolver is not configured")
	}
	doc, err := resolver.ResolveDocument(ctx, did)
	if err != nil {
		return "", fmt.Errorf("failed to resolve DID '%s': %w", did, err)
	}
	vm, err := SelectLatestActiveVMForKey(doc, purpose, kind)
	if err != nil {
		return "", err
	}
	return vm.ID, nil
}

// ResolveSigningVM resolves the DID document and returns the verification method
// to sign with: the pinned kid when given, otherwise the latest active VM for
// purpose. The returned entry lets the caller read the key type and pick the
// cryptosuite.
func ResolveSigningVM(ctx context.Context, did, purpose, pinnedKid string, resolver ResolverProvider) (*VerificationMethodEntry, string, error) {
	if resolver == nil {
		return nil, "", fmt.Errorf("document resolver is not configured")
	}

	url := NormalizeVerificationMethodURL(did, pinnedKid)
	vmDID := didFromVMURL(url)
	if vmDID == "" {
		vmDID = did
	}

	doc, err := resolver.ResolveDocument(ctx, vmDID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to resolve DID '%s': %w", vmDID, err)
	}

	vm, err := FindVerificationMethod(doc, url)
	if err != nil {
		return nil, "", err
	}

	if vm.Revoked != nil {
		return nil, "", fmt.Errorf("verification method '%s' was revoked at %s",
			vm.ID, vm.Revoked.UTC().Format(time.RFC3339))
	}
	if err := EnsureVMAuthorizedForPurpose(doc, vm.ID, purpose); err != nil {
		return nil, "", err
	}

	return vm, vm.ID, nil
}

// didFromVMURL returns the DID prefix of a verification method URL
// ("did:x:y#key-1" → "did:x:y"); empty when url is not a DID URL.
func didFromVMURL(url string) string {
	if !strings.HasPrefix(url, "did:") {
		return ""
	}
	if i := strings.IndexByte(url, '#'); i > 0 {
		return url[:i]
	}
	return url
}

// NormalizeVerificationMethodURL turns a caller-supplied kid into a full
// "did#fragment" URL. Accepts three input forms:
//   - "did:example:123#key-1"  → returned as-is (already full URL)
//   - "#key-1"                  → "<did>#key-1"
//   - "key-1"                   → "<did>#key-1"
func NormalizeVerificationMethodURL(did, kid string) string {
	if kid == "" {
		return ""
	}
	if strings.HasPrefix(kid, "did:") {
		return kid
	}
	if strings.HasPrefix(kid, "#") {
		return did + kid
	}
	return did + "#" + kid
}
