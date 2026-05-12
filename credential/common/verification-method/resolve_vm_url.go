package verificationmethod

import (
	"context"
	"fmt"
	"strings"
)

// ResolveVerificationMethodURL returns the full verification method URL (kid)
// for signing/verifying given DID and purpose by reading the DID document and
// picking the latest active VM in the relationship array for the given purpose.
func ResolveVerificationMethodURL(ctx context.Context, did, purpose string, resolver ResolverProvider) (string, error) {
	if resolver == nil {
		return "", fmt.Errorf("document resolver is not configured")
	}
	doc, err := resolver.ResolveDocument(ctx, did)
	if err != nil {
		return "", fmt.Errorf("failed to resolve DID '%s': %w", did, err)
	}
	vm, err := SelectLatestActiveVMForPurpose(doc, purpose)
	if err != nil {
		return "", err
	}
	return vm.ID, nil
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
