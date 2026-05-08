package verificationmethod

import (
	"context"
	"fmt"
)

// ResolveVerificationMethodURL returns the full verification method URL (kid)
// for signing/verifying given DID and purpose.
//
// Rules:
//   - If kid is non-empty, return "<did>#<kid>" (caller-specified pin).
//   - Otherwise resolve the DID document and pick the latest active VM in the
//     relationship array for the given purpose.
func ResolveVerificationMethodURL(ctx context.Context, did, purpose, kid string, resolver ResolverProvider) (string, error) {
	if kid != "" {
		return fmt.Sprintf("%s#%s", did, kid), nil
	}
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
