package verificationmethod

import (
	"fmt"
	"strings"
)

// SelectLatestActiveVMForPurpose picks the active verification method that
// holds the given purpose ("authentication" or "assertionMethod") and has
// the highest sequential `#key-N` index in the relationship array.
//
// Pila's append-only DID document grows by adding higher-numbered fragments
// on each rotation, so the maximum N corresponds to the most recently
// issued key. VMs whose id does not follow the `#key-N` convention are
// still considered but ranked as 0, ensuring an explicit `#key-N` entry
// always wins.
//
// Returns an error if doc is nil, the purpose is unsupported, the
// relationship array is empty, or no listed VM is active.
//
// This helper is intentionally document-based (no HTTP) so callers that
// already have a resolved DID Document from any source — Pila's gRPC
// resolver, an in-memory cache, a test fixture — can pick a signing key
// without going through the SDK's HTTPResolver.
func SelectLatestActiveVMForPurpose(doc *DIDDocument, purpose string) (*VerificationMethodEntry, error) {
	if doc == nil {
		return nil, fmt.Errorf("did document is nil")
	}

	var purposeArr []string
	switch purpose {
	case "authentication":
		purposeArr = doc.Authentication
	case "assertionMethod":
		purposeArr = doc.AssertionMethod
	default:
		return nil, fmt.Errorf("unsupported purpose: %s", purpose)
	}

	if len(purposeArr) == 0 {
		return nil, fmt.Errorf("no verification methods listed for purpose '%s' on DID '%s'", purpose, doc.ID)
	}

	var bestVM *VerificationMethodEntry
	bestN := -1
	for i := range doc.VerificationMethod {
		vm := &doc.VerificationMethod[i]
		if vm.Revoked != nil {
			continue
		}
		if !idInPurposeArray(vm.ID, doc.ID, purposeArr) {
			continue
		}
		n, ok := parseSequentialFragment(vm.ID, doc.ID)
		if !ok {
			n = 0
		}
		if n > bestN {
			bestN = n
			bestVM = vm
		}
	}

	if bestVM == nil {
		return nil, fmt.Errorf("no active verification method for purpose '%s' on DID '%s'", purpose, doc.ID)
	}
	return bestVM, nil
}

// SelectVMForPurpose chooses a verification method from a resolved DID
// Document, preferring an explicit kid when provided.
//
//   - kid empty (legacy tokens) → fall back to SelectLatestActiveVMForPurpose.
//   - kid non-empty → look up by id (full URL or fragment); the returned VM
//     may be revoked. Apply revocation timing and purpose authorization
//     checks separately at the verifier.
func SelectVMForPurpose(doc *DIDDocument, purpose, kid string) (*VerificationMethodEntry, error) {
	if kid == "" {
		return SelectLatestActiveVMForPurpose(doc, purpose)
	}
	if doc == nil {
		return nil, fmt.Errorf("did document is nil")
	}
	for i := range doc.VerificationMethod {
		vm := &doc.VerificationMethod[i]
		if vm.ID == kid {
			return vm, nil
		}
	}
	return nil, fmt.Errorf("verification method '%s' not found in DID '%s' document", kid, doc.ID)
}

// idInPurposeArray reports whether vmID (full URL or fragment) appears in
// the relationship array. The array stores either form depending on issuer
// convention; both must match.
func idInPurposeArray(vmID, did string, arr []string) bool {
	frag := vmID
	if strings.HasPrefix(vmID, did+"#") {
		frag = strings.TrimPrefix(vmID, did)
	}
	for _, ref := range arr {
		if ref == vmID || ref == frag {
			return true
		}
	}
	return false
}

// parseSequentialFragment extracts N from a VM id of the form "<did>#key-N".
// Returns (0, false) for ids that do not follow the convention.
func parseSequentialFragment(vmID, did string) (int, bool) {
	prefix := did + "#key-"
	if !strings.HasPrefix(vmID, prefix) {
		return 0, false
	}
	var n int
	if _, err := fmt.Sscanf(vmID[len(prefix):], "%d", &n); err != nil {
		return 0, false
	}
	return n, true
}
