package verificationmethod

import (
	"fmt"
	"strings"
)

// DIDFromVerificationMethodURL extracts the DID prefix from a verification
// method URL such as "did:nda:0xabc#key-1". The split is at the first '#';
// the URL must start with "did:" — empty input or non-DID URLs return an
// error.
func DIDFromVerificationMethodURL(verificationMethodURL string) (string, error) {
	if verificationMethodURL == "" {
		return "", fmt.Errorf("verification method is empty")
	}

	didPart, _, found := strings.Cut(verificationMethodURL, "#")
	if !found || didPart == "" {
		return "", fmt.Errorf("invalid verification method URL, could not extract DID: %s", verificationMethodURL)
	}
	if !strings.HasPrefix(didPart, "did:") {
		return "", fmt.Errorf("extracted DID '%s' is invalid, must start with 'did:'", didPart)
	}
	return didPart, nil
}

// FindVerificationMethod returns the VerificationMethodEntry whose Id equals
// verificationMethodURL. The lookup is by exact full-URL match; callers that
// need fragment-form matching should normalize first.
func FindVerificationMethod(doc *DIDDocument, verificationMethodURL string) (*VerificationMethodEntry, error) {
	if doc == nil {
		return nil, fmt.Errorf("did document is nil")
	}
	if verificationMethodURL == "" {
		return nil, fmt.Errorf("verification method is empty")
	}

	for i := range doc.VerificationMethod {
		vm := &doc.VerificationMethod[i]
		if vm.ID == verificationMethodURL {
			return vm, nil
		}
	}
	return nil, fmt.Errorf("verification method '%s' not found in DID '%s' document", verificationMethodURL, doc.ID)
}

// RequireController reports whether vm is controlled by the document it was
// taken from. CID 1.0 §3.3 requires the absolute controller URL to equal the
// controller document URL; a method that names another DID is not authorized
// by this document.
func RequireController(doc *DIDDocument, vm *VerificationMethodEntry) error {
	if doc == nil || vm == nil {
		return fmt.Errorf("verification method controller cannot be checked without a document and a method")
	}
	if vm.Controller != doc.ID {
		return fmt.Errorf("verification method %q controller %q does not equal the controller document %q", vm.ID, vm.Controller, doc.ID)
	}
	return nil
}
