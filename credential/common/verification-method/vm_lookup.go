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
