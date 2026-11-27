package verificationmethod

import (
	"fmt"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/internal/errtext"
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
		return "", fmt.Errorf("invalid verification method URL, could not extract DID: %q", errtext.Clip(verificationMethodURL))
	}
	if !strings.HasPrefix(didPart, "did:") {
		return "", fmt.Errorf("extracted DID %q is invalid, must start with 'did:'", errtext.Clip(didPart))
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
	return nil, fmt.Errorf("verification method %q not found in DID %q document", errtext.Clip(verificationMethodURL), errtext.Clip(doc.ID))
}

// RequireController checks that vm belongs to doc. CID 1.0 §3.3 takes the
// DID from the verification method URL and requires both the document id and
// the method's controller to equal that DID.
func RequireController(doc *DIDDocument, vm *VerificationMethodEntry) error {
	if doc == nil || vm == nil {
		return fmt.Errorf("verification method controller cannot be checked without a document and a method")
	}
	did, err := DIDFromVerificationMethodURL(vm.ID)
	if err != nil {
		return err
	}
	if doc.ID != did {
		return fmt.Errorf("DID document id %.64q is not the DID %.64q that verification method %.64q belongs to", doc.ID, did, vm.ID)
	}
	if vm.Controller != did {
		return fmt.Errorf("verification method %.64q controller %.64q is not the DID %.64q it belongs to", vm.ID, vm.Controller, did)
	}
	return nil
}
