package verificationmethod

import (
	"fmt"
	"strings"
)

// KeyKind identifies the key type a verification method holds, so VM selection
// can match the signer's key.
type KeyKind int

const (
	KeySecp256k1 KeyKind = iota
	KeyRSA
	KeyP256
)

func (k KeyKind) String() string {
	switch k {
	case KeySecp256k1:
		return "secp256k1"
	case KeyRSA:
		return "RSA"
	case KeyP256:
		return "P-256"
	default:
		return "unknown"
	}
}

func VMIsRSA(vm *VerificationMethodEntry) bool {
	return vm.PublicKeyJwk != nil && vm.PublicKeyJwk.Kty == "RSA"
}

func VMIsP256(vm *VerificationMethodEntry) bool {
	if vm.PublicKeyJwk != nil {
		return vm.PublicKeyJwk.Kty == "EC" && vm.PublicKeyJwk.Crv == "P-256"
	}
	if vm.PublicKeyMultibase != "" {
		_, _, err := DecodeP256PubMultibase(vm.PublicKeyMultibase)
		return err == nil
	}
	return false
}

// VMIsSecp256k1 matches an EC secp256k1 JWK or a publicKeyHex (the
// EcdsaSecp256k1VerificationKey2019 representation). P-256 keys never use
// publicKeyHex.
func VMIsSecp256k1(vm *VerificationMethodEntry) bool {
	if vm.PublicKeyJwk != nil {
		return vm.PublicKeyJwk.Kty == "EC" && vm.PublicKeyJwk.Crv == "secp256k1"
	}
	return vm.PublicKeyHex != ""
}

// VMKeyKind reports the key kind a verification method holds, and whether it was
// recognized. Signing uses it to pick the cryptosuite from the bound key.
func VMKeyKind(vm *VerificationMethodEntry) (KeyKind, bool) {
	switch {
	case VMIsSecp256k1(vm):
		return KeySecp256k1, true
	case VMIsP256(vm):
		return KeyP256, true
	case VMIsRSA(vm):
		return KeyRSA, true
	default:
		return KeySecp256k1, false
	}
}

// vmMatchesKind reports whether a verification method holds a key of the given
// kind, matched explicitly on its key material.
func vmMatchesKind(vm *VerificationMethodEntry, kind KeyKind) bool {
	switch kind {
	case KeyRSA:
		return VMIsRSA(vm)
	case KeyP256:
		return VMIsP256(vm)
	case KeySecp256k1:
		return VMIsSecp256k1(vm)
	default:
		return false
	}
}

// SelectLatestActiveVMForPurpose picks the active verification method that
// holds the given purpose ("authentication" or "assertionMethod") and has
// the highest sequential `#key-N` index in the relationship array.
func SelectLatestActiveVMForPurpose(doc *DIDDocument, purpose string) (*VerificationMethodEntry, error) {
	vm, err := selectLatestActiveVM(doc, purpose, nil)
	if err != nil {
		return nil, err
	}
	if vm == nil {
		return nil, fmt.Errorf("no active verification method for purpose '%s' on DID '%s'", purpose, doc.ID)
	}
	return vm, nil
}

// SelectLatestActiveVMForKey is like SelectLatestActiveVMForPurpose but only
// considers verification methods holding a key of the given kind — so an RSA
// signer never binds its proof to a secp256k1 VM (or vice versa) on a DID with
// keys of several kinds in the same relationship array.
func SelectLatestActiveVMForKey(doc *DIDDocument, purpose string, kind KeyKind) (*VerificationMethodEntry, error) {
	vm, err := selectLatestActiveVM(doc, purpose, func(vm *VerificationMethodEntry) bool {
		return vmMatchesKind(vm, kind)
	})
	if err != nil {
		return nil, err
	}
	if vm == nil {
		return nil, fmt.Errorf("no active %s verification method for purpose '%s' on DID '%s'", kind, purpose, doc.ID)
	}
	return vm, nil
}

// selectLatestActiveVM returns the active VM with the highest sequential
// `#key-N` index that satisfies match (match == nil accepts any). Returns
// (nil, nil) when none match.
func selectLatestActiveVM(doc *DIDDocument, purpose string, match func(*VerificationMethodEntry) bool) (*VerificationMethodEntry, error) {
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
		if match != nil && !match(vm) {
			continue
		}
		n, ok := parseSequentialFragment(vm.ID, doc.ID)
		if !ok {
			n = 0
		}
		// Higher #key-N wins. Tie (e.g. VMs without a sequential fragment, all
		// n=0) breaks on the lexicographically larger ID so selection is
		// deterministic regardless of the resolver's slice ordering.
		if n > bestN || (n == bestN && bestVM != nil && vm.ID > bestVM.ID) {
			bestN = n
			bestVM = vm
		}
	}

	return bestVM, nil
}

// SelectVMForPurpose chooses a verification method from a resolved DID
// Document, preferring an explicit kid when provided.
//
//   - kid empty (legacy tokens) → fall back to SelectLatestActiveVMForPurpose.
//   - kid non-empty → look up by id (full URL "did:...#key-1", "#key-1", or
//     bare "key-1"); the returned VM may be revoked. Apply revocation timing
//     and purpose authorization checks separately at the verifier.
func SelectVMForPurpose(doc *DIDDocument, purpose, kid string) (*VerificationMethodEntry, error) {
	if kid == "" {
		return SelectLatestActiveVMForPurpose(doc, purpose)
	}
	if doc == nil {
		return nil, fmt.Errorf("did document is nil")
	}

	canonicalKid := NormalizeVerificationMethodURL(doc.ID, kid)
	for i := range doc.VerificationMethod {
		vm := &doc.VerificationMethod[i]
		if vm.ID == canonicalKid {
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

// EnsureVMAuthorizedForPurpose mirrors the verifier's strict purpose check on
// the signing side: the VM must appear in the DID document's relationship array
// for purpose. Used when a kid is pinned (which otherwise bypasses the
// purpose-filtered selection), so a signer can't bind a proof to a key that the
// verifier would reject for that purpose.
func EnsureVMAuthorizedForPurpose(doc *DIDDocument, vmID, purpose string) error {
	var arr []string
	switch purpose {
	case "authentication":
		arr = doc.Authentication
	case "assertionMethod":
		arr = doc.AssertionMethod
	default:
		return fmt.Errorf("unsupported purpose '%s'", purpose)
	}
	if !idInPurposeArray(vmID, doc.ID, arr) {
		return fmt.Errorf("verification method '%s' is not granted purpose '%s' on DID '%s'", vmID, purpose, doc.ID)
	}
	return nil
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
