package did

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// VerificationPurpose is a DID relationship purpose supported by Pila.
type VerificationPurpose string

const (
	PurposeAuthentication  VerificationPurpose = "authentication"
	PurposeAssertionMethod VerificationPurpose = "assertionMethod"
)

var supportedPurposes = []VerificationPurpose{
	PurposeAuthentication,
	PurposeAssertionMethod,
}

// FindVerificationMethod returns the VM with the given full id (e.g.
// "did:nda:0x...#key-2") or fragment ("#key-2"). Returns nil if not found.
func (doc *DIDDocument) FindVerificationMethod(idOrFragment string) *VerificationMethod {
	if doc == nil {
		return nil
	}

	for i := range doc.VerificationMethod {
		vm := &doc.VerificationMethod[i]
		if vm.Id == idOrFragment {
			return vm
		}
		if strings.HasPrefix(idOrFragment, "#") && vm.Id == doc.Id+idOrFragment {
			return vm
		}
	}
	return nil
}

// AddVerificationMethod appends a new VM and grants it the listed purposes.
// If vm.Id is empty, it assigns the next sequential "did...#key-N" id.
//
// Returns the assigned VM id.
func (doc *DIDDocument) AddVerificationMethod(vm VerificationMethod, purposes []VerificationPurpose) (string, error) {
	if doc == nil {
		return "", fmt.Errorf("document is nil")
	}
	if doc.Id == "" {
		return "", fmt.Errorf("document.id is required")
	}

	if vm.Id == "" {
		vm.Id = nextSequentialKid(*doc)
	}
	if vm.Type == "" {
		vm.Type = "EcdsaSecp256k1VerificationKey2019"
	}
	if vm.Controller == "" {
		vm.Controller = doc.Id
	}

	if doc.FindVerificationMethod(vm.Id) != nil {
		return "", fmt.Errorf("verification method already exists: %s", vm.Id)
	}

	doc.VerificationMethod = append(doc.VerificationMethod, vm)

	for _, p := range purposes {
		if err := doc.addPurpose(p, vm.Id); err != nil {
			return "", err
		}
	}

	if err := doc.validateInvariants(); err != nil {
		return "", err
	}

	return vm.Id, nil
}

// RotateVerificationMethod appends newVM, copies purposes from oldKid to it,
// and marks oldKid revoked.
//
// Returns the new VM id.
func (doc *DIDDocument) RotateVerificationMethod(oldKid string, newVM VerificationMethod, reason string, revokedAt time.Time) (string, error) {
	if doc == nil {
		return "", fmt.Errorf("document is nil")
	}
	if oldKid == "" {
		return "", fmt.Errorf("old_kid is required")
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}
	if reason == "" {
		reason = "superseded"
	}

	oldVM := doc.FindVerificationMethod(oldKid)
	if oldVM == nil {
		return "", fmt.Errorf("verification method not found: %s", oldKid)
	}
	oldVMID := oldVM.Id

	purposes := doc.purposesOfKid(oldVM.Id)

	newID, err := doc.AddVerificationMethod(newVM, purposes)
	if err != nil {
		return "", err
	}

	// Re-fetch after appending (slice may reallocate, invalidating oldVM pointer).
	oldVM = doc.FindVerificationMethod(oldVMID)
	if oldVM == nil {
		return "", fmt.Errorf("verification method not found after append: %s", oldVMID)
	}
	oldVM.Revoked = &revokedAt
	oldVM.RevocationReason = reason

	// Move any purpose references that used fragment form to the canonical full id.
	doc.replacePurposeRefs(oldVM.Id, newID)

	if err := doc.validateInvariants(); err != nil {
		return "", err
	}

	return newID, nil
}

// RevokeVerificationMethod marks a VM as revoked.
func (doc *DIDDocument) RevokeVerificationMethod(kid string, reason string, revokedAt time.Time) error {
	if doc == nil {
		return fmt.Errorf("document is nil")
	}
	if kid == "" {
		return fmt.Errorf("kid is required")
	}
	if reason == "" {
		return fmt.Errorf("reason is required")
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}

	vm := doc.FindVerificationMethod(kid)
	if vm == nil {
		return fmt.Errorf("verification method not found: %s", kid)
	}

	vm.Revoked = &revokedAt
	vm.RevocationReason = reason

	return doc.validateInvariants()
}

// UpdateVerificationMethodPurposes adds/removes relationship references for a VM.
func (doc *DIDDocument) UpdateVerificationMethodPurposes(kid string, add []VerificationPurpose, remove []VerificationPurpose) error {
	if doc == nil {
		return fmt.Errorf("document is nil")
	}
	if kid == "" {
		return fmt.Errorf("kid is required")
	}
	if doc.FindVerificationMethod(kid) == nil {
		return fmt.Errorf("verification method not found: %s", kid)
	}

	for _, p := range add {
		if err := doc.addPurpose(p, kid); err != nil {
			return err
		}
	}
	for _, p := range remove {
		if err := doc.removePurpose(p, kid); err != nil {
			return err
		}
	}
	return doc.validateInvariants()
}

func (doc *DIDDocument) addPurpose(p VerificationPurpose, kid string) error {
	if !slices.Contains(supportedPurposes, p) {
		return fmt.Errorf("unsupported purpose: %s", p)
	}

	switch p {
	case PurposeAuthentication:
		doc.Authentication = addRefNormalized(doc.Authentication, kid, doc.Id)
	case PurposeAssertionMethod:
		doc.AssertionMethod = addRefNormalized(doc.AssertionMethod, kid, doc.Id)
	}
	return nil
}

func (doc *DIDDocument) removePurpose(p VerificationPurpose, kid string) error {
	if !slices.Contains(supportedPurposes, p) {
		return fmt.Errorf("unsupported purpose: %s", p)
	}

	switch p {
	case PurposeAuthentication:
		doc.Authentication = removeRefNormalized(doc.Authentication, kid, doc.Id)
	case PurposeAssertionMethod:
		doc.AssertionMethod = removeRefNormalized(doc.AssertionMethod, kid, doc.Id)
	}
	return nil
}

func canonRef(ref, did string) string {
	if strings.HasPrefix(ref, "#") {
		return did + ref
	}
	return ref
}

// addRefNormalized rewrites every entry in arr to canonical form, dedupes,
// then appends `kid` (also canonicalised) if not already present.
func addRefNormalized(arr []string, kid, did string) []string {
	target := canonRef(kid, did)
	seen := make(map[string]struct{}, len(arr)+1)
	out := make([]string, 0, len(arr)+1)
	for _, x := range arr {
		c := canonRef(x, did)
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	if _, dup := seen[target]; !dup {
		out = append(out, target)
	}
	return out
}

// removeRefNormalized rewrites entries to canonical form, dedupes, then drops
// any entry that matches kid (compared against canonical). Caller may pass
// kid as fragment ("#key-2") or full URL — both resolve to the same VM.
func removeRefNormalized(arr []string, kid, did string) []string {
	target := canonRef(kid, did)
	seen := make(map[string]struct{}, len(arr))
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		c := canonRef(x, did)
		if c == target {
			continue
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

// purposesOfKid returns the purposes that currently reference kid (full id or fragment).
func (doc *DIDDocument) purposesOfKid(kid string) []VerificationPurpose {
	out := []VerificationPurpose{}

	if containsKidRef(doc.Authentication, kid, doc.Id) {
		out = append(out, PurposeAuthentication)
	}
	if containsKidRef(doc.AssertionMethod, kid, doc.Id) {
		out = append(out, PurposeAssertionMethod)
	}
	return out
}

func containsKidRef(arr []string, kid, did string) bool {
	full := kid
	frag := kid
	if strings.HasPrefix(kid, did+"#") {
		frag = strings.TrimPrefix(kid, did)
	}
	if strings.HasPrefix(kid, "#") {
		full = did + kid
	}
	for _, x := range arr {
		if x == kid || x == full || x == frag {
			return true
		}
	}
	return false
}

// replacePurposeRefs rewrites purpose references for oldFullID to newFullID.
// Used by RotateVerificationMethod after the new VM has already been added
// via AddVerificationMethod.
func (doc *DIDDocument) replacePurposeRefs(oldFullID, newFullID string) {
	doc.Authentication = replaceAndNormalize(doc.Authentication, oldFullID, newFullID, doc.Id)
	doc.AssertionMethod = replaceAndNormalize(doc.AssertionMethod, oldFullID, newFullID, doc.Id)
}

// replaceAndNormalize replaces every reference matching oldID (fragment or
// full URL) with the canonical newID, then dedupes the result.
func replaceAndNormalize(arr []string, oldID, newID, did string) []string {
	oldCanon := canonRef(oldID, did)
	newCanon := canonRef(newID, did)
	seen := make(map[string]struct{}, len(arr))
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		c := canonRef(v, did)
		if c == oldCanon {
			c = newCanon
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

// validateInvariants enforces basic DID document integrity for Pila.
func (doc *DIDDocument) validateInvariants() error {
	if doc == nil {
		return fmt.Errorf("document is nil")
	}
	if doc.Id == "" {
		return fmt.Errorf("document.id is required")
	}
	if len(doc.VerificationMethod) == 0 {
		return fmt.Errorf("document must have at least one verification method")
	}

	seen := make(map[string]struct{}, len(doc.VerificationMethod))
	known := make(map[string]struct{}, len(doc.VerificationMethod)*2)

	for _, vm := range doc.VerificationMethod {
		if vm.Id == "" {
			return fmt.Errorf("verification method id is required")
		}
		if _, dup := seen[vm.Id]; dup {
			return fmt.Errorf("duplicate verification method id: %s", vm.Id)
		}
		seen[vm.Id] = struct{}{}
		known[vm.Id] = struct{}{}
		if frag, ok := strings.CutPrefix(vm.Id, doc.Id); ok {
			known[frag] = struct{}{}
		}
	}

	checkRefs := func(p VerificationPurpose, refs []string) error {
		for _, r := range refs {
			if _, ok := known[r]; !ok {
				return fmt.Errorf("%s contains unknown verification method: %s", p, r)
			}
		}
		return nil
	}

	if err := checkRefs(PurposeAuthentication, doc.Authentication); err != nil {
		return err
	}
	if err := checkRefs(PurposeAssertionMethod, doc.AssertionMethod); err != nil {
		return err
	}

	for _, vm := range doc.VerificationMethod {
		if vm.Revoked != nil && vm.RevocationReason == "" {
			return fmt.Errorf("verification method %s revoked but reason missing", vm.Id)
		}
	}

	return nil
}

// nextSequentialKid returns the next sequential "#key-N" id based on the
// highest N found in the document's verification methods.
func nextSequentialKid(doc DIDDocument) string {
	maxN := 0
	for _, vm := range doc.VerificationMethod {
		frag := strings.TrimPrefix(vm.Id, doc.Id)
		if !strings.HasPrefix(frag, "#key-") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(frag, "#key-"))
		if err != nil {
			continue
		}
		if n > maxN {
			maxN = n
		}
	}
	return doc.Id + fmt.Sprintf("#key-%d", maxN+1)
}
