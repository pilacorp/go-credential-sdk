package did

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
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

	target := canonicalVMID(doc.Id, idOrFragment)
	for i := range doc.VerificationMethod {
		vm := &doc.VerificationMethod[i]
		if canonicalVMID(doc.Id, vm.Id) == target {
			return vm
		}
	}

	return nil
}

// AddVerificationMethod appends a new VM and grants it the listed purposes.
// If vm.Id is empty, it assigns the next sequential "did...#key-N" id; a
// fragment id ("#key-3") is canonicalised to the full URL form.
//
// The VM must publish exactly one key material field: PublicKeyHex
// (secp256k1) or PublicKeyMultibase (P-256 Multikey). An empty Type is
// defaulted from that field; a Type that contradicts it is rejected.
//
// Returns the assigned VM id.
func (doc *DIDDocument) AddVerificationMethod(vm VerificationMethod, purposes []VerificationPurpose) (string, error) {
	if doc == nil {
		return "", fmt.Errorf("document is nil")
	}
	if doc.Id == "" {
		return "", fmt.Errorf("document.id is required")
	}

	expectedType, err := vmTypeFor(vm)
	if err != nil {
		return "", err
	}
	// Validate purposes before touching the document: a later failure must
	// not leave a half-added VM behind.
	if err := validatePurposes(purposes); err != nil {
		return "", err
	}

	if vm.Id == "" {
		vm.Id = doc.nextSequentialKid()
	}
	vm.Id = canonicalVMID(doc.Id, vm.Id)

	if vm.Type == "" {
		vm.Type = expectedType
	}
	if vm.Type != expectedType {
		return "", fmt.Errorf("verification method type %q does not match its key material: expected %s", vm.Type, expectedType)
	}

	if vm.Controller == "" {
		vm.Controller = doc.Id
	}

	if doc.FindVerificationMethod(vm.Id) != nil {
		return "", fmt.Errorf("verification method already exists: %s", vm.Id)
	}
	// Reject if the same key is already registered under a different id — the
	// caller is likely re-adding an existing key by mistake. Comparison is per
	// key material field, on the decoded key where that is possible.
	if existing := doc.findByKeyFingerprint(keyFingerprint(vm)); existing != "" {
		return "", fmt.Errorf("verification method with the same public key already exists: %s", existing)
	}

	doc.VerificationMethod = append(doc.VerificationMethod, vm)

	for _, p := range purposes {
		if err := doc.addPurpose(p, vm.Id); err != nil {
			return "", err
		}
	}

	return vm.Id, nil
}

// RotateVerificationMethod appends newVM, copies purposes from oldKid to it,
// and marks oldKid revoked. The new VM must use the same suite as the old
// one, so relying parties keep verifying the same way.
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

	newType, err := vmTypeFor(newVM)
	if err != nil {
		return "", err
	}

	oldIdx := -1
	oldVMID := ""
	target := canonicalVMID(doc.Id, oldKid)
	for i := range doc.VerificationMethod {
		vm := &doc.VerificationMethod[i]
		if canonicalVMID(doc.Id, vm.Id) == target {
			oldIdx = i
			oldVMID = vm.Id

			break
		}
	}
	if oldIdx < 0 {
		return "", fmt.Errorf("verification method not found: %s", oldKid)
	}
	if doc.VerificationMethod[oldIdx].Revoked != nil {
		return "", fmt.Errorf("verification method %q is already revoked", oldVMID)
	}

	oldType, err := vmTypeFor(doc.VerificationMethod[oldIdx])
	if err != nil {
		return "", fmt.Errorf("verification method %q: %w", oldVMID, err)
	}
	if oldType != newType {
		return "", fmt.Errorf("cannot rotate %q from %s to %s: the suite must stay the same", oldVMID, oldType, newType)
	}

	purposes := doc.purposesOfKid(oldVMID)

	newID, err := doc.AddVerificationMethod(newVM, purposes)
	if err != nil {
		return "", err
	}

	oldVM := &doc.VerificationMethod[oldIdx]
	if oldVM.Id != oldVMID {
		return "", fmt.Errorf("verification method index mismatch after append: %s", oldVMID)
	}
	oldVM.Revoked = &revokedAt
	oldVM.RevocationReason = reason

	return newID, nil
}

// RevokeVerificationMethod marks a VM as revoked. The VM stays in the
// relationship arrays on purpose: verifiers compare proof.created against the
// revoked timestamp, so removing the reference would also invalidate
// signatures made while the key was still active.
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
	if vm.Revoked != nil {
		return fmt.Errorf("verification method %q is already revoked at %s (reason: %s)",
			vm.Id, vm.Revoked.UTC().Format(time.RFC3339), vm.RevocationReason)
	}

	vm.Revoked = &revokedAt
	vm.RevocationReason = reason

	return nil
}

// AddVerificationMethodPurposes grants the given purposes to a VM by adding
// it to each relationship array. Idempotent: existing refs are not duplicated.
// A revoked VM cannot be granted new purposes.
func (doc *DIDDocument) AddVerificationMethodPurposes(kid string, purposes []VerificationPurpose) error {
	if doc == nil {
		return fmt.Errorf("document is nil")
	}
	if kid == "" {
		return fmt.Errorf("kid is required")
	}
	if len(purposes) == 0 {
		return fmt.Errorf("purposes is required")
	}

	vm := doc.FindVerificationMethod(kid)
	if vm == nil {
		return fmt.Errorf("verification method not found: %s", kid)
	}
	if vm.Revoked != nil {
		return fmt.Errorf("verification method %q is revoked", vm.Id)
	}
	if err := validatePurposes(purposes); err != nil {
		return err
	}

	for _, p := range purposes {
		if err := doc.addPurpose(p, kid); err != nil {
			return err
		}
	}

	return nil
}

// RemoveVerificationMethodPurposes revokes the given purposes from a VM by
// removing it from each relationship array. Idempotent: missing refs are
// silently ignored.
func (doc *DIDDocument) RemoveVerificationMethodPurposes(kid string, purposes []VerificationPurpose) error {
	if doc == nil {
		return fmt.Errorf("document is nil")
	}
	if kid == "" {
		return fmt.Errorf("kid is required")
	}
	if len(purposes) == 0 {
		return fmt.Errorf("purposes is required")
	}
	if doc.FindVerificationMethod(kid) == nil {
		return fmt.Errorf("verification method not found: %s", kid)
	}
	if err := validatePurposes(purposes); err != nil {
		return err
	}

	for _, p := range purposes {
		if err := doc.removePurpose(p, kid); err != nil {
			return err
		}
	}

	return nil
}

// vmTypeFor returns the suite a VM must be published under, derived from its
// key material field: publicKeyHex is secp256k1, publicKeyMultibase is a
// P-256 Multikey. A VM carrying neither, both, or the deprecated
// publicKeyJwk is rejected (model.go declares the fields mutually exclusive).
func vmTypeFor(vm VerificationMethod) (string, error) {
	if len(vm.PublicKeyJwk) > 0 {
		return "", fmt.Errorf("publicKeyJwk is not supported: publish secp256k1 as publicKeyHex or P-256 as publicKeyMultibase")
	}

	hasHex, hasMultibase := vm.PublicKeyHex != "", vm.PublicKeyMultibase != ""

	switch {
	case hasHex && hasMultibase:
		return "", fmt.Errorf("verification method must have publicKeyHex or publicKeyMultibase, not both")
	case hasHex:
		return secp256k1VMType, nil
	case hasMultibase:
		return multikeyVMType, nil
	default:
		return "", fmt.Errorf("verification method must have either publicKeyHex or publicKeyMultibase")
	}
}

// findByKeyFingerprint returns the id of the VM holding the same key, or "".
func (doc *DIDDocument) findByKeyFingerprint(fp string) string {
	if fp == "" {
		return ""
	}

	for _, existing := range doc.VerificationMethod {
		if keyFingerprint(existing) == fp {
			return existing.Id
		}
	}

	return ""
}

// keyFingerprint renders a VM's key material in a comparable form, namespaced
// by field so an empty field never matches another empty one.
func keyFingerprint(vm VerificationMethod) string {
	switch {
	case vm.PublicKeyHex != "":
		return "publicKeyHex:" + normalizeSecp256k1Hex(vm.PublicKeyHex)
	case vm.PublicKeyMultibase != "":
		// base58btc is case-sensitive — compare verbatim.
		return "publicKeyMultibase:" + vm.PublicKeyMultibase
	}

	return ""
}

// normalizeSecp256k1Hex reduces a hex key to its compressed point so the same
// key does not slip in twice as 04... and 02.... Input that is not a valid
// point is compared as lowercase hex without the "0x" prefix.
func normalizeSecp256k1Hex(h string) string {
	trimmed := strings.ToLower(strings.TrimPrefix(strings.ToLower(h), "0x"))

	raw, err := hex.DecodeString(trimmed)
	if err != nil {
		return trimmed
	}
	if pub, err := crypto.UnmarshalPubkey(raw); err == nil {
		return hex.EncodeToString(crypto.CompressPubkey(pub))
	}
	if pub, err := crypto.DecompressPubkey(raw); err == nil {
		return hex.EncodeToString(crypto.CompressPubkey(pub))
	}

	return trimmed
}

// validatePurposes rejects unknown purposes before any mutation happens.
func validatePurposes(purposes []VerificationPurpose) error {
	for _, p := range purposes {
		if !slices.Contains(supportedPurposes, p) {
			return fmt.Errorf("unsupported purpose: %s", p)
		}
	}

	return nil
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

// addRefNormalized rewrites every entry in arr to canonical form, dedupes,
// then appends `kid` (also canonicalised) if not already present.
func addRefNormalized(arr []string, kid, did string) []string {
	target := canonicalVMID(did, kid)
	seen := make(map[string]struct{}, len(arr)+1)
	out := make([]string, 0, len(arr)+1)
	for _, x := range arr {
		c := canonicalVMID(did, x)
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
	target := canonicalVMID(did, kid)
	seen := make(map[string]struct{}, len(arr))
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		c := canonicalVMID(did, x)
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
	target := canonicalVMID(did, kid)
	for _, x := range arr {
		if canonicalVMID(did, x) == target {
			return true
		}
	}

	return false
}

// nextSequentialKid returns the next sequential "#key-N" id based on the
// highest N found in the document's verification methods.
func (doc *DIDDocument) nextSequentialKid() string {
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
