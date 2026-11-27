// Package attribute encodes the on-chain records that publish a DID document's
// verification methods, and builds the document updates that change them.
//
// A DID document's keys reach the chain only through setAttribute and
// setAttributeByIssuer: the document hash alone carries no key. Two record
// shapes exist, and did-registrar reads both:
//
//   - "key/N": one verification method, #key-N, as a JSON Record.
//   - "vm": every verification method of the document, as a JSON array of
//     VMRecord. A bundle overwrites the whole set, so it names every method.
//
// did-registrar holds an update to what its attribute writes: a document that
// changes one method needs that method's key/N, one that changes more needs the
// "vm" bundle, and a revoked method needs a record carrying its revocation. The
// helpers in update.go produce a document and an attribute that satisfy this.
package attribute

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/didv2/did"
)

// Purpose short codes used in a record's "p" list.
const (
	PurposeAssert = "assert" // assertionMethod
	PurposeAuth   = "auth"   // authentication
)

// VMBundleAttributeName names the attribute that carries every verification
// method of a document in one value.
const VMBundleAttributeName = "vm"

// Verification method types a record's "kt" can name. A record without "kt" is
// secp256k1, which is what every record written before "kt" existed is.
const (
	KeyTypeSecp256k1  = "EcdsaSecp256k1VerificationKey2019"
	KeyTypeMultikey   = "Multikey"
	KeyTypeJsonWebKey = "JsonWebKey"
)

const (
	keyPrefix = "key/"
	kidPrefix = "key-"
)

// Record is the JSON value of a key/N attribute.
type Record struct {
	// PublicKey is the key: compressed hex for secp256k1, multibase for a
	// Multikey, the JWK as JSON for a JsonWebKey.
	PublicKey string `json:"k"`
	// Purposes lists the purpose short codes the method is granted.
	Purposes []string `json:"p"`
	// KeyType names the method type. Empty means secp256k1.
	KeyType string `json:"kt,omitempty"`
	// Revoked, when present, marks the method as revoked.
	Revoked *RevokedRecord `json:"revoked,omitempty"`
}

// RevokedRecord carries when a method was revoked and why.
type RevokedRecord struct {
	// Time is the moment the method was revoked.
	Time time.Time `json:"t"`
	// Reason is the revocation reason code (RFC 5280 §5.3.1).
	Reason string `json:"reason"`
}

// VMRecord is one entry of a "vm" bundle: a record and the "#fragment" of the
// method it describes.
type VMRecord struct {
	ID string `json:"id"`
	Record
}

// Validate enforces what did-registrar refuses: an empty key, a purpose other
// than auth or assert, a revocation without a time.
func (r *Record) Validate() error {
	if r.PublicKey == "" {
		return errors.New("record.k (public key) is required")
	}

	for _, p := range r.Purposes {
		if p != PurposeAssert && p != PurposeAuth {
			return fmt.Errorf("invalid purpose %q (only %q and %q are allowed)", p, PurposeAssert, PurposeAuth)
		}
	}

	if r.Revoked != nil && r.Revoked.Time.IsZero() {
		return errors.New("revoked.t is required when revoked is set")
	}

	return nil
}

// Encode validates the record and marshals it to the setAttribute value.
func (r *Record) Encode() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}

	return json.Marshal(r)
}

// Validate requires a "#fragment" id, then the record's own rules.
func (r VMRecord) Validate() error {
	if !strings.HasPrefix(r.ID, "#") || strings.TrimSpace(r.ID) == "#" {
		return fmt.Errorf("record.id must be a #fragment, got %q", r.ID)
	}

	return r.Record.Validate()
}

// DecodeRecord parses and validates a key/N value.
func DecodeRecord(value []byte) (*Record, error) {
	var r Record
	if err := json.Unmarshal(value, &r); err != nil {
		return nil, fmt.Errorf("decode attribute record: %w", err)
	}

	if err := r.Validate(); err != nil {
		return nil, err
	}

	return &r, nil
}

// EncodeVMBundle validates a bundle and marshals it to the setAttribute value.
// A bundle is non-empty and names no method twice.
func EncodeVMBundle(records []VMRecord) ([]byte, error) {
	if err := validateBundle(records); err != nil {
		return nil, err
	}

	return json.Marshal(records)
}

// DecodeVMBundle parses and validates a "vm" value.
func DecodeVMBundle(value []byte) ([]VMRecord, error) {
	var records []VMRecord
	if err := json.Unmarshal(value, &records); err != nil {
		return nil, fmt.Errorf("decode vm bundle: %w", err)
	}

	if err := validateBundle(records); err != nil {
		return nil, err
	}

	return records, nil
}

func validateBundle(records []VMRecord) error {
	if len(records) == 0 {
		return errors.New("vm bundle is empty")
	}

	seen := make(map[string]struct{}, len(records))

	for i, r := range records {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("vm bundle entry %d: %w", i, err)
		}

		key := strings.ToLower(r.ID)
		if _, dup := seen[key]; dup {
			return fmt.Errorf("vm bundle names %s twice", r.ID)
		}

		seen[key] = struct{}{}
	}

	return nil
}

// NameFor maps a verification method id ("did:nda:0x…#key-3", "#key-3" or
// "key-3") to its attribute name, "key/3".
func NameFor(kid string) (string, error) {
	frag := strings.TrimPrefix(Fragment(kid), "#")
	if !strings.HasPrefix(frag, kidPrefix) {
		return "", fmt.Errorf("verification method id %q is not #key-N", kid)
	}

	digits := strings.TrimPrefix(frag, kidPrefix)

	// did-registrar completes the attribute's index back into "#key-" + index,
	// digit for digit, so "#key-01" published as key/1 names #key-1 there.
	n, err := strconv.Atoi(digits)
	if err != nil || n < 1 || strconv.Itoa(n) != digits {
		return "", fmt.Errorf("verification method id %q has no key index", kid)
	}

	return keyPrefix + digits, nil
}

// NameToBytes32 is an attribute name in the contract's bytes32 form, right
// padded with zeros.
func NameToBytes32(name string) ([32]byte, error) {
	var b [32]byte
	if len(name) > len(b) {
		return b, fmt.Errorf("attribute name %q exceeds 32 bytes", name)
	}

	copy(b[:], name)

	return b, nil
}

// Fragment is the "#key-1" part of a verification method id, or the whole
// string when it has none.
func Fragment(id string) string {
	if i := strings.LastIndex(id, "#"); i >= 0 {
		return id[i:]
	}

	return id
}

// RecordFor turns one of the document's verification methods into its record.
func RecordFor(doc *did.DIDDocument, vm *did.VerificationMethod) *Record {
	return indexPurposes(doc).record(vm)
}

func (p purposeIndex) record(vm *did.VerificationMethod) *Record {
	rec := &Record{
		PublicKey: vm.PublicKeyHex,
		Purposes:  p.of(vm.Id),
	}

	switch vm.Type {
	case KeyTypeMultikey:
		rec.PublicKey = vm.PublicKeyMultibase
		rec.KeyType = KeyTypeMultikey
	case KeyTypeJsonWebKey:
		rec.PublicKey = JWKRecordKey(vm.PublicKeyJwk)
		rec.KeyType = KeyTypeJsonWebKey
	}

	if vm.Revoked != nil {
		rec.Revoked = &RevokedRecord{Time: *vm.Revoked, Reason: vm.RevocationReason}
	}

	return rec
}

// JWKRecordKey is the "k" of a JsonWebKey record: the JWK as JSON in RFC 7638
// member order (crv, kty, x, y). An empty JWK gives "", which Validate refuses.
func JWKRecordKey(jwk map[string]any) string {
	if len(jwk) == 0 {
		return ""
	}

	b, err := json.Marshal(map[string]any{
		"crv": jwk["crv"],
		"kty": jwk["kty"],
		"x":   jwk["x"],
		"y":   jwk["y"],
	})
	if err != nil {
		return ""
	}

	return string(b)
}

// ErrJsonWebKeyNotPublishable is returned for a JsonWebKey method. The record
// encoding is defined, but did-registrar refuses kt "JsonWebKey" until
// pilacorp/did-registrar#348 is deployed; a transaction carrying one would be
// signed, and its nonce spent, for an update that is refused.
var ErrJsonWebKeyNotPublishable = errors.New("JsonWebKey records are not accepted by did-registrar yet")

func publishable(vm *did.VerificationMethod) error {
	if vm.Type == KeyTypeJsonWebKey {
		return fmt.Errorf("verification method %s: %w", Fragment(vm.Id), ErrJsonWebKeyNotPublishable)
	}

	return nil
}

// KeyAttribute is the key/N attribute that publishes one verification method of
// the document.
func KeyAttribute(doc *did.DIDDocument, kid string) (string, []byte, error) {
	vm := doc.FindVerificationMethod(kid)
	if vm == nil {
		return "", nil, fmt.Errorf("verification method %q not found", kid)
	}

	if err := publishable(vm); err != nil {
		return "", nil, err
	}

	name, err := NameFor(vm.Id)
	if err != nil {
		return "", nil, err
	}

	value, err := RecordFor(doc, vm).Encode()
	if err != nil {
		return "", nil, fmt.Errorf("verification method %q: %w", vm.Id, err)
	}

	return name, value, nil
}

// BundleAttribute is the "vm" attribute that publishes every verification
// method of the document.
func BundleAttribute(doc *did.DIDDocument) (string, []byte, error) {
	if doc == nil || len(doc.VerificationMethod) == 0 {
		return "", nil, errors.New("document declares no verification method")
	}

	// One index for the whole bundle: reading both purpose lists per method was
	// quadratic, 730 ms for a 12000-method document.
	purposes := indexPurposes(doc)
	records := make([]VMRecord, 0, len(doc.VerificationMethod))

	for i := range doc.VerificationMethod {
		vm := &doc.VerificationMethod[i]
		if err := publishable(vm); err != nil {
			return "", nil, err
		}

		records = append(records, VMRecord{ID: Fragment(vm.Id), Record: *purposes.record(vm)})
	}

	value, err := EncodeVMBundle(records)
	if err != nil {
		return "", nil, err
	}

	return VMBundleAttributeName, value, nil
}

// purposeIndex holds which methods a document lists under assertionMethod and
// authentication, by fragment, so "#key-1" and "did:…#key-1" are the same
// method.
type purposeIndex struct {
	assert, auth map[string]struct{}
}

func indexPurposes(doc *did.DIDDocument) purposeIndex {
	byFragment := func(ids []string) map[string]struct{} {
		set := make(map[string]struct{}, len(ids))
		for _, id := range ids {
			set[Fragment(id)] = struct{}{}
		}

		return set
	}

	return purposeIndex{assert: byFragment(doc.AssertionMethod), auth: byFragment(doc.Authentication)}
}

// of reads the purpose codes the document grants one method.
func (p purposeIndex) of(kid string) []string {
	frag := Fragment(kid)

	var purposes []string
	if _, ok := p.assert[frag]; ok {
		purposes = append(purposes, PurposeAssert)
	}

	if _, ok := p.auth[frag]; ok {
		purposes = append(purposes, PurposeAuth)
	}

	return purposes
}
