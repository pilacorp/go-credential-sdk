package attribute

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/pilacorp/go-credential-sdk/didv2/did"
)

// Update is one change to a DID document, ready to sign: the new document, its
// hash, and the attribute that writes the change to the chain.
//
// Sign one transaction per chain the DID is on, each committing to DocHash and
// carrying Name and Value, then submit them together with Document.
type Update struct {
	// Document is the new document. The document passed in is not modified.
	Document *did.DIDDocument
	// DocHash is Document.Hash().
	DocHash string
	// Name is the attribute name: "key/N", or "vm" when the change touches
	// more than one method.
	Name string
	// Value is the attribute value.
	Value []byte
}

// AddVerificationMethod adds vm with the given purposes. vm.Id may be empty,
// in which case the next #key-N is assigned.
func AddVerificationMethod(doc *did.DIDDocument, vm did.VerificationMethod, purposes []did.VerificationPurpose) (*Update, error) {
	return change(doc, func(next *did.DIDDocument) (string, error) {
		return next.AddVerificationMethod(vm, purposes)
	})
}

// RevokeVerificationMethod marks kid revoked at revokedAt (now when zero) for
// reason. The record carries the revocation, so the key stops being valid on
// chain as well as in the document.
func RevokeVerificationMethod(doc *did.DIDDocument, kid, reason string, revokedAt time.Time) (*Update, error) {
	return change(doc, func(next *did.DIDDocument) (string, error) {
		return kid, next.RevokeVerificationMethod(kid, reason, revokedAt)
	})
}

// AddVerificationMethodPurposes grants kid the given purposes.
func AddVerificationMethodPurposes(doc *did.DIDDocument, kid string, purposes []did.VerificationPurpose) (*Update, error) {
	return change(doc, func(next *did.DIDDocument) (string, error) {
		return kid, next.AddVerificationMethodPurposes(kid, purposes)
	})
}

// RemoveVerificationMethodPurposes takes the given purposes away from kid.
func RemoveVerificationMethodPurposes(doc *did.DIDDocument, kid string, purposes []did.VerificationPurpose) (*Update, error) {
	return change(doc, func(next *did.DIDDocument) (string, error) {
		return kid, next.RemoveVerificationMethodPurposes(kid, purposes)
	})
}

// RotateVerificationMethod adds newVM with oldKid's purposes and revokes oldKid.
// Two methods change, so the attribute is the "vm" bundle: one key/N would
// write only one of them, and did-registrar refuses that.
func RotateVerificationMethod(
	doc *did.DIDDocument, oldKid string, newVM did.VerificationMethod, reason string, revokedAt time.Time,
) (*Update, error) {
	next, err := clone(doc)
	if err != nil {
		return nil, err
	}

	if _, err := next.RotateVerificationMethod(oldKid, newVM, reason, revokedAt); err != nil {
		return nil, err
	}

	name, value, err := BundleAttribute(next)
	if err != nil {
		return nil, err
	}

	return finish(next, name, value)
}

// change applies op to a copy of doc and publishes the one method op names.
func change(doc *did.DIDDocument, op func(next *did.DIDDocument) (string, error)) (*Update, error) {
	next, err := clone(doc)
	if err != nil {
		return nil, err
	}

	kid, err := op(next)
	if err != nil {
		return nil, err
	}

	name, value, err := KeyAttribute(next, kid)
	if err != nil {
		return nil, err
	}

	return finish(next, name, value)
}

func finish(next *did.DIDDocument, name string, value []byte) (*Update, error) {
	docHash, err := next.Hash()
	if err != nil {
		return nil, err
	}

	return &Update{Document: next, DocHash: docHash, Name: name, Value: value}, nil
}

// clone copies doc through its JSON form, which is what the hash and the
// registrar read, so the copy cannot share a slice or a map with the original.
func clone(doc *did.DIDDocument) (*did.DIDDocument, error) {
	if doc == nil {
		return nil, errors.New("document is nil")
	}

	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("copy document: %w", err)
	}

	var next did.DIDDocument
	if err := json.Unmarshal(raw, &next); err != nil {
		return nil, fmt.Errorf("copy document: %w", err)
	}

	return &next, nil
}
