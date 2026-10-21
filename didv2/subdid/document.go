package subdid

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/pilacorp/go-credential-sdk/didv2/did"
)

const (
	primaryKeyFragment = "#key-1"
	secp256k1VMType    = "EcdsaSecp256k1VerificationKey2019"
	subIDKey           = "subId"
)

var (
	subIDPattern         = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	didPattern           = regexp.MustCompile(`^did:[a-z]{1,16}(:[a-z]{1,16}){0,2}:0x[0-9a-f]{40}$`)
	compressedKeyPattern = regexp.MustCompile(`^0x0[23][0-9a-f]{64}$`)
)

// ParseSubID accepts a subId of 8 to 64 characters from [A-Za-z0-9_-] and
// returns its bytes unchanged.
func ParseSubID(s string) ([]byte, error) {
	if !subIDPattern.MatchString(s) {
		return nil, fmt.Errorf("subdid: subId must match %s", subIDPattern)
	}

	return []byte(s), nil
}

// SubDIDFor returns the Sub-DID whose #key-1 is pub, under the prefix of rootDID.
func SubDIDFor(rootDID string, pub *ecdsa.PublicKey) (string, error) {
	if pub == nil || pub.Curve != crypto.S256() || pub.X == nil || pub.Y == nil || !crypto.S256().IsOnCurve(pub.X, pub.Y) {
		return "", errors.New("subdid: public key must be a point on secp256k1")
	}
	if err := checkDID(rootDID); err != nil {
		return "", fmt.Errorf("subdid: root DID: %w", err)
	}

	return didPrefix(rootDID) + strings.ToLower(crypto.PubkeyToAddress(*pub).Hex()), nil
}

// ValidateSubDID checks the document rules of a Sub-DID under rootDID. It does
// not check the chain, the subId requirement of a flow, or the root consent.
func ValidateSubDID(doc *did.DIDDocument, rootDID string) error {
	if doc == nil {
		return errors.New("subdid: document is nil")
	}
	if err := doc.Validate(); err != nil {
		return fmt.Errorf("subdid: %w", err)
	}
	if err := checkDID(doc.Id); err != nil {
		return fmt.Errorf("subdid: document id: %w", err)
	}
	if err := checkDID(rootDID); err != nil {
		return fmt.Errorf("subdid: root DID: %w", err)
	}
	if didPrefix(doc.Id) != didPrefix(rootDID) {
		return fmt.Errorf("subdid: %s and root %s have different prefixes", doc.Id, rootDID)
	}
	if doc.Id == rootDID {
		return errors.New("subdid: a Sub-DID cannot be its own root")
	}
	if doc.Controller != rootDID {
		return fmt.Errorf("subdid: controller %q is not the root DID %s", doc.Controller, rootDID)
	}
	for _, vm := range doc.VerificationMethod {
		if !strings.HasPrefix(vm.Id, doc.Id+"#") {
			return fmt.Errorf("subdid: verification method id %q must start with %s#", vm.Id, doc.Id)
		}
	}
	if err := checkPrimaryKey(doc); err != nil {
		return err
	}
	if doc.DocumentMetadata == nil {
		return errors.New("subdid: didDocumentMetadata is missing")
	}

	return nil
}

func checkPrimaryKey(doc *did.DIDDocument) error {
	vm := doc.FindVerificationMethod(primaryKeyFragment)
	if vm == nil {
		return errors.New("subdid: #key-1 is missing")
	}
	if vm.Type != secp256k1VMType {
		return fmt.Errorf("subdid: #key-1 has type %q, want %s", vm.Type, secp256k1VMType)
	}
	if !compressedKeyPattern.MatchString(vm.PublicKeyHex) {
		return errors.New("subdid: #key-1 publicKeyHex must be a lowercase compressed secp256k1 key")
	}

	address, err := did.AddressFromPublicKeyHex(vm.PublicKeyHex)
	if err != nil {
		return fmt.Errorf("subdid: #key-1: %w", err)
	}
	if address != didAddress(doc.Id) {
		return fmt.Errorf("subdid: #key-1 belongs to %s, not to %s", address, doc.Id)
	}

	return nil
}

func checkDID(s string) error {
	if !didPattern.MatchString(s) {
		return fmt.Errorf("%q does not match %s", s, didPattern)
	}

	return nil
}

func didPrefix(s string) string {
	return s[:strings.LastIndex(s, ":")+1]
}

func didAddress(s string) string {
	return s[strings.LastIndex(s, ":")+1:]
}

// DocHash returns the 32 bytes of doc.Hash(): the Sub-DID's active leaf and
// the bytes its signature covers.
func DocHash(doc *did.DIDDocument) ([32]byte, error) {
	h, err := doc.Hash()
	if err != nil {
		return [32]byte{}, fmt.Errorf("subdid: %w", err)
	}

	b, err := hex.DecodeString(strings.TrimPrefix(h, "0x"))
	if err != nil || len(b) != 32 {
		return [32]byte{}, fmt.Errorf("subdid: document hash %q is not 32 bytes", h)
	}

	return [32]byte(b), nil
}
