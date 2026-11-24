package verificationmethod

import (
	"encoding/json"
	"time"
)

// JWK represents a JSON Web Key. It supports EC (secp256k1) and RSA keys.
type JWK struct {
	Kty string `json:"kty"`           // "EC" or "RSA"
	Crv string `json:"crv,omitempty"` // EC curve ("secp256k1")
	X   string `json:"x,omitempty"`   // EC X coordinate (base64url, raw)
	Y   string `json:"y,omitempty"`   // EC Y coordinate (base64url, raw)
	N   string `json:"n,omitempty"`   // RSA modulus (base64url)
	E   string `json:"e,omitempty"`   // RSA public exponent (base64url)
}

// VerificationMethodEntry represents a single verification method in a
// DID Document. Conforms to W3C CID 1.0 §2.2 — id/type/controller plus
// verification material (publicKeyHex for EcdsaSecp256k1VerificationKey2019,
// publicKeyJwk for JWK-encoded keys).
//
// Revoked and RevocationReason are Pila extensions following W3C MAY
// guidance for additional properties; see revocation.go for taxonomy.
type VerificationMethodEntry struct {
	ID                 string     `json:"id"`
	Type               string     `json:"type"`
	Controller         string     `json:"controller"`
	PublicKeyHex       string     `json:"publicKeyHex,omitempty"`
	PublicKeyJwk       *JWK       `json:"publicKeyJwk,omitempty"`
	PublicKeyMultibase string     `json:"publicKeyMultibase,omitempty"`
	Revoked            *time.Time `json:"revoked,omitempty"`
	RevocationReason   string     `json:"revocationReason,omitempty"`
}

// DIDDocument represents the structure of a resolved DID Document. Only
// the relationship arrays Pila exposes (`authentication`, `assertionMethod`)
// are typed; other W3C-defined arrays (keyAgreement, capabilityInvocation,
// capabilityDelegation) are intentionally omitted — see Pila's multi-VM
// design Option A.
//
// The relationship arrays (Authentication, AssertionMethod) may contain either
// a string VM id or an embedded VM object (DID Core §5.3.1). UnmarshalJSON
// handles both: a string is kept as-is, an object is decoded as a
// VerificationMethodEntry, its id is kept in the relationship array and the
// full entry is appended to VerificationMethod if not already present.
type DIDDocument struct {
	Context             []string                  `json:"@context"`
	ID                  string                    `json:"id"`
	VerificationMethod  []VerificationMethodEntry `json:"verificationMethod"`
	Authentication      []string                  `json:"authentication"`
	AssertionMethod     []string                  `json:"assertionMethod"`
	Controller          interface{}               `json:"controller"` // string or []string
	DIDDocumentMetadata map[string]interface{}    `json:"didDocumentMetadata"`
}

// UnmarshalJSON decodes a DID document, accepting both string references and
// embedded VM objects in the authentication and assertionMethod arrays.
func (d *DIDDocument) UnmarshalJSON(data []byte) error {
	// Use a plain struct with json.RawMessage for the mixed arrays.
	var raw struct {
		Context             []string                  `json:"@context"`
		ID                  string                    `json:"id"`
		VerificationMethod  []VerificationMethodEntry `json:"verificationMethod"`
		Authentication      []json.RawMessage         `json:"authentication"`
		AssertionMethod     []json.RawMessage         `json:"assertionMethod"`
		Controller          interface{}               `json:"controller"`
		DIDDocumentMetadata map[string]interface{}    `json:"didDocumentMetadata"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	d.Context = raw.Context
	d.ID = raw.ID
	d.VerificationMethod = raw.VerificationMethod
	d.Controller = raw.Controller
	d.DIDDocumentMetadata = raw.DIDDocumentMetadata

	vmIndex := make(map[string]bool, len(d.VerificationMethod))
	for _, vm := range d.VerificationMethod {
		vmIndex[vm.ID] = true
	}

	unmarshalRelationship := func(elems []json.RawMessage) ([]string, error) {
		ids := make([]string, 0, len(elems))
		for _, elem := range elems {
			// Try string first.
			var s string
			if err := json.Unmarshal(elem, &s); err == nil {
				ids = append(ids, s)
				continue
			}
			// Must be an embedded VM object.
			var vm VerificationMethodEntry
			if err := json.Unmarshal(elem, &vm); err != nil {
				return nil, err
			}
			ids = append(ids, vm.ID)
			if !vmIndex[vm.ID] {
				d.VerificationMethod = append(d.VerificationMethod, vm)
				vmIndex[vm.ID] = true
			}
		}
		return ids, nil
	}

	var err error
	d.Authentication, err = unmarshalRelationship(raw.Authentication)
	if err != nil {
		return err
	}
	d.AssertionMethod, err = unmarshalRelationship(raw.AssertionMethod)
	if err != nil {
		return err
	}

	return nil
}
