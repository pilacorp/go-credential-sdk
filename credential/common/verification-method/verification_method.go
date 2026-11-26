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
	// hasPrivate records that the decoded JWK carried d, the private key, so
	// the key parsers refuse it (RFC 7517; JsonWebSignature2020 §3.2.1 "MUST
	// never contain d"). The value itself is never kept, so it is never
	// marshalled again.
	hasPrivate bool
}

// UnmarshalJSON decodes a JWK and notes whether it carried d without keeping
// it.
func (j *JWK) UnmarshalJSON(b []byte) error {
	type plain JWK
	var aux struct {
		plain
		D json.RawMessage `json:"d"` // "d": null counts as present too
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*j = JWK(aux.plain)
	j.hasPrivate = len(aux.D) > 0
	return nil
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
	Expires            *time.Time `json:"expires,omitempty"`
}

// ExpiredAt reports whether the method is past its expires time at t.
// A method is expired at exactly its expires instant.
func (vm *VerificationMethodEntry) ExpiredAt(t time.Time) bool {
	return vm.Expires != nil && !t.Before(*vm.Expires)
}

// DIDDocument represents the structure of a resolved DID Document. Only
// the relationship arrays Pila exposes (`authentication`, `assertionMethod`)
// are typed; other W3C-defined arrays (keyAgreement, capabilityInvocation,
// capabilityDelegation) are intentionally omitted — see Pila's multi-VM
// design Option A.
type DIDDocument struct {
	Context             []string                  `json:"@context"`
	ID                  string                    `json:"id"`
	VerificationMethod  []VerificationMethodEntry `json:"verificationMethod"`
	Authentication      []string                  `json:"authentication"`
	AssertionMethod     []string                  `json:"assertionMethod"`
	Controller          interface{}               `json:"controller"` // string or []string
	DIDDocumentMetadata map[string]interface{}    `json:"didDocumentMetadata"`
}
