package verificationmethod

import "time"

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
// verification material: publicKeyMultibase (a Multikey, P-256 or secp256k1 —
// the curve is named by the multicodec prefix inside the value),
// publicKeyJwk for JWK-encoded keys, or publicKeyHex for the
// EcdsaSecp256k1VerificationKey2019 form.
//
// publicKeyHex is read but no longer the form to publish: DID Core defines no
// such property, so a conforming resolver finds no key material and treats the
// method as holding none (#91). All three are accepted on the reading side for
// as long as documents carrying hex exist.
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
type DIDDocument struct {
	Context             []string                  `json:"@context"`
	ID                  string                    `json:"id"`
	VerificationMethod  []VerificationMethodEntry `json:"verificationMethod"`
	Authentication      []string                  `json:"authentication"`
	AssertionMethod     []string                  `json:"assertionMethod"`
	Controller          interface{}               `json:"controller"` // string or []string
	DIDDocumentMetadata map[string]interface{}    `json:"didDocumentMetadata"`
}
