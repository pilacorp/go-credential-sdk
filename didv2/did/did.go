// Package did provides core DID domain logic including key pair generation,
// DID Document creation, and address derivation.
//
// This package is the foundation module used by both Wallet/App and Backend
// services in all deployment models.
package did

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"maps"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// Verification method types and contexts published by this package.
const (
	secp256k1VMType = "EcdsaSecp256k1VerificationKey2019"
	multikeyVMType  = "Multikey"

	// cidContext defines Multikey, publicKeyMultibase and revoked.
	cidContext = "https://www.w3.org/ns/cid/v1"
)

// GenerateECDSAKeyPair generates a new ECDSA key pair for DID creation.
//
// This is the foundational function for key pair generation used across all
// deployment models. In Model 2, Wallet/App calls this first before requesting
// an issuer signature from Backend.
//
// Returns a KeyPair containing both public and private keys. The private key
// should be stored securely as it proves ownership of the DID.
func GenerateECDSAKeyPair() (*KeyPair, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	return &KeyPair{
		PublicKey:  privateKey.Public().(*ecdsa.PublicKey),
		PrivateKey: privateKey,
	}, nil
}

// GenerateDualCurveKeyPair generates one scalar on P-256 and exposes it as both a
// secp256k1 key pair and a P-256 public key. P-256 first: n(P-256) < n(secp256k1).
func GenerateDualCurveKeyPair() (*KeyPair, error) {
	p256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate P-256 private key: %w", err)
	}

	scalar := make([]byte, 32)
	p256Priv.D.FillBytes(scalar)

	secpPriv, err := crypto.ToECDSA(scalar)
	if err != nil {
		return nil, fmt.Errorf("failed to reuse P-256 scalar on secp256k1: %w", err)
	}

	return &KeyPair{
		PublicKey:     &secpPriv.PublicKey,
		PrivateKey:    secpPriv,
		P256PublicKey: &p256Priv.PublicKey,
	}, nil
}

// GenerateDIDDocument creates a W3C-compliant DID Document from the provided parameters.
//
// The DID Document is the core identity document that:
//   - Declares the DID identifier
//   - Publishes the public key for verification
//   - Specifies the controller (Issuer)
//   - Includes metadata and verification methods
//
// The didPublicKey parameter is the hex-encoded public key (compressed or uncompressed).
// The did parameter is the full DID identifier (e.g., "did:nda:0x1234...").
// The hash parameter is an optional hash value to include in document metadata.
// The issuerDID parameter is the DID identifier of the Issuer (controller).
// The didType parameter specifies the type of DID (People, Item, Location, Activity).
// The metadata parameter contains additional key-value pairs for the document.
// The extraVMs parameter publishes extra verification methods, each keeping the id
// its spec sets or taking "#key-N" by position, with the purposes the spec lists.
//
// Returns a DIDDocument that can be hashed and included in blockchain transactions.
func GenerateDIDDocument(
	didPublicKey, did, hash, issuerDID string,
	didType DIDType,
	metadata map[string]any,
	extraVMs ...VerificationMethodSpec,
) *DIDDocument {
	docMetadata := make(map[string]any)
	maps.Copy(docMetadata, metadata)

	if didType.String() != "" {
		docMetadata["type"] = didType.String()
	}

	if hash != "" {
		docMetadata["hash"] = hash
	}

	specs := append([]VerificationMethodSpec{NewSpec(NewSecp256k1VM(did, "#key-1", didPublicKey))}, extraVMs...)
	vms, authentication, assertionMethod := NewVerificationMethods(specs...)

	return &DIDDocument{
		Context:            documentContext(vms),
		Id:                 did,
		Controller:         issuerDID,
		VerificationMethod: vms,
		Authentication:     authentication,
		AssertionMethod:    assertionMethod,
		DocumentMetadata:   docMetadata,
	}
}

// canonicalVMID expands a "#fragment" reference into a full DID URL.
func canonicalVMID(did, idOrFragment string) string {
	if strings.HasPrefix(idOrFragment, "#") {
		return did + idOrFragment
	}

	return idOrFragment
}

// NewSpec pairs a VM with its purposes; no purpose means both.
func NewSpec(vm VerificationMethod, purposes ...VerificationPurpose) VerificationMethodSpec {
	return VerificationMethodSpec{VM: vm, Purposes: purposes}
}

// NewVerificationMethods splits complete specs into the document's verification
// methods and its two relationship arrays.
func NewVerificationMethods(
	specs ...VerificationMethodSpec,
) (vms []VerificationMethod, authentication, assertionMethod []string) {
	vms = make([]VerificationMethod, 0, len(specs))
	authentication = make([]string, 0, len(specs))
	assertionMethod = make([]string, 0, len(specs))

	for _, s := range specs {
		vms = append(vms, s.VM)

		for _, p := range s.purposes() {
			switch p {
			case PurposeAuthentication:
				authentication = append(authentication, s.VM.Id)
			case PurposeAssertionMethod:
				assertionMethod = append(assertionMethod, s.VM.Id)
			}
		}
	}

	return vms, authentication, assertionMethod
}

// documentContext adds the CID context when the document publishes a Multikey VM.
func documentContext(vms []VerificationMethod) []string {
	ctx := []string{
		"https://w3id.org/security/v1",
		"https://www.w3.org/ns/did/v1",
	}

	for i := range vms {
		if vms[i].Type == multikeyVMType {
			return append(ctx, cidContext)
		}
	}

	return ctx
}

// NewSecp256k1VM builds a complete secp256k1 VM from a "#name" fragment.
func NewSecp256k1VM(did, fragment, publicKeyHex string) VerificationMethod {
	return VerificationMethod{
		Id:           canonicalVMID(did, fragment),
		Type:         secp256k1VMType,
		Controller:   did,
		PublicKeyHex: publicKeyHex,
	}
}

// NewP256MultikeyVM builds a complete Multikey VM from a "#name" fragment.
func NewP256MultikeyVM(did, fragment string, pub *ecdsa.PublicKey) (VerificationMethod, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return VerificationMethod{}, fmt.Errorf("NewP256MultikeyVM requires a P-256 public key")
	}

	multibase, err := encodePubMultibase(pub)
	if err != nil {
		return VerificationMethod{}, err
	}

	return VerificationMethod{
		Id:                 canonicalVMID(did, fragment),
		Type:               multikeyVMType,
		Controller:         did,
		PublicKeyMultibase: multibase,
	}, nil
}

// AddressFromPublicKeyHex converts a hex-encoded public key to an Ethereum address.
//
// Supports both compressed (33 bytes) and uncompressed (65 bytes) public key formats.
// The publicKeyHex parameter can include or omit the "0x" prefix.
//
// Returns the Ethereum address in lowercase hex format (with "0x" prefix).
// This address is used to derive the DID identifier and for on-chain operations.
func AddressFromPublicKeyHex(publicKeyHex string) (string, error) {
	// Decode hex-encoded public key
	publicKeyBytes, err := hex.DecodeString(strings.TrimPrefix(publicKeyHex, "0x"))
	if err != nil {
		return "", fmt.Errorf("failed to decode public key hex: %w", err)
	}

	var publicKey *ecdsa.PublicKey

	// Handle compressed public key (33 bytes)
	if len(publicKeyBytes) == 33 && (publicKeyBytes[0] == 0x02 || publicKeyBytes[0] == 0x03) {
		publicKey, err = crypto.DecompressPubkey(publicKeyBytes)
		if err != nil {
			return "", fmt.Errorf("failed to decompress public key: %w", err)
		}
	} else if len(publicKeyBytes) == 65 && publicKeyBytes[0] == 0x04 {
		// Handle uncompressed public key (65 bytes)
		publicKey, err = crypto.UnmarshalPubkey(publicKeyBytes)
		if err != nil {
			return "", fmt.Errorf("failed to unmarshal public key: %w", err)
		}
	} else {
		return "", fmt.Errorf("unsupported public key format: expected 33 bytes (compressed) or 65 bytes (uncompressed), got %d bytes", len(publicKeyBytes))
	}

	return strings.ToLower(crypto.PubkeyToAddress(*publicKey).Hex()), nil
}
