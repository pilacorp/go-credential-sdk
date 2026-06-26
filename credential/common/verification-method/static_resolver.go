package verificationmethod

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

// StaticResolver is an in-memory ResolverProvider backed by a fixed set of DID
// documents. It does no I/O, so it is ideal for tests and offline use — for
// example to verify credentials signed with key types the production DID
// resolver does not yet publish (RSA, P-256).
type StaticResolver struct {
	docs map[string]*DIDDocument
}

// NewStaticResolver builds a StaticResolver from the given documents, keyed by
// each document's ID.
func NewStaticResolver(docs ...*DIDDocument) *StaticResolver {
	r := &StaticResolver{docs: make(map[string]*DIDDocument, len(docs))}
	for _, d := range docs {
		r.Add(d)
	}
	return r
}

// Add registers (or replaces) a DID document, keyed by its ID.
func (r *StaticResolver) Add(doc *DIDDocument) {
	if doc != nil && doc.ID != "" {
		r.docs[doc.ID] = doc
	}
}

// ResolveDocument returns the registered document for did, or an error if none.
func (r *StaticResolver) ResolveDocument(_ context.Context, did string) (*DIDDocument, error) {
	if doc, ok := r.docs[did]; ok {
		return doc, nil
	}
	return nil, fmt.Errorf("static resolver: unknown did %q", did)
}

// NewDIDDocument builds a DID document exposing vms, listing every VM under
// both assertionMethod and authentication.
func NewDIDDocument(did string, vms ...VerificationMethodEntry) *DIDDocument {
	ids := make([]string, len(vms))
	for i := range vms {
		ids[i] = vms[i].ID
	}
	return &DIDDocument{
		ID:                 did,
		VerificationMethod: vms,
		AssertionMethod:    ids,
		Authentication:     ids,
	}
}

// NewSecp256k1VM builds an EcdsaSecp256k1VerificationKey2019 verification method
// from an uncompressed public key hex (0x04||X||Y). Used by ecdsa-rdfc-2019.
func NewSecp256k1VM(did, fragment, pubKeyHex string) VerificationMethodEntry {
	return VerificationMethodEntry{
		ID:           did + "#" + fragment,
		Type:         "EcdsaSecp256k1VerificationKey2019",
		Controller:   did,
		PublicKeyHex: pubKeyHex,
	}
}

// NewRSAVM builds a JsonWebKey2020 verification method from an RSA public key.
// Used by JsonWebSignature2020.
func NewRSAVM(did, fragment string, pub *rsa.PublicKey) VerificationMethodEntry {
	return VerificationMethodEntry{
		ID:         did + "#" + fragment,
		Type:       "JsonWebKey2020",
		Controller: did,
		PublicKeyJwk: &JWK{
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		},
	}
}

// NewP256VM builds a JsonWebKey2020 verification method from a P-256 public key.
// Used by ecdsa-sd-2023.
func NewP256VM(did, fragment string, pub *ecdsa.PublicKey) VerificationMethodEntry {
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	pub.X.FillBytes(xb)
	pub.Y.FillBytes(yb)
	return VerificationMethodEntry{
		ID:         did + "#" + fragment,
		Type:       "JsonWebKey2020",
		Controller: did,
		PublicKeyJwk: &JWK{
			Kty: "EC",
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(xb),
			Y:   base64.RawURLEncoding.EncodeToString(yb),
		},
	}
}

// NewBLS12381G2VM builds a Multikey verification method for bbs-2023.
func NewBLS12381G2VM(did, fragment, publicKeyMultibase string) VerificationMethodEntry {
	return VerificationMethodEntry{
		ID:                 did + "#" + fragment,
		Type:               "Multikey",
		Controller:         did,
		PublicKeyMultibase: publicKeyMultibase,
	}
}
