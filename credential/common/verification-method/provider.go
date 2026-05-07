package verificationmethod

// ResolverProvider abstracts how to resolve a DID document
// for a given verification method URL.
type ResolverProvider interface {
	GetPublicKey(verificationMethodURL string) (string, error)
}

// DocumentResolver is the optional extension that exposes the full DID
// Document plus the matching VerificationMethod entry. Implementations
// that satisfy DocumentResolver enable strict-purpose verification —
// callers that only have a static public key (e.g. StaticResolver) cannot
// run those checks and should skip them. Use a type assertion to detect
// support at the call site:
//
//	if dr, ok := resolver.(verificationmethod.DocumentResolver); ok { ... }
type DocumentResolver interface {
	ResolverProvider
	ResolveDocumentAndVM(verificationMethodURL string) (*DIDDocument, *VerificationMethodEntry, error)
}
