package verificationmethod

// ResolverProvider abstracts how to resolve a DID document
// for a given verification method URL.
type ResolverProvider interface {
	GetPublicKey(verificationMethodURL string) (string, error)
}
