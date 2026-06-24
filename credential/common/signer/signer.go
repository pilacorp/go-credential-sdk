package signer

// SignerProvider signs a digest produced by the SDK and returns the raw
// signature. The signing scheme (curve, padding) is determined by the
// verification method bound to the proof, not by the provider — except for the
// JsonWebSignature2020 (RSA) JOSE algorithm, which a provider may declare via
// AlgorithmProvider.
type SignerProvider interface {
	Sign(digest []byte) ([]byte, error)
}

// AlgorithmProvider lets a signer declare its JOSE algorithm for
// JsonWebSignature2020 (RSA). Signers that don't implement it default to
// "RS256". The SDK uses it to pick the hash and to write the JWS header.
type AlgorithmProvider interface {
	Algorithm() string
}

// AlgorithmOf returns p's JOSE algorithm, defaulting to "RS256".
func AlgorithmOf(p SignerProvider) string {
	if a, ok := p.(AlgorithmProvider); ok {
		return a.Algorithm()
	}
	return "RS256"
}
