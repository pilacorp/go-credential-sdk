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
// JsonWebSignature2020. Signers that don't implement it default to "PS256".
// The SDK writes it to the JWS header.
type AlgorithmProvider interface {
	Algorithm() string
}

// AlgorithmOf returns p's JOSE algorithm, defaulting to "PS256", the RSA
// algorithm of JsonWebSignature2020's table (RS256 is not in it).
func AlgorithmOf(p SignerProvider) string {
	if a, ok := p.(AlgorithmProvider); ok {
		return a.Algorithm()
	}
	return "PS256"
}
