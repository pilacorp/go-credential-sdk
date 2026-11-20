package jsonmap

import "sync/atomic"

// canonicalizeCount is incremented each time DocumentDigest or
// LegacyHexCanonicalize completes a full URDNA2015 canonicalization
// successfully. Package-internal tests read and reset it to verify that
// multi-proof verification caches the result. Production code never reads
// it; the atomic add is a single instruction and costs nothing measurable.
//
// The variable is package-global, so tests that assert its value must not
// run in parallel with any test that canonicalizes (including themselves).
var canonicalizeCount int64

func incCanonicalizeCount() { atomic.AddInt64(&canonicalizeCount, 1) }

// digestCache lazily computes and caches canonicalization results for a single
// JSONMap, so that verifying N proofs over the same body pays the
// canonicalization cost once per distinct canonical form rather than once per
// proof.
//
// Every method is nil-receiver-safe: a nil cache computes fresh from the
// JSONMap without storing, so callers always go through the cache method —
// no wrapper functions or if-nil branches at the call site.
//
// The cache is not safe for concurrent use: it is scoped to a single
// VerifyProof call which runs the loop sequentially.
type digestCache struct {
	// DocumentDigest result: SHA-256 of processor.Canonicalize(bodyWithoutProof).
	// Used by ecdsa-rdfc-2019 and EcdsaSecp256k1Signature2019.
	docDigest    []byte
	docDigestErr error
	docDigestOK  bool

	// LegacyHexCanonicalize result: ComputeDigest(CanonicalizeDocument(body)).
	// Used by legacy hex proofs and JsonWebSignature2020.
	legacyDigest    []byte
	legacyDigestErr error
	legacyDigestOK  bool

	// bodyWithoutProof result: deep copy of the document without proof.
	// Used by ecdsa-sd-2023 (which has its own canonicalization pipeline).
	bodyNoProof    map[string]interface{}
	bodyNoProofErr error
	bodyNoProofOK  bool
}

// documentDigest returns the DocumentDigest, caching the result when the
// receiver is non-nil. A nil receiver computes fresh without storing.
func (c *digestCache) documentDigest(m *JSONMap) ([]byte, error) {
	if c == nil {
		return m.DocumentDigest()
	}
	if !c.docDigestOK {
		c.docDigest, c.docDigestErr = m.DocumentDigest()
		c.docDigestOK = true
	}
	return c.docDigest, c.docDigestErr
}

// legacyHexCanonicalize returns the legacy digest, caching the result when the
// receiver is non-nil. A nil receiver computes fresh without storing.
func (c *digestCache) legacyHexCanonicalize(m *JSONMap) ([]byte, error) {
	if c == nil {
		return m.LegacyHexCanonicalize()
	}
	if !c.legacyDigestOK {
		c.legacyDigest, c.legacyDigestErr = m.LegacyHexCanonicalize()
		c.legacyDigestOK = true
	}
	return c.legacyDigest, c.legacyDigestErr
}

// bodyWithoutProof returns the body-without-proof, caching the result when the
// receiver is non-nil. A nil receiver computes fresh without storing.
func (c *digestCache) bodyWithoutProof(m *JSONMap) (map[string]interface{}, error) {
	if c == nil {
		return m.bodyWithoutProof()
	}
	if !c.bodyNoProofOK {
		c.bodyNoProof, c.bodyNoProofErr = m.bodyWithoutProof()
		c.bodyNoProofOK = true
	}
	return c.bodyNoProof, c.bodyNoProofErr
}
