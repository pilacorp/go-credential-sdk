package jsonmap

import "github.com/pilacorp/go-credential-sdk/credential/internal/sdverify"

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

	// sdDoc: a DocVerifier that lazily canonicalizes the body-without-proof
	// for ecdsa-sd-2023 verification. The DocVerifier caches the URDNA2015
	// canonical N-Quads so multiple sd proofs reuse the same canonicalization.
	sdDoc    *sdverify.DocVerifier
	sdDocErr error
	sdDocOK  bool

	// misses counts the number of canonical forms computed by this cache (one
	// per "compute" branch). Tests use it to verify that multi-proof
	// verification reuses the cached result.
	misses int
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
		if c.docDigestErr == nil {
			c.misses++
		}
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
		if c.legacyDigestErr == nil {
			c.misses++
		}
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

// sdDocument returns a DocVerifier that lazily canonicalizes the body-without-
// proof for ecdsa-sd-2023 verification. URDNA2015 runs the first time a proof
// gets past its header and parse checks; later proofs reuse the result.
// When the receiver is nil, a standalone DocVerifier is returned (no caching
// across calls — the single-proof path).
func (c *digestCache) sdDocument(m *JSONMap) (*sdverify.DocVerifier, error) {
	if c == nil {
		doc, err := m.bodyWithoutProof()
		if err != nil {
			return nil, err
		}
		return sdverify.NewDocVerifier(doc, nil), nil
	}
	if !c.sdDocOK {
		doc, err := c.bodyWithoutProof(m)
		if err != nil {
			c.sdDocErr = err
		} else {
			c.sdDoc = sdverify.NewDocVerifier(doc, &c.misses)
		}
		c.sdDocOK = true
	}
	return c.sdDoc, c.sdDocErr
}
