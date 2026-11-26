package jsonmap

import (
	"context"
	"crypto/sha256"

	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/internal/nquads"
)

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
	// bodyWithoutProof result: deep copy of the document without proof.
	bodyNoProof    map[string]interface{}
	bodyNoProofErr error
	bodyNoProofOK  bool

	// RDFC-1.0 N-Quads of the body without proof. ecdsa-rdfc-2019 and
	// EcdsaSecp256k1Signature2019 hash them; ecdsa-sd-2023 relabels them. One
	// result serves every proof of either kind.
	bodyNQuads    []string
	bodyNQuadsErr error
	bodyNQuadsOK  bool

	// SHA-256 of the joined N-Quads, for the rdfc and secp256k1 suites.
	bodyDigest    []byte
	bodyDigestErr error
	bodyDigestOK  bool

	// LegacyHexCanonicalize result: ComputeDigest(CanonicalizeDocument(body)).
	// Used by legacy hex proofs and JsonWebSignature2020.
	legacyDigest    []byte
	legacyDigestErr error
	legacyDigestOK  bool

	// misses counts the canonical forms this cache computed. Tests use it to
	// check that a proof set reuses them.
	misses int
}

// documentDigest returns SHA-256 of the canonical body, with the errors of
// JSONMap.DocumentDigest. A nil receiver computes fresh without storing.
func (c *digestCache) documentDigest(m *JSONMap) ([]byte, error) {
	if c == nil {
		return m.DocumentDigest()
	}
	if !c.bodyDigestOK {
		c.bodyDigest, c.bodyDigestErr = c.computeDocumentDigest(m)
		c.bodyDigestOK = true
	}
	return c.bodyDigest, c.bodyDigestErr
}

func (c *digestCache) computeDocumentDigest(m *JSONMap) ([]byte, error) {
	body, err := c.bodyWithoutProof(m)
	if err != nil {
		return nil, err
	}
	canonical, err := nquads.Join(c.canonicalNQuads(body))
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canonical)
	return digest[:], nil
}

// canonicalNQuads runs RDFC-1.0 on body the first time and returns the cached
// result, or the cached error, after that. body must be the cache's own
// bodyWithoutProof result.
func (c *digestCache) canonicalNQuads(body map[string]interface{}) ([]string, error) {
	if !c.bodyNQuadsOK {
		c.bodyNQuads, c.bodyNQuadsErr = processor.CanonicalizeNQuads(body)
		c.bodyNQuadsOK = true
		if c.bodyNQuadsErr == nil {
			c.misses++
		}
	}
	return c.bodyNQuads, c.bodyNQuadsErr
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

// sdCanonicalizer returns the canon function an ecdsa-sd-2023 proof check
// calls once the proof value has passed its header and parse checks. With a
// cache it shares the N-Quads that documentDigest hashes; a nil receiver
// canonicalizes on each call (the single-proof path).
func (c *digestCache) sdCanonicalizer(m *JSONMap) (func() ([]string, error), error) {
	body, err := c.bodyWithoutProof(m)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return func() ([]string, error) { return processor.CanonicalizeNQuads(body) }, nil
	}
	return func() ([]string, error) { return c.canonicalNQuads(body) }, nil
}

// didMemo resolves each DID once per proof set. Proofs signed by keys of one
// DID would otherwise fetch its document once per proof, and a resolver is
// usually a network call. Only successes are kept: the first failure ends the
// set. Not safe for concurrent use, like digestCache.
type didMemo struct {
	inner verificationmethod.ResolverProvider
	docs  map[string]*verificationmethod.DIDDocument
}

func (r *didMemo) ResolveDocument(ctx context.Context, did string) (*verificationmethod.DIDDocument, error) {
	if doc, ok := r.docs[did]; ok {
		return doc, nil
	}
	doc, err := r.inner.ResolveDocument(ctx, did)
	if err != nil {
		return nil, err
	}
	if r.docs == nil {
		r.docs = make(map[string]*verificationmethod.DIDDocument)
	}
	r.docs[did] = doc
	return doc, nil
}
