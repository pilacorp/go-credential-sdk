// Package typemeta implements SD-JWT VC Type Metadata,
// draft-ietf-oauth-sd-jwt-vc-19 §5 and §6, for the three roles: the
// publisher builds and encodes a Type Metadata document (Document,
// ParseEncoded); Issuer, Holder and Verifier retrieve a type's documents
// through a Resolver (§5.3), check and merge them with Load (§5.4-§5.7), and
// check a payload against the claim metadata with ValidateClaims (§5.6).
// Package dc uses it for IssueRequest.TypeMetadata and the Type Metadata
// options of Verify.
//
// Whether Type Metadata is processed at all, which retrieval methods are
// used and which publishers are trusted (§5.7, §7.8) are the caller's
// policy: a Resolver carries it. Rendering the credential, choosing a
// locale and fetching the images and SVG templates a document references
// are the display application's; CheckIntegrity checks what it fetches.
package typemeta

import (
	"context"
	"errors"
	"slices"
	"time"
)

var (
	// ErrNotFound: the Resolver has no document for the type, or the type
	// is outside its scope. A Resolver returns it before any request for a
	// type it cannot serve.
	ErrNotFound = errors.New("typemeta: no Type Metadata for the type")
	// ErrInvalid: a document cannot be used: its hash does not match (§6),
	// it is not a Type Metadata document (§5.2, §5.5), its vct is not the
	// type that led to it (§5.3), or the extends chain cannot be completed
	// (§5.4).
	ErrInvalid = errors.New("typemeta: Type Metadata document is invalid")
	// ErrClaims: claim metadata processing failed (§5.6): the claims of a
	// document break §5.6 and its subsections, merging along extends breaks
	// §5.6, §5.6.5.1, or the claim metadata is over a limit of the SDK.
	// §5.7: the credential MUST be rejected.
	ErrClaims = errors.New("typemeta: claim metadata is invalid")
	// ErrCycle: the extends chain comes back to a type already in it (§7.4).
	ErrCycle = errors.New("typemeta: extends cycle")
	// ErrViolated: claim metadata validation failed (§5.6): the payload
	// does not keep the claims of the Type Metadata.
	ErrViolated = errors.New("typemeta: payload violates the claim metadata")
)

// Limits on what Load, Encode, ParseEncoded and ValidateClaims read; draft 19
// sets none. A publisher's document over them is refused by every reader on
// this SDK. A limit on a document (its size, the chain, the type's display)
// is ErrInvalid, so a policy that does not require Type Metadata skips it. A
// limit on claim metadata (claims, a path, a claim's display, the values
// ValidateClaims reads) is ErrClaims: claim metadata the SDK cannot process,
// which §5.7 rejects whatever the policy.
const (
	maxDocumentBytes = 256 << 10
	maxChain         = 8
	maxClaims        = 1000
	maxPath          = 64
	maxDisplay       = 100
	// maxClaimVisits bounds the work of one ValidateClaims call, one unit per
	// value read and one more per 64 bytes of a key looked up: claims times
	// the values a path selects has no bound the other limits give.
	maxClaimVisits = 1 << 20
)

// Limits of NewHTTPResolver; draft 19 §3 asks for redirect, time and size
// bounds without a number.
const (
	fetchTimeout     = 5 * time.Second
	maxRedirects     = 3
	maxCacheLifetime = 24 * time.Hour
	maxCacheBytes    = 4 << 20
)

// Ref is a reference to a Type Metadata document: the vct of a credential
// with its vct#integrity, or the extends of a document with its
// extends#integrity (§5.3, §5.4). Integrity is "" when the reference has
// none. A vct#integrity that is present but empty is a failed integrity
// check (§6), not a missing one: a caller that reads it rejects the document
// itself, as dc.Verify does, and Load refuses an empty extends#integrity.
type Ref struct {
	VCT       string
	Integrity string
}

// Resolver returns the Type Metadata document of ref.VCT, as the exact
// bytes retrieved, unparsed. It does not check them: Load checks the hash,
// the structure and the vct. ref.Integrity is only a hint, for a resolver
// that caches by it (§5.3.4).
//
// A resolver with no document for ref.VCT returns an error wrapping
// ErrNotFound, without a request when the type is outside its scope; a
// failed retrieval returns another error. It must be safe for concurrent
// use. NewHTTPResolver, Static and Multi make one; a registry (§5.3.2) or an
// ecosystem's own method (§5.3.3) is the caller's implementation.
type Resolver interface {
	Metadata(ctx context.Context, ref Ref) ([]byte, error)
}

// Metadata is the Type Metadata of a type after Load: every document of the
// extends chain retrieved, checked and merged (§5.7: fully processed). It
// does not change once made, and goroutines may share it. Only Load makes a
// usable one; the zero value is refused by ValidateClaims, ValidateIssuance
// and dc.Issue.
type Metadata struct {
	vct         string
	chain       []string
	name        string
	description string
	display     []Display
	claims      []Claim
	docs        [][]byte
}

// VCT is the type the Metadata was loaded for: the VCT of the Ref passed to
// Load.
func (m *Metadata) VCT() string {
	if m == nil {
		return ""
	}
	return m.vct
}

// Chain is the vct of each document of the extends chain, the credential's
// type first (§5.4). A Consumer may match types by it besides aka_vcts
// (§5.4); dc.WithExtendedVCTMatch does.
func (m *Metadata) Chain() []string {
	if m == nil {
		return nil
	}
	return slices.Clone(m.chain)
}

// Name is the name of the credential's document, for developers (§5.2).
func (m *Metadata) Name() string {
	if m == nil {
		return ""
	}
	return m.name
}

// Description is the description of the credential's document, for
// developers (§5.2).
func (m *Metadata) Description() string {
	if m == nil {
		return ""
	}
	return m.description
}

// Display is the display metadata after extends: that of the nearest
// document in the chain that has one, the credential's first (§5.5.2). The
// display application picks the locale (§5.5) and must escape the text it
// shows (§7.6). The result is a deep copy.
func (m *Metadata) Display() []Display {
	if m == nil || m.display == nil {
		return nil
	}
	out := make([]Display, len(m.display))
	for i, d := range m.display {
		out[i] = d.clone()
	}
	return out
}

// Claims is the claim metadata after extends (§5.6.5): the claims of the
// furthest document first, each overridden by a nearer document with the
// same path, then the claims a nearer document adds. SD is "allowed" where
// no document sets sd (§5.6.4). The result is a deep copy.
func (m *Metadata) Claims() []Claim {
	if m == nil || m.claims == nil {
		return nil
	}
	out := make([]Claim, len(m.claims))
	for i, c := range m.claims {
		out[i] = c.clone()
	}
	return out
}

// Documents returns a copy of the bytes of every document of the chain, in
// the order of Chain, as they passed the integrity check. A consumer that
// understands an extension property (§5.2) reads it from them; how extension
// properties of a parent and a child combine is the consumer's, as draft 19
// does not say. The SDK does not check the content of extension properties:
// text that is displayed must be escaped (§7.6), and URLs must be checked
// before they are fetched.
func (m *Metadata) Documents() [][]byte {
	if m == nil {
		return nil
	}
	out := make([][]byte, len(m.docs))
	for i, d := range m.docs {
		out[i] = slices.Clone(d)
	}
	return out
}
