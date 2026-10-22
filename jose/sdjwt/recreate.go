// Ported from sd-jwt-python (Apache-2.0), src/sd_jwt/verifier.py
// (_extract_sd_claims, _unpack_disclosed_claims), and eudi-lib-jvm-sdjwt-kt
// (Apache-2.0), src/main/kotlin/eu/europa/ec/eudi/sdjwt/RecreateClaims.kt
// (recreateClaimsAndDisclosuresPerClaim) and SdJwtVerifier.kt
// (VerificationError). See jose/NOTICE.

package sdjwt

import (
	"fmt"
	"slices"
)

// Default bounds of Limits.
const (
	DefaultMaxBytes       = 1 << 20 // 1 MB, a whole compact SD-JWT
	DefaultMaxDisclosures = 1000
	DefaultMaxDepth       = 32 // nesting of objects and arrays
)

// Limits bounds the work Split and Recreate do on untrusted input; a zero or
// negative field means its default. The package functions Split and Recreate
// use the defaults.
type Limits struct {
	MaxBytes       int // Split: length of the compact SD-JWT
	MaxDisclosures int // Split and Recreate
	MaxDepth       int // Recreate: nesting depth of the payload with every disclosed value in place
}

func (l Limits) withDefaults() Limits {
	if l.MaxBytes <= 0 {
		l.MaxBytes = DefaultMaxBytes
	}
	if l.MaxDisclosures <= 0 {
		l.MaxDisclosures = DefaultMaxDisclosures
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = DefaultMaxDepth
	}
	return l
}

// Recreated is the result of Recreate.
type Recreated struct {
	// Claims is the processed payload: every disclosed claim in place, every
	// _sd and _sd_alg removed.
	Claims map[string]any
	opened map[string]Disclosure // path key → the disclosure that opened the claim there
}

// Disclosures returns what a holder must send for a verifier to see the claim
// at path: the disclosure of every concealed ancestor, outermost first, then
// the claim's own if it is concealed. It is empty for a claim that is not
// concealed and has no concealed ancestor; ok is false when path is not in
// Claims. Array indices count the elements of the recreated arrays.
func (r *Recreated) Disclosures(path Path) (ds []Disclosure, ok bool) {
	if path.validate() != nil {
		return nil, false
	}
	if _, ok := lookup(r.Claims, path); !ok {
		return nil, false
	}
	ds = []Disclosure{}
	for i := 1; i <= len(path); i++ {
		if d, ok := r.opened[path[:i].key()]; ok {
			ds = append(ds, d)
		}
	}
	return ds, true
}

// Recreate is Limits{}.Recreate.
func Recreate(payload map[string]any, disclosures []Disclosure) (*Recreated, error) {
	return Limits{}.Recreate(payload, disclosures)
}

// Recreate rebuilds the payload from the issuer-signed payload and the
// disclosures received with it (RFC 9901 section 7.1, steps 3 to 5). payload
// is not modified.
//  1. Every disclosure is re-read from its Encoded string (ParseDisclosure),
//     so its name, value and digest are those of the bytes received; more than
//     l.MaxDisclosures is ErrTooLarge; the same disclosure twice is
//     ErrDuplicateDigest.
//  2. A top-level _sd_alg other than "sha-256" is ErrSDAlg; absent means
//     sha-256.
//  3. The payload and every value opened along the way are walked:
//     - an object's _sd must be an array of strings (ErrMalformed); an
//     unmatched digest is ignored (a decoy, or a claim not disclosed); a
//     matched one must be a 3-item disclosure (ErrDisclosureShape) whose name
//     is not already in the object (ErrClaimExists), and is inserted and
//     walked;
//     - an array element that is an object with exactly one key ... holding a
//     string is a placeholder: matched, it must be a 2-item disclosure
//     (ErrDisclosureShape) and is replaced by its value, which is walked;
//     unmatched, it is removed;
//     - any other object holding ... is ErrReservedName; _sd_alg below the top
//     level is ErrSDAlg; nesting deeper than l.MaxDepth is ErrTooLarge.
//  4. A digest seen twice anywhere, including inside disclosed values, is
//     ErrDuplicateDigest.
//  5. A disclosure no digest points to is ErrUnreferencedDisclosure.
//  6. Every _sd and _sd_alg is removed; an object left empty stays {}.
func (l Limits) Recreate(payload map[string]any, disclosures []Disclosure) (*Recreated, error) {
	l = l.withDefaults()
	if len(disclosures) > l.MaxDisclosures {
		return nil, fmt.Errorf("%w: %d disclosures, at most %d", ErrTooLarge, len(disclosures), l.MaxDisclosures)
	}
	if alg, ok := payload[keySDAlg]; ok && alg != sdAlgSHA256 {
		return nil, fmt.Errorf("%w: _sd_alg %v, only %q is supported", ErrSDAlg, alg, sdAlgSHA256)
	}
	r := recreator{
		byDigest: make(map[string]*received, len(disclosures)),
		seen:     map[string]bool{},
		opened:   map[string]Disclosure{},
		maxDepth: l.MaxDepth,
	}
	order := make([]*received, 0, len(disclosures))
	for _, given := range disclosures {
		d, err := ParseDisclosure(given.Encoded)
		if err != nil {
			return nil, err
		}
		if r.byDigest[d.Digest] != nil {
			return nil, fmt.Errorf("%w: disclosure %s given twice", ErrDuplicateDigest, d.Digest)
		}
		rd := &received{d: d}
		r.byDigest[d.Digest] = rd
		order = append(order, rd)
	}

	claims, err := r.object(payload, nil, 1, true)
	if err != nil {
		return nil, err
	}
	for _, rd := range order {
		if !rd.used {
			return nil, fmt.Errorf("%w: %s", ErrUnreferencedDisclosure, rd.d.Digest)
		}
	}
	return &Recreated{Claims: claims, opened: r.opened}, nil
}

type received struct {
	d    Disclosure
	used bool
}

type recreator struct {
	byDigest map[string]*received
	seen     map[string]bool
	opened   map[string]Disclosure
	maxDepth int
}

func (r *recreator) value(v any, p Path, depth int) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		return r.object(t, p, depth, false)
	case []any:
		return r.array(t, p, depth)
	default:
		return v, nil
	}
}

func (r *recreator) object(obj map[string]any, p Path, depth int, top bool) (map[string]any, error) {
	if depth > r.maxDepth {
		return nil, fmt.Errorf("%w: nesting deeper than %d at %s", ErrTooLarge, r.maxDepth, p)
	}
	if _, ok := obj[keyEllipsis]; ok {
		return nil, fmt.Errorf("%w: %q in an object that is not an array element placeholder, at %s", ErrReservedName, keyEllipsis, p)
	}
	if _, ok := obj[keySDAlg]; ok && !top {
		return nil, fmt.Errorf("%w: _sd_alg below the top level, at %s", ErrSDAlg, p)
	}
	out := make(map[string]any, len(obj))
	keys := make([]string, 0, len(obj))
	for k := range obj {
		if k != keySD && k != keySDAlg {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys) // deterministic errors
	for _, k := range keys {
		v, err := r.value(obj[k], p.child(k), depth+1)
		if err != nil {
			return nil, err
		}
		out[k] = v
	}

	sd, ok := obj[keySD]
	if !ok {
		return out, nil
	}
	digests, ok := sd.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: _sd is not an array, at %s", ErrMalformed, p)
	}
	for _, item := range digests {
		digest, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%w: _sd holds a non-string, at %s", ErrMalformed, p)
		}
		rd, err := r.match(digest)
		if err != nil {
			return nil, err
		}
		if rd == nil {
			continue // a decoy, or a claim not disclosed
		}
		if rd.d.ArrayElement {
			return nil, fmt.Errorf("%w: 2-item disclosure %s referenced from _sd, at %s", ErrDisclosureShape, digest, p)
		}
		if _, exists := out[rd.d.Name]; exists {
			return nil, fmt.Errorf("%w: %q at %s", ErrClaimExists, rd.d.Name, p)
		}
		cp := p.child(rd.d.Name)
		r.opened[cp.key()] = rd.d
		v, err := r.value(rd.d.Value, cp, depth+1)
		if err != nil {
			return nil, err
		}
		out[rd.d.Name] = v
	}
	return out, nil
}

func (r *recreator) array(arr []any, p Path, depth int) ([]any, error) {
	if depth > r.maxDepth {
		return nil, fmt.Errorf("%w: nesting deeper than %d at %s", ErrTooLarge, r.maxDepth, p)
	}
	out := make([]any, 0, len(arr))
	for _, el := range arr {
		digest, isPlaceholder := placeholder(el)
		if !isPlaceholder {
			v, err := r.value(el, p.child(len(out)), depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}
		rd, err := r.match(digest)
		if err != nil {
			return nil, err
		}
		if rd == nil {
			continue // not disclosed, or a decoy: the element is removed
		}
		if !rd.d.ArrayElement {
			return nil, fmt.Errorf("%w: 3-item disclosure %s referenced from an array element, at %s", ErrDisclosureShape, digest, p)
		}
		cp := p.child(len(out))
		r.opened[cp.key()] = rd.d
		v, err := r.value(rd.d.Value, cp, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// match records digest as seen and returns its disclosure, or nil when none
// was received.
func (r *recreator) match(digest string) (*received, error) {
	if r.seen[digest] {
		return nil, fmt.Errorf("%w: %s", ErrDuplicateDigest, digest)
	}
	r.seen[digest] = true
	rd := r.byDigest[digest]
	if rd != nil {
		rd.used = true
	}
	return rd, nil
}

// placeholder reports whether el is {"...": "<digest>"}, the form of a
// concealed array element (RFC 9901 section 4.2.4.2).
func placeholder(el any) (string, bool) {
	obj, ok := el.(map[string]any)
	if !ok || len(obj) != 1 {
		return "", false
	}
	digest, ok := obj[keyEllipsis].(string)
	return digest, ok
}
