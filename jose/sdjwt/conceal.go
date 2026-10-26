// Ported from sd-jwt-python (Apache-2.0), src/sd_jwt/issuer.py
// (_create_sd_claims, _create_sd_claims_object, _create_sd_claims_list), and
// eudi-lib-jvm-sdjwt-kt (Apache-2.0), src/main/kotlin/eu/europa/ec/eudi/sdjwt/
// DecoyGen.kt. See jose/NOTICE.

package sdjwt

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"slices"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// ConcealOptions tunes Conceal; the zero value adds no decoy digest.
type ConcealOptions struct {
	// MinDigests pads every object's _sd and every array's {"...": digest}
	// placeholders with decoy digests up to MinDigests, in the payload and in
	// every disclosed value (RFC 9901 §4.2.5; §10.4 recommends decoys where
	// the number of claims reveals something). From 0 to 1000, and the
	// objects and arrays of the claims times MinDigests at most 20000.
	MinDigests int
}

// Conceal makes the claims at paths selectively disclosable (issuer side). It
// returns the SD-JWT payload and the disclosures, in the order to write them
// in the compact SD-JWT: deeper paths first, then by path, element by element
// (a name before an index, names by bytes, indices by value).
//
//  1. claims is copied through JSON (jose.EncodeJSON, jose.DecodeJSON), so
//     any JSON-encodable Go value works, numbers come back as json.Number,
//     nesting is at most jose.MaxJSONDepth, and the caller's map is never
//     modified.
//  2. claims must not hold _sd or ... at any depth (§4.1 rule 7), nor
//     _sd_alg: §4.1.1 forbids it below the top level, and Conceal writes the
//     top-level one itself, so a caller's value would conflict. At most 1000
//     paths; every path must exist and be given once. The objects and arrays
//     of claims times opts.MinDigests must be at most 20000, which bounds the
//     decoys of step 5; this is checked before any salt or decoy is made.
//  3. Paths are processed deepest first, so a claim concealed together with
//     its parent ends up inside the parent's disclosure (§4.2.6).
//  4. An object property becomes [salt, name, value] (§4.2.1), is removed,
//     and its digest goes into that object's _sd (§4.2.4.1). An array element
//     becomes [salt, value] (§4.2.2) and is replaced in place by
//     {"...": digest} (§4.2.4.2). Salts are 16 random bytes (§9.3 RECOMMENDS
//     at least 128 bits), base64url-encoded; disclosure JSON is compact,
//     without HTML escaping, UTF-8 kept.
//  5. Decoys pad every object and array, in the payload and in disclosed
//     values, up to opts.MinDigests; an array counts only its placeholders.
//     A decoy is base64url(SHA-256(16 random bytes)) (§4.2.5).
//  6. Every _sd is sorted (§4.2.4.1: its order must not reveal the claims'
//     order); arrays keep their order, and array decoys go at uniformly random
//     positions, since decoys at the end would mark the placeholders before
//     them as real.
//  7. _sd_alg: "sha-256" is added at the top level when the result holds any
//     digest, decoys included.
//
// Every error a caller can cause wraps jose.ErrInvalidArgument.
func Conceal(claims map[string]any, paths []Path, opts ConcealOptions) (map[string]any, []Disclosure, error) {
	if opts.MinDigests < 0 || opts.MinDigests > maxMinDigests {
		return nil, nil, fmt.Errorf("%w: sdjwt: MinDigests %d is outside [0, %d]", jose.ErrInvalidArgument, opts.MinDigests, maxMinDigests)
	}
	if len(paths) > maxPaths {
		return nil, nil, fmt.Errorf("%w: sdjwt: %d paths, at most %d", jose.ErrInvalidArgument, len(paths), maxPaths)
	}
	payload, err := copyClaims(claims)
	if err != nil {
		return nil, nil, err
	}
	containers, err := checkClaims(payload, nil)
	if err != nil {
		return nil, nil, err
	}
	// Step 5 pads every object and array up to MinDigests.
	if opts.MinDigests > 0 && containers > maxDigests/opts.MinDigests {
		return nil, nil, fmt.Errorf("%w: sdjwt: %d objects and arrays × MinDigests %d is over %d digests", jose.ErrInvalidArgument, containers, opts.MinDigests, maxDigests)
	}
	for _, p := range paths {
		if err := p.validate(); err != nil {
			return nil, nil, err
		}
		// Checked here, on the claims as given: once concealing starts, an
		// object holds an _sd that a later path such as {"_sd"} would find.
		if _, ok := lookup(payload, p); !ok {
			return nil, nil, fmt.Errorf("%w: sdjwt: path %s does not exist in the claims", jose.ErrInvalidArgument, p)
		}
	}

	// Deeper paths go first, so no later path runs through a value already
	// concealed, and every lookup below finds the value the caller meant.
	// Sorted, a path given twice sits next to itself.
	order := slices.Clone(paths)
	slices.SortFunc(order, Path.compare)
	for i := 1; i < len(order); i++ {
		if order[i-1].compare(order[i]) == 0 {
			return nil, nil, fmt.Errorf("%w: sdjwt: path %s given twice", jose.ErrInvalidArgument, order[i])
		}
	}
	c := concealer{minDigests: opts.MinDigests}
	disclosures := make([]Disclosure, 0, len(order))
	for _, p := range order {
		d, err := c.conceal(payload, p)
		if err != nil {
			return nil, nil, err
		}
		disclosures = append(disclosures, d)
	}
	c.finish(payload)
	// Every path leaves a digest, and MinDigests > 0 pads the top-level object.
	if len(paths) > 0 || opts.MinDigests > 0 {
		payload[keySDAlg] = sdAlgSHA256
	}
	return payload, disclosures, nil
}

type concealer struct {
	minDigests int
}

// While Conceal runs, an object's _sd holds a []string and a concealed array
// element is an arrayDigest; finish turns both into JSON once nothing below
// them will be concealed. checkClaims refuses _sd and ... in the input, so
// neither form can come from the caller.
type arrayDigest string

func (c *concealer) conceal(payload map[string]any, p Path) (Disclosure, error) {
	parent, _ := lookup(payload, p[:len(p)-1])
	value, ok := lookup(parent, p[len(p)-1:])
	if !ok {
		return Disclosure{}, fmt.Errorf("%w: sdjwt: path %s does not exist in the claims", jose.ErrInvalidArgument, p)
	}
	// Every path below p is concealed already: complete value before it is
	// encoded into the disclosure.
	value = c.finish(value)
	salt := newSalt()
	d := Disclosure{Salt: salt, Value: value}
	items := []any{salt, value}
	if name, ok := p[len(p)-1].(string); ok {
		d.Name = name
		items = []any{salt, name, value}
	} else {
		d.ArrayElement = true
	}
	raw, err := jose.EncodeJSON(items)
	if err != nil {
		return Disclosure{}, fmt.Errorf("sdjwt: disclosure for %s: %w", p, err)
	}
	d.Encoded = jose.EncodeSegment(raw)
	d.Digest = digestOf(d.Encoded)

	switch container := parent.(type) {
	case map[string]any:
		delete(container, d.Name)
		digests, _ := container[keySD].([]string)
		container[keySD] = append(digests, d.Digest)
	case []any:
		container[p[len(p)-1].(int)] = arrayDigest(d.Digest)
	}
	return d, nil
}

// finish completes every object and array in v: pads it with decoys up to
// minDigests, sorts _sd and writes placeholders as {"...": digest}. It returns
// the completed value, since padding an array makes a new slice.
func (c *concealer) finish(v any) any {
	switch t := v.(type) {
	case map[string]any:
		digests, _ := t[keySD].([]string)
		for k, child := range t {
			if k != keySD {
				t[k] = c.finish(child)
			}
		}
		for len(digests) < c.minDigests {
			digests = append(digests, decoy())
		}
		if len(digests) == 0 {
			return t
		}
		slices.Sort(digests)
		sd := make([]any, len(digests))
		for i, d := range digests {
			sd[i] = d
		}
		t[keySD] = sd
		return t
	case []any:
		placeholders := 0
		for i, el := range t {
			if _, ok := el.(arrayDigest); ok {
				placeholders++
				continue
			}
			t[i] = c.finish(el)
		}
		// Inserting each decoy at a uniformly random index among len(t)+1
		// gives every arrangement of decoys among the elements the same chance.
		for ; placeholders < c.minDigests; placeholders++ {
			i, err := rand.Int(rand.Reader, big.NewInt(int64(len(t)+1)))
			if err != nil {
				// Only a replaced rand.Reader fails, and rand.Read crashes then too.
				panic("sdjwt: crypto/rand: " + err.Error())
			}
			t = slices.Insert(t, int(i.Int64()), any(arrayDigest(decoy())))
		}
		for i, el := range t {
			if d, ok := el.(arrayDigest); ok {
				t[i] = map[string]any{keyEllipsis: string(d)}
			}
		}
		return t
	default:
		return v
	}
}

// decoy returns base64url(SHA-256(16 random bytes)), RFC 9901 §4.2.5.
func decoy() string {
	b := make([]byte, 16)
	rand.Read(b) // never returns an error since Go 1.24
	sum := sha256.Sum256(b)
	return jose.EncodeSegment(sum[:])
}

// newSalt returns 16 random bytes as base64url (RFC 9901 §4.2.1; §9.3
// RECOMMENDS at least 128 bits).
func newSalt() string {
	b := make([]byte, 16)
	rand.Read(b) // never returns an error since Go 1.24
	return jose.EncodeSegment(b)
}

func copyClaims(claims map[string]any) (map[string]any, error) {
	if claims == nil {
		return map[string]any{}, nil
	}
	raw, err := jose.EncodeJSON(claims)
	if err != nil {
		return nil, fmt.Errorf("sdjwt: claims: %w", err)
	}
	obj, err := jose.DecodeJSONObject(raw)
	if err != nil {
		// The JSON is valid, but DecodeJSON also refuses nesting past
		// jose.MaxJSONDepth and duplicate keys a json.Marshaler wrote.
		return nil, fmt.Errorf("%w: sdjwt: claims: %v", jose.ErrInvalidArgument, err)
	}
	return obj, nil
}

// checkClaims refuses reserved names and counts the objects and arrays in v,
// v included.
func checkClaims(v any, p Path) (containers int, err error) {
	switch t := v.(type) {
	case map[string]any:
		containers = 1
		for k, child := range t {
			if reserved(k) {
				return 0, fmt.Errorf("%w: sdjwt: claims hold the reserved name %q at %s", jose.ErrInvalidArgument, k, p)
			}
			n, err := checkClaims(child, p.child(k))
			if err != nil {
				return 0, err
			}
			containers += n
		}
	case []any:
		containers = 1
		for i, child := range t {
			n, err := checkClaims(child, p.child(i))
			if err != nil {
				return 0, err
			}
			containers += n
		}
	}
	return containers, nil
}
