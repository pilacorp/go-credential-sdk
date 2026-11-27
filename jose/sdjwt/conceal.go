// Concealing claims, on the issuer side: RFC 9901 §4.2.4 to §4.2.6.
// Ported from sd-jwt-python (Apache-2.0) at commit c5fda017,
// src/sd_jwt/issuer.py (_create_sd_claims, _create_sd_claims_object,
// _create_sd_claims_list), and eudi-lib-jvm-sdjwt-kt (Apache-2.0) at commit
// 19f408b9, src/main/kotlin/eu/europa/ec/eudi/sdjwt/DecoyGen.kt. See
// jose/NOTICE.

package sdjwt

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"slices"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/internal/errtext"
)

// ConcealOptions tunes Conceal; the zero value adds no decoy digest.
type ConcealOptions struct {
	// MinDigests pads every object's _sd and every array's {"...": digest}
	// placeholders with decoy digests up to MinDigests, in the payload and in
	// every disclosed value (RFC 9901 §4.2.5; §10.4 recommends decoys where
	// the number of claims reveals something). From 0 to 1000, and the
	// objects and arrays of the claims times MinDigests at most 20000.
	MinDigests int
	// NoArrayDecoys keeps decoys out of arrays, so MinDigests pads only the
	// _sd of objects. A receiver cannot tell an array decoy from a hidden
	// element, so a decoy shifts the index of every element after it; a
	// payload whose arrays are addressed by index as at issuance (Type
	// Metadata paths, SD-JWT VC draft 19 §5.6) needs arrays without decoys.
	NoArrayDecoys bool
	// Algorithm is the hash of every digest and the _sd_alg written:
	// AlgSHA256 (the default when empty), AlgSHA384 or AlgSHA512 (§4.1.1).
	Algorithm string
	// Decoys adds Count decoy digests to the object or array at Path after
	// the MinDigests padding (§4.2.5): to the object's _sd, or as array
	// placeholders at uniformly random positions. Path names a value in
	// claims as given, the root being the empty Path; each Path at most once,
	// and never an array when NoArrayDecoys is set. Counts are from 1 to 1000
	// and count towards the same 20000 digests as MinDigests.
	Decoys []Decoy
}

// Decoy is a number of decoy digests for the object or array at a path.
type Decoy struct {
	Path  Path
	Count int
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
//  5. Decoys pad every object and array (only objects with
//     opts.NoArrayDecoys), in the payload and in disclosed values, up to
//     opts.MinDigests; an array counts only its placeholders.
//     opts.Decoys adds decoys at chosen objects and arrays on top.
//     A decoy is base64url(hash(16 random bytes)): §4.2.5 recommends a hash
//     over a cryptographically secure random number.
//  6. Every _sd is sorted (§4.2.4.1: its order must not reveal the claims'
//     order); arrays keep their order, and array decoys go at uniformly random
//     positions, since decoys at the end would mark the placeholders before
//     them as real.
//  7. _sd_alg: opts.Algorithm (sha-256 when empty) is added at the top level
//     when the result holds any digest, decoys included.
//
// Every error a caller can cause wraps jose.ErrInvalidArgument, except an
// Algorithm this package does not implement, which wraps
// jose.ErrUnsupportedAlg; one that names a claim path is a *PathError.
func Conceal(claims map[string]any, paths []Path, opts ConcealOptions) (map[string]any, []Disclosure, error) {
	if opts.MinDigests < 0 || opts.MinDigests > maxMinDigests {
		return nil, nil, fmt.Errorf("%w: sdjwt: MinDigests %d is outside [0, %d]", jose.ErrInvalidArgument, opts.MinDigests, maxMinDigests)
	}
	if len(paths) > maxPaths {
		return nil, nil, fmt.Errorf("%w: sdjwt: %d paths, at most %d", jose.ErrInvalidArgument, len(paths), maxPaths)
	}
	alg := opts.Algorithm
	if alg == "" {
		alg = AlgSHA256
	}
	if !supportedAlg(alg) {
		return nil, nil, fmt.Errorf("%w: sdjwt: hash algorithm %s is not implemented, only %s", jose.ErrUnsupportedAlg, errtext.Quote(alg), quoteNames(supportedAlgs))
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
	decoys, err := decoysByPath(payload, opts.Decoys, containers*opts.MinDigests, opts.NoArrayDecoys)
	if err != nil {
		return nil, nil, err
	}
	for _, p := range paths {
		if err := p.validate(); err != nil {
			return nil, nil, err
		}
		// Checked here, on the claims as given: once concealing starts, an
		// object holds an _sd that a later path such as {"_sd"} would find.
		if _, ok := lookup(payload, p); !ok {
			return nil, nil, pathError(p, "path ", " does not exist in the claims")
		}
	}

	// Deeper paths go first, so no later path runs through a value already
	// concealed, and every lookup below finds the value the caller meant.
	// Sorted, a path given twice sits next to itself.
	order := slices.Clone(paths)
	slices.SortFunc(order, Path.compare)
	for i := 1; i < len(order); i++ {
		if order[i-1].compare(order[i]) == 0 {
			return nil, nil, pathError(order[i], "path ", " given twice")
		}
	}
	c := concealer{minDigests: opts.MinDigests, noArrayDecoys: opts.NoArrayDecoys, alg: alg, decoys: decoys}
	disclosures := make([]Disclosure, 0, len(order))
	for _, p := range order {
		d, err := c.conceal(payload, p)
		if err != nil {
			return nil, nil, err
		}
		disclosures = append(disclosures, d)
	}
	c.finish(payload, decoys)
	// Every path leaves a digest, and MinDigests > 0 pads the top-level object.
	if len(paths) > 0 || opts.MinDigests > 0 || decoys != nil {
		payload[keySDAlg] = alg
	}
	return payload, disclosures, nil
}

type concealer struct {
	minDigests    int
	noArrayDecoys bool
	alg           string
	decoys        *decoyNode // extra decoys by path; nil when none
}

// decoyNode is a trie of decoy paths over the claims as given, so finish
// finds the count at each node in O(1) and never formats a path.
type decoyNode struct {
	count int
	next  map[any]*decoyNode // by path element: string or int
}

// at returns the node for el below n, or nil when no decoy path goes there.
func (n *decoyNode) at(el any) *decoyNode {
	if n == nil {
		return nil
	}
	return n.next[el]
}

// decoysByPath checks opts.Decoys against the claims as given and returns
// their trie, nil when there are none. padded is the MinDigests decoys
// already allowed; noArrayDecoys refuses a path to an array.
func decoysByPath(claims map[string]any, decoys []Decoy, padded int, noArrayDecoys bool) (*decoyNode, error) {
	if len(decoys) == 0 {
		return nil, nil
	}
	root := &decoyNode{}
	total := padded
	for _, d := range decoys {
		if d.Count < 1 || d.Count > maxMinDigests {
			return nil, pathError(d.Path, fmt.Sprintf("%d decoys at ", d.Count), fmt.Sprintf(", from 1 to %d", maxMinDigests))
		}
		if len(d.Path) > 0 {
			if err := d.Path.validate(); err != nil {
				return nil, err
			}
		}
		v, ok := lookup(claims, d.Path)
		if !ok || !nests(v) {
			return nil, pathError(d.Path, "decoy path ", " is not an object or array in the claims")
		}
		if _, isArray := v.([]any); isArray && noArrayDecoys {
			return nil, pathError(d.Path, "decoy path ", " is an array, and NoArrayDecoys is set")
		}
		n := root
		for _, el := range d.Path {
			next := n.next[el]
			if next == nil {
				if n.next == nil {
					n.next = make(map[any]*decoyNode)
				}
				next = &decoyNode{}
				n.next[el] = next
			}
			n = next
		}
		if n.count > 0 {
			return nil, pathError(d.Path, "decoy path ", " given twice")
		}
		if total += d.Count; total > maxDigests {
			return nil, fmt.Errorf("%w: sdjwt: decoys over %d digests", jose.ErrInvalidArgument, maxDigests)
		}
		n.count = d.Count
	}
	return root, nil
}

// While Conceal runs, an object's _sd holds a []string and a concealed array
// element is an arrayDigest; finish turns both into JSON once nothing below
// them will be concealed. checkClaims refuses _sd and ... in the input, so
// neither form can come from the caller.
type arrayDigest string

func (c *concealer) conceal(payload map[string]any, p Path) (Disclosure, error) {
	parent, _ := lookup(payload, p[:len(p)-1])
	value, ok := lookup(parent, p[len(p)-1:])
	// Unreachable: Conceal checked every path exists, conceals the longest
	// first and refuses duplicates, so no earlier path removed this one. It
	// stays an error, not a panic, so a wrong reading refuses one call.
	if !ok {
		return Disclosure{}, pathError(p, "path ", " does not exist in the claims")
	}
	// Every path below p is concealed already: complete value before it is
	// encoded into the disclosure.
	n := c.decoys
	for _, el := range p {
		n = n.at(el)
	}
	value = c.finish(value, n)
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
	d.Digest = digestWith(d.Encoded, c.alg)

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

// finish completes every object and array in v, whose decoy trie node is n
// (nil when no decoy path reaches it): pads it with decoys up to minDigests,
// adds the decoys asked for at n, sorts _sd and writes placeholders as
// {"...": digest}. It returns the completed value, since padding an array
// makes a new slice.
func (c *concealer) finish(v any, n *decoyNode) any {
	var extra int
	if n != nil {
		extra = n.count
	}
	switch t := v.(type) {
	case map[string]any:
		digests, _ := t[keySD].([]string)
		for k, child := range t {
			if k != keySD {
				t[k] = c.finish(child, n.at(k))
			}
		}
		for len(digests) < c.minDigests {
			digests = append(digests, c.decoy())
		}
		for ; extra > 0; extra-- {
			digests = append(digests, c.decoy())
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
			t[i] = c.finish(el, n.at(i))
		}
		want := placeholders
		if !c.noArrayDecoys {
			want = max(want, c.minDigests)
		}
		want += extra
		if k := want - placeholders; k > 0 {
			t = c.withDecoys(t, k)
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

// decoy returns base64url(hash(16 random bytes)) with the concealer's
// algorithm, RFC 9901 §4.2.5.
func (c *concealer) decoy() string {
	b := make([]byte, 16)
	rand.Read(b) // never returns an error since Go 1.24
	return digestWith(string(b), c.alg)
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
				return 0, pathError(p, fmt.Sprintf("claims hold the reserved name %q at ", k), "")
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

// withDecoys returns t with k decoy placeholders at uniformly random
// positions: every arrangement of the decoys among the elements has the same
// chance, as k random inserts would give, in one pass over len(t)+k slots.
func (c *concealer) withDecoys(t []any, k int) []any {
	n := len(t) + k
	// Floyd's algorithm draws k distinct slots out of n.
	slot := make([]bool, n)
	for j := n - k; j < n; j++ {
		r, err := rand.Int(rand.Reader, big.NewInt(int64(j+1)))
		if err != nil {
			// Only a replaced rand.Reader fails, and rand.Read crashes then too.
			panic("sdjwt: crypto/rand: " + err.Error())
		}
		if i := int(r.Int64()); slot[i] {
			slot[j] = true
		} else {
			slot[i] = true
		}
	}
	out := make([]any, 0, n)
	next := 0
	for i := 0; i < n; i++ {
		if slot[i] {
			out = append(out, arrayDigest(c.decoy()))
			continue
		}
		out = append(out, t[next])
		next++
	}
	return out
}
