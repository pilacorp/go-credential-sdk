// Recreating the payload from the disclosures: RFC 9901 §7.1 steps 3 to 5.
// Ported from sd-jwt-python (Apache-2.0) at commit c5fda017,
// src/sd_jwt/verifier.py (_extract_sd_claims, _unpack_disclosed_claims), and
// eudi-lib-jvm-sdjwt-kt (Apache-2.0) at commit 19f408b9,
// src/main/kotlin/eu/europa/ec/eudi/sdjwt/RecreateClaims.kt and
// SdJwtVerifier.kt. See jose/NOTICE.

package sdjwt

import (
	"fmt"
	"slices"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/internal/errtext"
)

// Recreated is the result of Recreate.
type Recreated struct {
	// Claims is the Processed SD-JWT Payload (RFC 9901 §7.1): every disclosed
	// claim in place, every _sd and _sd_alg removed. Its tree is shared with
	// Issued and with every caller, and must not be modified.
	Claims map[string]any
	// issued is the payload as issued, built with Claims; see Issued.
	issued *Node
	// An index of the opened claims and their ancestors, never of the whole
	// payload: steps leads from a node one path element down, opened holds
	// the disclosure that opened the claim at a node. Node 0 is Claims.
	steps  map[step]int
	opened map[int]Disclosure
}

// Node is one value of the payload as the issuer issued it (RFC 9901 §4.2),
// seen from the disclosures received: every element of an array keeps the
// place it had at issuance, a hidden one included, and an object counts the
// digests it holds with no disclosure. A profile that addresses claims as
// issued, such as the claim paths of SD-JWT VC Type Metadata (draft 19
// §5.6), reads the payload through it.
type Node struct {
	// Value is the recreated value at this place, shared with
	// Recreated.Claims, and must not be modified; nil when Hidden.
	Value any
	// Disclosed is true when this value was itself opened from a
	// disclosure; a value inside a disclosed one is not.
	Disclosed bool
	// Hidden is true for an array element {"...": digest} with no
	// disclosure: a decoy or an element not disclosed, which a receiver
	// cannot tell apart.
	Hidden bool
	// Fields holds the claims of an object, those sitting in it and those
	// disclosed, without _sd and _sd_alg; nil when Value is not an object.
	Fields map[string]*Node
	// HiddenFields is the number of digests in the object's _sd with no
	// disclosure, decoys included.
	HiddenFields int
	// Elems holds the elements of an array at their places at issuance;
	// nil when Value is not an array.
	Elems []*Node
}

// Issued returns the top-level object of the payload as issued; nil for a
// nil r. Its values are shared with Claims and must not be modified.
func (r *Recreated) Issued() *Node {
	if r == nil {
		return nil
	}
	return r.issued
}

// step is one path element below node parent.
type step struct {
	parent int
	el     any // string or int
}

// Disclosures returns what a holder must send for a verifier to see the claim
// at path: the disclosure of every concealed ancestor, outermost first, then
// the claim's own if it is concealed (RFC 9901 §4.2.6). It is empty for a
// claim that is neither concealed nor under a concealed claim; ok is false
// when path is not in Claims, or holds an element other than a string or a
// non-negative int (see Path). Array indices count the elements of the
// recreated arrays. Each Disclosure's Value is shared with every other call
// and must not be modified.
func (r *Recreated) Disclosures(path Path) (ds []Disclosure, ok bool) {
	if r == nil || path.validate() != nil {
		return nil, false
	}
	if _, ok := lookup(r.Claims, path); !ok {
		return nil, false
	}
	ds = []Disclosure{}
	node := 0
	for _, el := range path {
		next, ok := r.steps[step{node, el}]
		if !ok {
			break // nothing below is concealed
		}
		node = next
		if d, ok := r.opened[node]; ok {
			ds = append(ds, d)
		}
	}
	return ds, true
}

// Disclosed reports whether the claim at path arrived through a disclosure:
// the claim, one of its ancestors or one of its descendants was opened from
// one (RFC 9901 §4.2). It is false for a nil r, an invalid path and a path not
// in Claims. Array indices count the elements of the recreated arrays. A
// profile that forbids a claim and its sub-claims in disclosures checks it
// with this.
func (r *Recreated) Disclosed(path Path) bool {
	if r == nil || path.validate() != nil {
		return false
	}
	if _, ok := lookup(r.Claims, path); !ok {
		return false
	}
	node := 0
	for _, el := range path {
		next, ok := r.steps[step{node, el}]
		if !ok {
			return false // neither concealed nor under a concealed claim
		}
		node = next
		if _, ok := r.opened[node]; ok {
			return true
		}
	}
	// steps holds only opened nodes and their ancestors, so a node reached
	// without an opened one on the way has an opened descendant.
	return true
}

// Recreate rebuilds the payload from the Issuer-signed JWT payload and the
// disclosures received with it: RFC 9901 §7.1 steps 3 to 5. It does not
// modify payload, which is a JSON tree as jose.DecodeJSONObject yields it
// (map[string]any, []any, json.Number): values of other Go types are kept as
// they are, not walked. Only Encoded of each disclosure is read, so the
// name, value and digest are those of the string received. Every error wraps
// jose.ErrMalformed:
//   - more than 1000 disclosures, or the same disclosure twice (§4);
//   - a top-level _sd_alg other than "sha-256" (§4.1.1, §7.1 step 2d; absent
//     means sha-256), or _sd_alg in any nested object (§4.1.1);
//   - an _sd that is not an array of strings (§4.2.4.1);
//   - a digest in _sd whose disclosure is not [salt, name, value], or whose
//     name is already in the object (§7.1 step 3c.ii);
//   - an array element {"...": digest} whose disclosure is not [salt, value]
//     (§7.1 step 3c.iii);
//   - any other object with a ... key (§4.1 rule 7, §4.2.4.2), such as
//     {"a": {"...": d}} or [{"...": d, "x": 1}];
//   - a digest that appears twice, in the payload or in disclosed values
//     (§7.1 step 4);
//   - a referenced disclosure ParseDisclosure refuses;
//   - a disclosure no digest references (§7.1 step 5), whatever it holds:
//     it is hashed, never parsed, so its cost is its length;
//   - nesting deeper than 32 objects and arrays, disclosed values in place.
//
// A digest with no disclosure is ignored, and an array element it stands for
// is removed (§7.1 steps 3c.i, 3d). An object left empty stays {} (step 3e).
func Recreate(payload map[string]any, disclosures []Disclosure) (*Recreated, error) {
	if len(disclosures) > maxDisclosures {
		return nil, fmt.Errorf("%w: sdjwt: %d disclosures, at most %d", jose.ErrMalformed, len(disclosures), maxDisclosures)
	}
	if alg, ok := payload[keySDAlg]; ok && alg != sdAlgSHA256 {
		// A payload value: its type and a bounded prefix of it, never raw.
		name, _ := alg.(string)
		return nil, fmt.Errorf("%w: sdjwt: _sd_alg %T %s is not supported, only %q", jose.ErrMalformed, alg, errtext.Quote(name), sdAlgSHA256)
	}
	r := recreator{
		byDigest: make(map[string]string, len(disclosures)),
		seen:     map[string]bool{},
		steps:    map[step]int{},
		opened:   map[int]Disclosure{},
	}
	order := make([]string, 0, len(disclosures)) // digests in the order received
	// The digest is over the encoded string (§4.2.3), so duplicates and
	// references are found without a parse; match parses the ones referenced.
	for _, given := range disclosures {
		digest := digestOf(given.Encoded)
		if _, dup := r.byDigest[digest]; dup {
			return nil, fmt.Errorf("%w: sdjwt: disclosure %s given twice", jose.ErrMalformed, digest)
		}
		r.byDigest[digest] = given.Encoded
		order = append(order, digest)
	}

	claims, issued, err := r.object(payload, &at{})
	if err != nil {
		return nil, err
	}
	for _, digest := range order {
		if !r.seen[digest] {
			return nil, fmt.Errorf("%w: sdjwt: no digest references disclosure %s", jose.ErrMalformed, digest)
		}
	}
	return &Recreated{Claims: claims, issued: issued, steps: r.steps, opened: r.opened}, nil
}

type recreator struct {
	byDigest map[string]string // encoded disclosure by digest
	seen     map[string]bool   // every digest met so far
	steps    map[step]int
	opened   map[int]Disclosure
}

// at is the place of a value in the recreated claims, linked to its parent's,
// so a child costs one small allocation whatever the length of the names
// above it. The value at depth d is at nesting level d+1, the payload at 1.
type at struct {
	up    *at
	el    any // string or int; nil for the payload
	depth int
	node  int // node in Recreated.steps; 0 for the payload, -1 until indexed
}

func (a *at) child(el any) *at {
	return &at{up: a, el: el, depth: a.depth + 1, node: -1}
}

// path is a's Path written for error text only, each name cut by
// errtext.Quote: names come from the received payload and disclosures, and
// depth is at most maxDepth, so the text stays bounded.
func (a *at) path() string {
	p := make(Path, a.depth)
	for n := a; n.up != nil; n = n.up {
		p[n.depth-1] = n.el
	}
	return p.format(errtext.Quote)
}

// index adds a and its ancestors not yet indexed to steps and returns a's
// node. Each place is indexed once, so the index costs O(input).
func (r *recreator) index(a *at) int {
	if a.node < 0 {
		parent := r.index(a.up)
		a.node = len(r.steps) + 1
		r.steps[step{parent, a.el}] = a.node
	}
	return a.node
}

// value, object and array return the recreated value and its Node as issued.
func (r *recreator) value(v any, a *at) (any, *Node, error) {
	if a.depth+1 > maxDepth && nests(v) {
		return nil, nil, fmt.Errorf("%w: sdjwt: nesting deeper than %d at %s", jose.ErrMalformed, maxDepth, a.path())
	}
	switch t := v.(type) {
	case map[string]any:
		return r.object(t, a)
	case []any:
		return r.array(t, a)
	default:
		return v, &Node{Value: v}, nil
	}
}

func (r *recreator) object(obj map[string]any, a *at) (map[string]any, *Node, error) {
	// Placeholders are handled by array before they get here.
	if _, ok := obj[keyEllipsis]; ok {
		return nil, nil, fmt.Errorf("%w: sdjwt: %q at %s is not an array element placeholder", jose.ErrMalformed, keyEllipsis, a.path())
	}
	if _, ok := obj[keySDAlg]; ok && a.depth > 0 {
		return nil, nil, fmt.Errorf("%w: sdjwt: _sd_alg below the top level, at %s", jose.ErrMalformed, a.path())
	}
	out := make(map[string]any, len(obj))
	node := &Node{Value: out, Fields: make(map[string]*Node, len(obj))}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		if k != keySD && k != keySDAlg {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys) // the same input fails with the same error
	for _, k := range keys {
		v, n, err := r.value(obj[k], a.child(k))
		if err != nil {
			return nil, nil, err
		}
		out[k] = v
		node.Fields[k] = n
	}

	sd, ok := obj[keySD]
	if !ok {
		return out, node, nil
	}
	digests, ok := sd.([]any)
	if !ok {
		return nil, nil, fmt.Errorf("%w: sdjwt: _sd at %s is not an array", jose.ErrMalformed, a.path())
	}
	for _, item := range digests {
		digest, ok := item.(string)
		if !ok {
			return nil, nil, fmt.Errorf("%w: sdjwt: _sd at %s holds a %T, not a string", jose.ErrMalformed, a.path(), item)
		}
		d, ok, err := r.match(digest)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			node.HiddenFields++ // a decoy, or a claim not disclosed
			continue
		}
		if d.ArrayElement {
			return nil, nil, fmt.Errorf("%w: sdjwt: _sd at %s references the array element disclosure %s", jose.ErrMalformed, a.path(), digest)
		}
		if _, exists := out[d.Name]; exists {
			return nil, nil, fmt.Errorf("%w: sdjwt: disclosure %s repeats the claim %s at %s", jose.ErrMalformed, digest, errtext.Quote(d.Name), a.path())
		}
		ca := a.child(d.Name)
		r.opened[r.index(ca)] = d
		v, n, err := r.value(d.Value, ca)
		if err != nil {
			return nil, nil, err
		}
		n.Disclosed = true
		out[d.Name] = v
		node.Fields[d.Name] = n
	}
	return out, node, nil
}

func (r *recreator) array(arr []any, a *at) ([]any, *Node, error) {
	out := make([]any, 0, len(arr))
	node := &Node{Elems: make([]*Node, 0, len(arr))}
	for _, el := range arr {
		digest, isPlaceholder := placeholder(el)
		if !isPlaceholder {
			v, n, err := r.value(el, a.child(len(out)))
			if err != nil {
				return nil, nil, err
			}
			out = append(out, v)
			node.Elems = append(node.Elems, n)
			continue
		}
		d, ok, err := r.match(digest)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			// A decoy, or an element not disclosed: removed from Claims,
			// kept in its place as issued.
			node.Elems = append(node.Elems, &Node{Hidden: true})
			continue
		}
		if !d.ArrayElement {
			return nil, nil, fmt.Errorf("%w: sdjwt: array element at %s references the object property disclosure %s", jose.ErrMalformed, a.path(), digest)
		}
		ca := a.child(len(out))
		r.opened[r.index(ca)] = d
		v, n, err := r.value(d.Value, ca)
		if err != nil {
			return nil, nil, err
		}
		n.Disclosed = true
		out = append(out, v)
		node.Elems = append(node.Elems, n)
	}
	node.Value = out
	return out, node, nil
}

// match records digest as seen and returns its disclosure, parsed only now;
// ok is false when none was received.
func (r *recreator) match(digest string) (d Disclosure, ok bool, err error) {
	if r.seen[digest] {
		// Any payload string can sit here: quoted, and cut at 64 characters,
		// which a real digest (43) never reaches.
		return Disclosure{}, false, fmt.Errorf("%w: sdjwt: digest %.64q appears more than once", jose.ErrMalformed, digest)
	}
	r.seen[digest] = true
	encoded, ok := r.byDigest[digest]
	if !ok {
		return Disclosure{}, false, nil
	}
	d, err = ParseDisclosure(encoded)
	if err != nil {
		return Disclosure{}, false, err
	}
	return d, true, nil
}

// placeholder reports whether el is {"...": "<digest>"}, an array element
// with exactly one key ... holding a string (RFC 9901 §4.2.4.2, §7.1 step
// 3b.ii).
func placeholder(el any) (string, bool) {
	obj, ok := el.(map[string]any)
	if !ok || len(obj) != 1 {
		return "", false
	}
	digest, ok := obj[keyEllipsis].(string)
	return digest, ok
}
