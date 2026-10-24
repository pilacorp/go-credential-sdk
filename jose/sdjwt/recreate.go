// Ported from sd-jwt-python (Apache-2.0), src/sd_jwt/verifier.py
// (_extract_sd_claims, _unpack_disclosed_claims), and eudi-lib-jvm-sdjwt-kt
// (Apache-2.0), src/main/kotlin/eu/europa/ec/eudi/sdjwt/RecreateClaims.kt
// and SdJwtVerifier.kt. See jose/NOTICE.

package sdjwt

import (
	"fmt"
	"slices"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// Recreated is the result of Recreate.
type Recreated struct {
	// Claims is the Processed SD-JWT Payload (RFC 9901 §7.1): every disclosed
	// claim in place, every _sd and _sd_alg removed.
	Claims map[string]any
	opened map[string]Disclosure // Path.key → the disclosure that opened the claim there
}

// Disclosures returns what a holder must send for a verifier to see the claim
// at path: the disclosure of every concealed ancestor, outermost first, then
// the claim's own if it is concealed (RFC 9901 §4.2.6). It is empty for a
// claim that is neither concealed nor under a concealed claim; ok is false
// when path is not in Claims. Array indices count the elements of the
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
	for i := 1; i <= len(path); i++ {
		if d, ok := r.opened[path[:i].key()]; ok {
			ds = append(ds, d)
		}
	}
	return ds, true
}

// Recreate rebuilds the payload from the Issuer-signed JWT payload and the
// disclosures received with it: RFC 9901 §7.1 steps 3 to 5. It does not
// modify payload. Only Encoded of each disclosure is read, so the name, value
// and digest are those of the string received. Every error wraps
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
//   - a disclosure no digest references (§7.1 step 5);
//   - nesting deeper than 32 objects and arrays, disclosed values in place.
//
// A digest with no disclosure is ignored, and an array element it stands for
// is removed (§7.1 steps 3c.i, 3d). An object left empty stays {} (step 3e).
func Recreate(payload map[string]any, disclosures []Disclosure) (*Recreated, error) {
	if len(disclosures) > maxDisclosures {
		return nil, fmt.Errorf("%w: sdjwt: %d disclosures, at most %d", jose.ErrMalformed, len(disclosures), maxDisclosures)
	}
	if alg, ok := payload[keySDAlg]; ok && alg != sdAlgSHA256 {
		return nil, fmt.Errorf("%w: sdjwt: _sd_alg %v is not supported, only %q", jose.ErrMalformed, alg, sdAlgSHA256)
	}
	r := recreator{
		byDigest: make(map[string]Disclosure, len(disclosures)),
		seen:     map[string]bool{},
		opened:   map[string]Disclosure{},
	}
	order := make([]string, 0, len(disclosures)) // digests in the order received
	for _, given := range disclosures {
		d, err := ParseDisclosure(given.Encoded)
		if err != nil {
			return nil, err
		}
		if _, dup := r.byDigest[d.Digest]; dup {
			return nil, fmt.Errorf("%w: sdjwt: disclosure %s given twice", jose.ErrMalformed, d.Digest)
		}
		r.byDigest[d.Digest] = d
		order = append(order, d.Digest)
	}

	claims, err := r.object(payload, nil)
	if err != nil {
		return nil, err
	}
	for _, digest := range order {
		if !r.seen[digest] {
			return nil, fmt.Errorf("%w: sdjwt: no digest references disclosure %s", jose.ErrMalformed, digest)
		}
	}
	return &Recreated{Claims: claims, opened: r.opened}, nil
}

// The value at path p is at nesting level len(p)+1, the payload at level 1.
type recreator struct {
	byDigest map[string]Disclosure
	seen     map[string]bool // every digest met so far
	opened   map[string]Disclosure
}

func (r *recreator) value(v any, p Path) (any, error) {
	if len(p)+1 > maxDepth && nests(v) {
		return nil, fmt.Errorf("%w: sdjwt: nesting deeper than %d at %s", jose.ErrMalformed, maxDepth, p)
	}
	switch t := v.(type) {
	case map[string]any:
		return r.object(t, p)
	case []any:
		return r.array(t, p)
	default:
		return v, nil
	}
}

func (r *recreator) object(obj map[string]any, p Path) (map[string]any, error) {
	// Placeholders are handled by array before they get here.
	if _, ok := obj[keyEllipsis]; ok {
		return nil, fmt.Errorf("%w: sdjwt: %q at %s is not an array element placeholder", jose.ErrMalformed, keyEllipsis, p)
	}
	if _, ok := obj[keySDAlg]; ok && len(p) > 0 {
		return nil, fmt.Errorf("%w: sdjwt: _sd_alg below the top level, at %s", jose.ErrMalformed, p)
	}
	out := make(map[string]any, len(obj))
	keys := make([]string, 0, len(obj))
	for k := range obj {
		if k != keySD && k != keySDAlg {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys) // the same input fails with the same error
	for _, k := range keys {
		v, err := r.value(obj[k], p.child(k))
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
		return nil, fmt.Errorf("%w: sdjwt: _sd at %s is not an array", jose.ErrMalformed, p)
	}
	for _, item := range digests {
		digest, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%w: sdjwt: _sd at %s holds a %T, not a string", jose.ErrMalformed, p, item)
		}
		d, ok, err := r.match(digest)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue // a decoy, or a claim not disclosed
		}
		if d.ArrayElement {
			return nil, fmt.Errorf("%w: sdjwt: _sd at %s references the array element disclosure %s", jose.ErrMalformed, p, digest)
		}
		if _, exists := out[d.Name]; exists {
			return nil, fmt.Errorf("%w: sdjwt: disclosure %s repeats the claim %q at %s", jose.ErrMalformed, digest, d.Name, p)
		}
		cp := p.child(d.Name)
		r.opened[cp.key()] = d
		v, err := r.value(d.Value, cp)
		if err != nil {
			return nil, err
		}
		out[d.Name] = v
	}
	return out, nil
}

func (r *recreator) array(arr []any, p Path) ([]any, error) {
	out := make([]any, 0, len(arr))
	for _, el := range arr {
		digest, isPlaceholder := placeholder(el)
		if !isPlaceholder {
			v, err := r.value(el, p.child(len(out)))
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}
		d, ok, err := r.match(digest)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue // a decoy, or an element not disclosed: removed
		}
		if !d.ArrayElement {
			return nil, fmt.Errorf("%w: sdjwt: array element at %s references the object property disclosure %s", jose.ErrMalformed, p, digest)
		}
		cp := p.child(len(out))
		r.opened[cp.key()] = d
		v, err := r.value(d.Value, cp)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// match records digest as seen and returns its disclosure; ok is false when
// none was received.
func (r *recreator) match(digest string) (d Disclosure, ok bool, err error) {
	if r.seen[digest] {
		return Disclosure{}, false, fmt.Errorf("%w: sdjwt: digest %s appears more than once", jose.ErrMalformed, digest)
	}
	r.seen[digest] = true
	d, ok = r.byDigest[digest]
	return d, ok, nil
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
