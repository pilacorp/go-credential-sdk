// Ported from sd-jwt-python (Apache-2.0), src/sd_jwt/issuer.py
// (_create_sd_claims, _create_sd_claims_object, _create_sd_claims_list), and
// eudi-lib-jvm-sdjwt-kt (Apache-2.0), src/main/kotlin/eu/europa/ec/eudi/sdjwt/
// DecoyGen.kt. See jose/NOTICE.

package sdjwt

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"slices"
	"sort"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// SaltProvider returns the salt for the disclosure of the claim at path. The
// default draws 16 random bytes and encodes them as base64url. Every salt of
// one Conceal call must be non-empty and unique.
type SaltProvider func(path Path) (string, error)

// ConcealOptions tunes Conceal; the zero value is what an issuer wants.
type ConcealOptions struct {
	// Decoys is the number of decoy digests added to every _sd array (not to
	// arrays). Default 0.
	Decoys int
	// Salts gives the salt of each disclosure. Default: 16 random bytes.
	Salts SaltProvider
	// Encode turns [salt, name, value] or [salt, value] into the JSON that is
	// base64url-encoded. Default jose.EncodeJSON: compact, no HTML escaping,
	// UTF-8 kept. Tests replace it to reproduce another library byte for byte.
	Encode func(disclosure []any) ([]byte, error)
}

// Conceal makes the claims at paths selectively disclosable (issuer side) and
// returns the SD-JWT payload and the disclosures, in the order they were
// created:
//  1. claims is normalised through JSON (jose.EncodeJSON, jose.DecodeJSON), so
//     any JSON-encodable Go value works and the caller's map is never
//     modified; it must not contain _sd, _sd_alg or ... at any depth;
//  2. every path must exist and walk the right types (string through an
//     object, int through an array); a path given twice is an error;
//  3. paths are processed deepest first, so a child concealed together with
//     its parent ends up inside the parent's disclosure; input order does not
//     matter;
//  4. an object property becomes [salt, name, value], is removed and its
//     digest appended to that object's _sd; an array element becomes
//     [salt, value] and is replaced by {"...": digest}, other positions
//     unchanged;
//  5. opts.Decoys random digests (base64url(SHA-256(32 random bytes))) are
//     added to every _sd array, then every _sd array is sorted, so its order
//     does not reveal the original order of the claims (RFC 9901 section
//     4.2.4.1);
//  6. _sd_alg: "sha-256" is added at the top level.
func Conceal(claims map[string]any, paths []Path, opts ConcealOptions) (map[string]any, []Disclosure, error) {
	if opts.Decoys < 0 {
		return nil, nil, fmt.Errorf("sdjwt: negative number of decoys")
	}
	c := concealer{decoys: opts.Decoys, salts: opts.Salts, encode: opts.Encode, used: map[string]bool{}}
	if c.salts == nil {
		c.salts = randomSalt
	}
	if c.encode == nil {
		c.encode = func(d []any) ([]byte, error) { return jose.EncodeJSON(d) }
	}

	payload, err := normalise(claims)
	if err != nil {
		return nil, nil, err
	}
	if err := checkNoReservedNames(payload, nil); err != nil {
		return nil, nil, err
	}
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		if err := p.validate(); err != nil {
			return nil, nil, err
		}
		if seen[p.key()] {
			return nil, nil, fmt.Errorf("%w: %s given twice", ErrInvalidPath, p)
		}
		seen[p.key()] = true
		if _, ok := lookup(payload, p); !ok {
			return nil, nil, fmt.Errorf("%w: %s does not exist in the claims", ErrInvalidPath, p)
		}
	}

	order := slices.Clone(paths)
	sort.SliceStable(order, func(i, j int) bool {
		if len(order[i]) != len(order[j]) {
			return len(order[i]) > len(order[j])
		}
		return order[i].key() < order[j].key()
	})
	disclosures := make([]Disclosure, 0, len(order))
	for _, p := range order {
		d, err := c.conceal(payload, p)
		if err != nil {
			return nil, nil, err
		}
		disclosures = append(disclosures, d)
	}
	if err := c.finish(payload); err != nil {
		return nil, nil, err
	}
	payload[keySDAlg] = sdAlgSHA256
	return payload, disclosures, nil
}

type concealer struct {
	decoys int
	salts  SaltProvider
	encode func([]any) ([]byte, error)
	used   map[string]bool // salts handed out so far
}

// digestList collects the digests of one object's _sd while Conceal runs;
// finish turns it into the sorted []any that is signed. Input claims never
// hold _sd, so an _sd member of this type is always one Conceal made.
type digestList struct{ digests []string }

func (c *concealer) conceal(payload map[string]any, p Path) (Disclosure, error) {
	parent, ok := lookup(payload, p[:len(p)-1])
	if !ok {
		return Disclosure{}, fmt.Errorf("%w: %s does not exist in the claims", ErrInvalidPath, p)
	}
	value, _ := lookup(parent, p[len(p)-1:])
	// Children were concealed first; their _sd arrays are complete now.
	if err := c.finish(value); err != nil {
		return Disclosure{}, err
	}
	salt, err := c.salts(p)
	if err != nil {
		return Disclosure{}, fmt.Errorf("sdjwt: salt for %s: %w", p, err)
	}
	if salt == "" || c.used[salt] {
		return Disclosure{}, fmt.Errorf("%w: salt for %s is empty or already used", ErrSalt, p)
	}
	c.used[salt] = true

	d := Disclosure{Salt: salt, Value: value}
	var items []any
	switch k := p[len(p)-1].(type) {
	case string:
		d.Name = k
		items = []any{salt, k, value}
	case int:
		d.ArrayElement = true
		items = []any{salt, value}
	}
	raw, err := c.encode(items)
	if err != nil {
		return Disclosure{}, fmt.Errorf("sdjwt: encode disclosure for %s: %w", p, err)
	}
	d.Encoded = jose.EncodeSegment(raw)
	d.Digest = digestOf(d.Encoded)

	switch container := parent.(type) {
	case map[string]any:
		delete(container, d.Name)
		list, _ := container[keySD].(*digestList)
		if list == nil {
			list = &digestList{}
			container[keySD] = list
		}
		list.digests = append(list.digests, d.Digest)
	case []any:
		container[p[len(p)-1].(int)] = map[string]any{keyEllipsis: d.Digest}
	}
	return d, nil
}

// finish completes every _sd array under v that is still being collected:
// adds the decoys and sorts it.
func (c *concealer) finish(v any) error {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			list, ok := child.(*digestList)
			if !ok || k != keySD {
				if err := c.finish(child); err != nil {
					return err
				}
				continue
			}
			for range c.decoys {
				d, err := decoyDigest()
				if err != nil {
					return err
				}
				list.digests = append(list.digests, d)
			}
			sort.Strings(list.digests)
			out := make([]any, len(list.digests))
			for i, d := range list.digests {
				out[i] = d
			}
			t[keySD] = out
		}
	case []any:
		for _, child := range t {
			if err := c.finish(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func normalise(claims map[string]any) (map[string]any, error) {
	if claims == nil {
		return map[string]any{}, nil
	}
	raw, err := jose.EncodeJSON(claims)
	if err != nil {
		return nil, fmt.Errorf("sdjwt: claims are not JSON: %w", err)
	}
	return jose.DecodeJSONObject(raw)
}

func checkNoReservedNames(v any, p Path) error {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if k == keySD || k == keySDAlg || k == keyEllipsis {
				return fmt.Errorf("%w: claims contain %q at %s", ErrReservedName, k, p.child(k))
			}
			if err := checkNoReservedNames(child, p.child(k)); err != nil {
				return err
			}
		}
	case []any:
		for i, child := range t {
			if err := checkNoReservedNames(child, p.child(i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func randomSalt(Path) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return jose.EncodeSegment(b), nil
}

func decoyDigest() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return jose.EncodeSegment(sum[:]), nil
}
