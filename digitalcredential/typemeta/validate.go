// Claim metadata validation: draft-ietf-oauth-sd-jwt-vc-19 §5.6, §5.6.1.2,
// §5.6.3 and §5.6.4, on the payload as issued.

package typemeta

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

// ValidateOptions tunes ValidateClaims to what the caller holds.
type ValidateOptions struct {
	// AllDisclosures says the caller holds every disclosure the issuer
	// issued, as the Holder does when it receives the credential. A digest
	// with no disclosure can then only be a decoy, which is no element of
	// the payload (RFC 9901 §4.2.5): hidden array elements are left out
	// before indexes are counted, and an object's undisclosed digests are
	// not counted, so a missing mandatory claim is seen as §5.6 says a
	// Holder with all Disclosures sees it. A Verifier never sets it (§5.6).
	AllDisclosures bool
}

// ValidateClaims checks issued, the payload as issued (sdjwt
// Recreated.Issued), against the claim metadata of m (draft 19 §5.6). Each
// Claim's path is processed as §5.6.1.2 says, counting array elements as
// issued; an element not disclosed is selected, but path components after it
// select nothing (§5.6). It then fails when:
//   - a path component is a string and a selected value is not an object, or
//     null or an index and a selected value is not an array (§5.6.1.2);
//   - mandatory is true and the claim is certainly not in the credential: a
//     key is missing from an object holding no undisclosed digest, or an
//     index is beyond an array (§5.6.3); while a digest is still unopened the
//     claim may be in it, and a Verifier must not count it missing (§5.6);
//   - sd is always and a selected claim is not itself a disclosure, or sd is
//     never and it is (§5.6.4).
//
// A claim no Claim selects is not checked. Errors wrap ErrViolated and name
// the Claim's path, never a claim value; a nil or zero m, or a nil issued, is
// jose.ErrInvalidArgument. A check that needs more than 1<<20 units, one per
// payload value read and one more per 64 bytes of a key looked up, summed
// over every Claim, stops with an error wrapping ErrClaims: claim metadata
// the SDK cannot process, which §5.7 rejects.
//
// §5.6 counts array elements as issued, and a decoy (RFC 9901 §4.2.5) is
// none, but a Verifier cannot tell a decoy from an undisclosed element:
// without AllDisclosures every undisclosed array entry counts as an element.
// For a credential whose issuer put decoys in an array a path selects, this
// check and the Holder's (AllDisclosures) can differ in either direction.
// dc.Issue with TypeMetadata adds no array decoys.
func (m *Metadata) ValidateClaims(issued *sdjwt.Node, opts ValidateOptions) error {
	if m == nil || m.vct == "" {
		return fmt.Errorf("%w: typemeta: ValidateClaims needs a Metadata made by Load", jose.ErrInvalidArgument)
	}
	if issued == nil {
		return fmt.Errorf("%w: typemeta: ValidateClaims of a nil payload", jose.ErrInvalidArgument)
	}
	budget := maxClaimVisits
	for i, c := range m.claims {
		err := c.check(issued, opts.AllDisclosures, &budget)
		if errors.Is(err, errBudget) {
			return fmt.Errorf("%w: typemeta: checking the payload against the claim metadata needs over %d units (one per value read, one more per 64 bytes of a key), the SDK's limit; smaller arrays, fewer claims over them or shorter keys in the claim metadata fit (draft-ietf-oauth-sd-jwt-vc-19 §5.7)", ErrClaims, maxClaimVisits)
		}
		if err != nil {
			return fmt.Errorf("%w: typemeta: claims[%d] with path %s: %v (draft-ietf-oauth-sd-jwt-vc-19 §5.6)", ErrViolated, i, formatPath(c.Path), err)
		}
	}
	return nil
}

// ValidateIssuance checks payload, the claims an issuer is about to sign with
// nothing concealed yet, as ValidateClaims with AllDisclosures checks the
// credential it becomes: each path in disclose is made a disclosure, the
// rest stays in the clear. Each path must be non-empty, of strings and
// non-negative ints, and name a claim in payload; otherwise the error is
// jose.ErrInvalidArgument. Violations wrap ErrViolated.
//
// An issuer checks by passing TypeMetadata to dc.Issue, which calls it on
// the payload it signs. Calling it and then dc.Issue without TypeMetadata is
// not the same: only with TypeMetadata does Issue add no decoys to arrays,
// which would move the indexes §5.6 counts.
//
// payload holds values as jose.DecodeJSON returns them: objects as
// map[string]any, arrays as []any, and a tree: no container is reachable
// twice, by a cycle or by sharing; dc.Issue passes such a copy. Any other Go container, such as []string or
// map[string]string, is read as one value and not walked.
func (m *Metadata) ValidateIssuance(payload map[string]any, disclose []sdjwt.Path) error {
	if m == nil || m.vct == "" {
		return fmt.Errorf("%w: typemeta: ValidateIssuance needs a Metadata made by Load", jose.ErrInvalidArgument)
	}
	if payload == nil {
		return fmt.Errorf("%w: typemeta: ValidateIssuance of a nil payload", jose.ErrInvalidArgument)
	}
	root := issuedNode(payload)
	for i, p := range disclose {
		n, err := disclosed(root, p)
		if err != nil {
			return fmt.Errorf("%w: typemeta: disclose[%d]: %v", jose.ErrInvalidArgument, i, err)
		}
		n.Disclosed = true
	}
	return m.ValidateClaims(root, ValidateOptions{AllDisclosures: true})
}

// errBudget is returned by check when the values it reads exceed budget.
var errBudget = errors.New("over the budget")

// check processes the path of c over root and applies mandatory and sd to
// what it selects. Each step is charged to budget for what it reads before
// it reads it: a key one per selected value plus one per 64 bytes, since a
// lookup hashes the whole key; null and, with all, an index the whole array
// (elems copies it); an index without all one.
func (c Claim) check(root *sdjwt.Node, all bool, budget *int) error {
	spend := func(n int) bool {
		*budget -= n
		return *budget >= 0
	}
	sel := []*sdjwt.Node{root}
	for _, el := range c.Path {
		key, isKey := el.(string)
		var next []*sdjwt.Node
		for _, n := range sel {
			if n.Hidden {
				continue // §5.6: its contents are unknown
			}
			cost := 1 + len(key)/64
			if !isKey && (el == nil || all) {
				cost = len(n.Elems)
			}
			if !spend(cost) {
				return errBudget
			}
			switch el := el.(type) {
			case string:
				if n.Fields == nil {
					return errors.New("a key is selected in a value that is not an object (§5.6.1.2)")
				}
				f, ok := n.Fields[el]
				if !ok {
					if c.Mandatory && (all || n.HiddenFields == 0) {
						return errors.New("a mandatory claim is not in the credential (§5.6.3)")
					}
					continue
				}
				next = append(next, f)
			case nil:
				if n.Elems == nil {
					return errors.New("every element is selected in a value that is not an array (§5.6.1.2)")
				}
				next = append(next, elems(n, all)...)
			case int:
				if n.Elems == nil {
					return errors.New("an index is selected in a value that is not an array (§5.6.1.2)")
				}
				es := elems(n, all)
				if el >= len(es) {
					if c.Mandatory {
						return errors.New("a mandatory claim is not in the credential (§5.6.3)")
					}
					continue
				}
				next = append(next, es[el])
			}
		}
		sel = next
	}
	for _, n := range sel {
		sd := n.Disclosed || n.Hidden
		switch {
		case c.SD == sdAlways && !sd:
			return errors.New("a selected claim is not selectively disclosable, and sd is always (§5.6.4)")
		case c.SD == sdNever && sd:
			return errors.New("a selected claim is selectively disclosable, and sd is never (§5.6.4)")
		}
	}
	return nil
}

// elems is the array of n as issued: with all, its hidden elements are
// decoys and left out.
func elems(n *sdjwt.Node, all bool) []*sdjwt.Node {
	if !all {
		return n.Elems
	}
	out := make([]*sdjwt.Node, 0, len(n.Elems))
	for _, e := range n.Elems {
		if !e.Hidden {
			out = append(out, e)
		}
	}
	return out
}

// issuedNode builds the Node tree of v, a value decoded as package jose
// decodes JSON, with nothing disclosed.
func issuedNode(v any) *sdjwt.Node {
	n := &sdjwt.Node{Value: v}
	switch v := v.(type) {
	case map[string]any:
		n.Fields = make(map[string]*sdjwt.Node, len(v))
		for k, f := range v {
			n.Fields[k] = issuedNode(f)
		}
	case []any:
		n.Elems = make([]*sdjwt.Node, len(v))
		for i, e := range v {
			n.Elems[i] = issuedNode(e)
		}
	}
	return n
}

// disclosed finds the node p names under root.
func disclosed(root *sdjwt.Node, p sdjwt.Path) (*sdjwt.Node, error) {
	if len(p) == 0 {
		return nil, errors.New("an empty path")
	}
	n := root
	for _, el := range p {
		switch el := el.(type) {
		case string:
			if n = n.Fields[el]; n == nil {
				return nil, fmt.Errorf("path %s names no claim of the payload", p)
			}
		case int:
			if el < 0 || el >= len(n.Elems) {
				return nil, fmt.Errorf("path %s names no claim of the payload", p)
			}
			n = n.Elems[el]
		default:
			return nil, fmt.Errorf("path %s has an element of type %T, want string or int", p, el)
		}
	}
	return n, nil
}

// formatPath writes a path of claim metadata as JSON, each key cut to 32
// bytes: the path comes from the publisher's document, never from the
// credential.
func formatPath(p []any) string {
	var b strings.Builder
	b.WriteByte('[')
	for i, el := range p {
		if i > 0 {
			b.WriteByte(',')
		}
		switch v := el.(type) {
		case string:
			if len(v) > 32 {
				cut := 32
				for cut > 0 && !utf8.RuneStart(v[cut]) {
					cut--
				}
				v = v[:cut] + "…"
			}
			b.WriteString(strconv.QuoteToASCII(v))
		case int:
			b.WriteString(strconv.Itoa(v))
		default:
			b.WriteString("null")
		}
	}
	b.WriteByte(']')
	return b.String()
}
