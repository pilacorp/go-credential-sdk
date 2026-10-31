// Processing Type Metadata: draft-ietf-oauth-sd-jwt-vc-19 §5.3 (retrieval),
// §5.4 (extends), §5.5.2 and §5.6.5 (merging), §5.7, §6 and §7.4.

package typemeta

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// Load retrieves the Type Metadata document for ref and every type it
// extends through r, checks integrity (§6) and structure (§5.2, §5.5, §5.6),
// merges the chain (§5.4, §5.5.2, §5.6.5), and returns metadata ready for
// ValidateClaims (draft 19 §5.7).
//
// Phase one walks the chain from ref: for each document it checks ctx, asks
// r, checks the size (256 KiB), the integrity of the reference that led to
// it, its structure (§5.2, §5.5) and that its vct equals that reference's
// (§5.3), then follows extends with extends#integrity. Phase two reads the
// claims of every document (§5.6) and merges from the furthest document
// down: a nearer display replaces the whole display (§5.5.2); a claim with
// the path of an inherited one overrides the properties it sets (§5.6.5).
//
// Errors:
//   - jose.ErrInvalidArgument: r or ctx nil, ref.VCT empty;
//   - an error of r, wrapped as returned, including ErrNotFound for ref
//     itself; ctx's error once it is done;
//   - ErrInvalid (phase one): the document is over 256 KiB, fails its
//     integrity, is not a Type Metadata document, has a vct other than the
//     reference's, or its chain is over 8 documents or has a parent r does
//     not find;
//   - ErrCycle: extends names a type already in the chain (§7.4);
//   - ErrClaims (phase two): claim metadata breaks §5.6, a child changes an
//     inherited sd of always or never, or an inherited mandatory true to
//     false (§5.6.5.1), or two claims share an svg_id.
//
// Load keeps nothing between calls. Texts quote no vct or URL.
func Load(ctx context.Context, r Resolver, ref Ref) (*Metadata, error) {
	if ctx == nil || r == nil {
		return nil, fmt.Errorf("%w: typemeta: Load needs a non-nil context and Resolver", jose.ErrInvalidArgument)
	}
	if ref.VCT == "" {
		return nil, fmt.Errorf("%w: typemeta: Load of an empty vct", jose.ErrInvalidArgument)
	}
	var docs []*document
	var raws [][]byte
	seen := map[string]bool{}
	for next := ref; ; {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("typemeta: Load: %w", err)
		}
		raw, err := r.Metadata(ctx, next)
		switch {
		case err != nil && len(docs) > 0 && errors.Is(err, ErrNotFound):
			// A missing parent leaves the type unprocessable, not unknown.
			return nil, invalid("document %d of the extends chain is not found; the type cannot be processed without it (draft-ietf-oauth-sd-jwt-vc-19 §5.4)", len(docs))
		case err != nil:
			return nil, fmt.Errorf("typemeta: document %d of the chain: %w", len(docs), err)
		}
		if len(raw) > maxDocumentBytes {
			return nil, invalid("document %d of the chain is over %d bytes, the SDK's limit", len(docs), maxDocumentBytes)
		}
		if next.Integrity != "" {
			if err := CheckIntegrity(raw, next.Integrity); err != nil {
				return nil, fmt.Errorf("document %d of the chain: %w", len(docs), err)
			}
		}
		d, err := readDocument(raw)
		if err != nil {
			return nil, fmt.Errorf("document %d of the chain: %w", len(docs), err)
		}
		if d.vct != next.VCT {
			return nil, invalid("document %d of the chain has a vct other than the type that led to it (draft-ietf-oauth-sd-jwt-vc-19 §5.3)", len(docs))
		}
		docs, raws = append(docs, d), append(raws, slices.Clone(raw))
		seen[d.vct] = true
		if !d.hasExtends {
			break
		}
		if seen[d.extends] {
			return nil, fmt.Errorf("%w: typemeta: document %d of the chain extends a type already in it (draft-ietf-oauth-sd-jwt-vc-19 §7.4)", ErrCycle, len(docs)-1)
		}
		if len(docs) == maxChain {
			return nil, invalid("the extends chain is over %d documents, the SDK's limit", maxChain)
		}
		next = Ref{VCT: d.extends, Integrity: d.extendsIntegrity}
	}

	m := &Metadata{vct: ref.VCT, name: docs[0].name, description: docs[0].description, docs: raws}
	var merged []claimMeta
	for i := len(docs) - 1; i >= 0; i-- {
		d := docs[i]
		m.chain = append(m.chain, d.vct)
		if d.hasDisplay {
			m.display = d.display
		}
		claims, err := d.readClaims()
		if err != nil {
			return nil, fmt.Errorf("document %d of the chain: %w", i, err)
		}
		if merged, err = mergeClaims(merged, claims); err != nil {
			return nil, fmt.Errorf("document %d of the chain: %w", i, err)
		}
	}
	slices.Reverse(m.chain)
	if err := checkSVGIDs(merged); err != nil {
		return nil, err
	}
	for _, c := range merged {
		if !c.hasSD {
			c.SD = sdAllowed // §5.6.4: allowed when omitted
		}
		m.claims = append(m.claims, c.Claim)
	}
	return m, nil
}

// mergeClaims applies the claims of a child document to inherited, those
// of its ancestors (§5.6.5). A child claim with the path of inherited ones
// overrides each property it sets in every one of them; other child claims
// are added after. Inherited claims are found by path key, so a layer costs
// one map lookup per child claim.
func mergeClaims(inherited, child []claimMeta) ([]claimMeta, error) {
	out := slices.Clone(inherited)
	byPath := make(map[string][]int, len(inherited))
	for j, p := range inherited {
		k := pathKey(p.Path)
		byPath[k] = append(byPath[k], j)
	}
	for i, c := range child {
		matches := byPath[pathKey(c.Path)]
		for _, j := range matches {
			p := &out[j]
			if c.hasSD {
				// §5.6.5.1: always and never cannot be changed; allowed, or no
				// sd, can.
				if p.hasSD && p.SD != sdAllowed && c.SD != p.SD {
					return nil, claimsErr("claims[%d] changes an inherited sd of %s (draft-ietf-oauth-sd-jwt-vc-19 §5.6.5.1)", i, p.SD)
				}
				p.SD, p.hasSD = c.SD, true
			}
			if c.hasMandatory {
				if p.Mandatory && !c.Mandatory {
					return nil, claimsErr("claims[%d] changes an inherited mandatory true to false (draft-ietf-oauth-sd-jwt-vc-19 §5.6.5.1)", i)
				}
				p.Mandatory, p.hasMandatory = c.Mandatory, true
			}
			// §5.6.5: the contents of a property are never merged.
			if c.hasDisplay {
				p.Display, p.hasDisplay = c.Display, true
			}
			if c.hasSVGID {
				p.SVGID, p.hasSVGID = c.SVGID, true
			}
		}
		if len(matches) == 0 {
			out = append(out, c)
		}
	}
	return out, nil
}

// pathKey encodes a path of claim metadata so that two paths have one key
// exactly when they are equal element by element: keys byte for byte, null
// with null, indexes by value. Each component is delimited, so no key can
// end inside another component.
func pathKey(path []any) string {
	var b strings.Builder
	for _, el := range path {
		switch el := el.(type) {
		case string:
			b.WriteString("s")
			b.WriteString(strconv.Itoa(len(el)))
			b.WriteString(":")
			b.WriteString(el)
		case nil:
			b.WriteString("n")
		case int:
			b.WriteString("i")
			b.WriteString(strconv.Itoa(el))
			b.WriteString(";")
		}
	}
	return b.String()
}
