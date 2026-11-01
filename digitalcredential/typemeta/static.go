// Preloaded documents: draft-ietf-oauth-sd-jwt-vc-19 §5.3.4 and §7.5.

package typemeta

import (
	"context"
	"fmt"
	"slices"

	"github.com/pilacorp/go-credential-sdk/jose"
)

type static map[string][]byte

// Static returns a Resolver over docs, documents the application ships or
// fetched ahead (§5.3.4, §7.5), each found by the vct it holds. It copies
// docs and reads only each vct; Load checks the rest. No document, one that
// is not a JSON object or has no non-empty string vct, or two with the same
// vct, is jose.ErrInvalidArgument. Metadata returns ErrNotFound for any
// other vct and the document for its own, whatever ref.Integrity, which Load
// checks.
func Static(docs ...[]byte) (Resolver, error) {
	if len(docs) == 0 {
		return nil, fmt.Errorf("%w: typemeta: Static needs at least one document", jose.ErrInvalidArgument)
	}
	s := make(static, len(docs))
	for i, d := range docs {
		vct, _, err := jose.DecodeJSONStringMember(d, "vct")
		if err != nil || vct == "" {
			return nil, fmt.Errorf("%w: typemeta: Static document %d is not a JSON object with a non-empty string vct (draft-ietf-oauth-sd-jwt-vc-19 §5.2)", jose.ErrInvalidArgument, i)
		}
		if _, dup := s[vct]; dup {
			return nil, fmt.Errorf("%w: typemeta: Static document %d has the vct of an earlier one", jose.ErrInvalidArgument, i)
		}
		s[vct] = slices.Clone(d)
	}
	return s, nil
}

func (s static) Metadata(ctx context.Context, ref Ref) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: typemeta: nil context", jose.ErrInvalidArgument)
	}
	d, ok := s[ref.VCT]
	if !ok {
		return nil, fmt.Errorf("%w: typemeta: no preloaded document for the vct", ErrNotFound)
	}
	return slices.Clone(d), nil
}
