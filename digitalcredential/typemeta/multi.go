// Combining resolvers, so that one application takes documents from several
// retrieval methods (draft-ietf-oauth-sd-jwt-vc-19 §5.3).

package typemeta

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// Multi returns a Resolver that asks resolvers in the order given. One that
// answers ErrNotFound passes ref to the next; the first other answer, an
// error included, is the result, so a failed retrieval never moves a type to
// another source. When none has the document, the result is ErrNotFound.
//
// No resolver, or a nil one, is jose.ErrInvalidArgument. resolvers is
// copied. The combined Metadata returns ctx.Err() as soon as ctx is done,
// before asking the next resolver, and jose.ErrInvalidArgument for a nil ctx.
func Multi(resolvers ...Resolver) (Resolver, error) {
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("%w: typemeta: Multi needs at least one resolver", jose.ErrInvalidArgument)
	}
	for i, r := range resolvers {
		if r == nil {
			return nil, fmt.Errorf("%w: typemeta: Multi resolver %d is nil", jose.ErrInvalidArgument, i)
		}
	}
	return multi(slices.Clone(resolvers)), nil
}

type multi []Resolver

func (m multi) Metadata(ctx context.Context, ref Ref) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: typemeta: nil context", jose.ErrInvalidArgument)
	}
	for _, r := range m {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		doc, err := r.Metadata(ctx, ref)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		return doc, err
	}
	return nil, fmt.Errorf("%w: typemeta: no resolver has a document for the vct", ErrNotFound)
}
