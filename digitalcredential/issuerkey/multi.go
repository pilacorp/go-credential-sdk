// Combining resolvers, so that one verifier accepts issuers whose keys come
// from different sources (draft-ietf-oauth-sd-jwt-vc-19 §2.5).

package issuerkey

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// Multi returns a Resolver that asks resolvers in the order given. A resolver
// that answers ErrIssuerNotSupported passes iss to the next; the first one
// that gives any other answer, an error included, gives the result. So a
// failed fetch never moves an issuer to another key source. When none
// accepts iss, the result is ErrIssuerNotSupported.
//
// No resolver, or a nil one, is jose.ErrInvalidArgument. resolvers is copied.
// The combined Keys returns ctx.Err() as soon as ctx is done, before asking
// the next resolver, and jose.ErrInvalidArgument for a nil ctx.
func Multi(resolvers ...Resolver) (Resolver, error) {
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("%w: issuerkey: Multi needs at least one resolver", jose.ErrInvalidArgument)
	}
	for i, r := range resolvers {
		if r == nil {
			return nil, fmt.Errorf("%w: issuerkey: Multi resolver %d is nil", jose.ErrInvalidArgument, i)
		}
	}
	return multi(slices.Clone(resolvers)), nil
}

type multi []Resolver

func (m multi) Keys(ctx context.Context, iss string) ([]PublicKey, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: issuerkey: nil context", jose.ErrInvalidArgument)
	}
	for _, r := range m {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		keys, err := r.Keys(ctx, iss)
		if errors.Is(err, ErrIssuerNotSupported) {
			continue
		}
		return keys, err
	}
	return nil, fmt.Errorf("%w: issuerkey: no resolver accepts this issuer", ErrIssuerNotSupported)
}
