// Package jwk converts EC public keys to and from JSON Web Key (RFC 7517):
// kty "EC" (RFC 7518 §6.2) on crv "P-256" (RFC 7518 §6.2.1.1) or "secp256k1"
// (RFC 8812 §3.1).
package jwk

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/internal/ec"
)

const (
	crvP256      = "P-256"     // RFC 7518 §6.2.1.1
	crvSecp256k1 = "secp256k1" // RFC 8812 §3.1
)

// ToPublicKey reads an EC public key from a JWK. Only kty "EC" with crv
// "P-256" or "secp256k1" is accepted; x and y must decode to exactly 32 bytes
// (no stripped leading zeros) and the point must be on the curve. A JWK
// carrying "d" is rejected. RFC 8812 §3.2 sets MUSTs on a JWK's alg, use and
// key_ops for ES256K; ToPublicKey reads the key only and leaves those checks,
// and kid, to the caller.
//
// A secp256k1 key comes back as *ecdsa.PublicKey with Curve secp256k1.S256().
func ToPublicKey(m map[string]any) (*ecdsa.PublicKey, error) {
	if m == nil {
		return nil, fmt.Errorf("%w: nil JWK", jose.ErrBadKey)
	}
	// Stricter than RFC 7517, which lets a JWK carry the private key: this is
	// the path for public keys (cnf, issuer metadata), and accepting d here
	// invites callers to pass, store or log private keys through it.
	if _, ok := m["d"]; ok {
		return nil, fmt.Errorf("%w: JWK carries a private key (d)", jose.ErrBadKey)
	}
	// RFC 7517 §4.1 and RFC 7518 §6.2: kty "EC" for an EC key.
	if kty, _ := m["kty"].(string); kty != "EC" {
		return nil, fmt.Errorf("%w: kty must be EC", jose.ErrBadKey)
	}
	var p ec.Point
	crv, _ := m["crv"].(string)
	kind, ok := kindForCrv(crv)
	if !ok {
		return nil, fmt.Errorf("%w: crv %q is neither P-256 nor secp256k1", jose.ErrBadKey, crv)
	}
	p.Kind = kind
	var err error
	if p.X, err = coordinate(m, "x"); err != nil {
		return nil, err
	}
	if p.Y, err = coordinate(m, "y"); err != nil {
		return nil, err
	}
	if err := p.CheckOnCurve(); err != nil {
		return nil, err
	}
	return p.PublicKey(), nil
}

// FromPublicKey writes key as a JWK carrying kty, crv, x and y only, with x
// and y left-padded to 32 bytes (RFC 7518 §6.2.1.2 and §6.2.1.3, RFC 8812
// §3.1).
func FromPublicKey(key *ecdsa.PublicKey) (map[string]any, error) {
	p, err := ec.FromPublicKey(key)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"kty": "EC",
		"crv": crvOf(p.Kind),
		"x":   jose.EncodeSegment(p.X[:]),
		"y":   jose.EncodeSegment(p.Y[:]),
	}, nil
}

func coordinate(m map[string]any, name string) ([32]byte, error) {
	var out [32]byte
	s, ok := m[name].(string)
	if !ok {
		return out, fmt.Errorf("%w: %s must be a string", jose.ErrBadKey, name)
	}
	b, err := jose.DecodeSegment(s)
	if err != nil {
		return out, fmt.Errorf("%w: %s: %v", jose.ErrBadKey, name, err)
	}
	// RFC 7518 §6.2.1.2 and §6.2.1.3, RFC 8812 §3.1: the full 32 bytes,
	// leading zeros kept. A shorter value names the same integer, so without
	// this check two JWKs would encode one key.
	if len(b) != 32 {
		return out, fmt.Errorf("%w: %s must be 32 bytes, got %d", jose.ErrBadKey, name, len(b))
	}
	new(big.Int).SetBytes(b).FillBytes(out[:])
	return out, nil
}

// crvOf panics on an invalid kind, like ec.Kind.Name.
func crvOf(k ec.Kind) string {
	switch k {
	case ec.P256:
		return crvP256
	case ec.Secp256k1:
		return crvSecp256k1
	}
	panic(fmt.Sprintf("jose: invalid curve kind %d", k))
}

// kindForCrv maps the crv values of RFC 7518 §6.2.1.1 and RFC 8812 §3.1; the
// comparison is case-sensitive (RFC 7518 §6.2.1.1).
func kindForCrv(crv string) (ec.Kind, bool) {
	switch crv {
	case crvP256:
		return ec.P256, true
	case crvSecp256k1:
		return ec.Secp256k1, true
	}
	return 0, false
}
