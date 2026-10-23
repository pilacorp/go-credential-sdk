// Package jwk converts EC public keys to and from JSON Web Key (RFC 7517):
// kty "EC" (RFC 7518 §6.2) on crv "P-256" (RFC 7518 §6.2.1.1) or "secp256k1"
// (RFC 8812 §3.1).
package jwk

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/internal/ec"
)

// ErrBadKey wraps every error of ToPublicKey and FromPublicKey: the JWK is
// not a public EC key on P-256 or secp256k1, or fails the RFC 8812 §3.2
// checks, or the *ecdsa.PublicKey is nil, on another curve, or not on its
// curve. No standard defines it.
var ErrBadKey = errors.New("jwk: bad key")

const (
	crvP256      = "P-256"     // RFC 7518 §6.2.1.1
	crvSecp256k1 = "secp256k1" // RFC 8812 §3.1
	algES256K    = "ES256K"    // RFC 8812 §3.2
)

// ToPublicKey reads an EC public key from a JWK. Only kty "EC" with crv
// "P-256" or "secp256k1" is accepted; x and y must decode to exactly 32 bytes
// (no stripped leading zeros) and the point must be on the curve. A JWK
// carrying "d" is rejected. On crv "secp256k1" it makes the checks of RFC
// 8812 §3.2, here rather than in the caller, which no longer sees the JWK: alg,
// if present, is "ES256K"; use, if present, is "sig"; key_ops, if present,
// includes "verify", the operation the returned key is for. RFC 7517 and RFC
// 7518 set no such values for P-256, so those members, and kid, are not read.
//
// A secp256k1 key comes back as *ecdsa.PublicKey with Curve secp256k1.S256().
func ToPublicKey(m map[string]any) (*ecdsa.PublicKey, error) {
	if m == nil {
		return nil, fmt.Errorf("%w: nil JWK", ErrBadKey)
	}
	// Stricter than RFC 7517, which lets a JWK carry the private key: this is
	// the path for public keys (cnf, issuer metadata), and accepting d here
	// invites callers to pass, store or log private keys through it.
	if _, ok := m["d"]; ok {
		return nil, fmt.Errorf("%w: JWK carries a private key (d)", ErrBadKey)
	}
	// RFC 7517 §4.1 and RFC 7518 §6.2: kty "EC" for an EC key.
	if kty, _ := m["kty"].(string); kty != "EC" {
		return nil, fmt.Errorf("%w: kty must be EC", ErrBadKey)
	}
	var p ec.Point
	crv, _ := m["crv"].(string)
	kind, ok := kindForCrv(crv)
	if !ok {
		return nil, fmt.Errorf("%w: crv %q is neither P-256 nor secp256k1", ErrBadKey, crv)
	}
	p.Kind = kind
	if kind == ec.Secp256k1 {
		if err := checkES256KMembers(m); err != nil {
			return nil, err
		}
	}
	var err error
	if p.X, err = coordinate(m, "x"); err != nil {
		return nil, err
	}
	if p.Y, err = coordinate(m, "y"); err != nil {
		return nil, err
	}
	if err := p.CheckOnCurve(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadKey, err)
	}
	return p.PublicKey(), nil
}

// FromPublicKey writes key as a JWK carrying kty, crv, x and y only, with x
// and y left-padded to 32 bytes (RFC 7518 §6.2.1.2 and §6.2.1.3, RFC 8812
// §3.1).
func FromPublicKey(key *ecdsa.PublicKey) (map[string]any, error) {
	p, err := ec.FromPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadKey, err)
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
		return out, fmt.Errorf("%w: %s must be a string", ErrBadKey, name)
	}
	b, err := jose.DecodeSegment(s)
	if err != nil {
		return out, fmt.Errorf("%w: %s: %v", ErrBadKey, name, err)
	}
	// RFC 7518 §6.2.1.2 and §6.2.1.3, RFC 8812 §3.1: the full 32 bytes,
	// leading zeros kept. A shorter value names the same integer, so without
	// this check two JWKs would encode one key.
	if len(b) != 32 {
		return out, fmt.Errorf("%w: %s must be 32 bytes, got %d", ErrBadKey, name, len(b))
	}
	new(big.Int).SetBytes(b).FillBytes(out[:])
	return out, nil
}

// checkES256KMembers makes the RFC 8812 §3.2 checks on a secp256k1 JWK. A
// member of the wrong JSON type fails too: it cannot represent the value the
// RFC requires.
func checkES256KMembers(m map[string]any) error {
	if v, ok := m["alg"]; ok {
		if alg, _ := v.(string); alg != algES256K {
			return fmt.Errorf("%w: alg of a secp256k1 key must be ES256K (RFC 8812 §3.2)", ErrBadKey)
		}
	}
	if v, ok := m["use"]; ok {
		if use, _ := v.(string); use != "sig" {
			return fmt.Errorf("%w: use of a secp256k1 key must be sig (RFC 8812 §3.2)", ErrBadKey)
		}
	}
	if v, ok := m["key_ops"]; ok && !includesVerify(v) {
		return fmt.Errorf("%w: key_ops of a secp256k1 key must include verify (RFC 8812 §3.2)", ErrBadKey)
	}
	return nil
}

// includesVerify reports whether key_ops is an array holding "verify". JSON
// decodes to []any; []string is what a caller building the map in Go writes.
func includesVerify(keyOps any) bool {
	switch ops := keyOps.(type) {
	case []any:
		return slices.Contains(ops, any("verify"))
	case []string:
		return slices.Contains(ops, "verify")
	}
	return false
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
