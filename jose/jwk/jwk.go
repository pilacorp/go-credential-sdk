// Package jwk converts EC public keys to and from JSON Web Key (RFC 7517):
// kty "EC" (RFC 7518 §6.2) on crv "P-256" (RFC 7518 §6.2.1.1) or "secp256k1"
// (RFC 8812 §3.1).
package jwk

import (
	"crypto"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/internal/ec"
)

// ErrBadKey wraps every error of ToPublicKey and FromPublicKey except those
// that wrap jose.ErrUnsupportedKey. It means the JWK is not a valid public
// key of a type ToPublicKey converts, or fails the RFC 8812 §3.2 checks, or the key given
// to FromPublicKey is nil or not on its curve. No standard defines it.
//
// jose.ErrUnsupportedKey: ToPublicKey got a JWK that carries no d and whose
// kty, or crv of an EC key, is a string it does not convert, or
// FromPublicKey got a key that is not an ECDSA key on P-256 or secp256k1.
// Other key types and curves can be registered (RFC 7517 §4.1, RFC 7518
// §6.2.1.1), so the JWK may be valid: it never also matches ErrBadKey.
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
// m is read as jose.DecodeJSONObject yields a JSON object, where a JSON
// array is []any: on crv secp256k1 a key_ops built in Go as []string is not
// that []any, so the key is refused; P-256 does not read key_ops.
//
// A JWK carrying d is ErrBadKey whatever its kty. Otherwise a kty other than
// "EC", or a crv other than those two, the empty string included, is
// jose.ErrUnsupportedKey; a missing or non-string kty or crv is ErrBadKey.
//
// The key comes back as an *ecdsa.PublicKey, on secp256k1.S256() for a
// secp256k1 key. Its type is crypto.PublicKey so other key types can be added
// without changing the signature.
func ToPublicKey(m map[string]any) (crypto.PublicKey, error) {
	if m == nil {
		return nil, fmt.Errorf("%w: nil JWK", ErrBadKey)
	}
	// Stricter than RFC 7517, which lets a JWK carry the private key: this is
	// the path for public keys (cnf, issuer metadata), and accepting d here
	// invites callers to pass, store or log private keys through it.
	if _, ok := m["d"]; ok {
		return nil, fmt.Errorf("%w: JWK carries a private key (d)", ErrBadKey)
	}
	// RFC 7517 §4.1: kty MUST be present, a case-sensitive string; RFC 7518
	// §6.2.1 and §6.2.1.1: so is crv of an EC key. Both come from the JWK's
	// sender, so they are quoted and cut at 16 characters, more than any name
	// the IANA JOSE registries hold.
	kty, ok := m["kty"].(string)
	if !ok {
		return nil, fmt.Errorf("%w: kty is missing or not a string", ErrBadKey)
	}
	if kty != "EC" {
		return nil, fmt.Errorf("%w: kty %.16q; the SDK supports kty EC on P-256 and secp256k1", jose.ErrUnsupportedKey, kty)
	}
	crv, ok := m["crv"].(string)
	if !ok {
		return nil, fmt.Errorf("%w: crv is missing or not a string", ErrBadKey)
	}
	var p ec.Point
	kind, ok := kindForCrv(crv)
	if !ok {
		return nil, fmt.Errorf("%w: crv %.16q; the SDK supports P-256 and secp256k1", jose.ErrUnsupportedKey, crv)
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
// §3.1). key must be an *ecdsa.PublicKey on one of the two curves.
func FromPublicKey(key crypto.PublicKey) (map[string]any, error) {
	p, err := ec.FromPublicKey(key)
	if errors.Is(err, jose.ErrUnsupportedKey) {
		return nil, err
	}
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
		return fmt.Errorf("%w: key_ops of a secp256k1 key must be a JSON array including verify (RFC 7517 §4.3, RFC 8812 §3.2)", ErrBadKey)
	}
	return nil
}

// includesVerify reports whether key_ops is a JSON array holding "verify".
func includesVerify(keyOps any) bool {
	ops, _ := keyOps.([]any)
	return slices.Contains(ops, any("verify"))
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
