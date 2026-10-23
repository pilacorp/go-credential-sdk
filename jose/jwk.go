package jose

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
)

// PublicKeyFromJWK reads an EC public key from a JWK (RFC 7517/7518; secp256k1
// per RFC 8812). Only kty "EC" with crv "P-256" or "secp256k1" is accepted; x
// and y must decode to exactly 32 bytes (no stripped leading zeros) and the
// point must be on the curve. A JWK carrying "d" is rejected: a private key
// never belongs in cnf or in issuer metadata. Other members (kid, use, alg)
// are ignored here and left to the caller.
//
// A secp256k1 key comes back as *ecdsa.PublicKey with Curve secp256k1.S256().
func PublicKeyFromJWK(jwk map[string]any) (*ecdsa.PublicKey, error) {
	if jwk == nil {
		return nil, fmt.Errorf("%w: nil JWK", ErrBadKey)
	}
	if _, ok := jwk["d"]; ok {
		return nil, fmt.Errorf("%w: JWK carries a private key (d)", ErrBadKey)
	}
	if kty, _ := jwk["kty"].(string); kty != "EC" {
		return nil, fmt.Errorf("%w: kty must be EC", ErrBadKey)
	}
	crv, _ := jwk["crv"].(string)
	var p ecPoint
	switch crv {
	case crvP256:
		p.kind = curveP256
	case crvSecp256k1:
		p.kind = curveSecp256k1
	default:
		return nil, fmt.Errorf("%w: crv %q is neither P-256 nor secp256k1", ErrBadKey, crv)
	}
	var err error
	if p.x, err = jwkCoordinate(jwk, "x"); err != nil {
		return nil, err
	}
	if p.y, err = jwkCoordinate(jwk, "y"); err != nil {
		return nil, err
	}
	if err := p.checkOnCurve(); err != nil {
		return nil, err
	}
	return p.publicKey(), nil
}

// JWKFromPublicKey writes key as a JWK carrying kty, crv, x and y only, with
// x and y left-padded to 32 bytes.
func JWKFromPublicKey(key *ecdsa.PublicKey) (map[string]any, error) {
	p, err := coordinates(key)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"kty": "EC",
		"crv": p.kind.crv(),
		"x":   EncodeSegment(p.x[:]),
		"y":   EncodeSegment(p.y[:]),
	}, nil
}

func jwkCoordinate(jwk map[string]any, name string) ([32]byte, error) {
	var out [32]byte
	s, ok := jwk[name].(string)
	if !ok {
		return out, fmt.Errorf("%w: %s must be a string", ErrBadKey, name)
	}
	b, err := DecodeSegment(s)
	if err != nil {
		return out, fmt.Errorf("%w: %s: %v", ErrBadKey, name, err)
	}
	// RFC 7518 §6.2.1.2: the full 32 bytes, leading zeros kept. A shorter
	// value names the same integer, so without this check two JWKs would encode
	// one key.
	if len(b) != 32 {
		return out, fmt.Errorf("%w: %s must be 32 bytes, got %d", ErrBadKey, name, len(b))
	}
	new(big.Int).SetBytes(b).FillBytes(out[:])
	return out, nil
}
