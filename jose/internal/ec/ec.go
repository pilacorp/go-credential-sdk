// Package ec holds the two curves the JOSE packages accept, P-256 (RFC 7518
// §6.2.1.1) and secp256k1 (RFC 8812 §3.1), an EC public key as a point on one
// of them, its partial public-key validation, and steps 3 to 9 of ECDSA
// verification by it (FIPS 186-5 §6.4.2); each dispatches on the curve in one
// place. Steps 1 (r and s in [1, n-1]) and 2 (the SHA-256 digest) are done by
// jose/jws. Which alg or crv names a curve is left to jose/jws and jose/jwk.
package ec

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// Kind names one of the two supported curves.
type Kind int

const (
	P256 Kind = iota + 1
	Secp256k1
)

// kindOf names the curve by its parameters rather than by identity, so a
// secp256k1 key built on go-ethereum's curve, or on any other implementation,
// is recognised the same as one built on decred's.
func kindOf(c elliptic.Curve) (Kind, bool) {
	if c == nil {
		return 0, false
	}
	p := c.Params()
	if p == nil {
		return 0, false
	}
	if sameCurve(p, elliptic.P256().Params()) {
		return P256, true
	}
	if sameCurve(p, secp256k1.S256().Params()) {
		return Secp256k1, true
	}
	return 0, false
}

func sameCurve(a, b *elliptic.CurveParams) bool {
	return a.P != nil && a.N != nil && a.P.Cmp(b.P) == 0 && a.N.Cmp(b.N) == 0
}

// Name, Curve, CheckOnCurve and VerifyRS panic on a Kind that is neither P256
// nor Secp256k1: every Kind comes from kindOf or a caller's mapping after its ok is checked, so
// another value is a bug in this module, not bad input.
func (k Kind) Name() string {
	switch k {
	case P256:
		return "P-256"
	case Secp256k1:
		return "secp256k1"
	}
	panic(fmt.Sprintf("jose: invalid curve kind %d", k))
}

func (k Kind) Curve() elliptic.Curve {
	switch k {
	case P256:
		return elliptic.P256()
	case Secp256k1:
		return secp256k1.S256()
	}
	panic(fmt.Sprintf("jose: invalid curve kind %d", k))
}

// Point is a public key reduced to what the JOSE packages work with: its
// curve and its affine coordinates, 32 bytes each.
type Point struct {
	Kind Kind
	X, Y [32]byte
}

// PublicKey returns p as an *ecdsa.PublicKey on the curve of its kind.
func (p Point) PublicKey() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: p.Kind.Curve(),
		X:     new(big.Int).SetBytes(p.X[:]),
		Y:     new(big.Int).SetBytes(p.Y[:]),
	}
}

// FromPublicKey returns the key's curve and affine coordinates, and checks the
// point is on the key's curve. A key that fails is jose.ErrBadKey.
func FromPublicKey(key *ecdsa.PublicKey) (Point, error) {
	if key == nil || key.X == nil || key.Y == nil {
		return Point{}, fmt.Errorf("%w: nil key", jose.ErrBadKey)
	}
	kind, ok := kindOf(key.Curve)
	if !ok {
		return Point{}, fmt.Errorf("%w: curve is neither P-256 nor secp256k1", jose.ErrBadKey)
	}
	if key.X.Sign() < 0 || key.Y.Sign() < 0 || key.X.BitLen() > 256 || key.Y.BitLen() > 256 {
		return Point{}, fmt.Errorf("%w: coordinate out of range", jose.ErrBadKey)
	}
	p := Point{Kind: kind}
	key.X.FillBytes(p.X[:])
	key.Y.FillBytes(p.Y[:])
	if err := p.CheckOnCurve(); err != nil {
		return Point{}, err
	}
	return p, nil
}

// CheckOnCurve is partial public-key validation, SP 800-186 App. D.1.1.1
// (= SEC 1 v2.0 §3.2.3.1): x and y in [0, p-1] and on the curve. FIPS 186-5
// §6.4.2 says the verification key should be checked so (SP 800-186 App.
// D.1). The curve libraries' own point decoding performs both checks.
func (p Point) CheckOnCurve() error {
	uncompressed := make([]byte, 0, 65)
	uncompressed = append(uncompressed, 0x04)
	uncompressed = append(uncompressed, p.X[:]...)
	uncompressed = append(uncompressed, p.Y[:]...)
	var err error
	switch p.Kind {
	case P256:
		_, err = ecdh.P256().NewPublicKey(uncompressed)
	case Secp256k1:
		_, err = secp256k1.ParsePubKey(uncompressed)
	default:
		panic(fmt.Sprintf("jose: invalid curve kind %d", p.Kind))
	}
	if err != nil {
		return fmt.Errorf("%w: point is not on %s: %v", jose.ErrBadKey, p.Kind.Name(), err)
	}
	return nil
}

// VerifyRS runs FIPS 186-5 §6.4.2 steps 3 to 9: it reports whether sig, a
// 64-byte r||s, is an ECDSA signature by p over digest. The caller must have
// done step 1: the secp256k1 verifier reduces r and s mod n, so n+1 acts as 1.
func (p Point) VerifyRS(digest, sig []byte) bool {
	switch p.Kind {
	case P256:
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		return ecdsa.Verify(p.PublicKey(), digest, r, s)
	case Secp256k1:
		var fx, fy secp256k1.FieldVal
		fx.SetBytes(&p.X)
		fy.SetBytes(&p.Y)
		var r, s secp256k1.ModNScalar
		r.SetByteSlice(sig[:32])
		s.SetByteSlice(sig[32:])
		return decredecdsa.NewSignature(&r, &s).Verify(digest, secp256k1.NewPublicKey(&fx, &fy))
	}
	panic(fmt.Sprintf("jose: invalid curve kind %d", p.Kind))
}
