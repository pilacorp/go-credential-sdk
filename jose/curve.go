package jose

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	AlgES256  = "ES256"  // ECDSA P-256 with SHA-256
	AlgES256K = "ES256K" // ECDSA secp256k1 with SHA-256 (RFC 8812)

	crvP256      = "P-256"
	crvSecp256k1 = "secp256k1"
)

type curveKind int

const (
	curveP256 curveKind = iota + 1
	curveSecp256k1
)

// kindOf names the curve by its parameters rather than by identity, so a
// secp256k1 key built on go-ethereum's curve, or on any other implementation,
// is recognised the same as one built on decred's.
func kindOf(c elliptic.Curve) (curveKind, bool) {
	if c == nil {
		return 0, false
	}
	p := c.Params()
	if p == nil {
		return 0, false
	}
	if sameCurve(p, elliptic.P256().Params()) {
		return curveP256, true
	}
	if sameCurve(p, secp256k1.S256().Params()) {
		return curveSecp256k1, true
	}
	return 0, false
}

func sameCurve(a, b *elliptic.CurveParams) bool {
	return a.P != nil && a.N != nil && a.P.Cmp(b.P) == 0 && a.N.Cmp(b.N) == 0
}

// alg, crv and curve panic on a curveKind that is neither P-256 nor
// secp256k1: every curveKind comes from kindOf or kindForAlg after their ok is
// checked, so another value is a bug in this package, not bad input.
func (k curveKind) alg() string {
	switch k {
	case curveP256:
		return AlgES256
	case curveSecp256k1:
		return AlgES256K
	}
	panic(fmt.Sprintf("jose: invalid curveKind %d", k))
}

func (k curveKind) crv() string {
	switch k {
	case curveP256:
		return crvP256
	case curveSecp256k1:
		return crvSecp256k1
	}
	panic(fmt.Sprintf("jose: invalid curveKind %d", k))
}

func (k curveKind) curve() elliptic.Curve {
	switch k {
	case curveP256:
		return elliptic.P256()
	case curveSecp256k1:
		return secp256k1.S256()
	}
	panic(fmt.Sprintf("jose: invalid curveKind %d", k))
}

func kindForAlg(alg string) (curveKind, bool) {
	switch alg {
	case AlgES256:
		return curveP256, true
	case AlgES256K:
		return curveSecp256k1, true
	}
	return 0, false
}

// NormalizeLowS returns s if s <= n/2, otherwise n-s. Both are valid ECDSA
// signatures over the same input; fixing one keeps one encoding per signed
// token, so a hash over the token (the anchoring leaf) is stable. Same rule as
// credential/common/signer.NormalizeLowS, which this module cannot import
// without pulling in go-ethereum.
//
// s must be a valid signature scalar, 1 <= s <= n-1 (check it first; Sign and
// anchor.Leaf do). A nil curve or s gives nil. The result is otherwise always
// a new big.Int, never s itself, so changing it never changes s.
func NormalizeLowS(curve elliptic.Curve, s *big.Int) *big.Int {
	if curve == nil || s == nil || curve.Params() == nil || curve.Params().N == nil {
		return nil
	}
	n := curve.Params().N
	if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		return new(big.Int).Sub(n, s)
	}
	return new(big.Int).Set(s)
}

// inScalarRange reports whether 1 <= v <= n-1; nil is never in range.
func inScalarRange(v, n *big.Int) bool {
	return v != nil && n != nil && v.Sign() > 0 && v.Cmp(n) < 0
}

// coordinates returns the key's affine coordinates as 32 bytes each, and
// checks the point is on the key's curve. A key that fails is ErrBadKey.
func coordinates(key *ecdsa.PublicKey) (curveKind, [32]byte, [32]byte, error) {
	var x, y [32]byte
	if key == nil || key.X == nil || key.Y == nil {
		return 0, x, y, fmt.Errorf("%w: nil key", ErrBadKey)
	}
	kind, ok := kindOf(key.Curve)
	if !ok {
		return 0, x, y, fmt.Errorf("%w: curve is neither P-256 nor secp256k1", ErrBadKey)
	}
	if key.X.Sign() < 0 || key.Y.Sign() < 0 || key.X.BitLen() > 256 || key.Y.BitLen() > 256 {
		return 0, x, y, fmt.Errorf("%w: coordinate out of range", ErrBadKey)
	}
	key.X.FillBytes(x[:])
	key.Y.FillBytes(y[:])
	if err := checkOnCurve(kind, x, y); err != nil {
		return 0, x, y, err
	}
	return kind, x, y, nil
}

// checkOnCurve uses the curve libraries' own point decoding, which rejects
// coordinates >= p and points off the curve.
func checkOnCurve(kind curveKind, x, y [32]byte) error {
	uncompressed := make([]byte, 0, 65)
	uncompressed = append(uncompressed, 0x04)
	uncompressed = append(uncompressed, x[:]...)
	uncompressed = append(uncompressed, y[:]...)
	var err error
	if kind == curveP256 {
		_, err = ecdh.P256().NewPublicKey(uncompressed)
	} else {
		_, err = secp256k1.ParsePubKey(uncompressed)
	}
	if err != nil {
		return fmt.Errorf("%w: point is not on %s: %v", ErrBadKey, kind.crv(), err)
	}
	return nil
}
