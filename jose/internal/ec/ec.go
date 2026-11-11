// Package ec holds the two curves the JOSE packages accept, P-256 (RFC 7518
// §6.2.1.1) and secp256k1 (RFC 8812 §3.1), an EC public key as a point on one
// of them, its partial public-key validation, a private key on one of them,
// and ECDSA signing (FIPS 186-5 §6.4.1) and verification (§6.4.2) with r||s,
// every step but hashing the message; each dispatches on the curve in one
// place. Hashing is left to the caller, as is which alg or crv names a curve
// (jose/jws and jose/jwk).
package ec

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/internal/errtext"
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
// point is on the key's curve. A key that is not an *ecdsa.PublicKey, or one
// on another curve, wraps jose.ErrUnsupportedKey and names what it got; any
// other error means a broken key of a supported kind and wraps no sentinel,
// so the caller wraps it in its own ErrBadKey.
func FromPublicKey(key crypto.PublicKey) (Point, error) {
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		if key == nil {
			return Point{}, errors.New("nil key")
		}
		return Point{}, fmt.Errorf("%w: key type %T; the SDK supports *ecdsa.PublicKey on P-256 or secp256k1", jose.ErrUnsupportedKey, key)
	}
	if pub == nil || pub.Curve == nil || pub.X == nil || pub.Y == nil {
		return Point{}, errors.New("nil key")
	}
	kind, err := kindOfKey(pub.Curve)
	if err != nil {
		return Point{}, err
	}
	if pub.X.Sign() < 0 || pub.Y.Sign() < 0 || pub.X.BitLen() > 256 || pub.Y.BitLen() > 256 {
		return Point{}, errors.New("coordinate out of range")
	}
	p := Point{Kind: kind}
	pub.X.FillBytes(p.X[:])
	pub.Y.FillBytes(p.Y[:])
	if err := p.CheckOnCurve(); err != nil {
		return Point{}, err
	}
	return p, nil
}

// supported ends the text of a jose.ErrUnsupportedKey for a curve, so the
// caller learns what to pass instead; a key of another Go type names the
// type to pass.
const supported = "the SDK supports ECDSA keys on P-256 and secp256k1"

// kindOfKey is kindOf for a curve taken from a key: a curve with no
// parameters is a broken key, one with other parameters is unsupported.
func kindOfKey(c elliptic.Curve) (Kind, error) {
	if c.Params() == nil {
		return 0, errors.New("curve has no parameters")
	}
	kind, ok := kindOf(c)
	if !ok {
		return 0, fmt.Errorf("%w: curve %s; %s", jose.ErrUnsupportedKey, errtext.Quote(c.Params().Name), supported)
	}
	return kind, nil
}

// PrivateKey is an ECDSA private key on one of the two curves: the scalar d,
// 32 bytes, and the point d·G it was checked against.
type PrivateKey struct {
	Point Point
	d     [32]byte
}

// FromPrivateKey copies priv after checking it, as FromPublicKey does, plus
// d in [1, n-1] and d·G equal to priv.PublicKey (SEC 1 v2.0 §3.2; FIPS 186-5
// §6.4.1 input 2, App. A.2.1), so a key whose two halves disagree is refused
// at build time rather than signing tokens no one can verify. The error
// classes are those of FromPublicKey.
func FromPrivateKey(key crypto.PrivateKey) (PrivateKey, error) {
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		if key == nil {
			return PrivateKey{}, errors.New("nil key")
		}
		return PrivateKey{}, fmt.Errorf("%w: key type %T; the SDK supports *ecdsa.PrivateKey on P-256 or secp256k1", jose.ErrUnsupportedKey, key)
	}
	if priv == nil || priv.Curve == nil {
		return PrivateKey{}, errors.New("nil key")
	}
	kind, err := kindOfKey(priv.Curve)
	if err != nil {
		return PrivateKey{}, err
	}
	pt, err := FromPublicKey(&priv.PublicKey)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("public key: %w", err)
	}
	if !inScalarRange(priv.D, kind.Curve().Params().N) {
		return PrivateKey{}, errors.New("d outside [1, n-1]")
	}
	k := PrivateKey{Point: pt}
	priv.D.FillBytes(k.d[:])
	if !bytes.Equal(k.publicBytes(), pt.uncompressed()) {
		return PrivateKey{}, errors.New("public key does not match d")
	}
	return k, nil
}

// publicBytes returns d·G, uncompressed (SEC 1 v2.0 §2.3.3).
func (k PrivateKey) publicBytes() []byte {
	switch k.Point.Kind {
	case P256:
		// d is in [1, n-1], which is all NewPrivateKey checks.
		priv, err := ecdh.P256().NewPrivateKey(k.d[:])
		if err != nil {
			panic(fmt.Sprintf("jose: P-256 scalar in range refused: %v", err))
		}
		return priv.PublicKey().Bytes()
	case Secp256k1:
		return secp256k1.PrivKeyFromBytes(k.d[:]).PubKey().SerializeUncompressed()
	}
	panic(fmt.Sprintf("jose: invalid curve kind %d", k.Point.Kind))
}

// SignRS runs ECDSA signature generation (FIPS 186-5 §6.4.1, every step but
// hashing) over digest and returns r||s, 32 bytes each, left-padded with
// zeros (RFC 7518 §3.4, RFC 8812 §3.2). P-256 takes its nonce from
// crypto/rand as crypto/ecdsa does; secp256k1 derives it by RFC 6979 and
// returns the low-S form, as the decred library does. k is read only, so
// concurrent calls are safe.
func (k PrivateKey) SignRS(digest []byte) ([]byte, error) {
	out := make([]byte, 64)
	switch k.Point.Kind {
	case P256:
		priv := &ecdsa.PrivateKey{PublicKey: *k.Point.PublicKey(), D: new(big.Int).SetBytes(k.d[:])}
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
		if err != nil {
			return nil, err
		}
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
	case Secp256k1:
		sig := decredecdsa.Sign(secp256k1.PrivKeyFromBytes(k.d[:]), digest)
		r, s := sig.R(), sig.S()
		r.PutBytesUnchecked(out[:32])
		s.PutBytesUnchecked(out[32:])
	default:
		panic(fmt.Sprintf("jose: invalid curve kind %d", k.Point.Kind))
	}
	return out, nil
}

// CheckOnCurve is partial public-key validation, SP 800-186 App. D.1.1.1
// (= SEC 1 v2.0 §3.2.3.1): x and y in [0, p-1] and on the curve. FIPS 186-5
// §6.4.2 says the verification key should be checked so (SP 800-186 App.
// D.1). The curve libraries' own point decoding performs both checks.
func (p Point) CheckOnCurve() error {
	uncompressed := p.uncompressed()
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
		return fmt.Errorf("point is not on %s: %v", p.Kind.Name(), err)
	}
	return nil
}

// uncompressed returns 0x04 || X || Y (SEC 1 v2.0 §2.3.3).
func (p Point) uncompressed() []byte {
	out := make([]byte, 0, 65)
	out = append(out, 0x04)
	out = append(out, p.X[:]...)
	return append(out, p.Y[:]...)
}

// VerifyRS runs ECDSA verification (FIPS 186-5 §6.4.2, steps 1 and 3 to 9) of
// sig, r||s with 32 bytes each, by p over digest, the step 2 hash. Its errors
// wrap no sentinel: the caller wraps them in its own.
func (p Point) VerifyRS(digest, sig []byte) error {
	n := p.Kind.Curve().Params().N
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	// Step 1 (= SEC 1 v2.0 §4.1.4 step 1). The secp256k1 verifier below
	// reduces r and s mod n, so without this check n+1 would pass as 1.
	if !inScalarRange(r, n) || !inScalarRange(s, n) {
		return errors.New("r or s outside [1, n-1]")
	}
	var ok bool
	switch p.Kind {
	case P256:
		ok = ecdsa.Verify(p.PublicKey(), digest, r, s)
	case Secp256k1:
		var fx, fy secp256k1.FieldVal
		fx.SetBytes(&p.X)
		fy.SetBytes(&p.Y)
		var rs, ss secp256k1.ModNScalar
		rs.SetByteSlice(sig[:32])
		ss.SetByteSlice(sig[32:])
		ok = decredecdsa.NewSignature(&rs, &ss).Verify(digest, secp256k1.NewPublicKey(&fx, &fy))
	default:
		panic(fmt.Sprintf("jose: invalid curve kind %d", p.Kind))
	}
	if !ok {
		return errors.New("signature does not verify")
	}
	return nil
}

// inScalarRange reports whether 1 <= v <= n-1; nil is never in range.
func inScalarRange(v, n *big.Int) bool {
	return v != nil && n != nil && v.Sign() > 0 && v.Cmp(n) < 0
}
