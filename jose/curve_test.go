package jose

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestNormalizeLowS(t *testing.T) {
	for name, curve := range map[string]elliptic.Curve{"P-256": elliptic.P256(), "secp256k1": secp256k1.S256()} {
		t.Run(name, func(t *testing.T) {
			n := curve.Params().N
			half := new(big.Int).Rsh(n, 1)
			for _, tc := range []struct{ in, want *big.Int }{
				{big.NewInt(1), big.NewInt(1)},
				{half, half},
				{new(big.Int).Add(half, big.NewInt(1)), new(big.Int).Sub(n, new(big.Int).Add(half, big.NewInt(1)))},
				{new(big.Int).Sub(n, big.NewInt(1)), big.NewInt(1)},
			} {
				in := new(big.Int).Set(tc.in)
				got := NormalizeLowS(curve, in)
				if got.Cmp(tc.want) != 0 {
					t.Fatalf("NormalizeLowS(%v) = %v, want %v", tc.in, got, tc.want)
				}
				if got == in {
					t.Fatalf("NormalizeLowS(%v) returned its input", tc.in)
				}
				got.SetInt64(42)
				if in.Cmp(tc.in) != 0 {
					t.Fatalf("changing the result changed the input")
				}
			}
		})
	}
}

func TestNilInputs(t *testing.T) {
	if NormalizeLowS(nil, big.NewInt(1)) != nil || NormalizeLowS(elliptic.P256(), nil) != nil {
		t.Fatal("NormalizeLowS with a nil argument must return nil")
	}
	n := elliptic.P256().Params().N
	if inScalarRange(nil, n) || inScalarRange(big.NewInt(1), nil) {
		t.Fatal("nil must not be in range")
	}
}

func TestInvalidCurveKindPanics(t *testing.T) {
	for name, f := range map[string]func(){
		"alg":   func() { curveKind(0).alg() },
		"crv":   func() { curveKind(0).crv() },
		"curve": func() { curveKind(0).curve() },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("no panic for curveKind(0)")
				}
			}()
			f()
		})
	}
}
