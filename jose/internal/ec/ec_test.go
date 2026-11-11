package ec

import (
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestInvalidKindPanics(t *testing.T) {
	for name, f := range map[string]func(){
		"Name":         func() { Kind(0).Name() },
		"Curve":        func() { Kind(0).Curve() },
		"CheckOnCurve": func() { _ = Point{}.CheckOnCurve() },
		"VerifyRS":     func() { _ = Point{}.VerifyRS(make([]byte, 32), make([]byte, 64)) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("no panic for Kind(0)")
				}
			}()
			f()
		})
	}
}

func TestInScalarRange(t *testing.T) {
	n := elliptic.P256().Params().N
	for _, tc := range []struct {
		v    *big.Int
		want bool
	}{
		{nil, false},
		{big.NewInt(0), false},
		{big.NewInt(1), true},
		{new(big.Int).Sub(n, big.NewInt(1)), true},
		{n, false},
	} {
		if got := inScalarRange(tc.v, n); got != tc.want {
			t.Fatalf("inScalarRange(%v) = %v, want %v", tc.v, got, tc.want)
		}
	}
	if inScalarRange(big.NewInt(1), nil) {
		t.Fatal("nil n must not be in range")
	}
}
