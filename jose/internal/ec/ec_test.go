package ec

import "testing"

func TestInvalidKindPanics(t *testing.T) {
	for name, f := range map[string]func(){
		"Name":         func() { Kind(0).Name() },
		"Curve":        func() { Kind(0).Curve() },
		"CheckOnCurve": func() { _ = Point{}.CheckOnCurve() },
		"VerifyRS":     func() { Point{}.VerifyRS(make([]byte, 32), make([]byte, 64)) },
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
