package jwt

import (
	"strings"
	"testing"
	"time"
)

func TestSetIssuedAt(t *testing.T) {
	signedAt := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

	p := map[string]interface{}{"validFrom": "2020-01-01T00:00:00Z", "validUntil": "2030-01-01T00:00:00Z"}
	SetIssuedAt(p, signedAt)

	if p["iat"] != signedAt.Unix() {
		t.Fatalf("iat = %v, want the signing time %v", p["iat"], signedAt.Unix())
	}
	// exp and nbf describe the signature, not the credential. Deriving them
	// from the validity period would state one fact in the other's field, and
	// vc-jose-cose calls nbf on a signature NOT RECOMMENDED outright.
	if _, ok := p["exp"]; ok {
		t.Fatalf("exp written from validUntil: %v", p["exp"])
	}
	if _, ok := p["nbf"]; ok {
		t.Fatalf("nbf written from validFrom: %v", p["nbf"])
	}
}

func TestCheckTimeClaims(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name    string
		payload map[string]interface{}
		wantErr string
	}{
		{
			name:    "inside the window",
			payload: map[string]interface{}{"nbf": float64(now.Add(-time.Hour).Unix()), "exp": float64(now.Add(time.Hour).Unix())},
		},
		{
			name:    "no claims at all",
			payload: map[string]interface{}{},
		},
		{
			name:    "expired",
			payload: map[string]interface{}{"exp": float64(now.Add(-time.Second).Unix())},
			wantErr: "signature expired at",
		},
		{
			name:    "not yet valid",
			payload: map[string]interface{}{"nbf": float64(now.Add(time.Hour).Unix())},
			wantErr: "not valid before",
		},
		{
			name:    "exp exactly now is already expired",
			payload: map[string]interface{}{"exp": float64(now.Unix())},
			wantErr: "signature expired at",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckTimeClaims(tc.payload, now)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}
