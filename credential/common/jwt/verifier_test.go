package jwt

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func encodePayload(t *testing.T, payload map[string]interface{}) string {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func TestJWTProofPurpose(t *testing.T) {
	cases := []struct {
		name        string
		header      map[string]interface{}
		payload     map[string]interface{}
		wantPurpose string
		wantErr     bool
	}{
		{
			name:        "vc+jwt header",
			header:      map[string]interface{}{"typ": "vc+jwt"},
			payload:     map[string]interface{}{"id": "urn:uuid:1"},
			wantPurpose: "assertionMethod",
		},
		{
			name:        "application/vc+jwt header",
			header:      map[string]interface{}{"typ": "application/vc+jwt"},
			payload:     map[string]interface{}{"id": "urn:uuid:1"},
			wantPurpose: "assertionMethod",
		},
		{
			name:        "vp+jwt header",
			header:      map[string]interface{}{"typ": "vp+jwt"},
			payload:     map[string]interface{}{"id": "urn:uuid:1"},
			wantPurpose: "authentication",
		},
		{
			name:        "legacy vc claim",
			header:      map[string]interface{}{"typ": "JWT"},
			payload:     map[string]interface{}{"vc": map[string]interface{}{}},
			wantPurpose: "assertionMethod",
		},
		{
			name:        "legacy vp claim",
			header:      map[string]interface{}{"typ": "JWT"},
			payload:     map[string]interface{}{"vp": map[string]interface{}{}},
			wantPurpose: "authentication",
		},
		{
			name:        "type array VerifiableCredential",
			header:      map[string]interface{}{},
			payload:     map[string]interface{}{"type": []interface{}{"VerifiableCredential", "AlumniCredential"}},
			wantPurpose: "assertionMethod",
		},
		{
			name:        "type array VerifiablePresentation",
			header:      map[string]interface{}{},
			payload:     map[string]interface{}{"type": []interface{}{"VerifiablePresentation"}},
			wantPurpose: "authentication",
		},
		{
			name:    "unknown payload and header",
			header:  map[string]interface{}{"typ": "JWT"},
			payload: map[string]interface{}{"foo": "bar"},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b64 := encodePayload(t, tc.payload)
			purpose, err := jwtProofPurpose(tc.header, b64)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got purpose %q", purpose)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if purpose != tc.wantPurpose {
				t.Fatalf("got purpose %q, want %q", purpose, tc.wantPurpose)
			}
		})
	}
}

func TestJWTIssuer(t *testing.T) {
	cases := []struct {
		name       string
		payload    map[string]interface{}
		wantIssuer string
		wantErr    bool
	}{
		{
			name:       "iss claim",
			payload:    map[string]interface{}{"iss": "did:example:iss"},
			wantIssuer: "did:example:iss",
		},
		{
			name:       "issuer string field",
			payload:    map[string]interface{}{"issuer": "did:example:issuer-string"},
			wantIssuer: "did:example:issuer-string",
		},
		{
			name:       "issuer object field with id",
			payload:    map[string]interface{}{"issuer": map[string]interface{}{"id": "did:example:issuer-obj"}},
			wantIssuer: "did:example:issuer-obj",
		},
		{
			name:       "holder string field",
			payload:    map[string]interface{}{"holder": "did:example:holder-string"},
			wantIssuer: "did:example:holder-string",
		},
		{
			name:       "holder object field with id",
			payload:    map[string]interface{}{"holder": map[string]interface{}{"id": "did:example:holder-obj"}},
			wantIssuer: "did:example:holder-obj",
		},
		{
			name:    "missing issuer",
			payload: map[string]interface{}{"id": "urn:uuid:1"},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b64 := encodePayload(t, tc.payload)
			issuer, err := jwtIssuer(b64)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got issuer %q", issuer)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if issuer != tc.wantIssuer {
				t.Fatalf("got issuer %q, want %q", issuer, tc.wantIssuer)
			}
		})
	}
}

func TestJWTIssuedAt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	// Test with iat integer
	p1 := map[string]interface{}{"iat": now.Unix()}
	tm1, err := jwtIssuedAt(encodePayload(t, p1))
	if err != nil || tm1 == nil || tm1.Unix() != now.Unix() {
		t.Fatalf("iat failed: got %v, err %v", tm1, err)
	}

	// Test with validFrom fallback
	p2 := map[string]interface{}{"validFrom": now.Format(time.RFC3339)}
	tm2, err := jwtIssuedAt(encodePayload(t, p2))
	if err != nil || tm2 == nil || tm2.Unix() != now.Unix() {
		t.Fatalf("validFrom fallback failed: got %v, err %v", tm2, err)
	}

	// Test when absent
	p3 := map[string]interface{}{"id": "urn:uuid:1"}
	tm3, err := jwtIssuedAt(encodePayload(t, p3))
	if err != nil || tm3 != nil {
		t.Fatalf("absent failed: got %v, err %v", tm3, err)
	}
}
