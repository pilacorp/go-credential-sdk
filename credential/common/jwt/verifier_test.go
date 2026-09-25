package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
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

func TestJWTSigner(t *testing.T) {
	const (
		vcPurpose = "assertionMethod"
		vpPurpose = "authentication"
	)

	cases := []struct {
		name       string
		purpose    string
		payload    map[string]interface{}
		wantSigner string
		wantErr    string
	}{
		{
			name:       "iss claim alone",
			purpose:    vcPurpose,
			payload:    map[string]interface{}{"iss": "did:example:iss"},
			wantSigner: "did:example:iss",
		},
		{
			name:       "issuer string field alone",
			purpose:    vcPurpose,
			payload:    map[string]interface{}{"issuer": "did:example:issuer-string"},
			wantSigner: "did:example:issuer-string",
		},
		{
			name:       "issuer object field with id",
			purpose:    vcPurpose,
			payload:    map[string]interface{}{"issuer": map[string]interface{}{"id": "did:example:issuer-obj"}},
			wantSigner: "did:example:issuer-obj",
		},
		{
			name:       "holder string field alone",
			purpose:    vpPurpose,
			payload:    map[string]interface{}{"holder": "did:example:holder-string"},
			wantSigner: "did:example:holder-string",
		},
		{
			name:       "holder object field with id",
			purpose:    vpPurpose,
			payload:    map[string]interface{}{"holder": map[string]interface{}{"id": "did:example:holder-obj"}},
			wantSigner: "did:example:holder-obj",
		},
		{
			name:       "iss agrees with issuer",
			purpose:    vcPurpose,
			payload:    map[string]interface{}{"iss": "did:example:a", "issuer": "did:example:a"},
			wantSigner: "did:example:a",
		},
		{
			name:       "iss agrees with issuer.id",
			purpose:    vcPurpose,
			payload:    map[string]interface{}{"iss": "did:example:a", "issuer": map[string]interface{}{"id": "did:example:a"}},
			wantSigner: "did:example:a",
		},
		{
			name:       "VC 1.1: iss agrees with the nested vc.issuer",
			purpose:    vcPurpose,
			payload:    map[string]interface{}{"iss": "did:example:a", "vc": map[string]interface{}{"issuer": "did:example:a"}},
			wantSigner: "did:example:a",
		},

		// The rule this function exists for: signing with one key while
		// naming another party as the issuer must not verify.
		{
			name:    "iss contradicts issuer",
			purpose: vcPurpose,
			payload: map[string]interface{}{"iss": "did:example:attacker", "issuer": "did:example:victim"},
			wantErr: `iss "did:example:attacker" does not match issuer "did:example:victim"`,
		},
		{
			name:    "iss contradicts issuer.id",
			purpose: vcPurpose,
			payload: map[string]interface{}{"iss": "did:example:attacker", "issuer": map[string]interface{}{"id": "did:example:victim"}},
			wantErr: `iss "did:example:attacker" does not match issuer "did:example:victim"`,
		},
		{
			name:    "iss contradicts holder",
			purpose: vpPurpose,
			payload: map[string]interface{}{"iss": "did:example:attacker", "holder": "did:example:victim"},
			wantErr: `iss "did:example:attacker" does not match holder "did:example:victim"`,
		},
		{
			name:    "VC 1.1: iss contradicts the nested vc.issuer",
			purpose: vcPurpose,
			payload: map[string]interface{}{"iss": "did:example:attacker", "vc": map[string]interface{}{"issuer": "did:example:victim"}},
			wantErr: `iss "did:example:attacker" does not match issuer "did:example:victim"`,
		},

		// A presentation never takes its signer from issuer: doing so would
		// let anyone name a holder the presentation never had.
		{
			name:    "presentation does not fall back to issuer",
			purpose: vpPurpose,
			payload: map[string]interface{}{"issuer": "did:example:attacker"},
			wantErr: "both iss and holder are absent",
		},
		{
			name:    "credential does not fall back to holder",
			purpose: vcPurpose,
			payload: map[string]interface{}{"holder": "did:example:someone"},
			wantErr: "both iss and issuer are absent",
		},
		{
			name:    "no signer named at all",
			purpose: vcPurpose,
			payload: map[string]interface{}{"id": "urn:uuid:1"},
			wantErr: "both iss and issuer are absent",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b64 := encodePayload(t, tc.payload)
			signer, err := jwtSigner(b64, tc.purpose)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error, got signer %q", signer)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if signer != tc.wantSigner {
				t.Fatalf("got signer %q, want %q", signer, tc.wantSigner)
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
