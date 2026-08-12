package sdjwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// mkDisclosure encodes a disclosure array and returns it with its digest.
func mkDisclosure(t *testing.T, sdAlg string, arr ...interface{}) (string, string) {
	t.Helper()

	b, err := json.Marshal(arr)
	if err != nil {
		t.Fatalf("marshal disclosure: %v", err)
	}
	disc := base64.RawURLEncoding.EncodeToString(b)

	h, err := hashDisclosure(sdAlg, disc)
	if err != nil {
		t.Fatalf("hash disclosure: %v", err)
	}

	return disc, h
}

func TestValidateDisclosureDigests(t *testing.T) {
	nameDisc, nameHash := mkDisclosure(t, AlgSHA256, "salt-1", "name", "Alice")
	elemDisc, elemHash := mkDisclosure(t, AlgSHA256, "salt-2", "gold")
	orphanDisc, _ := mkDisclosure(t, AlgSHA256, "salt-3", "role", "admin")

	// Digests nested under a "vc" claim, as this SDK's JWT credentials encode them.
	payload := func() map[string]interface{} {
		return map[string]interface{}{
			"iss": "did:example:issuer",
			"vc": map[string]interface{}{
				"_sd_alg": AlgSHA256,
				"credentialSubject": map[string]interface{}{
					"_sd":  []interface{}{nameHash, "ZGVjb3ktZGlnZXN0LXdpdGgtbm8tZGlzY2xvc3VyZQ"},
					"tags": []interface{}{map[string]interface{}{"...": elemHash}, "verified"},
				},
			},
		}
	}

	tests := []struct {
		name        string
		payload     map[string]interface{}
		disclosures []string
		wantErr     string
	}{
		{
			name:        "no disclosures",
			payload:     payload(),
			disclosures: nil,
		},
		{
			name:        "object field and array element both referenced",
			payload:     payload(),
			disclosures: []string{nameDisc, elemDisc},
		},
		{
			name:        "empty strings are skipped",
			payload:     payload(),
			disclosures: []string{"", nameDisc, ""},
		},
		{
			name:        "orphan disclosure is rejected",
			payload:     payload(),
			disclosures: []string{nameDisc, orphanDisc},
			wantErr:     "not present in the issuer-signed payload",
		},
		{
			name:        "same disclosure presented twice",
			payload:     payload(),
			disclosures: []string{nameDisc, nameDisc},
			wantErr:     "presented more than once",
		},
		{
			name:        "malformed disclosure",
			payload:     payload(),
			disclosures: []string{"not-base64url!!"},
			wantErr:     "failed to decode disclosure",
		},
		{
			name: "digest hashed under a different algorithm is rejected",
			payload: map[string]interface{}{
				"vc": map[string]interface{}{
					"_sd_alg": AlgSHA512,
					"_sd":     []interface{}{nameHash},
				},
			},
			disclosures: []string{nameDisc},
			wantErr:     "not present in the issuer-signed payload",
		},
		{
			name: "unsupported _sd_alg",
			payload: map[string]interface{}{
				"vc": map[string]interface{}{"_sd_alg": "md5", "_sd": []interface{}{nameHash}},
			},
			disclosures: []string{nameDisc},
			wantErr:     "unsupported _sd_alg",
		},
		{
			name: "conflicting _sd_alg values",
			payload: map[string]interface{}{
				"_sd_alg": AlgSHA256,
				"vc":      map[string]interface{}{"_sd_alg": AlgSHA512, "_sd": []interface{}{nameHash}},
			},
			disclosures: []string{nameDisc},
			wantErr:     "conflicting _sd_alg",
		},
		{
			name: "_sd_alg absent defaults to sha-256",
			payload: map[string]interface{}{
				"vc": map[string]interface{}{"_sd": []interface{}{nameHash}},
			},
			disclosures: []string{nameDisc},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDisclosureDigests(tt.payload, tt.disclosures)

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateDisclosureDigests() = %v, want nil", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("ValidateDisclosureDigests() = nil, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestValidateDisclosureDigests_MatchesIssuedCredential ties the check to
// BuildDisclosures: everything the issuer emits must pass validation against the
// payload it produced.
func TestValidateDisclosureDigests_MatchesIssuedCredential(t *testing.T) {
	vcMap := map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"name":  "Alice",
			"email": "alice@example.com",
			"tags":  []interface{}{"gold", "verified"},
		},
	}

	for _, sdAlg := range []string{AlgSHA256, AlgSHA384, AlgSHA512} {
		t.Run(sdAlg, func(t *testing.T) {
			result, err := BuildDisclosures(BuildDisclosuresInput{
				VC: vcMap,
				SelectivePaths: []string{
					"credentialSubject.name",
					"credentialSubject.email",
					"credentialSubject.tags[0]",
				},
				HashAlgorithm: sdAlg,
				Shuffle:       true,
				Decoys:        []DecoyConfig{{Path: "credentialSubject", Count: 3}},
			})
			if err != nil {
				t.Fatalf("build disclosures: %v", err)
			}

			payload := map[string]interface{}{"vc": result.ProcessedVC}
			if err := ValidateDisclosureDigests(payload, result.Disclosures); err != nil {
				t.Fatalf("issued disclosures failed validation: %v", err)
			}
		})
	}
}
