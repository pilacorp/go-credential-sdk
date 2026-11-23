package jsonmap

import (
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// strictPurposeCheck is what separates "this signature is valid" from "this key
// was allowed to make it". Every JSON-LD verifier in the package ends on it —
// ecdsa-rdfc-2019, ecdsa-sd-2023, JsonWebSignature2020 and
// EcdsaSecp256k1Signature2019 — and so does the JWT one. A key listed only
// under authentication must not be able to issue a credential, and a revoked
// key must stop working on the terms its revocation reason sets.
//
// The table drives the function directly so every branch is reachable without
// signing anything; the two tests below it prove one verifier is actually
// wired to it.

const (
	purposeDID = "did:example:purpose"
	purposeVM  = purposeDID + "#key-1"
)

func mustTime(t *testing.T, value string) *time.Time {
	t.Helper()

	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("fixture timestamp %q: %v", value, err)
	}

	return &parsed
}

func TestStrictPurposeCheck(t *testing.T) {
	for _, tc := range []struct {
		name            string
		assertionMethod []string
		authentication  []string
		revoked         string
		reason          string
		proofPurpose    string
		created         string
		wantErr         string
	}{
		{
			name:            "a key granted the purpose it claims",
			assertionMethod: []string{"#key-1"},
			proofPurpose:    "assertionMethod",
			created:         "2026-06-01T00:00:00Z",
		},
		{
			// idInArray accepts either spelling, because a DID document may
			// write the relationship as a fragment or as the full URL.
			name:            "the same grant written as a full URL",
			assertionMethod: []string{purposeVM},
			proofPurpose:    "assertionMethod",
			created:         "2026-06-01T00:00:00Z",
		},
		{
			name:           "a login key may not issue a credential",
			authentication: []string{"#key-1"},
			proofPurpose:   "assertionMethod",
			created:        "2026-06-01T00:00:00Z",
			wantErr:        "is not granted purpose 'assertionMethod'",
		},
		{
			name:            "an issuing key may not authenticate",
			assertionMethod: []string{"#key-1"},
			proofPurpose:    "authentication",
			created:         "2026-06-01T00:00:00Z",
			wantErr:         "is not granted purpose 'authentication'",
		},
		{
			// capabilityInvocation and capabilityDelegation are deliberately
			// not modelled; an unknown purpose is refused rather than waved
			// through on an empty relationship array.
			name:            "a purpose this SDK does not model",
			assertionMethod: []string{"#key-1"},
			proofPurpose:    "capabilityInvocation",
			created:         "2026-06-01T00:00:00Z",
			wantErr:         "unsupported proofPurpose 'capabilityInvocation'",
		},
		{
			name:            "signed after a soft revocation",
			assertionMethod: []string{"#key-1"},
			revoked:         "2026-03-10T00:00:00Z",
			reason:          verificationmethod.ReasonSuperseded,
			proofPurpose:    "assertionMethod",
			created:         "2026-06-01T00:00:00Z",
			wantErr:         "is not earlier",
		},
		{
			// The case that matters most for the people already holding
			// credentials: retiring a key must not invalidate what it signed
			// while it was live. A future "tighten this up" change that drops
			// the comparison lands here.
			name:            "signed before a soft revocation stays valid",
			assertionMethod: []string{"#key-1"},
			revoked:         "2026-06-01T00:00:00Z",
			reason:          verificationmethod.ReasonSuperseded,
			proofPurpose:    "assertionMethod",
			created:         "2026-03-10T00:00:00Z",
		},
		{
			// The boundary is exclusive: the check is created.Before(revoked),
			// so a proof stamped at the revocation instant is already too late.
			name:            "signed at the exact revocation instant",
			assertionMethod: []string{"#key-1"},
			revoked:         "2026-06-01T00:00:00Z",
			reason:          verificationmethod.ReasonSuperseded,
			proofPurpose:    "assertionMethod",
			created:         "2026-06-01T00:00:00Z",
			wantErr:         "is not earlier",
		},
		{
			// A compromised key is assumed to have been in the wrong hands
			// before anyone noticed, so the signing time proves nothing.
			name:            "keyCompromise invalidates even earlier signatures",
			assertionMethod: []string{"#key-1"},
			revoked:         "2026-06-01T00:00:00Z",
			reason:          verificationmethod.ReasonKeyCompromise,
			proofPurpose:    "assertionMethod",
			created:         "2026-03-10T00:00:00Z",
			wantErr:         "revoked with hard reason 'keyCompromise'",
		},
		{
			name:            "a hard reason with no revoked timestamp still rejects",
			assertionMethod: []string{"#key-1"},
			reason:          verificationmethod.ReasonKeyCompromise,
			proofPurpose:    "assertionMethod",
			created:         "2026-03-10T00:00:00Z",
			wantErr:         "revoked with hard reason 'keyCompromise'",
		},
		{
			name:            "an unparseable proof.created on a revoked key",
			assertionMethod: []string{"#key-1"},
			revoked:         "2026-06-01T00:00:00Z",
			reason:          verificationmethod.ReasonSuperseded,
			proofPurpose:    "assertionMethod",
			created:         "yesterday",
			wantErr:         "invalid proof.created timestamp",
		},
		{
			// A revoked key needs created to show the proof came first.
			name:            "a missing proof.created on a revoked key",
			assertionMethod: []string{"#key-1"},
			revoked:         "2026-06-01T00:00:00Z",
			reason:          verificationmethod.ReasonSuperseded,
			proofPurpose:    "assertionMethod",
			wantErr:         "proof has no created",
		},
		{
			// DI 1.0 §2.1: when created is present it is a dateTimeStamp,
			// whether or not the key is revoked.
			name:            "an unparseable proof.created on a live key",
			assertionMethod: []string{"#key-1"},
			proofPurpose:    "assertionMethod",
			created:         "yesterday",
			wantErr:         "invalid proof.created timestamp",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vm := verificationmethod.VerificationMethodEntry{
				ID:               purposeVM,
				Type:             "EcdsaSecp256k1VerificationKey2019",
				Controller:       purposeDID,
				RevocationReason: tc.reason,
			}
			if tc.revoked != "" {
				vm.Revoked = mustTime(t, tc.revoked)
			}
			doc := &verificationmethod.DIDDocument{
				ID:                 purposeDID,
				VerificationMethod: []verificationmethod.VerificationMethodEntry{vm},
				AssertionMethod:    tc.assertionMethod,
				Authentication:     tc.authentication,
			}

			err := strictPurposeCheck(doc, &vm, tc.proofPurpose, tc.created)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("a proof that should be accepted was refused: %v", err)
				}

				return
			}
			if err == nil {
				t.Fatalf("accepted, want an error mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one mentioning %q", err, tc.wantErr)
			}
		})
	}
}

// DI 1.0 §2.1: when created is present it must be an XML Schema dateTimeStamp.
// time.RFC3339 gets this wrong in both directions: it accepts a comma fraction
// and offsets past +14:00, and refuses T24:00:00Z.
func TestParseCreated(t *testing.T) {
	for _, tc := range []struct {
		input string
		ok    bool
	}{
		{"2026-01-01T00:00:00Z", true},
		{"2026-01-01T00:00:00+09:00", true},
		{"2026-01-01T00:00:00-05:30", true},
		{"2026-01-01T00:00:00.123Z", true},
		{"2026-01-01T00:00:00.123456789Z", true},
		{"2026-01-01T24:00:00Z", true},      // end of day is valid
		{"2026-01-01T24:00:00.0Z", true},    // end of day with zero fraction
		{"2026-01-01T00:00:00+14:00", true}, // max offset
		{"2026-01-01T00:00:00-00:00", true}, // negative zero offset

		{"2026-01-01T00:00:00,5Z", false},    // comma fraction: not dateTimeStamp
		{"2026-01-01T00:00:00+14:01", false}, // offset past +14:00
		{"2026-01-01T00:00:00+23:59", false}, // RFC3339 accepts; dateTimeStamp refuses
		{"2026-01-01T00:00:00", false},       // missing time zone
		{"not-a-date", false},                // garbage
		{"yesterday", false},                 // word
		{"", false},                          // empty
		{"2026-01-01", false},                // date only
		{"2026-01-01T24:00:01Z", false},      // past end of day
		{"2026-01-01T24:01:00Z", false},      // past end of day
		{"2026-01-01T25:00:00Z", false},      // hour 25
		{"2026-01-01T00:60:00Z", false},      // minute 60
		{"2026-01-01T00:00:60Z", false},      // second 60
	} {
		_, err := parseCreated(tc.input)
		if tc.ok && err != nil {
			t.Errorf("parseCreated(%q): unexpected error: %v", tc.input, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("parseCreated(%q): want error, got nil", tc.input)
		}
	}
}

// T24:00:00Z (end of day) is 00:00:00 on the next day.
func TestParseCreated_EndOfDay(t *testing.T) {
	got, err := parseCreated("2026-01-01T24:00:00Z")
	if err != nil {
		t.Fatalf("parseCreated: %v", err)
	}
	want := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// A non-string created (number, object, array) goes into proof.Extra and must
// be refused.
func TestVerifyProof_RefusesNonStringCreated(t *testing.T) {
	sp, pub := testKeyPair(t)
	for _, created := range []interface{}{42, map[string]interface{}{"v": 1}, []interface{}{"a"}} {
		m := testCredential()
		proof := &dto.Proof{
			Type:               DataIntegrityProof,
			Created:            "2024-01-01T00:00:00Z",
			VerificationMethod: "did:example:issuer#key-1",
			ProofPurpose:       "assertionMethod",
			Cryptosuite:        ECDSARDFC2019,
		}
		attachSignedECDSAProof(t, &m, sp, proof)

		// Tamper with the proof's created field after signing: set a non-string
		// value that the decoder puts into Extra.
		rawProof := m.getFirstProof().(map[string]interface{})
		rawProof["created"] = created
		m["proof"] = rawProof

		ok, err := (&m).VerifyProof(issuerResolver(t, pub), "")
		if err == nil && ok {
			t.Errorf("created=%T: verified, want refusal", created)
		}
		if err == nil || !strings.Contains(err.Error(), "proof.created") {
			t.Errorf("created=%T: err = %v, want a proof.created error", created, err)
		}
	}
}
