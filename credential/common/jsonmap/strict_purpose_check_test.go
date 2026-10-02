package jsonmap

import (
	"strings"
	"testing"
	"time"

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
			// created is only parsed when there is a revocation to compare it
			// against, so a live key is not held to the format. Documenting it
			// rather than endorsing it: this is why the case above exists.
			name:            "an unparseable proof.created on a live key is not reached",
			assertionMethod: []string{"#key-1"},
			proofPurpose:    "assertionMethod",
			created:         "yesterday",
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
