package ecdsasd

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

const testProofContext = "https://w3id.org/security/data-integrity/v2"

// testProofConfig returns a complete proof configuration: the proof options
// plus the securing document's @context, as CreateBaseProof expects it.
func testProofConfig(context interface{}) map[string]interface{} {
	return map[string]interface{}{
		"@context":           context,
		"type":               "DataIntegrityProof",
		"cryptosuite":        Cryptosuite,
		"created":            "2024-01-01T00:00:00Z",
		"verificationMethod": "did:example:issuer#key-1",
		"proofPurpose":       "assertionMethod",
	}
}

// TestHashProofConfig_RejectsConfigThatCanonicalizesToNothing is a regression
// test. hashProofConfig used to canonicalize through the string-coercing
// CanonicalizeDocument, which returns an empty N-Quads set with no error when
// the @context does not define the proof terms. It then hashed sha256(""),
// leaving proofPurpose, verificationMethod, created and cryptosuite entirely
// unbound from the signature: an attacker could rewrite them and the proof
// still verified. CanonicalizeNative fails instead.
func TestHashProofConfig_RejectsConfigThatCanonicalizesToNothing(t *testing.T) {
	emptyHash := sha256.Sum256(nil)

	for _, tc := range []struct {
		name    string
		context interface{}
	}{
		{"no context", nil},
		{"context defining unrelated terms", map[string]interface{}{"name": "https://schema.org/name"}},
		{"context defining nothing", map[string]interface{}{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testProofConfig(tc.context)
			if tc.context == nil {
				delete(cfg, "@context")
			}

			got, err := hashProofConfig(cfg)
			if err == nil {
				t.Fatalf("expected an error, got hash %x", got)
			}
			if !strings.Contains(err.Error(), "hash proof config") {
				t.Fatalf("error = %q, want it wrapped by hashProofConfig", err)
			}
			if got != nil {
				t.Fatalf("expected no hash alongside the error, got %x", got)
			}
			if len(got) == len(emptyHash) && [32]byte(got) == emptyHash {
				t.Fatal("hashProofConfig returned sha256(\"\")")
			}
		})
	}
}

// TestHashProofConfig_BindsEveryProofOption: changing any option in the config
// must change the hash, or that option is not covered by the signature.
func TestHashProofConfig_BindsEveryProofOption(t *testing.T) {
	base, err := hashProofConfig(testProofConfig(testProofContext))
	if err != nil {
		t.Fatalf("hashProofConfig: %v", err)
	}

	for field, tampered := range map[string]string{
		"proofPurpose":       "authentication",
		"verificationMethod": "did:evil:attacker#key-9",
		"created":            "2030-06-06T00:00:00Z",
	} {
		t.Run(field, func(t *testing.T) {
			cfg := testProofConfig(testProofContext)
			cfg[field] = tampered
			got, err := hashProofConfig(cfg)
			if err != nil {
				t.Fatalf("hashProofConfig: %v", err)
			}
			if string(got) == string(base) {
				t.Fatalf("changing %q did not change the proof hash; it is not bound to the signature", field)
			}
		})
	}
}

// TestHashProofConfig_DoesNotMutateCaller: hashing must leave the caller's
// configuration and its nested @context untouched.
func TestHashProofConfig_DoesNotMutateCaller(t *testing.T) {
	nested := map[string]interface{}{"@vocab": "https://example.org/v#"}
	cfg := testProofConfig([]interface{}{testProofContext, nested})
	before := fmt.Sprint(cfg)

	if _, err := hashProofConfig(cfg); err != nil {
		t.Fatalf("hashProofConfig: %v", err)
	}

	if got := fmt.Sprint(cfg); got != before {
		t.Errorf("proof config was mutated\n got: %s\nwant: %s", got, before)
	}
	if _, ok := nested["@vocab"]; !ok || len(nested) != 1 {
		t.Errorf("nested @context object was mutated: %v", nested)
	}
}
