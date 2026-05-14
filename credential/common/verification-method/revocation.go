package verificationmethod

// Revocation reasons follow RFC 5280 §5.3.1 (CRL Reason Codes) naming where
// applicable. Pila keeps a minimal built-in taxonomy with two semantic tiers:
//
//	Soft reasons — credentials signed BEFORE the revoked timestamp remain
//	  valid. Used for planned key replacements and graceful key retirements.
//	Hard reasons — invalidate ALL credentials signed by the key, regardless
//	  of proof.created. Used when the private key is suspected or known to
//	  be compromised.
//
// Reference: https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1
const (
	ReasonSuperseded    = "superseded"
	ReasonKeyCompromise = "keyCompromise"
)

// IsHardRevocationReason reports whether the reason indicates a key
// compromise, in which case verifiers must reject every signature ever
// produced by the key.
func IsHardRevocationReason(reason string) bool {
	switch reason {
	// Only keyCompromise is "hard" in the DID context: it invalidates ALL
	// proofs signed by this key, regardless of signing time.
	//
	// Other reasons (including custom ones) are treated as "soft": proofs
	// created BEFORE the revoked timestamp may remain valid (subject to policy).
	case ReasonKeyCompromise:
		return true
	}
	return false
}
