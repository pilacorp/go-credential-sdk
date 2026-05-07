package verificationmethod

// Revocation reasons follow RFC 5280 §5.3.1 (CRL Reason Codes). Pila uses a
// subset of those codes with two semantic tiers:
//
//   Soft reasons — credentials signed BEFORE the revoked timestamp remain
//     valid. Used for planned key replacements and graceful key retirements.
//   Hard reasons — invalidate ALL credentials signed by the key, regardless
//     of proof.created. Used when the private key is suspected or known to
//     be compromised.
//
// Reference: https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1
const (
	ReasonSuperseded           = "superseded"
	ReasonCessationOfOperation = "cessationOfOperation"
	ReasonKeyCompromise        = "keyCompromise"
	ReasonCACompromise         = "cACompromise"
	ReasonAACompromise         = "aACompromise"
)

// IsHardRevocationReason reports whether the reason indicates a key
// compromise, in which case verifiers must reject every signature ever
// produced by the key.
func IsHardRevocationReason(reason string) bool {
	switch reason {
	case ReasonKeyCompromise, ReasonCACompromise, ReasonAACompromise:
		return true
	}
	return false
}
