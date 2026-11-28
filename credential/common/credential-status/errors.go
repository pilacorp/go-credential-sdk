package credentialstatus

import (
	"errors"
	"fmt"
)

// The error types of Bitstring Status List v1.0: MALFORMED_VALUE_ERROR (§3),
// RANGE_ERROR (§3.2 step 10) and the three of §3.5. Every error this package
// returns for a status list or entry wraps one of them, or one of the SDK's
// own kinds below, except a caller bug: a missing resolver or ForPurpose on a
// nil list. A bit
// that is set is not an error kind: the list verified and the status holds.
//
// The list's fields are checked before its proof, so that a list refused for
// a cheap reason costs no DID resolution or canonicalization; the kind names
// the first check that failed. §3.2 checks proofs first, so a list that is
// both forged and malformed reports MALFORMED_VALUE_ERROR here where the
// algorithm would report STATUS_VERIFICATION_ERROR; either way it is refused.
var (
	// ErrStatusRetrieval: the status list could not be fetched or read (§3.2
	// step 4, STATUS_RETRIEVAL_ERROR). Retrying may help.
	ErrStatusRetrieval = errors.New("STATUS_RETRIEVAL_ERROR")
	// ErrStatusVerification: the list was fetched but did not verify (§3.5
	// STATUS_VERIFICATION_ERROR): a proof (§3.2 step 4) or its statusPurpose
	// (step 5), or one of this SDK's checks on its issuer and validity period.
	ErrStatusVerification = errors.New("STATUS_VERIFICATION_ERROR")
	// ErrStatusListLength: the bitstring is shorter than the 131,072 entries
	// §3.2 step 9 requires (STATUS_LIST_LENGTH_ERROR).
	ErrStatusListLength = errors.New("STATUS_LIST_LENGTH_ERROR")
	// ErrMalformedValue: an entry or list property breaks a MUST of §2 (§3,
	// MALFORMED_VALUE_ERROR).
	ErrMalformedValue = errors.New("MALFORMED_VALUE_ERROR")
	// ErrRange: the entry's index is outside the bitstring (§3.2 step 10,
	// RANGE_ERROR).
	ErrRange = errors.New("RANGE_ERROR")

	// ErrUnsupported: a conforming entry this reader does not check: a
	// statusPurpose other than revocation and suspension, or statusSize
	// other than 1 (§1.3 lets a processor support only size 1). Not a
	// Bitstring Status List error type.
	ErrUnsupported = errors.New("unsupported status entry")
	// ErrStatusListTooLarge: the response or the decompressed bitstring is
	// over this SDK's 16 MiB limit. Bitstring Status List sets no maximum, so
	// the list may be conforming; retrying does not help.
	ErrStatusListTooLarge = errors.New("status list too large")
)

var errorKinds = []error{ErrStatusRetrieval, ErrStatusVerification, ErrStatusListLength, ErrMalformedValue, ErrRange, ErrUnsupported, ErrStatusListTooLarge}

// withKind wraps err with kind, unless it already carries a kind.
func withKind(kind, err error) error {
	if err == nil {
		return nil
	}
	for _, k := range errorKinds {
		if errors.Is(err, k) {
			return err
		}
	}
	return fmt.Errorf("%w: %w", kind, err)
}
