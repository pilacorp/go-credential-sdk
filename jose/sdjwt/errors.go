package sdjwt

import "errors"

// Every error the package returns for bad input wraps one of these, so a
// caller maps it with errors.Is and keeps the wrapped detail for logs. Errors
// caused by bad base64url or JSON also wrap jose.ErrMalformed.
var (
	// ErrMalformed: an SD-JWT, a disclosure or a payload member (_sd) that does
	// not have the required shape.
	ErrMalformed = errors.New("sdjwt: malformed")
	// ErrTooLarge: input over a Limits bound (bytes, disclosures, depth).
	ErrTooLarge = errors.New("sdjwt: too large")
	// ErrInvalidPath: a Path that is empty, has an element other than string
	// or int, does not exist in the claims, or is given twice.
	ErrInvalidPath = errors.New("sdjwt: invalid path")
	// ErrReservedName: _sd, _sd_alg or ... used as a claim name, or an object
	// holding ... that is not an array element placeholder.
	ErrReservedName = errors.New("sdjwt: reserved name")
	// ErrSalt: a SaltProvider that returned an empty or repeated salt.
	ErrSalt = errors.New("sdjwt: bad salt")
	// ErrDisclosureShape: a disclosure that is not [salt, value] or
	// [salt, name, value], or whose kind does not match where its digest is
	// (a 2-item disclosure for an _sd digest, a 3-item one for an array
	// element).
	ErrDisclosureShape = errors.New("sdjwt: disclosure shape")
	// ErrDuplicateDigest: a digest found twice in the payload or in disclosed
	// values, or the same disclosure given twice.
	ErrDuplicateDigest = errors.New("sdjwt: duplicate digest")
	// ErrUnreferencedDisclosure: a disclosure no digest points to.
	ErrUnreferencedDisclosure = errors.New("sdjwt: unreferenced disclosure")
	// ErrClaimExists: a disclosure that would overwrite a claim already in
	// its object.
	ErrClaimExists = errors.New("sdjwt: claim already exists")
	// ErrSDAlg: a top-level _sd_alg other than "sha-256", or _sd_alg below the
	// top level.
	ErrSDAlg = errors.New("sdjwt: unsupported or misplaced _sd_alg")

	// ErrKBInvalid: a Key Binding JWT with a bad signature, a typ other than
	// kb+jwt, a payload that is not a JSON object, or an iat outside the
	// accepted window.
	ErrKBInvalid = errors.New("sdjwt: invalid key binding JWT")
	// ErrKBAudience: aud missing, not a string, or not the expected audience.
	ErrKBAudience = errors.New("sdjwt: key binding JWT audience mismatch")
	// ErrKBNonce: nonce missing, not a string, or not the expected nonce.
	ErrKBNonce = errors.New("sdjwt: key binding JWT nonce mismatch")
	// ErrKBSDHash: sd_hash missing, not a string, or not the hash of the
	// presentation as received.
	ErrKBSDHash = errors.New("sdjwt: key binding JWT sd_hash mismatch")
)
