// Package digitalcredential implements IETF SD-JWT VC (dc+sd-jwt,
// draft-ietf-oauth-sd-jwt-vc-19); for a W3C VC secured with SD-JWT
// (vc+sd-jwt) use credential/vc.
//
// Issue signs an SD-JWT VC for an issuer, and Present builds what its holder
// sends to a verifier. Verifying comes in a later change.
package digitalcredential
