// Package digitalcredential implements IETF SD-JWT VC (dc+sd-jwt,
// draft-ietf-oauth-sd-jwt-vc-19); for a W3C VC secured with SD-JWT
// (vc+sd-jwt) use credential/vc.
//
// Issue signs an SD-JWT VC for an issuer, Present builds what its holder
// sends to a verifier, and Verify checks what a verifier receives: the
// issuer's signature, the Disclosures, the claims, Key Binding and status.
package digitalcredential
