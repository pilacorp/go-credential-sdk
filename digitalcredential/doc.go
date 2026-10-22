// IETF SD-JWT VC (`dc+sd-jwt`); for a W3C VC secured with SD-JWT (`vc+sd-jwt`) use `credential/vc`.
//
// Package digitalcredential issues, presents and verifies SD-JWT VC
// credentials (draft-ietf-oauth-sd-jwt-vc). Issue, Parse, Present and Verify
// are added in later steps; for now the module carries:
//
//   - statuslist: Token Status List (draft-ietf-oauth-status-list-21): build,
//     encode, sign and check status lists.
//
// The module imports jose from this repository and nothing else from it: no
// go-ethereum, no package of the root module.
package digitalcredential
