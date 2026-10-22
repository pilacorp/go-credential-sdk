// Package jose signs and verifies compact JWS (RFC 7515) with ES256 (P-256)
// and ES256K (secp256k1), and converts EC public keys to and from JWK.
//
// It is the part the SD-JWT formats share: dc+sd-jwt (module
// digitalcredential) uses it now, and vc+sd-jwt can move onto it later. It
// knows nothing about SD-JWT, disclosures or vct.
//
// The module imports neither go-ethereum nor the root module of
// go-credential-sdk. Signing goes through Signer, which has the same method set
// as credential/common/signer.SignerProvider, so every existing provider
// (in-memory, Vault callback) works without importing go-ethereum.
//
// Everything a token carries is read strictly, so that one token has one
// reading: base64url without padding, line breaks or non-zero trailing bits
// (DecodeSegment), JSON without duplicate keys or trailing data and with
// numbers kept as json.Number (DecodeJSON).
package jose
