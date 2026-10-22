// Package statuslist builds, signs and reads Token Status Lists
// (draft-ietf-oauth-status-list-21) for SD-JWT VC credentials.
//
// Issuer side (written from scratch from draft 21 §4 and §5): New / FromBytes,
// Set / Get, Encode (ZLIB at best compression, base64url), SignToken (a
// statuslist+jwt signed through jose.Sign), and ChainListID, the id under
// which List.Bytes() — exactly the inflated lst of the token — is anchored on
// chain.
//
// Verifier side: Decode (strict base64url, inflate limit) and Checker, which
// fetches a status list token through an SSRF-checking client, checks its
// signature with the credential issuer's key first, then typ, sub, iat and
// exp, reads the entry and caches the list by ttl. Every failure is an error,
// never a status value. Reading a list back from the chain is not part of this
// package yet.
//
// The root package digitalcredential imports statuslist (Verify returns a
// statuslist.Result), so statuslist never imports it. The few types both need
// are declared here and match the root ones by construction:
// IssuerKeyResolver has the method set of digitalcredential.IssuerKeyResolver,
// SigningKey the fields of digitalcredential.SigningKey, and Ref is the
// credential's status reference.
package statuslist
