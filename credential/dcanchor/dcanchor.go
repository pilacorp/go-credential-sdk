// Package dcanchor holds NDA DID's anchoring conventions for an SD-JWT VC
// (draft-ietf-oauth-sd-jwt-vc-19), the digital credential of module
// github.com/pilacorp/go-credential-sdk/digitalcredential: the leaf of an
// issued credential, which goes into a Merkle tree whose root is anchored (see
// package vcanchor), and the id under which a Token Status List
// (draft-ietf-oauth-status-list-21) is anchored. Neither is a rule of a
// standard; the standard rules they rest on are cited where they are applied.
// The digitalcredential module does not import this package.
package dcanchor

import (
	"crypto/sha256"
	"strconv"
	"strings"
)

// Leaf returns the anchoring leaf of an SD-JWT VC: SHA-256 over the bytes of
// its Issuer-signed JWT exactly as given, the part of token before the first
// "~" (RFC 9901 §4). token is an SD-JWT or SD-JWT+KB in compact form, as
// digitalcredential.Issue or Present writes it, or its Issuer-signed JWT
// alone, so an issued credential and every presentation of it have one leaf;
// what follows the first "~" is neither read nor checked.
//
// The leaf identifies these exact bytes, so take it from the string Issue
// returns. Any other serialization is a different credential with no
// anchored leaf, even one that verifies under the same key: the same token
// with its ECDSA signature's S flipped to n−S is one.
//
// Leaf parses and verifies nothing and returns a leaf for any string. Anyone
// can write a token, so its leaf means nothing until the token is verified:
// the leaf identifies a credential only for a token Issue returned, or one
// verified as an SD-JWT VC (its Issuer's signature,
// draft-ietf-oauth-sd-jwt-vc-19 §2.4, and typ dc+sd-jwt, §2.2.1), as
// [github.com/pilacorp/go-credential-sdk/digitalcredential.Verify] does. It
// names the signed credential, not who presents it: a presented token whose
// leaf is anchored proves no possession of the credential, which only Key
// Binding shows.
func Leaf(token string) [32]byte {
	// RFC 9901 §4: the Issuer-signed JWT is the part before the first "~",
	// a character the base64url alphabet does not have.
	jwt, _, _ := strings.Cut(token, "~")
	return sha256.Sum256([]byte(jwt))
}

// ChainListID returns the id under which NDA DID anchors a Token Status List
// of SD-JWT VCs: "dc-b", bits in decimal, "-", listID in decimal with no
// leading zero, e.g. "dc-b1-7". bits is the entry width of the list whose
// bytes are anchored (draft-ietf-oauth-status-list-21 §4.1), so a reader of
// the chain knows how to read them; listID is the issuer's id of the list,
// unique among its lists. An id always starts with "dc-", so it never equals
// an id of decimal digits only, the form NDA DID's W3C VC lists use. Neither
// argument is checked: a bits other than 1, 2, 4 or 8 gives an id that no
// reader computing it from a token finds.
func ChainListID(bits int, listID uint64) string {
	return "dc-b" + strconv.Itoa(bits) + "-" + strconv.FormatUint(listID, 10)
}
