// The compact serialization of an SD-JWT: RFC 9901 §4.

package digitalcredential

import (
	"crypto/sha256"
	"strings"

	"github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

// compactSDJWT writes an SD-JWT in compact form (RFC 9901 §4): the
// Issuer-signed JWT, then each disclosure, each followed by "~", the last one
// too. Issue and Present both write through it.
func compactSDJWT(issuerJWT string, disclosures []sdjwt.Disclosure) string {
	var b strings.Builder
	b.WriteString(issuerJWT)
	b.WriteByte('~')
	for _, d := range disclosures {
		b.WriteString(d.Encoded)
		b.WriteByte('~')
	}
	return b.String()
}

// Hash returns SHA-256 over the bytes of the Issuer-signed JWT of an SD-JWT
// VC exactly as given, the part of token before the first "~" (RFC 9901 §4).
// token is an SD-JWT or SD-JWT+KB in compact form, as Issue or Present writes
// it, or its Issuer-signed JWT alone, so an issued credential and every
// presentation of it have one hash; what follows the first "~" is neither read
// nor checked.
//
// The hash names these exact bytes, so take it from the string Issue returns.
// Any other serialization is a different credential, even one that verifies
// under the same key: the same token with its ECDSA signature's S flipped to
// n−S is one.
//
// Hash parses and verifies nothing and returns a hash for any string. Anyone
// can write a token, so its hash means nothing until the token is verified:
// it names a credential only for a token Issue returned or one [Verify]
// accepted. It names the signed credential, not who presents it; only Key
// Binding shows possession.
func Hash(token string) [32]byte {
	// The Issuer-signed JWT ends at the first "~", a character the base64url
	// alphabet does not have.
	jwt, _, _ := strings.Cut(token, "~")
	return sha256.Sum256([]byte(jwt))
}
