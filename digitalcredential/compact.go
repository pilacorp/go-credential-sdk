// The compact serialization of an SD-JWT: RFC 9901 §4.

package digitalcredential

import (
	"strings"

	"github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

// compactSDJWT writes an SD-JWT in compact form (RFC 9901 §4): the
// Issuer-signed JWT, then each disclosure, each followed by "~", the last one
// too.
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
