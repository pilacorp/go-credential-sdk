// Integrity of referenced documents: draft-ietf-oauth-sd-jwt-vc-19 §6, the
// "integrity metadata" string of W3C Subresource Integrity (REC 2016-06-23)
// §3.5.

package typemeta

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/sri"
)

// Integrity returns "sha256-" and the base64 SHA-256 of doc: the integrity
// metadata an issuer writes as vct#integrity, and a publisher as
// extends#integrity or uri#integrity, over exactly the bytes served.
func Integrity(doc []byte) string {
	sum := sha256.Sum256(doc)
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

// CheckIntegrity checks data against integrity as draft 19 §6 says, reading
// the string per SRI §3.5 and §3.3.3: tokens split on whitespace, the
// options after "?" dropped; a token is sha256, sha384 or sha512 in any
// case, "-", and base64 of the standard alphabet (CSP Level 2 §4.2). Other
// tokens are ignored. Only the tokens of the strongest algorithm left count,
// and data passes when its digest equals one of them, octet for octet. CORS
// plays no part (§6). An error wraps ErrInvalid: no token left, or none
// matches. A display application checks with it the logo, background image
// and SVG templates it fetches.
func CheckIntegrity(data []byte, integrity string) error {
	if err := sri.Check(data, integrity); err != nil {
		return fmt.Errorf("%w: typemeta: %v (draft-ietf-oauth-sd-jwt-vc-19 §6)", ErrInvalid, err)
	}
	return nil
}
