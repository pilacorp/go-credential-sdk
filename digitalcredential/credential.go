// The SD-JWT VC object and its compact serialization: RFC 9901 §4.

package dc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

// Credential is one SD-JWT VC in compact form, an SD-JWT or an SD-JWT+KB
// (RFC 9901 §4). It holds only the string it was made from and never changes.
// Parse, Issue and Credential.Present make one; a nil or zero Credential is
// not a credential.
type Credential struct {
	compact string
}

// Parse reads compact, a credential as received, and keeps the string as is.
// It checks only the structure with sdjwt.Split: it reads no header, payload
// or signature, so it checks nothing a credential claims.
//
// A string sdjwt.Split refuses, a bare JWT without "~" or one over 1 MiB
// included, is *Error with CodeMalformed wrapping that error, so
// errors.Is(err, jose.ErrMalformed) holds too.
func Parse(compact string) (*Credential, error) {
	if _, _, _, err := sdjwt.Split(compact); err != nil {
		return nil, &Error{Code: CodeMalformed, Err: err}
	}
	return &Credential{compact: compact}, nil
}

// Serialize returns the string the credential was made from, exactly: the
// one passed to Parse, or the one Issue or Present built. A nil or zero
// Credential returns "".
func (c *Credential) Serialize() string {
	if c == nil {
		return ""
	}
	return c.compact
}

// Hash returns SHA-256, as 64 lowercase hex characters, of the Issuer-signed
// JWT exactly as held: the part of the string before the first "~" (RFC 9901
// §4). The credential Issue returns and every presentation of it have one
// hash, since a presentation changes only what follows the first "~". The
// signature is not normalized: the same JWT with its ECDSA S changed to n−S
// verifies under the same key and is another credential with another hash.
//
// Hash checks nothing, so take it only of a credential Issue just returned,
// or one a Verifier accepted. The Issuer-signed JWT is the same in every
// presentation, so this hash also links the presentations of one credential
// to each other (RFC 9901 §10.1). A nil or zero Credential is
// jose.ErrInvalidArgument, so that it never stands for the hash of "".
func (c *Credential) Hash() (string, error) {
	if c == nil || c.compact == "" {
		return "", fmt.Errorf("%w: dc: Hash of a nil or zero Credential; make one with Parse, Issue or Present", jose.ErrInvalidArgument)
	}
	// The Issuer-signed JWT ends at the first "~", a character the base64url
	// alphabet does not have.
	jwt, _, _ := strings.Cut(c.compact, "~")
	sum := sha256.Sum256([]byte(jwt))
	return hex.EncodeToString(sum[:]), nil
}

// compactSDJWT writes an SD-JWT in compact form (RFC 9901 §4): the
// Issuer-signed JWT, then each disclosure, each followed by "~", the last one
// too, from the bytes of each part as they are.
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
