// Package jwttest builds and checks signatures without the code under test,
// so a test can tell whether the SDK was right to accept or refuse one.
package jwttest

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/jwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// SignExternally signs data the way a caller outside the SDK does: SHA-256,
// then the raw signer output (65 bytes for secp256k1).
func SignExternally(t *testing.T, s signer.SignerProvider, data string) []byte {
	t.Helper()
	digest := sha256.Sum256([]byte(data))
	sig, err := s.Sign(digest[:])
	if err != nil {
		t.Fatalf("external sign: %v", err)
	}
	return sig
}

// VerifyByHand builds signingInput.signature (r||s) and runs it through the
// SDK's JWT verifier.
func VerifyByHand(resolver verificationmethod.ResolverProvider, signingInput string, sig []byte) error {
	if len(sig) == 65 {
		sig = sig[:64]
	}
	return jwt.NewJWTVerifier(resolver).VerifyJWT(signingInput + "." + base64.RawURLEncoding.EncodeToString(sig))
}

// Counting wraps a signer and records how many digests reach it.
type Counting struct {
	signer.SignerProvider
	Calls int
}

// Sign counts the call and signs with the wrapped signer.
func (c *Counting) Sign(digest []byte) ([]byte, error) {
	c.Calls++
	return c.SignerProvider.Sign(digest)
}

// PadBitAlias sets the lowest unused bit of the last character of an
// unpadded base64url segment whose length is 2 mod 4 (a 64-byte signature
// is 86 characters, the last one carrying 4 unused bits). A lenient decoder
// returns the same bytes; with unused bits set it is not the canonical
// encoding (RFC 4648 §3.5) and a strict decoder refuses it.
func PadBitAlias(t testing.TB, seg string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	v := strings.IndexByte(alphabet, seg[len(seg)-1])
	if v < 0 || v&0x0f != 0 {
		t.Fatalf("last character %q is not a canonical 4-unused-bit character", seg[len(seg)-1])
	}
	return seg[:len(seg)-1] + string(alphabet[v|1])
}
