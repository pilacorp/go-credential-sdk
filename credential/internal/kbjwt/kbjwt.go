// Package kbjwt verifies the Key Binding JWT of an SD-JWT (RFC 9901 section
// 4.3) for both the credential and the presentation paths, so the two apply
// the same checks.
package kbjwt

import (
	"crypto"
	"fmt"
	"strings"
	"time"

	josesdjwt "github.com/pilacorp/go-credential-sdk/jose/sdjwt"

	"github.com/pilacorp/go-credential-sdk/credential/common/sdjwt"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// DefaultMaxAge is the oldest iat a KB-JWT may carry when the caller sets no
// maximum age.
const DefaultMaxAge = 5 * time.Minute

// Params are the verifier's expectations for the KB-JWT.
type Params struct {
	Audience  string
	Nonce     string
	MaxAge    time.Duration // DefaultMaxAge when zero or negative
	ClockSkew time.Duration
}

// Verify checks kbJWT against the holder key in payload's cnf.jwk and against
// the SD-JWT the verifier received: the issuer-signed JWT (signingInput and
// signature) followed by disclosures. kind names the token in error messages
// ("credential" or "presentation").
func Verify(kind string, payload map[string]interface{}, signingInput, signature string,
	disclosures []string, kbJWT string, p Params) error {
	if kbJWT == "" {
		return fmt.Errorf("KB-JWT required but not present")
	}
	// SDHash is sha-256 only. A token whose _sd_alg is another algorithm
	// cannot produce the right sd_hash, so the KB-JWT would never verify.
	if alg, _ := payload["_sd_alg"].(string); alg != "" && alg != sdjwt.DefaultHashAlgorithm {
		return fmt.Errorf("KB-JWT requires sha-256 disclosures; %s _sd_alg is %q", kind, alg)
	}
	holderKey, err := cnfKey(payload)
	if err != nil {
		return fmt.Errorf("KB-JWT: %w", err)
	}
	// sd_hash is computed over the SD-JWT as the verifier receives it,
	// without the KB-JWT (RFC 9901 section 4.3.1). Rebuild it from the
	// signed form.
	var sb strings.Builder
	sb.WriteString(signingInput + "." + signature)
	for _, d := range disclosures {
		if d == "" {
			continue
		}
		sb.WriteString("~")
		sb.WriteString(d)
	}
	sb.WriteString("~")

	maxAge := p.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	if _, err := josesdjwt.VerifyKBJWT(kbJWT, holderKey, josesdjwt.KBVerifyParams{
		Audience:  p.Audience,
		Nonce:     p.Nonce,
		SDHash:    josesdjwt.SDHash(sb.String()),
		MaxAge:    maxAge,
		ClockSkew: p.ClockSkew,
	}); err != nil {
		return fmt.Errorf("KB-JWT: %w", err)
	}
	return nil
}

// cnfKey reads the holder's public key from the cnf.jwk claim of a payload
// (RFC 9901 section 4.1.2, RFC 7800 section 3.2).
func cnfKey(payload map[string]interface{}) (crypto.PublicKey, error) {
	cnfRaw, ok := payload["cnf"]
	if !ok {
		return nil, fmt.Errorf("payload has no cnf claim; issuer must set cnf.jwk to bind a holder")
	}
	cnf, ok := cnfRaw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("cnf is %T, not a JSON object", cnfRaw)
	}
	jwkRaw, ok := cnf["jwk"]
	if !ok {
		return nil, fmt.Errorf("cnf has no jwk member")
	}
	jwkMap, ok := jwkRaw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("cnf.jwk is %T, not a JSON object", jwkRaw)
	}
	kty, _ := jwkMap["kty"].(string)
	crv, _ := jwkMap["crv"].(string)
	x, _ := jwkMap["x"].(string)
	y, _ := jwkMap["y"].(string)
	if kty == "" || crv == "" || x == "" || y == "" {
		return nil, fmt.Errorf("cnf.jwk is missing kty, crv, x or y")
	}
	pub, err := vmpkg.ECPubFromJWK(&vmpkg.JWK{Kty: kty, Crv: crv, X: x, Y: y})
	if err != nil {
		return nil, fmt.Errorf("cnf.jwk: %w", err)
	}
	return pub, nil
}
