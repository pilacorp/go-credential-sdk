// Package jwtproof holds the JwtProof2020 header rules that
// credential/common/crypto and credential/common/jsonmap both check, so the
// rule has one home and is not part of the exported API.
package jwtproof

import (
	"fmt"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/internal/errtext"
	"github.com/pilacorp/go-credential-sdk/credential/internal/jwtutil"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
)

// CheckHeader applies to JwtProof2020 the header rules VCDM 1.1 §6.3.1 sets
// for JWT-encoded credentials: "alg MUST be set for digital signatures", and
// "typ, if present, MUST be set to JWT". This verifier checks secp256k1 with SHA-256 only, so alg must name
// that: ES256K (RFC 8812 §3.2) or ES256K-R, the recoverable form did-jwt, the
// library behind JwtProof2020, writes (did-jwt's name; IANA does not register
// it). The signature length is not tied to alg: a 65-byte signature labelled
// ES256K (go-ethereum's output) verifies as before. typ compares as a media
// type (RFC 7515 §4.1.9): any case, with or without "application/". crit
// names extensions the recipient must understand (RFC 7515 §4.1.11); this
// verifier understands none, so a header that lists any is refused.
func CheckHeader(jwtToken string) error {
	header, err := DecodeHeader(jwtToken)
	if err != nil {
		return err
	}
	alg, _ := header["alg"].(string)
	if alg != "ES256K" && alg != "ES256K-R" {
		return fmt.Errorf("JWT header alg %q is not supported: want ES256K or ES256K-R", errtext.Clip(alg))
	}
	if typ, present := header["typ"]; present {
		s, ok := typ.(string)
		if !ok || !(jws.Header{"typ": s}).TypIs("JWT") {
			return fmt.Errorf("JWT header typ must be JWT")
		}
	}
	if _, present := header["crit"]; present {
		return fmt.Errorf("JWT header crit is not supported: this verifier understands no JWS extension")
	}
	return nil
}

// DecodeHeader decodes the JOSE header of a compact JWT, a JSON object.
func DecodeHeader(jwtToken string) (map[string]interface{}, error) {
	dot := strings.IndexByte(jwtToken, '.')
	if dot <= 0 {
		return nil, fmt.Errorf("invalid JWT format")
	}
	// The payload is read by the same rules (jwtutil.DecodePayload).
	header, err := jwtutil.DecodeHeaderSegment(jwtToken[:dot])
	if err != nil {
		return nil, fmt.Errorf("JWT header is not a JSON object: %w", err)
	}
	return header, nil
}
