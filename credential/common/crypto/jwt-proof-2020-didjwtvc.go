package crypto

import (
	"github.com/pilacorp/go-credential-sdk/credential/internal/didjwtvc"
)

// A JwtProof2020 body that fails the VC-JWT 1.1 mapping check is accepted when
// it equals what did-jwt-vc, the library that defined JwtProof2020, decodes
// from the signed JWT (internal/didjwtvc). That object keeps the claims
// VC-JWT 1.1 does not map (iat, aud, nonce) and moves others in ways VCDM 1.1
// §6.3.1 leaves open. Every member of it comes from the signed payload, so a
// body equal to it is bound by the signature.
//
// did-jwt-vc leaves members it does not move (validFrom, validUntil, custom
// members) nested under vc or vp. Every check after this one reads the top
// level, so such a member would be signed but never checked; a body whose
// decoded form keeps one there is refused.

// bodyIsDidJwtVcForm reports whether body, without its proof, equals what
// did-jwt-vc decodes from the signed payload claims.
// The form shares nested values with claims; it is only compared, never
// changed, so claims stay as signed.
func bodyIsDidJwtVcForm(claims, body map[string]interface{}, isVP bool) bool {
	var form map[string]interface{}
	var err error
	claimKey := "vc"
	if isVP {
		claimKey = "vp"
		form, err = didjwtvc.NormalizePresentationPayload(claims)
	} else {
		form, err = didjwtvc.NormalizeCredentialPayload(claims)
	}
	if err != nil {
		return false
	}
	if leftover, ok := form[claimKey].(map[string]interface{}); ok {
		for k := range leftover {
			if _, onTop := form[k]; !onTop {
				return false
			}
		}
	}
	// did-jwt-vc sets proof to the JWT itself; the body's proof is what
	// carried the JWT here, so only the other members are compared.
	delete(form, "proof")
	rest := make(map[string]interface{}, len(body))
	for k, v := range body {
		if k != "proof" {
			rest[k] = v
		}
	}
	return jsonDeepEqual(rest, form)
}
