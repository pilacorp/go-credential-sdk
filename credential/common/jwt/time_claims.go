package jwt

import (
	"encoding/json"
	"fmt"
	"time"
)

// The RFC 7519 time claims a vc-jose-cose token carries beside the document.
//
// These describe the SIGNATURE, not the credential. vc-jose-cose § Claims is
// explicit: "When the iat (Issued At) and/or exp (Expiration Time) JWT claims
// are present, they represent the issuance and expiration time of the
// signature, respectively. Note that these are different from the validFrom and
// validUntil properties defined in Validity Period, which represent the
// validity of the data that is being secured."
//
// So the two pairs are deliberately NOT mirrors of each other and must not be
// cross-checked: a credential valid until 2030 may carry a signature that
// expires next month, and both statements are true at once. The spec's list of
// claim/property pairs that must not conflict — iss/issuer, jti/id,
// sub/credentialSubject.id — leaves exp and nbf out for this reason.

// SetIssuedAt records when the signature was produced. RFC 7519 §4.1.6 defines
// iat as the time the JWT was issued, and vc-jose-cose reads it as the issuance
// time of the signature; the soft-revocation check asks exactly that question.
//
// exp is not written alongside it. It would mean "this signature stops being
// acceptable then", which is a policy the SDK has no basis to invent, and
// deriving it from validUntil would state the credential's validity in a field
// reserved for the signature's. nbf is not written either — vc-jose-cose says
// its use "is NOT RECOMMENDED, as it makes little sense to attempt to assign a
// future date to a signature".
func SetIssuedAt(payload map[string]interface{}, signedAt time.Time) {
	payload["iat"] = signedAt.Unix()
}

// CheckTimeClaims enforces RFC 7519 §4.1.4–4.1.5 on a token that carries these
// claims: a JWT "MUST NOT be accepted for processing" on or after exp, nor
// before nbf. Issuers using other implementations do set them, and nothing read
// them before. nbf is still honoured when present even though this SDK does not
// produce it, since the RFC binds on what the token says, not on who wrote it.
func CheckTimeClaims(payload map[string]interface{}, now time.Time) error {
	sec, ok, err := numericClaim(payload, "nbf")
	if err != nil {
		return err
	}
	if ok && now.Before(time.Unix(sec, 0)) {
		return fmt.Errorf("signature is not valid before %s (nbf)", time.Unix(sec, 0).UTC().Format(time.RFC3339))
	}

	sec, ok, err = numericClaim(payload, "exp")
	if err != nil {
		return err
	}
	if ok && !now.Before(time.Unix(sec, 0)) {
		return fmt.Errorf("signature expired at %s (exp)", time.Unix(sec, 0).UTC().Format(time.RFC3339))
	}
	return nil
}

// numericClaim reads a NumericDate claim. JSON numbers decode as float64, but a
// decoder set to UseNumber yields json.Number, and claims assembled in memory
// before signing are still int64.
func numericClaim(payload map[string]interface{}, name string) (int64, bool, error) {
	raw, ok := payload[name]
	if !ok || raw == nil {
		return 0, false, nil
	}
	var sec int64
	switch t := raw.(type) {
	case float64:
		sec = int64(t)
	case int64:
		sec = t
	case json.Number:
		v, err := t.Int64()
		if err != nil {
			return 0, false, fmt.Errorf("invalid %s value: %w", name, err)
		}
		sec = v
	default:
		return 0, false, fmt.Errorf("invalid %s type: %T", name, raw)
	}
	if sec <= 0 {
		return 0, false, fmt.Errorf("invalid %s value: %v", name, raw)
	}
	return sec, true, nil
}
