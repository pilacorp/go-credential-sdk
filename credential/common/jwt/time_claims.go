package jwt

import (
	"encoding/json"
	"fmt"
	"time"
)

// SetIssuedAt records when the signature was produced, which is what the
// soft-revocation check compares against. Per vc-jose-cose § Claims these time
// claims describe the signature, not the credential, and are "different from
// the validFrom and validUntil properties" — so nothing here is derived from
// the validity period. exp is left out because the SDK has no signature expiry
// policy to state, and nbf because the spec calls its use NOT RECOMMENDED.
func SetIssuedAt(payload map[string]interface{}, signedAt time.Time) {
	payload["iat"] = signedAt.Unix()
}

// CheckTimeClaims enforces RFC 7519 §4.1.4–4.1.5: a JWT "MUST NOT be accepted
// for processing" on or after exp, nor before nbf. Issuers on other
// implementations set them even though this SDK does not, and the RFC binds on
// what the token says rather than on who wrote it.
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
