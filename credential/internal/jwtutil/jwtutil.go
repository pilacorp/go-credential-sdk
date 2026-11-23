// Package jwtutil holds the JWT helpers that credential/vc, credential/vp and
// credential/common/jwt all need.
//
// It lives under internal/ deliberately. These are not API: nothing outside this
// module calls them, and anything exported from credential/common/jwt has to
// keep working forever once a version is tagged. Keeping them here means the
// three packages can share one copy without that promise.
package jwtutil

import (
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// SetIssuedAt records when the signing input was fixed — which is when the
// credential or presentation was built, not when it was signed. The two are the
// same moment for AddProofByProvider and can be far apart for AddCustomProof,
// where an HSM or an approval step signs later; a signature attached then does
// not move iat, because moving it would change the bytes the signature covers.
//
// That is what the soft-revocation check compares against. Per vc-jose-cose
// § Claims these time claims describe the signature, not the credential, and are
// "different from the validFrom and validUntil properties" — so nothing here is
// derived from the validity period. exp is left out because the SDK has no
// signature expiry policy to state, and nbf because the spec calls its use NOT
// RECOMMENDED.
func SetIssuedAt(payload map[string]interface{}, builtAt time.Time) {
	payload["iat"] = builtAt.Unix()
}

// CheckTimeClaims enforces RFC 7519 §4.1.4–4.1.5: a JWT "MUST NOT be accepted
// for processing" on or after exp, nor before nbf. Issuers on other
// implementations set them even though this SDK does not, and the RFC binds on
// what the token says rather than on who wrote it.
//
// leeway widens both bounds to absorb clock skew between issuer and verifier,
// as RFC 7519 allows ("some small leeway, usually no more than a few minutes").
// Zero keeps the exact comparison.
func CheckTimeClaims(payload map[string]interface{}, leeway time.Duration) error {
	now := time.Now()
	sec, ok, err := NumericClaim(payload, "nbf")
	if err != nil {
		return err
	}
	if ok && now.Add(leeway).Before(time.Unix(sec, 0)) {
		return fmt.Errorf("signature is not valid before %s (nbf)", time.Unix(sec, 0).UTC().Format(time.RFC3339))
	}

	sec, ok, err = NumericClaim(payload, "exp")
	if err != nil {
		return err
	}
	if ok && !now.Add(-leeway).Before(time.Unix(sec, 0)) {
		return fmt.Errorf("signature expired at %s (exp)", time.Unix(sec, 0).UTC().Format(time.RFC3339))
	}

	return nil
}

// NumericClaim reads a NumericDate claim. JSON numbers decode as float64, but a
// decoder set to UseNumber yields json.Number, and claims assembled in memory
// before signing are still int64. A NumericDate may have a fraction (RFC 7519
// §2), which is dropped; one past the last second time.Time holds is refused.
func NumericClaim(payload map[string]interface{}, name string) (int64, bool, error) {
	raw, ok := payload[name]
	if !ok || raw == nil {
		return 0, false, nil
	}
	var sec int64
	switch t := raw.(type) {
	case float64:
		v, ok := secondsFromFloat(t)
		if !ok {
			return 0, false, fmt.Errorf("invalid %s value: %v", name, raw)
		}
		sec = v
	case int64:
		sec = t
	case json.Number:
		v, err := t.Int64()
		if err != nil {
			f, ferr := t.Float64()
			if ferr != nil {
				return 0, false, fmt.Errorf("invalid %s value: %w", name, ferr)
			}
			var ok bool
			if v, ok = secondsFromFloat(f); !ok {
				return 0, false, fmt.Errorf("invalid %s value: %v", name, raw)
			}
		}
		sec = v
	default:
		return 0, false, fmt.Errorf("invalid %s type: %T", name, raw)
	}
	if sec <= 0 || sec > maxUnix {
		return 0, false, fmt.Errorf("invalid %s value: %v", name, raw)
	}

	return sec, true, nil
}

// maxUnix is the last second time.Time holds: time.Unix adds the seconds from
// year 1 to 1970 to its argument, so a larger value wraps to a date in the
// past and a far-future nbf would read as long gone. jose/jwt, a separate
// module, holds the same bound.
const maxUnix = math.MaxInt64 - 62135596800

// secondsFromFloat truncates f to whole seconds. Go leaves the conversion of a
// float64 outside the int64 range, or of NaN, to the CPU, so the same claim
// would pass on one machine and fail on another; those values are refused.
func secondsFromFloat(f float64) (int64, bool) {
	if !(f > math.MinInt64 && f < math.MaxInt64) {
		return 0, false
	}
	return int64(f), true
}

// TrimRecoveryByte drops go-ethereum's trailing recovery id, so a 65-byte
// secp256k1 signature becomes the 64-byte r||s a JWS carries.
func TrimRecoveryByte(signature []byte) []byte {
	if len(signature) == 65 {
		return signature[:64]
	}

	return signature
}

// curveOrder returns the order n of the curve named by alg ("ES256" → P-256,
// "ES256K" → secp256k1). Unknown algorithms return nil and the caller skips
// normalization.
func curveOrder(alg string) *big.Int {
	switch alg {
	case "ES256":
		return elliptic.P256().Params().N
	case "ES256K":
		return secp256k1.S256().N
	}
	return nil
}

// NormalizeLowS returns the low-S form (s <= n/2) of a 64-byte r||s ECDSA
// signature, so every token the SDK signs has one canonical signature.
// Verification still accepts high-S, so a copy with s replaced by n-s
// verifies too and has a different Hash().
//
// alg names the JWS algorithm ("ES256" or "ES256K"). An unrecognised alg is
// returned unchanged — an extra algorithm does not break existing signatures.
func NormalizeLowS(alg string, sig []byte) []byte {
	if len(sig) != 64 {
		return sig
	}
	n := curveOrder(alg)
	if n == nil {
		return sig
	}
	halfN := new(big.Int).Rsh(n, 1) // n/2
	s := new(big.Int).SetBytes(sig[32:])
	if s.Cmp(halfN) > 0 {
		s.Sub(n, s)
		out := make([]byte, 64)
		copy(out[:32], sig[:32])
		s.FillBytes(out[32:])
		return out
	}
	return sig
}
