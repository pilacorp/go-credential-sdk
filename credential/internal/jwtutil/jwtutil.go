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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/pilacorp/go-credential-sdk/credential/internal/errtext"
	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
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
	sec, err := NumericDate(raw)
	if err != nil {
		return 0, false, fmt.Errorf("invalid %s %w", name, err)
	}

	return sec, true, nil
}

// NumericDate reads one NumericDate value as NumericClaim does, as whole
// seconds since the epoch. Two edges differ from RFC 7519 §2: zero and
// negative values are refused, and a fraction is dropped, so an nbf of 1.5
// admits a token from second 1 and an exp of 1.5 refuses it from second 1.
func NumericDate(raw interface{}) (int64, error) {
	var sec int64
	switch t := raw.(type) {
	case float64:
		v, ok := secondsFromFloat(t)
		if !ok {
			return 0, fmt.Errorf("value: %s", errtext.Clip(fmt.Sprint(raw)))
		}
		sec = v
	case int64:
		sec = t
	case json.Number:
		v, err := t.Int64()
		if err != nil {
			f, ferr := t.Float64()
			if ferr != nil {
				return 0, fmt.Errorf("value: %w", ferr)
			}
			var ok bool
			if v, ok = secondsFromFloat(f); !ok {
				return 0, fmt.Errorf("value: %s", errtext.Clip(fmt.Sprint(raw)))
			}
		}
		sec = v
	default:
		return 0, fmt.Errorf("type: %T", raw)
	}
	if sec <= 0 || sec > maxUnix {
		return 0, fmt.Errorf("value: %s", errtext.Clip(fmt.Sprint(raw)))
	}

	return sec, nil
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

// DecodePayload decodes the payload of a compact JWT without checking its
// signature. The caller verifies the signature, or reads only claims whose
// worth does not depend on it.
func DecodePayload(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format")
	}
	payloadBytes, err := jose.DecodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}
	claims, err := DecodeJSONObject(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT payload: %w", err)
	}
	return claims, nil
}

// PlaceholderSignature has the encoded length of the 64-byte r||s signature
// every SDK signing path attaches, so a builder can parse its finished token
// back before anything is signed.
func PlaceholderSignature() string {
	return strings.Repeat("A", 86)
}

// EncodeSegment marshals v as a JWS header or payload segment, and refuses
// one DecodeSegmentObject would refuse (nesting over jose.MaxJSONDepth), so
// the SDK never signs what it cannot parse back.
func EncodeSegment(v interface{}) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	if _, err := DecodeJSONObject(b); err != nil {
		return "", fmt.Errorf("the SDK could not parse it back: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// MarshalSegment is EncodeSegment without the read-back, for a builder that
// parses its whole token back with its own parser anyway.
func MarshalSegment(v interface{}) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CheckHeaderSize refuses a header segment over MaxHeaderBytes, the bound
// DecodeHeaderSegment and jose/jws.Verify apply.
func CheckHeaderSize(seg string) error {
	if len(seg) > maxHeaderSegment {
		return fmt.Errorf("%w: header is over %d bytes", jose.ErrMalformed, MaxHeaderBytes)
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

// CheckHeaderToSign refuses, before anything is signed, a header segment a
// verifier would refuse for its size; the kid is what a caller can make long.
func CheckHeaderToSign(seg, kid string) error {
	if CheckHeaderSize(seg) != nil {
		return fmt.Errorf("%w: the JOSE header is over %d bytes (kid of %d bytes), the most a verifier reads",
			jose.ErrInvalidArgument, MaxHeaderBytes, len(kid))
	}
	return nil
}

// MaxHeaderBytes bounds a decoded JOSE header: jose/jws's bound, so the SDK
// refuses what jws.Verify would and nothing more.
const MaxHeaderBytes = jws.MaxHeaderBytes

// maxHeaderSegment is the base64url length of MaxHeaderBytes, unpadded.
const maxHeaderSegment = (4*MaxHeaderBytes + 2) / 3

// DecodeHeaderSegment is DecodeSegmentObject for a JOSE header: a segment
// over 64 KiB, which jose/jws.Verify would refuse, is refused before it is
// decoded, so a large header costs nothing on any route.
func DecodeHeaderSegment(seg string) (map[string]interface{}, error) {
	if err := CheckHeaderSize(seg); err != nil {
		return nil, err
	}
	return DecodeSegmentObject(seg)
}

// DecodeSegmentObject reads one base64url segment of a compact JWS, a header
// or a payload: jose.DecodeSegment (RFC 7515 §2, pad bits zero per RFC 4648
// §3.5), then DecodeJSONObject.
func DecodeSegmentObject(seg string) (map[string]interface{}, error) {
	b, err := jose.DecodeSegment(seg)
	if err != nil {
		return nil, err
	}
	return DecodeJSONObject(b)
}

// DecodeJSONObject reads a JWT header, payload or disclosure value by module
// jose's rules (one value, valid UTF-8, no duplicate key, bounded depth), so
// the SDK reads the bytes a signature covers the way jose/jws.Verify does,
// and gives numbers as float64, as encoding/json does.
func DecodeJSONObject(data []byte) (map[string]interface{}, error) {
	obj, err := jose.DecodeJSONObject(data)
	if err != nil {
		return nil, err
	}
	if err := FloatNumbersInPlace(obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// FloatNumbersInPlace is FloatNumbers on a tree nothing else holds, such as
// one just decoded: it changes v itself instead of copying it, so a payload
// costs one tree, not two, before its signature is checked.
func FloatNumbersInPlace(v map[string]interface{}) error {
	_, err := numbers(v, false, true)
	return err
}

// FloatNumbers returns a copy of v with every json.Number as the float64
// encoding/json would give: integers past 2^53 are rounded, as there.
func FloatNumbers(v interface{}) (interface{}, error) {
	return numbers(v, false, false)
}

// FloatNumbersExact is FloatNumbers for data the caller will sign: an
// integer literal (no '.', 'e' or 'E') past ±2^53 stays a json.Number, so its
// digits are not changed.
func FloatNumbersExact(v interface{}) (interface{}, error) {
	return numbers(v, true, false)
}

func numbers(v interface{}, exact, inPlace bool) (interface{}, error) {
	switch t := v.(type) {
	case json.Number:
		f, err := strconv.ParseFloat(t.String(), 64)
		if err != nil {
			// Refused in both modes, so what is built here can be read back.
			// Read input is malformed; data a caller is building is the
			// caller's mistake.
			sentinel := jose.ErrMalformed
			if exact {
				sentinel = jose.ErrInvalidArgument
			}
			// The *strconv.NumError would repeat the whole literal.
			var ne *strconv.NumError
			if errors.As(err, &ne) {
				err = ne.Err
			}
			return nil, fmt.Errorf("%w: number %.32q does not fit a float64: %w", sentinel, t.String(), err)
		}
		if exact && !strings.ContainsAny(t.String(), ".eE") {
			// An integer literal: float64 holds it exactly up to 2^53.
			if i, err := strconv.ParseInt(t.String(), 10, 64); err != nil || i > 1<<53 || i < -(1<<53) {
				return t, nil
			}
		}
		return f, nil
	case map[string]interface{}:
		out := t
		if !inPlace {
			out = make(map[string]interface{}, len(t))
		}
		for k, el := range t {
			c, err := numbers(el, exact, inPlace)
			if err != nil {
				return nil, err
			}
			out[k] = c
		}
		return out, nil
	case []interface{}:
		out := t
		if !inPlace {
			out = make([]interface{}, len(t))
		}
		for i, el := range t {
			c, err := numbers(el, exact, inPlace)
			if err != nil {
				return nil, err
			}
			out[i] = c
		}
		return out, nil
	}
	return v, nil
}
