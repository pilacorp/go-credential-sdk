package crypto

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/util"
)

// This file ports the decoder of did-jwt-vc 5.0.2 (src/converters.ts:
// normalizeCredential, normalizeJwtCredentialPayload, normalizeJwtPresentationPayload),
// the library that defined JwtProof2020. A holder using it gets a VC-JWT or
// VP-JWT as the object that decoder returns. That object keeps the claims VC-JWT 1.1 does not map (iat, aud, nonce) and moves
// others in ways VCDM 1.1 §6.3.1 leaves open, so the mapping check alone
// refuses it. Every member of the decoded object comes from the signed payload,
// so a body equal to it is bound by the signature.
//
// The port follows the JavaScript semantics it depends on: truthiness, object
// spread, Set de-duplication and Date.toISOString. Inputs that make
// did-jwt-vc throw, and shapes this port does not cover (legacy attestation
// payloads, nested JWTs with cty "JWT", years outside 0-9999), return an error,
// so such bodies fall back to the mapping check.
//
// did-jwt-vc leaves members it does not move (validFrom, validUntil, custom
// members) nested under vc or vp. Every check after this one reads the top
// level, so such a member would be signed but never checked; a body whose
// decoded form keeps one there is refused.

var errNotDidJwtVcForm = errors.New("body is not the did-jwt-vc form")

// didJwtVcJWTFormat is JWT_FORMAT in did-jwt-vc src/types.ts.
var didJwtVcJWTFormat = regexp.MustCompile(`^[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*$`)

// didJwtJWSFormat is the JWS pattern decodeJWS in did-jwt src/JWT.ts accepts.
var didJwtJWSFormat = regexp.MustCompile(`^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$`)

// didJwtVcAdditionalProps is additionalPropNames in did-jwt-vc src/converters.ts.
var didJwtVcAdditionalProps = []string{"evidence", "termsOfUse", "refreshService", "credentialSchema", "credentialStatus"}

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
		form, err = didJwtVcPresentationPayload(claims)
	} else {
		form, err = didJwtVcCredentialPayload(claims)
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

func didJwtVcCredentialPayload(input map[string]interface{}) (map[string]interface{}, error) {
	if jsTruthy(input["sub"]) && jsTruthy(input["iss"]) && jsTruthy(input["claim"]) && jsTruthy(input["iat"]) {
		return nil, errNotDidJwtVcForm // legacy attestation format, not ported
	}
	result := util.DeepCopyMap(input)
	vc, _ := result["vc"].(map[string]interface{})
	inputVC, _ := input["vc"].(map[string]interface{})

	subject := map[string]interface{}{}
	jsSpread(subject, input["credentialSubject"])
	if inputVC != nil {
		jsSpread(subject, inputVC["credentialSubject"])
	}
	result["credentialSubject"] = subject
	if jsTruthy(input["sub"]) && !jsTruthy(jsMember(input["credentialSubject"], "id")) {
		subject["id"] = input["sub"]
		delete(result, "sub")
	}
	if vc != nil {
		delete(vc, "credentialSubject")
	}

	if issuer, present := input["issuer"]; !present || jsTypeofObject(issuer) {
		obj := map[string]interface{}{}
		if iss, ok := input["iss"]; ok {
			obj["id"] = iss
		}
		jsSpread(obj, issuer)
		result["issuer"] = obj
		if !jsTruthy(jsMember(issuer, "id")) {
			delete(result, "iss")
		}
	}

	if !jsTruthy(input["id"]) && jsTruthy(input["jti"]) {
		if !jsTruthy(result["id"]) {
			result["id"] = result["jti"]
		}
		delete(result, "jti")
	}

	result["type"] = jsDedup(jsAsArray(result["type"]), jsAsArray(jsMember(vc, "type")))
	if vc != nil {
		delete(vc, "type")
	}

	if inputVC != nil {
		for _, prop := range didJwtVcAdditionalProps {
			if !jsTruthy(inputVC[prop]) {
				continue
			}
			if !jsTruthy(result[prop]) {
				result[prop] = inputVC[prop]
			}
			if vc != nil {
				delete(vc, prop)
			}
		}
	}

	result["@context"] = jsDedup(jsAsArray(input["context"]), jsAsArray(input["@context"]), jsAsArray(jsMember(inputVC, "@context")))
	delete(result, "context")
	if vc != nil {
		delete(vc, "@context")
	}

	if err := didJwtVcDates(input, result); err != nil {
		return nil, err
	}
	if jsTruthy(result["vc"]) && jsKeyCount(result["vc"]) == 0 {
		delete(result, "vc")
	}
	return result, nil
}

func didJwtVcPresentationPayload(input map[string]interface{}) (map[string]interface{}, error) {
	result := util.DeepCopyMap(input)
	vp, _ := result["vp"].(map[string]interface{})
	inputVP, _ := input["vp"].(map[string]interface{})

	var creds []interface{}
	for _, c := range append(jsAsArray(input["verifiableCredential"]), jsAsArray(jsMember(inputVP, "verifiableCredential"))...) {
		if c == nil {
			continue
		}
		n, err := didJwtVcCredential(c)
		if err != nil {
			return nil, err
		}
		creds = append(creds, n)
	}
	if creds == nil {
		creds = []interface{}{}
	}
	result["verifiableCredential"] = creds
	if vp != nil {
		delete(vp, "verifiableCredential")
	}

	if jsTruthy(input["iss"]) && !jsTruthy(input["holder"]) {
		result["holder"] = input["iss"]
		delete(result, "iss")
	}

	if jsTruthy(input["aud"]) {
		result["verifier"] = jsDedup(jsAsArray(input["verifier"]), jsAsArray(input["aud"]))
		delete(result, "aud")
	}

	if _, hasID := input["id"]; jsTruthy(input["jti"]) && !hasID {
		result["id"] = input["jti"]
		delete(result, "jti")
	}

	result["type"] = jsDedup(jsAsArray(input["type"]), jsAsArray(jsMember(inputVP, "type")))
	if vp != nil {
		delete(vp, "type")
	}

	result["@context"] = jsDedup(jsAsArray(input["context"]), jsAsArray(input["@context"]), jsAsArray(jsMember(inputVP, "@context")))
	delete(result, "context")
	if vp != nil {
		delete(vp, "@context")
	}

	if err := didJwtVcDates(input, result); err != nil {
		return nil, err
	}
	if jsTruthy(result["vp"]) && jsKeyCount(result["vp"]) == 0 {
		delete(result, "vp")
	}
	return result, nil
}

// didJwtVcCredential is normalizeCredential, for one verifiableCredential entry.
func didJwtVcCredential(input interface{}) (map[string]interface{}, error) {
	switch v := input.(type) {
	case string:
		if didJwtVcJWTFormat.MatchString(v) {
			return didJwtVcJWTCredential(v)
		}
		var parsed interface{}
		if err := json.Unmarshal([]byte(v), &parsed); err != nil {
			return nil, errNotDidJwtVcForm
		}
		if _, isString := parsed.(string); isString {
			return nil, errNotDidJwtVcForm // not ported: a JSON string holding a credential
		}
		return didJwtVcCredential(parsed)
	case map[string]interface{}:
		if proof, ok := v["proof"].(map[string]interface{}); ok && jsTruthy(proof["jwt"]) {
			jwt, ok := proof["jwt"].(string)
			if !ok {
				return nil, errNotDidJwtVcForm
			}
			out, err := didJwtVcJWTCredential(jwt)
			if err != nil {
				return nil, err
			}
			out["proof"] = v["proof"]
			return out, nil
		}
		out, err := didJwtVcCredentialPayload(v)
		if err != nil {
			return nil, err
		}
		if _, ok := out["proof"]; !ok {
			out["proof"] = map[string]interface{}{}
		}
		return out, nil
	default:
		return nil, errNotDidJwtVcForm
	}
}

// didJwtVcJWTCredential is normalizeJwtCredential: decode without verifying,
// then attach the JWT as its JwtProof2020 proof.
func didJwtVcJWTCredential(jwt string) (map[string]interface{}, error) {
	if !didJwtJWSFormat.MatchString(jwt) {
		return nil, errNotDidJwtVcForm
	}
	parts := strings.Split(jwt, ".")
	var header, payload map[string]interface{}
	for i, dst := range []*map[string]interface{}{&header, &payload} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil || json.Unmarshal(raw, dst) != nil || *dst == nil {
			return nil, errNotDidJwtVcForm
		}
	}
	if header["cty"] == "JWT" {
		return nil, errNotDidJwtVcForm // nested JWT, not ported
	}
	out, err := didJwtVcCredentialPayload(payload)
	if err != nil {
		return nil, err
	}
	out["proof"] = map[string]interface{}{"type": "JwtProof2020", "jwt": jwt}
	return out, nil
}

// didJwtVcDates fills issuanceDate from nbf, else iat, and expirationDate from
// exp, removing the claim it used, as both did-jwt-vc payload decoders do.
func didJwtVcDates(input, result map[string]interface{}) error {
	if !jsTruthy(input["issuanceDate"]) && (jsTruthy(input["iat"]) || jsTruthy(input["nbf"])) {
		claim := "iat"
		if jsTruthy(input["nbf"]) {
			claim = "nbf"
		}
		date, err := jsISODate(input[claim])
		if err != nil {
			return err
		}
		result["issuanceDate"] = date
		delete(result, claim)
	}
	if !jsTruthy(input["expirationDate"]) && jsTruthy(input["exp"]) {
		date, err := jsISODate(input["exp"])
		if err != nil {
			return err
		}
		result["expirationDate"] = date
		delete(result, "exp")
	}
	return nil
}

// jsISODate is new Date(seconds * 1000).toISOString().
func jsISODate(v interface{}) (string, error) {
	seconds, ok := v.(float64)
	if !ok {
		return "", errNotDidJwtVcForm // not ported: JavaScript number coercion
	}
	ms := math.Trunc(seconds * 1000)
	if math.IsNaN(ms) || math.Abs(ms) > 8.64e15 {
		return "", errNotDidJwtVcForm // JavaScript Date throws RangeError
	}
	t := time.UnixMilli(int64(ms)).UTC()
	if t.Year() < 0 || t.Year() > 9999 {
		return "", errNotDidJwtVcForm // toISOString's six-digit years, not ported
	}
	return t.Format("2006-01-02T15:04:05.000Z"), nil
}

// jsTruthy is JavaScript truthiness for a decoded JSON value.
func jsTruthy(v interface{}) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case float64:
		return t != 0 && !math.IsNaN(t)
	case string:
		return t != ""
	default:
		return true
	}
}

// jsTypeofObject is typeof v === "object": objects, arrays and null.
func jsTypeofObject(v interface{}) bool {
	switch v.(type) {
	case nil, map[string]interface{}, []interface{}:
		return true
	}
	return false
}

// jsMember is v?.[key] for a decoded JSON value: only objects have members
// that JSON can carry.
func jsMember(v interface{}, key string) interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m[key]
	}
	return nil
}

// jsSpread copies the own enumerable properties of v into dst, as {...v}.
func jsSpread(dst map[string]interface{}, v interface{}) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			dst[k] = val
		}
	case []interface{}:
		for i, val := range t {
			dst[strconv.Itoa(i)] = val
		}
	case string:
		for i, r := range []rune(t) {
			dst[strconv.Itoa(i)] = string(r)
		}
	}
}

// jsKeyCount is Object.keys(v).length for a truthy decoded JSON value.
func jsKeyCount(v interface{}) int {
	switch t := v.(type) {
	case map[string]interface{}:
		return len(t)
	case []interface{}:
		return len(t)
	case string:
		return len([]rune(t))
	}
	return 0
}

// jsAsArray is asArray in did-jwt-vc: an array as-is, anything else wrapped.
// A missing member is undefined, which notEmpty later drops like null.
func jsAsArray(v interface{}) []interface{} {
	if a, ok := v.([]interface{}); ok {
		return a
	}
	return []interface{}{v}
}

// jsDedup is [...new Set(lists.flat().filter(notEmpty))]: primitives are
// de-duplicated by value, objects and arrays are never equal to each other.
func jsDedup(lists ...[]interface{}) []interface{} {
	out := []interface{}{}
	seen := map[interface{}]bool{}
	for _, list := range lists {
		for _, v := range list {
			switch v.(type) {
			case nil:
				continue
			case string, float64, bool:
				if seen[v] {
					continue
				}
				seen[v] = true
			}
			out = append(out, v)
		}
	}
	return out
}
