// Package didjwtvc ports the decoder of did-jwt-vc 5.0.2 (src/converters.ts:
// normalizeCredential, normalizeJwtCredentialPayload and
// normalizeJwtPresentationPayload), the library that defined JwtProof2020. A
// holder using it gets a VC-JWT or VP-JWT as the object that decoder returns.
//
// The port follows the JavaScript semantics the decoder depends on (js.go).
// Inputs that make did-jwt-vc throw, and shapes this port does not cover
// (legacy attestation payloads, nested JWTs with cty "JWT", years outside
// 0-9999, a credentialSubject or issuer that is not an object), return
// ErrUnsupported.
//
// It only decodes. Whether a decoded object is bound by a signature is the
// caller's rule (common/crypto, JwtProof2020).
package didjwtvc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

// ErrUnsupported is returned for an input did-jwt-vc refuses or this port does
// not cover.
var ErrUnsupported = errors.New("not a payload the did-jwt-vc decoder handles")

// jwtFormat is JWT_FORMAT in did-jwt-vc src/types.ts.
var jwtFormat = regexp.MustCompile(`^[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*$`)

// jwsFormat is the JWS pattern decodeJWS in did-jwt src/JWT.ts accepts.
var jwsFormat = regexp.MustCompile(`^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$`)

// additionalPropNames is additionalPropNames in did-jwt-vc src/converters.ts.
var additionalPropNames = []string{"evidence", "termsOfUse", "refreshService", "credentialSchema", "credentialStatus"}

// Decoded is a credential or presentation as did-jwt-vc's verifyCredential or
// verifyPresentation gives it, with the other signed values that carry its
// top-level members.
type Decoded struct {
	// Form is the decoded object.
	Form map[string]interface{}
	// Nested lists, for a top-level member, the members of the signed vc or
	// vp claim with that name that the decoder left nested or overrode.
	// "credentialSubject.id" names the id inside credentialSubject.
	Nested map[string][]interface{}
}

// DecodeCredential gives what did-jwt-vc's verifyCredential returns for the
// payload of a VC-JWT: normalizeJwtCredentialPayload, then the checks of
// validateCredentialPayload.
func DecodeCredential(payload map[string]interface{}) (Decoded, error) {
	form, err := normalizeCredentialPayload(payload)
	if err != nil {
		return Decoded{}, err
	}
	if err := validateCredentialPayload(form); err != nil {
		return Decoded{}, err
	}

	return Decoded{Form: form, Nested: nestedBeside(payload, "vc")}, nil
}

// DecodePresentation gives what did-jwt-vc's verifyPresentation returns for
// the payload of a VP-JWT: normalizeJwtPresentationPayload, then the checks of
// validatePresentationPayload.
func DecodePresentation(payload map[string]interface{}) (Decoded, error) {
	form, err := normalizePresentationPayload(payload)
	if err != nil {
		return Decoded{}, err
	}
	if err := validatePresentationPayload(form); err != nil {
		return Decoded{}, err
	}

	return Decoded{
		Form:   form,
		Nested: nestedBeside(payload, "vp"),
	}, nil
}

// nestedBeside lists the members of the signed vc or vp claim that the decoded
// form shows at the top level under the same name. The decoders merge
// @context and type into arrays that keep every value, and decode each
// verifiableCredential of a presentation, so those are left out. Of
// credentialSubject only the id can be replaced, by sub; its other members
// win over a top-level credentialSubject.
func nestedBeside(payload map[string]interface{}, claimKey string) map[string][]interface{} {
	signed := map[string][]interface{}{}
	container, _ := payload[claimKey].(map[string]interface{})
	for k, v := range container {
		switch {
		case k == "@context" || k == "type":
		case claimKey == "vp" && k == "verifiableCredential":
		case claimKey == "vc" && k == "credentialSubject":
			if id, ok := jsMember(v, "id"), jsMemberPresent(v, "id"); ok {
				signed["credentialSubject.id"] = append(signed["credentialSubject.id"], id)
			}
		default:
			signed[k] = append(signed[k], v)
		}
	}
	return signed
}

// normalizeCredentialPayload is normalizeJwtCredentialPayload: the credential
// did-jwt-vc returns for the payload of a VC-JWT.
func normalizeCredentialPayload(input map[string]interface{}) (map[string]interface{}, error) {
	if jsTruthy(input["sub"]) && jsTruthy(input["iss"]) && jsTruthy(input["claim"]) && jsTruthy(input["iat"]) {
		return nil, ErrUnsupported // legacy attestation format, not ported
	}
	result := copyMap(input)
	vc, _ := result["vc"].(map[string]interface{})
	if vc != nil {
		vc = copyMap(vc)
		result["vc"] = vc
	}
	inputVC, _ := input["vc"].(map[string]interface{})

	subject := map[string]interface{}{}
	if err := jsSpread(subject, input["credentialSubject"]); err != nil {
		return nil, err
	}
	if inputVC != nil {
		if err := jsSpread(subject, inputVC["credentialSubject"]); err != nil {
			return nil, err
		}
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
		if err := jsSpread(obj, issuer); err != nil {
			return nil, err
		}
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
		for _, prop := range additionalPropNames {
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

	if err := normalizeDates(input, result); err != nil {
		return nil, err
	}
	if jsTruthy(result["vc"]) && jsKeyCount(result["vc"]) == 0 {
		delete(result, "vc")
	}
	return result, nil
}

// normalizePresentationPayload is normalizeJwtPresentationPayload: the
// presentation did-jwt-vc returns for the payload of a VP-JWT, each credential
// it holds decoded as normalizeCredential does.
func normalizePresentationPayload(input map[string]interface{}) (map[string]interface{}, error) {
	result := copyMap(input)
	vp, _ := result["vp"].(map[string]interface{})
	if vp != nil {
		vp = copyMap(vp)
		result["vp"] = vp
	}
	inputVP, _ := input["vp"].(map[string]interface{})

	var creds []interface{}
	for _, c := range append(jsAsArray(input["verifiableCredential"]), jsAsArray(jsMember(inputVP, "verifiableCredential"))...) {
		if c == nil {
			continue
		}
		n, err := normalizeCredential(c)
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

	if err := normalizeDates(input, result); err != nil {
		return nil, err
	}
	if jsTruthy(result["vp"]) && jsKeyCount(result["vp"]) == 0 {
		delete(result, "vp")
	}
	return result, nil
}

// normalizeCredential is normalizeCredential, for one verifiableCredential entry.
func normalizeCredential(input interface{}) (map[string]interface{}, error) {
	switch v := input.(type) {
	case string:
		if jwtFormat.MatchString(v) {
			return normalizeJWTCredential(v)
		}
		var parsed interface{}
		if err := json.Unmarshal([]byte(v), &parsed); err != nil {
			return nil, ErrUnsupported
		}
		if _, isString := parsed.(string); isString {
			return nil, ErrUnsupported // not ported: a JSON string holding a credential
		}
		return normalizeCredential(parsed)
	case map[string]interface{}:
		if proof, ok := v["proof"].(map[string]interface{}); ok && jsTruthy(proof["jwt"]) {
			jwt, ok := proof["jwt"].(string)
			if !ok {
				return nil, ErrUnsupported
			}
			out, err := normalizeJWTCredential(jwt)
			if err != nil {
				return nil, err
			}
			out["proof"] = v["proof"]
			return out, nil
		}
		out, err := normalizeCredentialPayload(v)
		if err != nil {
			return nil, err
		}
		if _, ok := out["proof"]; !ok {
			out["proof"] = map[string]interface{}{}
		}
		return out, nil
	default:
		return nil, ErrUnsupported
	}
}

// normalizeJWTCredential is normalizeJwtCredential: decode without verifying,
// then attach the JWT as its JwtProof2020 proof.
func normalizeJWTCredential(jwt string) (map[string]interface{}, error) {
	if !jwsFormat.MatchString(jwt) {
		return nil, ErrUnsupported
	}
	parts := strings.Split(jwt, ".")
	var header, payload map[string]interface{}
	for i, dst := range []*map[string]interface{}{&header, &payload} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil || json.Unmarshal(raw, dst) != nil || *dst == nil {
			return nil, ErrUnsupported
		}
	}
	if header["cty"] == "JWT" {
		return nil, ErrUnsupported // nested JWT, not ported
	}
	out, err := normalizeCredentialPayload(payload)
	if err != nil {
		return nil, err
	}
	out["proof"] = map[string]interface{}{"type": "JwtProof2020", "jwt": jwt}
	return out, nil
}

// normalizeDates fills issuanceDate from nbf, else iat, and expirationDate from
// exp, removing the claim it used, as both did-jwt-vc payload decoders do.
func normalizeDates(input, result map[string]interface{}) error {
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

// copyMap copies the top level of m. The decoders change only the top level of
// the payload and of its vc or vp member; nested values are shared with the
// input and never changed.
func copyMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
