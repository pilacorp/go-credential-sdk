package didjwtvc

import (
	"math"
	"strings"
	"time"
)

// defaultContext is DEFAULT_CONTEXT in did-jwt-vc src/types.ts.
const defaultContext = "https://www.w3.org/2018/credentials/v1"

// validateCredentialPayload is validateCredentialPayload in did-jwt-vc
// src/index.ts, run on a decoded credential.
func validateCredentialPayload(form map[string]interface{}) error {
	if !jsIncludes(form["@context"], defaultContext) || !jsIncludes(form["type"], "VerifiableCredential") {
		return ErrUnsupported
	}
	if jsKeyCount(form["credentialSubject"]) == 0 {
		return ErrUnsupported
	}
	for _, k := range []string{"issuanceDate", "expirationDate"} {
		if jsTruthy(form[k]) && !validTimestamp(form[k]) {
			return ErrUnsupported
		}
	}
	return nil
}

// validatePresentationPayload is validatePresentationPayload in did-jwt-vc
// src/index.ts, run on a decoded presentation, whose credentials are already
// decoded objects.
func validatePresentationPayload(form map[string]interface{}) error {
	if !jsIncludes(form["@context"], defaultContext) || !jsIncludes(form["type"], "VerifiablePresentation") {
		return ErrUnsupported
	}
	creds, _ := form["verifiableCredential"].([]interface{})
	for _, c := range creds {
		vc, ok := c.(map[string]interface{})
		if !ok {
			return ErrUnsupported
		}
		if err := validateCredentialPayload(vc); err != nil {
			return err
		}
	}
	if jsTruthy(form["expirationDate"]) && !validTimestamp(form["expirationDate"]) {
		return ErrUnsupported
	}
	return nil
}

// validTimestamp is validateTimestamp in did-jwt-vc src/validators.ts: an
// integer below 1e11 seconds, or a date string whose instant is one. The rule
// is JavaScript's Date parser, not a VC data model rule, so it is kept here
// rather than in vcdm: a string is read as Go's time.Parse(time.RFC3339) reads
// it, without a comma (uppercase T and Z, no leap second), a subset of what
// Date reads, and other strings are refused.
func validTimestamp(v interface{}) bool {
	switch t := v.(type) {
	case float64:
		return t == math.Trunc(t) && t < 1e11
	case string:
		if strings.ContainsRune(t, ',') {
			return false
		}
		parsed, err := time.Parse(time.RFC3339, t)
		return err == nil && math.Floor(float64(parsed.UnixMilli())/1000) < 1e11
	}
	return false
}
