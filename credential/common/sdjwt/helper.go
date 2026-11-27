package sdjwt

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/internal/jwtutil"
	josesdjwt "github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

// DecodedDisclosure represents a decoded disclosure that Holder can use to understand what it contains.
type DecodedDisclosure struct {
	Disclosure  string      // Original disclosure string
	Salt        string      // The salt value
	FieldName   string      // The field name (for object field disclosures)
	Value       interface{} // The value (for object field: claim value, for array: element value)
	IsArrayElem bool        // True if this is an array element disclosure
}

// IsSDJWT checks whether the input string looks like an SD-JWT.
func IsSDJWT(raw string) bool {
	if raw == "" {
		return false
	}

	s := strings.TrimSpace(strings.Trim(raw, "\""))
	if !strings.Contains(s, "~") {
		return false
	}

	parts := strings.SplitN(s, "~", 2)
	if len(parts) < 2 {
		return false
	}

	return isJWT(parts[0])
}

// Parse splits an SD-JWT into issuer-signed JWT and its disclosures with
// jose/sdjwt.Split, the reader ParseJOSECredential uses: the RFC 9901 §4
// format (the trailing ~, no empty disclosure), no repeated disclosure, and
// jose's caps of 1 MiB and 1000 disclosures. It also decodes all disclosures and populates DecodedDisclosures for
// easy access by Holders.
func Parse(raw string) (*ParsedSDJWT, error) {
	if !IsSDJWT(raw) {
		return nil, fmt.Errorf("invalid SD-JWT format")
	}
	s := strings.TrimSpace(strings.Trim(raw, "\""))
	issuer, disclosures, kbJWT, err := josesdjwt.Split(s)
	if err != nil {
		return nil, fmt.Errorf("invalid SD-JWT: %w", err)
	}
	// Skipping a Key Binding JWT silently was worse than not supporting it:
	// a verifier that asked for holder binding would get a nil error back
	// from a token whose binding nothing checked. Refused until it is
	// verified.
	if kbJWT != "" {
		return nil, fmt.Errorf(
			"SD-JWT carries a key binding JWT, which this SDK does not verify yet; present the credential without it")
	}

	decodedDisclosures, err := DecodeDisclosures(disclosures)
	if err != nil {
		return nil, fmt.Errorf("failed to decode disclosures: %w", err)
	}

	return &ParsedSDJWT{
		BaseJWT:            issuer,
		Disclosures:        disclosures,
		DecodedDisclosures: decodedDisclosures,
	}, nil
}

// BuildSDJWTPresentation builds an SD-JWT presentation string from the issuer-signed JWT
// and a subset of disclosure strings.
//
// The trailing "~" is written even when nothing is selected, because that is
// what makes the result an SD-JWT: RFC 9901 §4
// terminates the combined format with it, and a holder revealing nothing is
// still presenting an SD-JWT. Omitting it returned a bare JWT, which IsSDJWT
// does not recognise — so the digests were never folded out of the payload and
// a presentation whose header says vc+sd-jwt was enveloped as vc+jwt.
//
// Callers must not hand a plain JWT here; Present checks that the credential
// has disclosures before calling.
func BuildSDJWTPresentation(issuerSignedJWT string, selectedDisclosures []string) string {
	var sb strings.Builder
	sb.WriteString(issuerSignedJWT)
	for _, sel := range selectedDisclosures {
		if sel == "" {
			continue
		}
		sb.WriteString("~")
		sb.WriteString(sel)
	}
	sb.WriteString("~")

	return sb.String()
}

// DecodeDisclosures decodes disclosure strings into DecodedDisclosure so a
// Holder can inspect each field name and value before selecting which to
// present. Each disclosure is decoded through jose/sdjwt.ParseDisclosure, which
// rejects the claim names "_sd" and "..." (RFC 9901 §4.2.1) and "_sd_alg"
// (kept at the top level by §4.1.1). Numbers in a value are float64, as
// encoding/json decodes them.
// DecodedDisclosure carries no digest, since that depends on the SD-JWT's
// _sd_alg.
func DecodeDisclosures(disclosures []string) ([]DecodedDisclosure, error) {
	result := make([]DecodedDisclosure, 0, len(disclosures))
	for _, disc := range disclosures {
		if disc == "" {
			continue
		}
		p, err := josesdjwt.ParseDisclosure(disc)
		if err != nil {
			return nil, fmt.Errorf("decode disclosure: %w", err)
		}
		value, err := jwtutil.FloatNumbers(p.Value)
		if err != nil {
			return nil, fmt.Errorf("decode disclosure: %w", err)
		}
		dec := DecodedDisclosure{
			Disclosure:  disc,
			Salt:        p.Salt,
			FieldName:   p.Name,
			Value:       value,
			IsArrayElem: p.ArrayElement,
		}
		result = append(result, dec)
	}
	return result, nil
}

var jwtRegex = regexp.MustCompile(`^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+(\.[A-Za-z0-9\-_]+)?$`)

// isJWT performs a simple regex check for JWT format: header.payload[.signature].
func isJWT(s string) bool {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	return jwtRegex.MatchString(s)
}
