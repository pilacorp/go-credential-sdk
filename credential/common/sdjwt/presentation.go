package sdjwt

import (
	"fmt"
	"strings"
)

// CreatePresentation builds an SD-JWT presentation string from the issuer-signed JWT
// and a subset of disclosure strings. The Holder uses this to present only selected
// disclosures to a Verifier. selectedDisclosures must be a subset of the original
// disclosures (typically from Parsed.Disclosures). Empty segments in selectedDisclosures
// are skipped. The output format is: <IssuerSignedJWT>~D1~D2~...~
func CreatePresentation(issuerSignedJWT string, selectedDisclosures []string) string {
	var sb strings.Builder
	sb.WriteString(issuerSignedJWT)
	for _, d := range selectedDisclosures {
		if d == "" {
			continue
		}
		sb.WriteString("~")
		sb.WriteString(d)
	}
	sb.WriteString("~")
	return sb.String()
}

// HolderSDJWT is the holder's handle to an SD-JWT for building presentations.
// Create it with NewHolderSDJWT(sdJWTString); then use GetDisclosures, AddDisclosures,
// and SerializeWithDisclosures to prepare what to send to a Verifier.
// HolderSDJWT implements SDJWTHolder.
type sdJWTHolder struct {
	parsedSDJWT *ParsedSDJWT
}

// NewHolderSDJWT parses the SD-JWT string and returns a HolderSDJWT for holder operations.
// The holder can then get disclosures, add more (e.g. from storage), and build a presentation
// with selected disclosures. Returns an error if the input is not a valid SD-JWT format.
func NewHolderSDJWT(sdJWTString string) (SDJWTHolder, error) {
	parsed, err := Parse(sdJWTString)
	if err != nil {
		return nil, err
	}
	return &sdJWTHolder{parsedSDJWT: parsed}, nil
}

// GetDisclosures implements SDJWTHolder. Returns a copy of the disclosure strings.
func (h *sdJWTHolder) GetDisclosures() ([]string, bool) {
	if h.parsedSDJWT == nil || len(h.parsedSDJWT.Disclosures) == 0 {
		return nil, false
	}
	out := make([]string, len(h.parsedSDJWT.Disclosures))
	copy(out, h.parsedSDJWT.Disclosures)
	return out, true
}

// GetIssuerSignedJWT implements SDJWTHolder.
func (h *sdJWTHolder) GetIssuerSignedJWT() (string, bool) {
	if h.parsedSDJWT == nil {
		return "", false
	}
	return h.parsedSDJWT.IssuerSignedJWT, true
}

// AddDisclosures appends disclosure strings to this HolderSDJWT (e.g. disclosures
// restored from storage or received from another source). They can be included
// in a later SerializeWithDisclosures call.
func (h *sdJWTHolder) AddDisclosures(disclosures []string) {
	if h.parsedSDJWT == nil || len(disclosures) == 0 {
		return
	}
	for _, d := range disclosures {
		if d == "" {
			continue
		}
		h.parsedSDJWT.Disclosures = append(h.parsedSDJWT.Disclosures, d)
	}
}

// SerializeWithDisclosures implements SDJWTHolder.
func (h *sdJWTHolder) SerializeWithDisclosures(selectedDisclosures []string) (string, error) {
	if h.parsedSDJWT == nil || len(h.parsedSDJWT.Disclosures) == 0 {
		return "", fmt.Errorf("no SD-JWT disclosures")
	}
	return CreatePresentation(h.parsedSDJWT.IssuerSignedJWT, selectedDisclosures), nil
}
