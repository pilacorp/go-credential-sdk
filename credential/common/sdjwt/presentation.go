package sdjwt

import "strings"

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
