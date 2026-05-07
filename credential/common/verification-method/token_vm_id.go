package verificationmethod

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// ParseTokenVMID extracts the verification method id (full URL) the credential
// was signed with.
//
// Supported inputs:
//   - JWT compact JWS: reads the `kid` claim in the JOSE header.
//   - JSON credential/presentation: reads `proof.verificationMethod` on the outer
//     proof object (or the first element when `proof` is a list).
//
// Tokens that omit the VM id are rejected (legacy tokens without kid /
// verificationMethod are not supported).
func ParseTokenVMID(token string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", fmt.Errorf("token is empty")
	}

	// JWT path: 3-segment compact JWS, header is the first segment.
	if parts := strings.Split(token, "."); len(parts) == 3 {
		headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err == nil {
			var hdr struct {
				Kid string `json:"kid"`
			}
			if err := json.Unmarshal(headerBytes, &hdr); err == nil && hdr.Kid != "" {
				return hdr.Kid, nil
			}
		}
	}

	// JSON credential/presentation path: parse and read proof.verificationMethod.
	var doc map[string]interface{}
	_ = json.Unmarshal([]byte(token), &doc)

	if proof, ok := doc["proof"].(map[string]interface{}); ok {
		if vm, ok := proof["verificationMethod"].(string); ok && vm != "" {
			return vm, nil
		}
	}
	// Some credentials carry a list of proofs — try the first one.
	if proofList, ok := doc["proof"].([]interface{}); ok && len(proofList) > 0 {
		if proof, ok := proofList[0].(map[string]interface{}); ok {
			if vm, ok := proof["verificationMethod"].(string); ok && vm != "" {
				return vm, nil
			}
		}
	}

	return "", fmt.Errorf("token is missing verification method id (kid/verificationMethod)")
}
