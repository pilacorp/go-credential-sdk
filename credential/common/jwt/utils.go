package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
)

func GetDocumentFromJWT(tokenString string, docType string) (jsonmap.JSONMap, error) {
	parts := strings.Split(tokenString, ".")

	payload, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var jsonMap jsonmap.JSONMap
	err = json.Unmarshal(payload, &jsonMap)
	if err != nil {
		return nil, err
	}

	documentData, ok := jsonMap[docType]
	if !ok {
		return nil, fmt.Errorf("document type %s not found in JWT", docType)
	}

	documentMap, ok := documentData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("document is not a valid JSON object")
	}

	document := jsonmap.JSONMap(documentMap)
	return document, nil
}
