package vp

import (
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/internal/vcdm"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// envelopeJOSECredential wraps a signed vc+jwt or vc+sd-jwt in the VCDM 2.0
// §4.13 EnvelopedVerifiableCredential that a presentation carries: the token
// goes in a data: URL whose media type names the scheme that secured it. A
// vp+jwt and a JSON presentation build the same envelope.
func envelopeJOSECredential(i int, cred *vc.JOSECredential) (map[string]interface{}, error) {
	serialized, err := cred.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize credential at index %d: %w", i, err)
	}
	// The assertion cannot be skipped here: signingInput and signature
	// belong to vc.JOSECredential and are not reachable from this package.
	// Swallowing a failed assertion left credStr empty, and the error then
	// came out of envelopeMediaType as "credential is not signed" — right
	// by accident, about the wrong thing.
	credStr, ok := serialized.(string)
	if !ok {
		return nil, fmt.Errorf("credential at index %d serialized to %T, want a token string", i, serialized)
	}
	mediaType, err := envelopeMediaType(credStr)
	if err != nil {
		return nil, fmt.Errorf("credential at index %d: %w", i, err)
	}
	return map[string]interface{}{
		"@context": []interface{}{vcdm.ContextV2},
		"type":     []interface{}{vc.TypeEnvelopedVC},
		"id":       fmt.Sprintf("data:application/%s,%s", mediaType, credStr),
	}, nil
}

// checkEnvelopedCredential holds an entry typed EnvelopedVerifiableCredential
// to the VCDM 2.0 §4.13 MUSTs, for every presentation that reads one: the
// v2 @context, and an id that is a data: URL naming a scheme this SDK parses.
func checkEnvelopedCredential(i int, entry map[string]interface{}) error {
	if !vcdm.HasType(entry["type"], vc.TypeEnvelopedVC) {
		return fmt.Errorf("credential at index %d: type must be %s", i, vc.TypeEnvelopedVC)
	}
	if !vcdm.HasType(entry["@context"], vcdm.ContextV2) {
		return fmt.Errorf("credential at index %d: enveloped credential @context must include %s",
			i, vcdm.ContextV2)
	}
	id, _ := entry["id"].(string)
	_, token, ok := vcdm.CutEnvelopedDataURL(id)
	if !ok {
		return fmt.Errorf("credential at index %d: enveloped credential id must be a data: URL, "+
			"data:application/vc+jwt,<token> or data:application/vc+sd-jwt,<token>", i)
	}
	if token == "" {
		return fmt.Errorf("credential at index %d: enveloped credential id is a data: URL with no token", i)
	}
	return nil
}

// envelopeForJSONPresentation replaces, in a JSON presentation's serialized
// verifiableCredential list, each vc+jwt or vc+sd-jwt token with its envelope,
// so the presentation's Data Integrity proof covers it (VCDM 2.0 §4.13). creds
// is the list m was serialized from, index for index.
func envelopeForJSONPresentation(m PresentationData, creds []vc.Credential) error {
	list, ok := m["verifiableCredential"].([]interface{})
	if !ok {
		return nil
	}
	for i, cred := range creds {
		switch c := cred.(type) {
		case *vc.JOSECredential:
			// EnvelopedVerifiableCredential is a VCDM 2.0 term. Under a v1
			// @context JSON-LD leaves it undefined, so the proof would not
			// cover the envelope.
			if first := vcdm.FirstContext(m["@context"]); first != vcdm.ContextV2 {
				return fmt.Errorf("%w: credential at index %d is a vc+jwt or vc+sd-jwt credential, "+
					"which needs the presentation's @context to start with %s",
					ErrCredentialNotObject, i, vcdm.ContextV2)
			}
			envelope, err := envelopeJOSECredential(i, c)
			if err != nil {
				return err
			}
			list[i] = envelope
		case *vc.JWTCredential:
			return fmt.Errorf("%w: credential at index %d was built with NewJWTCredential; "+
				"present it with NewJWTPresentation", ErrCredentialNotObject, i)
		}
	}
	return nil
}
