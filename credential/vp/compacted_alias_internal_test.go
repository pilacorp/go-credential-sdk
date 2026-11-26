package vp

import (
	"errors"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
)

// A checked VP key renamed through a context alias keeps its IRI, so json-gold
// reads it as the same property while the SDK, which reads the raw key, sees
// nothing. The compacted-form check must refuse it with ErrNotCompactedForm,
// whatever the proof would say (#207 review).
func TestVerifyCompactedForm_ContextAliasRenamesCheckedKey(t *testing.T) {
	base := func() map[string]interface{} {
		return map[string]interface{}{
			"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
			"type":     []interface{}{"VerifiablePresentation"},
			"holder":   "did:example:holder",
		}
	}
	if err := (&JSONPresentation{presentationData: PresentationData(base())}).verifyCompactedForm(); err != nil {
		t.Fatalf("a plain presentation was refused: %v", err)
	}

	for _, tc := range []struct {
		key, alias, iri string
		def             map[string]interface{}
	}{
		{key: "holder", alias: "holderX", def: map[string]interface{}{
			"@id": "https://www.w3.org/2018/credentials#holder", "@type": "@id"}},
	} {
		t.Run(tc.key, func(t *testing.T) {
			doc := base()
			doc[tc.alias] = doc[tc.key]
			delete(doc, tc.key)
			doc["@context"] = []interface{}{"https://www.w3.org/ns/credentials/v2",
				map[string]interface{}{tc.alias: tc.def}}
			err := (&JSONPresentation{presentationData: PresentationData(doc)}).verifyCompactedForm()
			if !errors.Is(err, processor.ErrNotCompactedForm) {
				t.Fatalf("err = %v, want ErrNotCompactedForm for %s renamed to %s", err, tc.key, tc.alias)
			}
		})
	}
}
