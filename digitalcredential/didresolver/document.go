// Reading a DID Resolution Result or DID document: DID Resolution §4, §7 and
// W3C Controlled Identifiers v1.0 (CID) §2.2, §2.3.2, §3.3.

package didresolver

import (
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
	"github.com/pilacorp/go-credential-sdk/jose"
)

// parseResolution returns the DID document of did held in body, a resolution
// result or a document alone. §9.1 lets a resolver send either, and a result
// is told by its didDocument member, not by Content-Type, so a DIDResolver of
// any transport is read the same way. A document has its id at the top level
// and must match did, so reading one as the other finds no document.
//
// didDocumentMetadata is read at the top level of both forms: a result has it
// there (§7), and some resolvers embed it in the document they return.
func parseResolution(body []byte, did string) (map[string]any, error) {
	top, err := jose.DecodeJSONObject(body)
	if err != nil {
		return nil, fault("the resolution is not a JSON object: %w; the DID resolver must fix it", err)
	}
	if meta, _ := top["didResolutionMetadata"].(map[string]any); meta["error"] != nil {
		return nil, fault("the DID resolver reports an error (DID Resolution §4)")
	}
	if meta, _ := top["didDocumentMetadata"].(map[string]any); meta["deactivated"] == true {
		return nil, fault("the DID is deactivated (DID Resolution §4.3)")
	}
	doc := top
	if v, ok := top["didDocument"]; ok {
		if doc, _ = v.(map[string]any); doc == nil {
			return nil, fault("the resolution result holds no DID document (DID Resolution §4)")
		}
	}
	if id, _ := doc["id"].(string); id != did {
		return nil, fault("the id of the DID document is not string equal to the DID resolved (DID Resolution §4); the DID resolver or the issuer must fix it")
	}
	return doc, nil
}

// assertionKeys walks assertionMethod in its order. As RFC 7517 §5 does for a
// JWK, a method this SDK cannot use is skipped so the others still verify,
// and a document whose structure is wrong is not used at all.
func assertionKeys(doc map[string]any, did string, now time.Time) ([]issuerkey.PublicKey, error) {
	methods, err := methodsByID(doc, did)
	if err != nil {
		return nil, err
	}
	keys := []issuerkey.PublicKey{}
	v, ok := doc["assertionMethod"]
	if !ok {
		return keys, nil
	}
	refs, ok := v.([]any)
	if !ok {
		return nil, fault("assertionMethod is not a set (CID §2.3.2)")
	}
	seen := make(map[string]bool, len(refs))
	for _, ref := range refs {
		var id string
		var vm map[string]any
		switch e := ref.(type) {
		case string:
			id = absoluteID(e, did)
			vm = methods[id]
		case map[string]any:
			id, _ = e["id"].(string)
			id = absoluteID(id, did)
			vm = e
		default:
			return nil, fault("assertionMethod holds an element that is neither a reference nor a verification method (CID §2.3.2)")
		}
		if vm == nil || seen[id] || !belongs(vm, id, did) || !inForce(vm, now) {
			continue
		}
		seen[id] = true
		if pub := publicKey(vm); pub != nil {
			keys = append(keys, issuerkey.PublicKey{KID: id, Public: pub})
		}
	}
	return keys, nil
}

// methodsByID indexes verificationMethod by absolute id. Two definitions of
// one id leave a reference with no single meaning, so the document is refused
// rather than one chosen.
func methodsByID(doc map[string]any, did string) (map[string]map[string]any, error) {
	v, ok := doc["verificationMethod"]
	if !ok {
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, fault("verificationMethod is not a set (CID §2.2)")
	}
	methods := make(map[string]map[string]any, len(list))
	for _, e := range list {
		vm, ok := e.(map[string]any)
		if !ok {
			return nil, fault("verificationMethod holds an element that is not a map (CID §2.2)")
		}
		id, _ := vm["id"].(string)
		id = absoluteID(id, did)
		if _, dup := methods[id]; dup && id != "" {
			return nil, fault("verificationMethod defines one id twice (CID §2.2)")
		}
		methods[id] = vm
	}
	return methods, nil
}

// absoluteID resolves a relative DID URL "#fragment" against the document
// (DID Core 1.0 §3.2.2); an absolute one stays as it is.
func absoluteID(id, did string) string {
	if strings.HasPrefix(id, "#") {
		return did + id
	}
	return id
}

// belongs applies the binding of CID §3.3: the method lives in this document
// and names it as controller. A method of another document would have to be
// fetched from there, which this resolver does not do, so it is not trusted
// on this document's word.
func belongs(vm map[string]any, id, did string) bool {
	fragment, ok := strings.CutPrefix(id, did+"#")
	controller, _ := vm["controller"].(string)
	return ok && fragment != "" && controller == did
}

// inForce applies revoked and expires (CID §2.2): systems "are expected to not
// verify any proofs associated with the verification method at or after" those
// times. Both MUST be a dateTimeStamp, so one this reader cannot read might
// mean the key is gone, and the key is dropped.
func inForce(vm map[string]any, now time.Time) bool {
	for _, name := range []string{"revoked", "expires"} {
		v, ok := vm[name]
		if !ok {
			continue
		}
		s, _ := v.(string)
		if t, err := time.Parse(time.RFC3339, s); err != nil || !now.Before(t) {
			return false
		}
	}
	return true
}
