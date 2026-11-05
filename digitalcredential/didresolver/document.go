// Reading a DID Resolution Result or DID document: DID Resolution §4, §7, §8,
// the status table of §9.1, and W3C Controlled Identifiers v1.0 (CID) §2.2,
// §2.3.2, §3.3.

package didresolver

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
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
		// No %w: the decoder's text can quote bytes of the body.
		return nil, fault("invalid resolver response: not a valid JSON object")
	}
	// deactivated first (DID Resolution §4.3): §9.1 has its 410 override any
	// other status, so a result read here means what it would over HTTP.
	if meta, _ := top["didDocumentMetadata"].(map[string]any); meta["deactivated"] == true {
		return nil, answer(http.StatusGone, "")
	}
	if meta, _ := top["didResolutionMetadata"].(map[string]any); meta["error"] != nil {
		return nil, resolutionError(meta["error"])
	}
	doc := top
	if v, ok := top["didDocument"]; ok {
		if doc, _ = v.(map[string]any); doc == nil {
			return nil, fault("invalid resolver response: no DID document")
		}
	}
	// DID Resolution §4: id string equal to the DID resolved.
	if id, _ := doc["id"].(string); id != did {
		return nil, fault("invalid DID document: id does not match the DID")
	}
	return doc, nil
}

// statusOf is the table of DID Resolution §9.1: the HTTP status of each
// error type of §8. A result read from any transport goes through answer, as
// the HTTP binding does, so one answer of a resolver means the same however
// it came.
var statusOf = map[string]int{
	"INVALID_DID":                  http.StatusBadRequest,
	"INVALID_DID_URL":              http.StatusBadRequest,
	"INVALID_OPTIONS":              http.StatusBadRequest,
	"NOT_FOUND":                    http.StatusNotFound,
	"REPRESENTATION_NOT_SUPPORTED": http.StatusNotAcceptable,
	"INVALID_DID_DOCUMENT":         http.StatusInternalServerError,
	"METHOD_NOT_SUPPORTED":         http.StatusNotImplemented,
	"FEATURE_NOT_SUPPORTED":        http.StatusNotImplemented,
	"INTERNAL_ERROR":               http.StatusInternalServerError,
}

// answer is the outcome of issuerkey.Resolver a status of §9.1 gives: 400 and
// 501 refuse the DID, 404 and 410 say it has no key. Any other status is not
// an answer, and answer returns nil: the caller reports a failed retrieval,
// so an outage never reads as a missing key. said names what the resolver
// sent, for the text.
func answer(status int, said string) error {
	switch status {
	case http.StatusBadRequest, http.StatusNotImplemented:
		return fmt.Errorf("%w: didresolver: resolver refused this DID (%s)", issuerkey.ErrIssuerNotSupported, said)
	case http.StatusNotFound:
		return fault("DID not found")
	case http.StatusGone:
		return fault("DID is deactivated")
	}
	return nil
}

// resolutionError is the error of a result whose didResolutionMetadata holds
// error, an object whose type is a URL (§8). The text names a type of §8, or
// none, never text of the resolver.
func resolutionError(e any) error {
	obj, _ := e.(map[string]any)
	typ, _ := obj["type"].(string)
	name, ok := strings.CutPrefix(typ, "https://www.w3.org/ns/did#")
	status, known := statusOf[name]
	if !ok || !known {
		return errors.New("didresolver: resolver returned an unknown error")
	}
	if err := answer(status, name); err != nil {
		return err
	}
	return fmt.Errorf("didresolver: resolver returned %s", name)
}

// assertionKeys walks assertionMethod in its order. As RFC 7517 §5 does for a
// JWK, a method this SDK cannot use is skipped so the others still verify,
// and a document whose structure is wrong is not used at all.
func assertionKeys(doc map[string]any, did string, now time.Time, accept AcceptKeyFunc) ([]issuerkey.PublicKey, error) {
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
		// CID §2.3.2: a set of verification methods.
		return nil, fault("invalid DID document: assertionMethod is not an array")
	}
	seen := make(map[string]map[string]any, len(refs))
	for _, ref := range refs {
		var id string
		var vm map[string]any
		switch e := ref.(type) {
		case string:
			id = absoluteID(e, did)
			vm = methods[id]
		case map[string]any:
			// CID §2.2.4: an embedded method is read directly, so what
			// verificationMethod holds for this id does not count.
			id, _ = e["id"].(string)
			id = absoluteID(id, did)
			vm = e
		default:
			return nil, fault("invalid DID document: assertionMethod has an entry that is neither a string nor an object")
		}
		// A method is judged once, and only one this SDK can use reaches
		// accept, so Config.AcceptKey is asked once and only about a key it
		// could accept.
		if vm == nil {
			continue
		}
		_, judged := seen[id]
		if err := define(seen, id, vm); err != nil {
			return nil, err
		}
		if judged {
			continue
		}
		if !belongs(vm, id, did) {
			continue
		}
		pub := publicKey(vm)
		if pub == nil {
			continue
		}
		if info, ok := keyInfo(vm, id, now); ok && accept(info) {
			keys = append(keys, issuerkey.PublicKey{KID: id, Public: pub})
		}
	}
	return keys, nil
}

// methodsByID indexes verificationMethod by absolute id (CID §2.2).
func methodsByID(doc map[string]any, did string) (map[string]map[string]any, error) {
	methods := map[string]map[string]any{}
	v, ok := doc["verificationMethod"]
	if !ok {
		return methods, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, fault("invalid DID document: verificationMethod is not an array")
	}
	for _, e := range list {
		vm, ok := e.(map[string]any)
		if !ok {
			return nil, fault("invalid DID document: verificationMethod has an entry that is not an object")
		}
		id, _ := vm["id"].(string)
		if err := define(methods, absoluteID(id, did), vm); err != nil {
			return nil, err
		}
	}
	return methods, nil
}

// define adds vm under id, within verificationMethod or within
// assertionMethod. CID forbids a repeated id for a service, not for a
// verification method, so this is stricter than the text: two different
// definitions of one id leave a reference with no single meaning, and a clean
// copy could bring back a key the other revokes, so the document is refused
// rather than one chosen. An equal copy changes neither, so it is no conflict.
func define(methods map[string]map[string]any, id string, vm map[string]any) error {
	if prev, dup := methods[id]; dup && id != "" && !reflect.DeepEqual(prev, vm) {
		return fault("invalid DID document: two keys have the same id")
	}
	methods[id] = vm
	return nil
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

// keyInfo reads what vm says of its key's lifetime (CID §2.2). revoked and
// expires MUST be a dateTimeStamp, so one this reader cannot read might mean
// the key is gone: ok is false and the key is dropped before any AcceptKeyFunc
// sees it. So is the zero time, which KeyInfo would show as no time at all and
// turn a key revoked long ago into one in force.
func keyInfo(vm map[string]any, id string, now time.Time) (info KeyInfo, ok bool) {
	info = KeyInfo{ID: id, At: now}
	for _, f := range []struct {
		name string
		at   *time.Time
	}{{"revoked", &info.Revoked}, {"expires", &info.Expires}} {
		v, present := vm[f.name]
		if !present {
			continue
		}
		s, _ := v.(string)
		t, err := time.Parse(time.RFC3339, s)
		if err != nil || t.IsZero() {
			return KeyInfo{}, false
		}
		*f.at = t
	}
	info.RevocationReason, _ = vm["revocationReason"].(string)
	return info, true
}
