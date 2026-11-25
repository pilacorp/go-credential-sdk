package credentialstatus

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	whatwgurl "github.com/nlnwa/whatwg-url/url"

	"github.com/pilacorp/go-credential-sdk/credential/internal/errtext"
	"github.com/pilacorp/go-credential-sdk/credential/internal/urlx"
	"github.com/pilacorp/go-credential-sdk/credential/internal/vcdm"
)

// Entry is a BitstringStatusListEntry whose fields passed the checks
// Bitstring Status List v1.0 §2.1 puts on them.
type Entry struct {
	Purpose string // statusPurpose
	ListURL string // statusListCredential
	Index   string // statusListIndex: base-10 digits, any length
	Size    int64  // statusSize; 1 when absent
}

// ParseEntry checks every field of a BitstringStatusListEntry that §2.1
// constrains, whatever its statusPurpose, so a malformed entry is refused
// whether or not its list is read. An optional field set to null counts as
// absent. Values echoed in errors are clipped. ListURL is the URL's WHATWG
// serialization without its fragment, so the list fetched and counted is the
// one checked here.
func ParseEntry(m map[string]interface{}) (Entry, error) {
	var e Entry

	// §2.1: type MUST be BitstringStatusListEntry.
	if !vcdm.HasType(m["type"], "BitstringStatusListEntry") {
		return e, fmt.Errorf("credentialStatus.type must be BitstringStatusListEntry")
	}

	e.Purpose, _ = m["statusPurpose"].(string)
	if e.Purpose == "" {
		return e, fmt.Errorf("credentialStatus.statusPurpose is required")
	}

	raw := m["statusListCredential"]
	if raw == nil {
		return e, fmt.Errorf("credentialStatus.statusListCredential is required")
	}
	var ok bool
	e.ListURL, ok = raw.(string)
	if !ok || e.ListURL == "" {
		return e, fmt.Errorf("credentialStatus.statusListCredential must be a non-empty string")
	}
	listURL, err := parseURL(e.ListURL, "credentialStatus.statusListCredential")
	if err != nil {
		return e, err
	}
	e.ListURL = listURL.Href(true) // the fragment is never sent

	// §2.1 defers the entry id to VC Data Model v2.0 §4.4: a single URL. It
	// "MUST NOT be the URL for the status list".
	if raw := m["id"]; raw != nil {
		id, isString := raw.(string)
		if !isString {
			return e, fmt.Errorf("credentialStatus.id must be a URL")
		}
		idURL, err := parseURL(id, "credentialStatus.id")
		if err != nil {
			return e, err
		}
		if sameURL(idURL, listURL) {
			return e, fmt.Errorf("credentialStatus.id must not be the statusListCredential URL")
		}
	}

	raw = m["statusListIndex"]
	if raw == nil {
		return e, fmt.Errorf("credentialStatus.statusListIndex is required")
	}
	e.Index, ok = raw.(string)
	if !ok || e.Index == "" {
		return e, fmt.Errorf("credentialStatus.statusListIndex must be a non-empty string")
	}
	// §2.1: an arbitrary size integer, 0 or more, written in base 10.
	if !isBase10Digits(e.Index) {
		return e, fmt.Errorf("invalid credentialStatus.statusListIndex %q: must be a base-10 integer, 0 or more", errtext.Clip(e.Index))
	}

	// §2.1: statusSize, if present, is an integer greater than zero; absent
	// means 1.
	e.Size = 1
	if raw := m["statusSize"]; raw != nil {
		n, isInt := jsonInteger(raw)
		if !isInt || n < 1 {
			return e, fmt.Errorf("credentialStatus.statusSize %s must be an integer greater than zero", errtext.Clip(fmt.Sprint(raw)))
		}
		e.Size = n
	}

	// §2.1: statusMessage is required when statusSize is greater than 1 and,
	// when present, holds one {status, message} object per status value.
	messages := m["statusMessage"]
	if e.Size > 1 && messages == nil {
		return e, fmt.Errorf("credentialStatus.statusMessage is required when statusSize is greater than 1")
	}
	if messages != nil {
		if err := checkStatusMessages(messages, e.Size); err != nil {
			return e, err
		}
	}

	// §2.1: statusReference, if present, is a URL or an array of URLs.
	if raw := m["statusReference"]; raw != nil {
		if err := checkStatusReference(raw); err != nil {
			return e, err
		}
	}
	return e, nil
}

// IsRefresh reports a refresh entry. §2.1 says a refresh status "does not
// invalidate the verifiable credential", so a verifier need not read its list.
func (e Entry) IsRefresh() bool { return e.Purpose == "refresh" }

// Position returns the bit position of an entry this reader reads: purpose
// revocation or suspension, statusSize 1 (§1.3 lets a processor support only
// that size) and an index that fits an int.
func (e Entry) Position() (int, error) {
	if err := checkSupportedPurpose(e.Purpose); err != nil {
		return 0, err
	}
	if !isBase10Digits(e.Index) {
		return 0, fmt.Errorf("invalid credentialStatus.statusListIndex %q: must be a base-10 integer, 0 or more", errtext.Clip(e.Index))
	}
	if e.Size != 1 {
		return 0, fmt.Errorf("credentialStatus.statusSize %d is not supported: only 1-bit status entries are", e.Size)
	}
	// The digits are checked above, so Atoi fails only on range; the NumError
	// would echo the whole index, so it is not wrapped.
	position, err := strconv.Atoi(e.Index)
	if err != nil {
		return 0, fmt.Errorf("invalid credentialStatus.statusListIndex %q: %w", errtext.Clip(e.Index), strconv.ErrRange)
	}
	return position, nil
}

// checkStatusMessages checks statusMessage against statusSize: an array of
// 2^size objects, each with a string status ("0x" hex) and a string message.
func checkStatusMessages(raw interface{}, size int64) error {
	msgs, ok := raw.([]interface{})
	if !ok {
		return fmt.Errorf("credentialStatus.statusMessage must be an array")
	}
	// An array cannot hold 2^31 elements here, so a larger size never matches.
	if size >= 31 || int64(len(msgs)) != int64(1)<<size {
		return fmt.Errorf("credentialStatus.statusMessage has %d elements, statusSize %d needs 2^%d", len(msgs), size, size)
	}
	for i, v := range msgs {
		obj, ok := v.(map[string]interface{})
		if !ok {
			return fmt.Errorf("credentialStatus.statusMessage[%d] must be an object", i)
		}
		status, _ := obj["status"].(string)
		if !isHexStatus(status) {
			return fmt.Errorf("credentialStatus.statusMessage[%d].status must be a hexadecimal string prefixed with 0x", i)
		}
		if _, ok := obj["message"].(string); !ok {
			return fmt.Errorf("credentialStatus.statusMessage[%d].message must be a string", i)
		}
	}
	return nil
}

// checkStatusReference checks that statusReference is a URL or an array of
// URLs.
func checkStatusReference(raw interface{}) error {
	refs, isArray := raw.([]interface{})
	if !isArray {
		refs = []interface{}{raw}
	}
	for _, v := range refs {
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("credentialStatus.statusReference must be a URL or an array of URLs")
		}
		if _, err := parseURL(s, "credentialStatus.statusReference"); err != nil {
			return err
		}
	}
	return nil
}

// parseURL parses s as a URL of the WHATWG URL Standard, the [URL] §2.1
// cites, at a cost linear in its length (urlx.Parse).
func parseURL(s, field string) (*whatwgurl.Url, error) {
	return urlx.Parse(s, field)
}

// sameURL compares two URLs by their WHATWG serialization, with an empty
// fragment counted as none. A non-empty fragment makes another URL, as in the
// §2.1 example where the entry id is the list URL plus "#94567".
func sameURL(a, b *whatwgurl.Url) bool {
	return a.Href(true)+a.Hash() == b.Href(true)+b.Hash()
}

// isBase10Digits reports whether s is one or more ASCII digits.
func isBase10Digits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isHexStatus reports whether s is "0x" followed by one or more hex digits.
func isHexStatus(s string) bool {
	digits, ok := strings.CutPrefix(s, "0x")
	if !ok || digits == "" {
		return false
	}
	for i := 0; i < len(digits); i++ {
		if !strings.ContainsRune("0123456789abcdefABCDEF", rune(digits[i])) {
			return false
		}
	}
	return true
}

// jsonInteger returns v as an integer when it is a whole number: float64 or
// json.Number from decoded JSON, or a Go integer in contents built without a
// JSON round trip. A string is not a number.
func jsonInteger(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case float64:
		if n != math.Trunc(n) || math.Abs(n) > 1<<53 {
			return 0, false
		}
		return int64(n), true
	case float32:
		return jsonInteger(float64(n))
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true
		}
		f, err := n.Float64()
		if err != nil || f != math.Trunc(f) || math.Abs(f) > 1<<53 {
			return 0, false
		}
		return int64(f), true
	case int:
		return int64(n), true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint8:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint:
		if uint64(n) > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case uint64:
		if n > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	}
	return 0, false
}
