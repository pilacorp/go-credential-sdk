package credentialstatus

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestParseEntry_Section21 checks the Bitstring Status List v1.0 §2.1 rules on
// an entry's fields, which hold for every statusPurpose.
func TestParseEntry_Section21(t *testing.T) {
	const list = "https://example.com/credentials/status/3"
	valid := func() map[string]interface{} {
		return map[string]interface{}{
			"id": list + "#94567", "type": "BitstringStatusListEntry", "statusPurpose": "refresh",
			"statusListIndex": "94567", "statusListCredential": list,
		}
	}
	_, err := ParseEntry(valid())
	assert.NoError(t, err, "§2.1 example entry")

	for name, c := range map[string]struct {
		edit func(map[string]interface{})
		want string
	}{
		"index with sign":    {func(m map[string]interface{}) { m["statusListIndex"] = "+3" }, "must be a base-10 integer"},
		"negative index":     {func(m map[string]interface{}) { m["statusListIndex"] = "-1" }, "must be a base-10 integer"},
		"list URL not a URL": {func(m map[string]interface{}) { m["statusListCredential"] = "not a url" }, "must be a URL"},
		"list URL authority too long": {func(m map[string]interface{}) {
			m["statusListCredential"] = "https://" + strings.Repeat("@", 300) + "h.example/l"
		}, "byte authority"},
		"id is the list URL":      {func(m map[string]interface{}) { m["id"] = list }, "must not be the statusListCredential URL"},
		"id not a URL":            {func(m map[string]interface{}) { m["id"] = "not a url" }, "must be a URL"},
		"statusSize zero":         {func(m map[string]interface{}) { m["statusSize"] = float64(0) }, "greater than zero"},
		"size 2 without messages": {func(m map[string]interface{}) { m["statusSize"] = float64(2) }, "statusMessage is required"},
		"messages of wrong length": {func(m map[string]interface{}) {
			m["statusMessage"] = []interface{}{map[string]interface{}{"status": "0x0", "message": "a"}}
		}, "needs 2^1"},
		"statusReference a number": {func(m map[string]interface{}) { m["statusReference"] = float64(7) }, "statusReference must be a URL"},
	} {
		m := valid()
		c.edit(m)
		_, err := ParseEntry(m)
		assert.ErrorContains(t, err, c.want, name)
		assert.ErrorIs(t, err, ErrMalformedValue, name)
	}
}
