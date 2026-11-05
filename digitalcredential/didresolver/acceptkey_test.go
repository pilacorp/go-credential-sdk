package didresolver

import (
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
)

// keysWith runs Keys on the JSON of v at the fixed time, with accept as AcceptKey.
func keysWith(t *testing.T, v any, accept AcceptKeyFunc) ([]issuerkey.PublicKey, error) {
	t.Helper()
	return keysAt(t, v, now, accept)
}

// The rule of CID §2.2, a key verifies before its revoked and expires times and
// not at or after them, except that a key revoked for a stated reason other
// than keyCompromise outlives its revoked time.
func TestDefaultAcceptKey(t *testing.T) {
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	before, after := at.Add(-time.Second), at.Add(time.Second)
	for name, tc := range map[string]struct {
		k    KeyInfo
		want bool
	}{
		"no time":                {KeyInfo{At: at}, true},
		"revoked later":          {KeyInfo{At: at, Revoked: after}, true},
		"revoked at":             {KeyInfo{At: at, Revoked: at}, false},
		"revoked before":         {KeyInfo{At: at, Revoked: before}, false},
		"expires later":          {KeyInfo{At: at, Expires: after}, true},
		"expires at":             {KeyInfo{At: at, Expires: at}, false},
		"expires before":         {KeyInfo{At: at, Expires: before}, false},
		"revoked later, expired": {KeyInfo{At: at, Revoked: after, Expires: before}, false},
		"superseded, revoked":    {KeyInfo{At: at, Revoked: before, RevocationReason: "superseded"}, true},
		"superseded, revoked at": {KeyInfo{At: at, Revoked: at, RevocationReason: "superseded"}, true},
		"superseded, expired":    {KeyInfo{At: at, Revoked: before, Expires: before, RevocationReason: "superseded"}, false},
		"compromised, revoked":   {KeyInfo{At: at, Revoked: before, RevocationReason: "keyCompromise"}, false},
		"no reason, revoked":     {KeyInfo{At: at, Revoked: before}, false},
		"other reason, revoked":  {KeyInfo{At: at, Revoked: before, RevocationReason: "cessationOfOperation"}, true},
		"other reason, expired":  {KeyInfo{At: at, Revoked: before, Expires: before, RevocationReason: "cessationOfOperation"}, false},
	} {
		if got := DefaultAcceptKey(tc.k); got != tc.want {
			t.Errorf("%s: DefaultAcceptKey = %v; want %v", name, got, tc.want)
		}
	}
}

// AcceptKey is given what the document says, for keys in force as well, and
// its answer alone decides.
func TestAcceptKeyIsGivenWhatTheDocumentSays(t *testing.T) {
	past := now.Add(-time.Hour)
	later := now.Add(time.Hour)
	for name, tc := range map[string]struct {
		vm   map[string]any
		want KeyInfo
	}{
		"in force": {
			multikeyVM(),
			KeyInfo{ID: vmID, At: now},
		},
		"revoked later": {
			multikeyVM("revoked", later.Format(time.RFC3339)),
			KeyInfo{ID: vmID, Revoked: later, At: now},
		},
		"revoked with a reason": {
			multikeyVM("revoked", past.Format(time.RFC3339), "revocationReason", "superseded"),
			KeyInfo{ID: vmID, Revoked: past, RevocationReason: "superseded", At: now},
		},
		"a reason that is not a string": {
			multikeyVM("revoked", past.Format(time.RFC3339), "revocationReason", 5),
			KeyInfo{ID: vmID, Revoked: past, At: now},
		},
		"expired": {
			multikeyVM("expires", past.Format(time.RFC3339)),
			KeyInfo{ID: vmID, Expires: past, At: now},
		},
		"revoked, expiry still ahead": {
			multikeyVM("revoked", past.Format(time.RFC3339), "expires", later.Format(time.RFC3339), "revocationReason", "keyCompromise"),
			KeyInfo{ID: vmID, Revoked: past, Expires: later, RevocationReason: "keyCompromise", At: now},
		},
	} {
		for _, accept := range []bool{true, false} {
			var got []KeyInfo
			keys, err := keysWith(t, document([]any{tc.vm}, []any{vmID}), func(k KeyInfo) bool {
				got = append(got, k)
				return accept
			})
			if err != nil {
				t.Errorf("%s: %v", name, err)
				continue
			}
			if len(got) != 1 || got[0] != tc.want {
				t.Errorf("%s: AcceptKey got %+v; want one call with %+v", name, got, tc.want)
			}
			if (len(keys) == 1) != accept {
				t.Errorf("%s: AcceptKey returned %v but Keys returned %d keys", name, accept, len(keys))
			}
		}
	}
}

// Without AcceptKey, Keys applies DefaultAcceptKey to what the document says.
func TestKeysUsesDefaultAcceptKeyWithoutAcceptKey(t *testing.T) {
	past := now.Add(-time.Hour).Format(time.RFC3339)
	for name, tc := range map[string]struct {
		vm   map[string]any
		want int
	}{
		"in force":             {multikeyVM(), 1},
		"revoked superseded":   {multikeyVM("revoked", past, "revocationReason", "superseded"), 1},
		"superseded, expired":  {multikeyVM("revoked", past, "expires", past, "revocationReason", "superseded"), 0},
		"revoked other reason": {multikeyVM("revoked", past, "revocationReason", "cessationOfOperation"), 1},
		"revoked compromised":  {multikeyVM("revoked", past, "revocationReason", "keyCompromise"), 0},
		"revoked, no reason":   {multikeyVM("revoked", past), 0},
		"reason not a string":  {multikeyVM("revoked", past, "revocationReason", 5), 0},
		"expired":              {multikeyVM("expires", past), 0},
		"revoked at year one":  {multikeyVM("revoked", "0001-01-01T00:00:00Z"), 0},
		"expires at year one":  {multikeyVM("expires", "0001-01-01T00:00:00Z"), 0},
	} {
		if keys, err := keysWith(t, document([]any{tc.vm}, []any{vmID}), nil); err != nil || len(keys) != tc.want {
			t.Errorf("%s: keys = %d, err = %v; want %d", name, len(keys), err, tc.want)
		}
	}
}

// A method Keys cannot use never reaches AcceptKey, so it cannot bring back a
// key the document does not offer.
func TestAcceptKeyIsNotCalledForAKeyKeysCannotUse(t *testing.T) {
	past := now.Add(-time.Hour).Format(time.RFC3339)
	other := "did:example:999"
	for name, doc := range map[string]map[string]any{
		"revoked not a time":       document([]any{multikeyVM("revoked", "soon")}, []any{vmID}),
		"revoked null":             document([]any{multikeyVM("revoked", nil)}, []any{vmID}),
		"revoked, expires garbled": document([]any{multikeyVM("revoked", past, "expires", "soon")}, []any{vmID}),
		"expires not a string":     document([]any{multikeyVM("expires", 1)}, []any{vmID}),
		"revoked at year one":      document([]any{multikeyVM("revoked", "0001-01-01T00:00:00Z")}, []any{vmID}),
		"expires at year one":      document([]any{multikeyVM("expires", "0001-01-01T00:00:00Z")}, []any{vmID}),
		"another controller":       document([]any{multikeyVM("controller", other)}, []any{vmID}),
		"another document":         document([]any{multikeyVM("id", other+"#k")}, []any{other + "#k"}),
		"not in assertionMethod":   document([]any{multikeyVM()}, nil),
		"no key it can read":       document([]any{multikeyVM("publicKeyMultibase", "zBAD")}, []any{vmID}),
	} {
		calls := 0
		keys, err := keysWith(t, doc, func(KeyInfo) bool { calls++; return true })
		if err != nil || calls != 0 || len(keys) != 0 {
			t.Errorf("%s: calls = %d, keys = %d, err = %v; want no call and no key", name, calls, len(keys), err)
		}
	}
}

// Each method is judged on its own: a rotation keeps the old key beside the
// new, a compromise does not.
func TestDefaultAcceptKeyJudgesEachMethod(t *testing.T) {
	past := now.Add(-time.Hour).Format(time.RFC3339)
	old := multikeyVM("id", "#old", "revoked", past, "revocationReason", "superseded")
	stolen := multikeyVM("id", "#stolen", "revoked", past, "revocationReason", "keyCompromise")
	fresh := multikeyVM("id", "#new")
	keys, err := keysWith(t, document([]any{old, stolen, fresh}, []any{"#old", "#stolen", "#new"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, k := range keys {
		got = append(got, k.KID)
	}
	if len(got) != 2 || got[0] != testDID+"#old" || got[1] != testDID+"#new" {
		t.Errorf("KIDs = %v", got)
	}
}

// A method listed twice is judged once, whatever AcceptKey answers.
func TestAcceptKeyIsCalledOncePerMethod(t *testing.T) {
	for _, accept := range []bool{true, false} {
		calls := 0
		keys, err := keysWith(t, document([]any{multikeyVM()}, []any{vmID, "#k"}), func(KeyInfo) bool {
			calls++
			return accept
		})
		if err != nil || calls != 1 || (len(keys) == 1) != accept {
			t.Errorf("accept %v: calls = %d, keys = %d, err = %v; want 1 call", accept, calls, len(keys), err)
		}
	}
}
