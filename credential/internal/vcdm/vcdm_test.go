package vcdm

import (
	"strings"
	"testing"
	"time"
)

func TestCheckValidity(t *testing.T) {
	now := time.Now()
	at := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }

	cases := []struct {
		name       string
		validFrom  string
		validUntil string
		leeway     time.Duration
		wantErr    string
	}{
		{name: "no window"},
		{name: "inside the window", validFrom: at(-time.Hour), validUntil: at(time.Hour)},
		{name: "not valid yet", validFrom: at(5 * time.Second), wantErr: "credential is not valid yet"},
		{name: "expired", validUntil: at(-5 * time.Second), wantErr: "credential is expired"},
		{name: "validFrom ahead, within leeway", validFrom: at(5 * time.Second), leeway: 10 * time.Second},
		{name: "validFrom ahead, beyond leeway", validFrom: at(15 * time.Second), leeway: 10 * time.Second, wantErr: "credential is not valid yet"},
		{name: "validUntil passed, within leeway", validUntil: at(-5 * time.Second), leeway: 10 * time.Second},
		{name: "validUntil passed, beyond leeway", validUntil: at(-15 * time.Second), leeway: 10 * time.Second, wantErr: "credential is expired"},
		{name: "unparsable validFrom", validFrom: "yesterday", wantErr: "failed to parse validFrom"},
		{name: "unparsable validUntil", validUntil: "tomorrow", wantErr: "failed to parse validUntil"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := map[string]interface{}{}
			if tc.validFrom != "" {
				doc[ValidFrom] = tc.validFrom
			}
			if tc.validUntil != "" {
				doc[ValidUntil] = tc.validUntil
			}
			err := CheckValidity("credential", doc, tc.leeway)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

// Vectors from the lexical space of XML Schema 1.1 Part 2 dateTime (§3.3.7.2)
// and dateTimeStamp (§3.4.28).
func TestParseDateTime(t *testing.T) {
	utc := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	cases := []struct {
		in        string
		stamp     bool // ParseDateTimeStamp accepts it
		dateTime  bool // ParseDateTime accepts it
		wantInUTC string
	}{
		{"2020-01-01T00:00:00Z", true, true, "2020-01-01T00:00:00Z"},
		{"2020-01-01T07:00:00+07:00", true, true, "2020-01-01T00:00:00Z"},
		{"2020-01-01T00:00:00.25Z", true, true, "2020-01-01T00:00:00.25Z"},
		{"2019-12-31T24:00:00Z", true, true, "2020-01-01T00:00:00Z"},
		{"2020-01-01T00:00:00", false, true, "2020-01-01T00:00:00Z"},
		{"2020-01-01T00:00:00,5Z", false, false, ""},
		{"2020-01-01t00:00:00Z", false, false, ""},
		{"2020-01-01T25:00:00Z", false, false, ""},
		{"2020-13-01T00:00:00Z", false, false, ""},
		{"2020-01-01", false, false, ""},
		{"2020-01-01T00:00:00+15:00", false, false, ""},
		{"2020-02-30T00:00:00Z", false, false, ""},
		{"12020-01-01T00:00:00Z", false, false, ""},
	}
	for _, c := range cases {
		got, err := ParseDateTimeStamp(c.in)
		if (err == nil) != c.stamp {
			t.Errorf("ParseDateTimeStamp(%q) err = %v, want accepted = %v", c.in, err, c.stamp)
		} else if err == nil && !got.Equal(utc(c.wantInUTC)) {
			t.Errorf("ParseDateTimeStamp(%q) = %v, want %s", c.in, got, c.wantInUTC)
		}
		got, err = ParseDateTime(c.in)
		if (err == nil) != c.dateTime {
			t.Errorf("ParseDateTime(%q) err = %v, want accepted = %v", c.in, err, c.dateTime)
		} else if err == nil && !got.Equal(utc(c.wantInUTC)) {
			t.Errorf("ParseDateTime(%q) = %v, want %s", c.in, got, c.wantInUTC)
		}
	}
}

// A value the pattern takes but the calendar does not have is refused with
// the wanted form, not Go's layout, and without the value.
func TestParseDateTime_ErrorText(t *testing.T) {
	for _, in := range []string{"2020-02-30T00:00:00Z", "123456789012345678901234567890-01-01T00:00:00Z", "2020-01-01"} {
		_, err := ParseDateTimeStamp(in)
		if err == nil || !strings.HasPrefix(err.Error(), "want a ") || strings.Contains(err.Error(), in) {
			t.Errorf("%q: err = %v, want a 'want a ...' text without the value", in, err)
		}
	}
}

// VC Data Model 2.0 §5.8: a validFrom or validUntil serialized without an
// offset MUST be interpreted as UTC.
func TestCheckValidity_ZonelessReadAsUTC(t *testing.T) {
	if err := CheckValidity("credential", map[string]interface{}{ValidUntil: "2999-01-01T00:00:00"}, 0); err != nil {
		t.Fatalf("zoneless validUntil refused: %v", err)
	}
	if err := CheckValidity("credential", map[string]interface{}{ValidUntil: "2000-01-01T00:00:00"}, 0); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("err = %v, want expired", err)
	}
}

func TestCheckValidity_DateMemberNotAString(t *testing.T) {
	for _, name := range []string{"validFrom", "validUntil", "issuanceDate", "expirationDate"} {
		err := CheckValidity("credential", map[string]interface{}{name: 1700000000.0}, 0)
		if err == nil || !strings.Contains(err.Error(), "must be a string") {
			t.Errorf("%s: err = %v, want a must-be-a-string error", name, err)
		}
	}
}

// A date member that is there must be a date-time, an empty string included.
func TestCheckValidity_EmptyDateMember(t *testing.T) {
	for _, name := range []string{ValidFrom, ValidUntil, IssuanceDate, ExpirationDate} {
		err := CheckValidity("credential", map[string]interface{}{name: ""}, 0)
		if err == nil || !strings.Contains(err.Error(), "failed to parse "+name) {
			t.Errorf("%s: err = %v, want a parse error", name, err)
		}
	}
}
