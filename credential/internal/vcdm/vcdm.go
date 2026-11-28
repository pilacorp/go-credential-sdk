// Package vcdm holds the small Verifiable Credentials Data Model helpers that
// both the vc and vp packages need.
//
// It lives under internal/ on purpose. These are not API: nothing outside this
// module should depend on them, and anything exported from credential/vc or
// credential/vp has to be kept working forever once a version is tagged. The
// alternative — a copy in each package — is how two checks that must agree drift
// apart, which is a bug this repository has already shipped once.
package vcdm

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ContextV2 is the @context VC Data Model 2.0 §4.3 requires first on every
// credential and presentation.
const ContextV2 = "https://www.w3.org/ns/credentials/v2"

// ContextV1 is the VC 1.1 base context. Recognised, never written.
const ContextV1 = "https://www.w3.org/2018/credentials/v1"

// HasType reports whether a type property names want. The data model defines the
// property as an array, but a single type is commonly written as a bare string,
// so both shapes are read.
func HasType(v interface{}, want string) bool {
	switch t := v.(type) {
	case string:
		return t == want
	case []interface{}:
		for _, e := range t {
			if s, ok := e.(string); ok && s == want {
				return true
			}
		}
	case []string:
		for _, s := range t {
			if s == want {
				return true
			}
		}
	}

	return false
}

// FirstContext returns the first entry of an @context property, which is the one
// the data model pins. A bare string counts as its own first entry; anything
// else yields "" and the caller reports it.
func FirstContext(v interface{}) string {
	switch c := v.(type) {
	case string:
		return c
	case []interface{}:
		if len(c) > 0 {
			first, _ := c[0].(string)

			return first
		}
	case []string:
		if len(c) > 0 {
			return c[0]
		}
	}

	return ""
}

// dateTimePattern is the lexical space of XML Schema 1.1 Part 2 dateTime
// (§3.3.7.2). The zone group is optional there and required in dateTimeStamp
// (§3.4.28). Years outside 0000-9999 match but cannot be read as time.Time.
var dateTimePattern = regexp.MustCompile(
	`^-?([1-9][0-9]{3,}|0[0-9]{3})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])` +
		`T(([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]+)?|24:00:00(\.0+)?)` +
		`(?P<zone>Z|[+-]((0[0-9]|1[0-3]):[0-5][0-9]|14:00))?$`)

var zoneGroup = dateTimePattern.SubexpIndex("zone")

// ParseDateTimeStamp reads a date-time with a time zone, as a Data Integrity
// proof's created (DI 1.0 §2.1, a dateTimeStamp). DI 1.0 lets a processor
// consume a value serialized without an offset; this reader refuses it.
// T24:00:00 is the start of the next day.
func ParseDateTimeStamp(s string) (time.Time, error) {
	return parseDateTime(s, true)
}

// ParseDateTime reads a date-time whose time zone may be left out, and reads
// such a value as UTC. VC Data Model 2.0 §5.8 requires that for validFrom and
// validUntil (§4.9, dateTimeStamp values serialized without an offset). For
// VCDM 1.1 issuanceDate (§4.6) and expirationDate (§4.8), XML Schema dateTime
// values, it is this SDK's choice: XML Schema leaves the order against a zoned
// value partial (§3.3.7.1), and one instant keeps every verifier in step.
// T24:00:00 is the start of the next day.
func ParseDateTime(s string) (time.Time, error) {
	return parseDateTime(s, false)
}

// Date members of a credential or presentation: validFrom and validUntil
// (VCDM 2.0 §4.9) and issuanceDate and expirationDate (VCDM 1.1 §4.6, §4.8).
const (
	ValidFrom      = "validFrom"
	ValidUntil     = "validUntil"
	IssuanceDate   = "issuanceDate"
	ExpirationDate = "expirationDate"
)

// IsDateMember reports whether name is one of the date members.
func IsDateMember(name string) bool {
	switch name {
	case ValidFrom, ValidUntil, IssuanceDate, ExpirationDate:
		return true
	}
	return false
}

func parseDateTime(s string, zoneRequired bool) (time.Time, error) {
	m := dateTimePattern.FindStringSubmatch(s)
	if m == nil || (zoneRequired && m[zoneGroup] == "") {
		if zoneRequired {
			return time.Time{}, fmt.Errorf("want a date-time with a time zone, such as 2026-01-01T00:00:00Z")
		}
		return time.Time{}, fmt.Errorf("want a date-time, such as 2026-01-01T00:00:00Z")
	}
	if m[zoneGroup] == "" {
		s += "Z"
	}
	endOfDay := strings.Contains(s, "T24:00:00")
	if endOfDay {
		s = strings.Replace(s, "T24:00:00", "T00:00:00", 1)
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		// The pattern takes dates the calendar does not have (February 30)
		// and years outside 0000-9999, which XML Schema allows and
		// time.Time does not hold.
		return time.Time{}, fmt.Errorf("want a year from 0000 to 9999 and a date the calendar has, such as 2026-01-01T00:00:00Z")
	}
	if endOfDay {
		t = t.AddDate(0, 0, 1)
	}
	return t, nil
}

// ValidityPairs are the members CheckValidity reads, from and until, in the
// order it reads them.
var ValidityPairs = [][2]string{{ValidFrom, ValidUntil}, {IssuanceDate, ExpirationDate}}

// CheckValidity enforces the validity period a credential or presentation
// states, at the current time widened by leeway on both sides: validFrom and
// validUntil (VCDM 2.0), and issuanceDate and expirationDate (VCDM 1.1 §4.6,
// §4.8). Each pair is read when present, whatever @context says, so a
// document that mixes contexts cannot move its dates out of view. what names
// the document in the error ("credential", "presentation").
func CheckValidity(what string, doc map[string]interface{}, leeway time.Duration) error {
	for _, pair := range ValidityPairs {
		from, err := dateMember(doc, pair[0])
		if err != nil {
			return err
		}
		until, err := dateMember(doc, pair[1])
		if err != nil {
			return err
		}
		if err := checkBounds(what, from, until, leeway); err != nil {
			return err
		}
	}
	return nil
}

// dateBound is one end of a validity period: the member name, its value, and
// whether the member is there.
type dateBound struct {
	name, value string
	present     bool
}

func checkBounds(what string, from, until dateBound, leeway time.Duration) error {
	now := time.Now()
	if from.present {
		t, err := ParseDateTime(from.value)
		if err != nil {
			return fmt.Errorf("failed to parse %s: %w", from.name, err)
		}
		if now.Add(leeway).Before(t) {
			return fmt.Errorf("%s is not valid yet", what)
		}
	}
	if until.present {
		t, err := ParseDateTime(until.value)
		if err != nil {
			return fmt.Errorf("failed to parse %s: %w", until.name, err)
		}
		if now.Add(-leeway).After(t) {
			return fmt.Errorf("%s is expired", what)
		}
	}
	return nil
}

// dateMember reads a date member of doc. A member that is there must be a
// date-time string, empty included (VCDM 1.1 §4.6: issuanceDate "MUST be";
// §4.8 and VCDM 2.0 §4.9: "If present ... MUST be").
func dateMember(doc map[string]interface{}, name string) (dateBound, error) {
	v, ok := doc[name]
	if !ok {
		return dateBound{name: name}, nil
	}
	s, ok := v.(string)
	if !ok {
		return dateBound{}, fmt.Errorf("failed to parse %s: field %q must be a string, got %T", name, name, v)
	}
	return dateBound{name: name, value: s, present: true}, nil
}
