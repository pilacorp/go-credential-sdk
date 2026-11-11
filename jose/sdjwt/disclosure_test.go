package sdjwt

import "testing"

// RFC 9901 §4.2.1 builds this disclosure from
// ["_26bc4LT-ac6q2KI6cBW5es", "family_name", "Möbius"], and §4.2.3 gives its
// digest.
func TestParseDisclosureRFCExample(t *testing.T) {
	d, err := ParseDisclosure("WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0")
	if err != nil {
		t.Fatal(err)
	}
	if d.Digest != "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0" {
		t.Errorf("digest %s", d.Digest)
	}
	if d.Salt != "_26bc4LT-ac6q2KI6cBW5es" || d.Name != "family_name" || d.Value != "Möbius" || d.ArrayElement {
		t.Errorf("parsed %+v", d)
	}
}
