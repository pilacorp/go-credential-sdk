package uri

import "testing"

// The examples of RFC 3986 §1.1.2 are URIs; each rejected string breaks one
// rule of §3 or, for http and https, RFC 9110 §4.2.1.
func TestCheck(t *testing.T) {
	for _, s := range []string{
		"ftp://ftp.is.co.za/rfc/rfc1808.txt",
		"http://www.ietf.org/rfc/rfc2396.txt",
		"ldap://[2001:db8::7]/c=GB?objectClass?one",
		"mailto:John.Doe@example.com",
		"news:comp.infosystems.www.servers.unix",
		"tel:+1-816-555-1212",
		"telnet://192.0.2.16:80/",
		"urn:oasis:names:specification:docbook:dtd:xml:4.1.2",
		"https://%CF%83.example.com/root",
		"did:example:123",
	} {
		if err := Check(s); err != nil {
			t.Errorf("Check(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range []string{
		"",
		"1http://example.com",       // §3.1: scheme starts with ALPHA
		"https://bücher.example/x",  // §3.2.2: a reg-name is ASCII
		"https://example.com/a b",   // §3.3: space is not a pchar
		"https://example.com/%zz",   // §2.1: pct-encoded is two HEXDIG
		"https://example.com?q=<x>", // §3.4
		"https://example.com#f#g",   // §3.5: "#" is not in a fragment
		"https://example.com:8x/",   // §3.2.3: port is DIGIT
		"https://[fe80::1%25eth0]/", // §3.2.2: no zone in an IP-literal
		"https://[::1/",             // §3.2.2: IP-literal is bracketed
		"https:///issuer",           // RFC 9110 §4.2.2: empty host
		"https:issuer",              // RFC 9110 §4.2.2: no authority
		"HTTP://user@:443/",         // RFC 9110 §4.2.1, scheme in any case
	} {
		if err := Check(s); err == nil {
			t.Errorf("Check(%q) = nil, want an error", s)
		}
	}
}
