// draft-ietf-oauth-sd-jwt-vc-19 §7.1; IANA IPv4 and IPv6 Special-Purpose
// Address Registries (RFC 6890, updated by RFC 8190), last updated 2025-10-09.

package safehttp

import "net/netip"

// blocked holds the blocks a fetch must never connect to.
var blocked = mustPrefixes(
	// IANA IPv4 and IPv6 Special-Purpose Address Registries, last updated
	// 2025-10-09: the entries marked Globally Reachable = False, without those
	// nested in another one. ::1/128 and ::/128 fall in ::/96 below and are
	// judged as 0.0.0.1 and 0.0.0.0; ::ffff:0:0/96 is unwrapped the same way.
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.2.0/24", "192.88.99.2/32",
	"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"240.0.0.0/4",
	"64:ff9b:1::/48", "100::/64", "100:0:0:1::/64", "2001:db8::/32",
	"3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10",

	// 192.0.0.0/24 and 2001::/23 are marked False, but blocks nested in them
	// are marked True (anycast, AMT, AS112-v6, ORCHIDv2, DETs) and Teredo
	// 2001::/32 is N/A. Both are refused whole: none of those hosts an issuer
	// or a status list.
	"192.0.0.0/24", "2001::/23",
	// Not in the special-purpose registries: multicast (RFC 1112 §4;
	// RFC 4291 §2.7) and the site-local fec0::/10, deprecated by RFC 3879 §4.
	"224.0.0.0/4", "ff00::/8", "fec0::/10",
)

var (
	ipv4Compatible = netip.MustParsePrefix("::/96")
	nat64          = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour      = netip.MustParsePrefix("2002::/16")
)

// Blocked reports whether a connection to ip must be refused: ip is not a
// valid address, or it falls in a block listed above. An IPv6 address that
// carries an IPv4 address (IPv4-mapped, IPv4-compatible, NAT64 64:ff9b::/96,
// 6to4) is judged by that IPv4 address.
func Blocked(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	// Prefix.Contains never matches an address with a zone, so fe80::1%eth0
	// would pass.
	ip = ip.WithZone("")
	ip = embeddedIPv4(ip)
	for _, p := range blocked {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func embeddedIPv4(ip netip.Addr) netip.Addr {
	if ip.Is4In6() {
		return ip.Unmap()
	}
	b := ip.As16()
	switch {
	case ipv4Compatible.Contains(ip), nat64.Contains(ip):
		return netip.AddrFrom4([4]byte(b[12:16]))
	case sixToFour.Contains(ip):
		return netip.AddrFrom4([4]byte(b[2:6]))
	}
	return ip
}

func mustPrefixes(s ...string) []netip.Prefix {
	ps := make([]netip.Prefix, len(s))
	for i, v := range s {
		ps[i] = netip.MustParsePrefix(v)
	}
	return ps
}
