// Package safehttp provides an HTTP client and dialer control that refuse
// connections to non-public (RFC 1918, loopback, link-local, etc.) addresses.
// The @context document loader and the status-list credential fetcher share it.
// digitalcredential/internal/safehttp keeps its own table because that module
// cannot import this one: change the two tables together, no build or test
// compares them.
package safehttp

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// ErrNonPublicAddress is returned by RefuseNonPublic when the dial target
// resolves to a non-public IP.
var ErrNonPublicAddress = errors.New("address is not public")

// NewPublicOnlyClient returns an *http.Client whose dialer refuses non-public
// addresses after DNS resolution, on every dial (including redirects). No proxy
// is configured because a proxy would hide the target address.
func NewPublicOnlyClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: RefuseNonPublic}
	return &http.Client{Transport: &http.Transport{
		DialContext:            dialer.DialContext,
		TLSHandshakeTimeout:    5 * time.Second,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           100,
		IdleConnTimeout:        90 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}}
}

// RefuseNonPublic is a net.Dialer Control function: it judges the address
// actually connected to, after DNS resolution, on every redirect and every
// attempt.
func RefuseNonPublic(_, address string, _ syscall.RawConn) error {
	// An address that is not ip:port is refused too: the dialer passes an empty
	// host unresolved, and dialing ":443" reaches the local host.
	ap, err := netip.ParseAddrPort(address)
	if err != nil || !IsPublicAddr(ap.Addr()) {
		return ErrNonPublicAddress
	}
	return nil
}

// nonPublicPrefixes lists the IANA special-purpose registries' entries that are
// not globally reachable, plus multicast and deprecated site-local.
var nonPublicPrefixes = func() []netip.Prefix {
	var prefixes []netip.Prefix
	for _, p := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.88.99.2/32", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"64:ff9b:1::/48", "100::/64", "100:0:0:1::/64", "2001::/23", "2001:db8::/32",
		"3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
	} {
		prefixes = append(prefixes, netip.MustParsePrefix(p))
	}
	return prefixes
}()

var (
	ipv4CompatiblePrefix = netip.MustParsePrefix("::/96")
	nat64Prefix          = netip.MustParsePrefix("64:ff9b::/96")
	sixToFourPrefix      = netip.MustParsePrefix("2002::/16")
)

// IsPublicAddr reports whether ip may be connected to. An IPv6 address that
// carries an IPv4 address is judged by that IPv4 address.
func IsPublicAddr(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	// Prefix.Contains never matches an address with a zone.
	ip = ip.WithZone("")
	b := ip.As16()
	switch {
	case ip.Is4In6():
		ip = ip.Unmap()
	case ipv4CompatiblePrefix.Contains(ip), nat64Prefix.Contains(ip):
		ip = netip.AddrFrom4([4]byte(b[12:16]))
	case sixToFourPrefix.Contains(ip):
		ip = netip.AddrFrom4([4]byte(b[2:6]))
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
