package safehttp

import (
	"net/netip"
	"testing"
)

// One address per block, taken from the IANA Special-Purpose Address
// Registries (iana-ipv4-special-registry-1.csv sha256 cbc4b765…2aac,
// iana-ipv6-special-registry-1.csv sha256 bf56772a…ba66, both last updated
// 2025-10-09), plus globally reachable neighbours that must pass.
func TestBlocked(t *testing.T) {
	refused := []string{
		"0.1.2.3", "10.0.0.5", "100.100.100.200", "127.0.0.1", "169.254.169.254",
		"172.31.255.255", "192.0.0.9", "192.0.2.1", "192.88.99.2", "192.168.1.1",
		"198.19.0.1", "198.51.100.7", "203.0.113.9", "240.0.0.1", "255.255.255.255",
		"224.0.0.1",
		"::1", "::", "::ffff:10.0.0.5", "::a00:5", "64:ff9b::a9fe:a9fe", "2002:7f00:1::",
		"64:ff9b:1::1", "100::1", "100:0:0:1::1", "2001::1", "2001:1::1", "2001:db8::1",
		"3fff::1", "5f00::1", "fd12::1", "fe80::1", "fe80::1%eth0", "fec0::1", "ff02::1",
	}
	allowed := []string{
		"8.8.8.8", "100.63.255.255", "100.128.0.0", "172.32.0.0", "192.0.1.255",
		"192.31.196.1", "192.52.193.1", "192.175.48.1",
		"2606:4700:4700::1111", "2620:4f:8000::1", "2001:200::1",
		"::ffff:8.8.8.8", "64:ff9b::808:808", "2002:808:808::",
	}
	for _, s := range refused {
		if !Blocked(netip.MustParseAddr(s)) {
			t.Errorf("Blocked(%s) = false, want true", s)
		}
	}
	for _, s := range allowed {
		if Blocked(netip.MustParseAddr(s)) {
			t.Errorf("Blocked(%s) = true, want false", s)
		}
	}
	if !Blocked(netip.Addr{}) {
		t.Error("Blocked(invalid) = false, want true")
	}
}
