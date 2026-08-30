package netmonitor

import (
	"errors"
	"fmt"
	"net/netip"
)

// ErrNonPublicEgressIP reports an address that is outside the strict public
// egress perimeter.
var ErrNonPublicEgressIP = errors.New("resolved IP is not public egress")

type nonPublicEgressPrefix struct {
	prefix netip.Prefix
	reason string
}

// These ranges supplement netip's address properties with special-purpose
// ranges that are still reported as global unicast. The list is deliberately
// conservative for an SSRF-style perimeter: transition and local-use prefixes
// that can encode another destination are not treated as public endpoints.
var allocatedPublicIPv6 = netip.MustParsePrefix("2000::/3")

var nonPublicEgressPrefixes = []nonPublicEgressPrefix{
	// IPv4 special-purpose, documentation, and benchmarking ranges.
	{netip.MustParsePrefix("0.0.0.0/8"), "reserved"},
	{netip.MustParsePrefix("100.64.0.0/10"), "carrier-grade NAT"},
	{netip.MustParsePrefix("192.0.0.0/24"), "reserved"},
	{netip.MustParsePrefix("192.0.2.0/24"), "documentation"},
	{netip.MustParsePrefix("192.88.99.0/24"), "reserved"},
	{netip.MustParsePrefix("198.18.0.0/15"), "benchmarking"},
	{netip.MustParsePrefix("198.51.100.0/24"), "documentation"},
	{netip.MustParsePrefix("203.0.113.0/24"), "documentation"},
	{netip.MustParsePrefix("240.0.0.0/4"), "reserved"},

	// IPv6 local-use, transition, documentation, and benchmarking ranges.
	{netip.MustParsePrefix("::/96"), "reserved"},
	{netip.MustParsePrefix("::ffff:0:0:0/96"), "reserved"},
	{netip.MustParsePrefix("64:ff9b::/96"), "reserved translation"},
	{netip.MustParsePrefix("64:ff9b:1::/48"), "local-use translation"},
	{netip.MustParsePrefix("100::/64"), "reserved discard-only"},
	{netip.MustParsePrefix("2001::/32"), "reserved transition"},
	{netip.MustParsePrefix("2001:2::/48"), "benchmarking"},
	{netip.MustParsePrefix("2001:10::/28"), "reserved"},
	{netip.MustParsePrefix("2001:20::/28"), "reserved"},
	{netip.MustParsePrefix("2001:30::/28"), "reserved"},
	{netip.MustParsePrefix("2001::/23"), "reserved"},
	{netip.MustParsePrefix("2001:db8::/32"), "documentation"},
	{netip.MustParsePrefix("2002::/16"), "reserved transition"},
	{netip.MustParsePrefix("3ffe::/16"), "reserved"},
	{netip.MustParsePrefix("3fff::/20"), "documentation"},
	{netip.MustParsePrefix("5f00::/16"), "reserved"},
	{netip.MustParsePrefix("fec0::/10"), "reserved site-local"},
}

// IsPublicEgressIP reports whether addr is a globally routable endpoint that
// is safe to use in strict public-egress mode. IPv4-mapped IPv6 addresses are
// classified by their embedded IPv4 address.
func IsPublicEgressIP(addr netip.Addr) bool {
	return publicEgressRejectionReason(addr) == ""
}

// ValidatePublicEgressIP rejects addresses that must not cross a strict public
// egress perimeter, including loopback, unspecified, private, carrier-grade
// NAT, link-local, multicast, and reserved/documentation/benchmark ranges.
func ValidatePublicEgressIP(addr netip.Addr) error {
	reason := publicEgressRejectionReason(addr)
	if reason == "" {
		return nil
	}
	return fmt.Errorf("%w: %s (%s)", ErrNonPublicEgressIP, addr, reason)
}

func publicEgressRejectionReason(addr netip.Addr) string {
	if !addr.IsValid() {
		return "invalid address"
	}
	if addr.Zone() != "" {
		return "zoned address"
	}
	addr = addr.Unmap()

	switch {
	case addr.IsUnspecified():
		return "unspecified"
	case addr.IsLoopback():
		return "loopback"
	case addr.IsPrivate():
		return "private"
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		return "link-local"
	case addr.IsMulticast():
		return "multicast"
	}

	for _, denied := range nonPublicEgressPrefixes {
		if denied.prefix.Contains(addr) {
			return denied.reason
		}
	}
	if addr.Is6() && !allocatedPublicIPv6.Contains(addr) {
		return "reserved"
	}
	if !addr.IsGlobalUnicast() {
		return "non-global unicast"
	}
	return ""
}
