package ipaddr

import "net/netip"

// AddrInfo is one address considered while choosing what to publish.
type AddrInfo struct {
	IP          netip.Addr
	Temporary   bool
	ScopeGlobal bool
}

// SelectIPv4 uses the kernel route source when it is a publishable IPv4 address.
// Otherwise it uses the first global-scope IPv4 address. Private addresses are
// included: Linux scope global covers RFC1918, which is the usual DDNS target.
func SelectIPv4(route netip.Addr, addrs []AddrInfo) (netip.Addr, bool) {
	if ip, ok := usableV4(route); ok {
		return ip, true
	}
	for _, a := range addrs {
		if !a.ScopeGlobal || a.Temporary {
			continue
		}
		if ip, ok := usableV4(a.IP); ok {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

// SelectIPv6 returns the first global-scope IPv6 address that is not temporary.
func SelectIPv6(addrs []AddrInfo) (netip.Addr, bool) {
	for _, a := range addrs {
		if !a.ScopeGlobal || a.Temporary {
			continue
		}
		ip := a.IP.Unmap()
		if !ip.IsValid() || !ip.Is6() || ip.Is4In6() {
			continue
		}
		if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			continue
		}
		return ip, true
	}
	return netip.Addr{}, false
}

func usableV4(ip netip.Addr) (netip.Addr, bool) {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.Is4() {
		return netip.Addr{}, false
	}
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return netip.Addr{}, false
	}
	return ip, true
}
