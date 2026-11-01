//go:build linux

package ipaddr

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Detect returns the IPv4 address used to reach server and the first
// non-temporary global IPv6 address. Either address may be invalid.
func Detect(server netip.Addr, port int) (netip.Addr, netip.Addr, error) {
	if port < 1 || port > 65535 {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("port: must be between 1 and 65535")
	}
	var route netip.Addr
	if server.Is4() {
		route, _ = dialSource(server, port)
	}
	v4s, err := list(netlink.FAMILY_V4)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("list ipv4 addresses: %w", err)
	}
	v6s, err := list(netlink.FAMILY_V6)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("list ipv6 addresses: %w", err)
	}
	v4, _ := SelectIPv4(route, v4s)
	v6, _ := SelectIPv6(v6s)
	if !v4.IsValid() && !v6.IsValid() {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("could not determine any local IP address (IPv4 or IPv6)")
	}
	return v4, v6, nil
}

func dialSource(server netip.Addr, port int) (netip.Addr, error) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: server.AsSlice(), Port: port})
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP == nil {
		return netip.Addr{}, fmt.Errorf("missing local address")
	}
	ip, ok := netip.AddrFromSlice(local.IP)
	if !ok {
		return netip.Addr{}, fmt.Errorf("invalid local address")
	}
	return ip.Unmap(), nil
}

func list(family int) ([]AddrInfo, error) {
	addrs, err := netlink.AddrList(nil, family)
	if err != nil {
		return nil, err
	}
	out := make([]AddrInfo, 0, len(addrs))
	for _, a := range addrs {
		if a.IPNet == nil || a.IP == nil {
			continue
		}
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			continue
		}
		out = append(out, AddrInfo{
			IP:          ip.Unmap(),
			Temporary:   a.Flags&unix.IFA_F_TEMPORARY != 0,
			ScopeGlobal: a.Scope == unix.RT_SCOPE_UNIVERSE,
		})
	}
	return out, nil
}
