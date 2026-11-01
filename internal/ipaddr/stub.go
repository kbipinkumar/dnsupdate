//go:build !linux

package ipaddr

import (
	"fmt"
	"net/netip"
)

// Detect reports that address discovery is unavailable off Linux.
func Detect(server netip.Addr, port int) (netip.Addr, netip.Addr, error) {
	return netip.Addr{}, netip.Addr{}, fmt.Errorf("local address detection is only supported on linux")
}
