package ipaddr

import (
	"net/netip"
	"testing"
)

func TestSelectIPv4PrefersRouteSource(t *testing.T) {
	route := netip.MustParseAddr("192.168.1.9")
	got, ok := SelectIPv4(route, []AddrInfo{{
		IP:          netip.MustParseAddr("10.0.0.2"),
		ScopeGlobal: true,
	}})
	if !ok || got != route {
		t.Fatalf("got %s ok=%v", got, ok)
	}
}

func TestSelectIPv4FallsBackToGlobal(t *testing.T) {
	got, ok := SelectIPv4(netip.MustParseAddr("127.0.0.1"), []AddrInfo{
		{IP: netip.MustParseAddr("169.254.1.1"), ScopeGlobal: false},
		{IP: netip.MustParseAddr("10.1.1.1"), ScopeGlobal: true},
	})
	if !ok || got != netip.MustParseAddr("10.1.1.1") {
		t.Fatalf("got %s ok=%v", got, ok)
	}
}

func TestSelectIPv4RejectsLinkLocalRoute(t *testing.T) {
	_, ok := SelectIPv4(netip.MustParseAddr("169.254.2.2"), nil)
	if ok {
		t.Fatal("link-local route source was accepted")
	}
}

func TestSelectIPv6SkipsTemporaryAndLinkLocal(t *testing.T) {
	stable := netip.MustParseAddr("2001:db8::2")
	got, ok := SelectIPv6([]AddrInfo{
		{IP: netip.MustParseAddr("fe80::1"), ScopeGlobal: false},
		{IP: netip.MustParseAddr("2001:db8::1"), Temporary: true, ScopeGlobal: true},
		{IP: stable, ScopeGlobal: true},
	})
	if !ok || got != stable {
		t.Fatalf("got %s ok=%v", got, ok)
	}
}

func TestSelectIPv6IncludesULA(t *testing.T) {
	ula := netip.MustParseAddr("fd00::10")
	got, ok := SelectIPv6([]AddrInfo{{IP: ula, ScopeGlobal: true}})
	if !ok || got != ula {
		t.Fatalf("got %s ok=%v", got, ok)
	}
}
