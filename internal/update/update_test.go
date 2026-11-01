package update

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"dnsupdate/internal/config"
)

const (
	testSecret  = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	otherSecret = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
)

func resolved(server string, port int, secret string) config.Resolved {
	addr := netip.MustParseAddr(server)
	return config.Resolved{
		Server:    addr,
		Port:      port,
		Zone:      "example.com.",
		Domain:    "example.com.",
		TTL:       3600,
		Interval:  5 * time.Minute,
		KeyName:   dns.CanonicalName("test-key"),
		Algorithm: dns.HmacSHA256,
		Secret:    secret,
	}
}

type fakeZone struct {
	mu        sync.Mutex
	a         []netip.Addr
	aaaa      []netip.Addr
	updates   int
	last      *dns.Msg
	serveFail bool
}

func (z *fakeZone) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if r.Opcode == dns.OpcodeUpdate {
		m := new(dns.Msg)
		if err := w.TsigStatus(); err != nil {
			m.SetRcode(r, dns.RcodeNotAuth)
		} else {
			m.SetReply(r)
			z.mu.Lock()
			z.updates++
			z.last = r.Copy()
			z.mu.Unlock()
		}
		if t := r.IsTsig(); t != nil {
			m.SetTsig(t.Hdr.Name, t.Algorithm, 300, time.Now().Unix())
		}
		_ = w.WriteMsg(m)
		return
	}

	m := new(dns.Msg)
	m.SetReply(r)
	z.mu.Lock()
	fail := z.serveFail
	z.mu.Unlock()
	if fail {
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
		return
	}
	if len(r.Question) == 1 {
		q := r.Question[0]
		z.mu.Lock()
		defer z.mu.Unlock()
		switch q.Qtype {
		case dns.TypeA:
			for _, ip := range z.a {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   ip.AsSlice(),
				})
			}
		case dns.TypeAAAA:
			for _, ip := range z.aaaa {
				m.Answer = append(m.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
					AAAA: ip.AsSlice(),
				})
			}
		}
	}
	_ = w.WriteMsg(m)
}

func startServer(t *testing.T, z *fakeZone) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{
		Listener: ln,
		Net:      "tcp",
		Handler:  z,
		TsigSecret: map[string]string{
			dns.CanonicalName("test-key"): testSecret,
		},
		MsgAcceptFunc: acceptQueryAndUpdate,
		ReadTimeout:   2 * time.Second,
		WriteTimeout:  2 * time.Second,
	}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("dns server did not start")
	}
	t.Cleanup(func() { _ = srv.Shutdown() })

	tcp, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("addr %T", ln.Addr())
	}
	return tcp.IP.String(), tcp.Port
}

func acceptQueryAndUpdate(dh dns.Header) dns.MsgAcceptAction {
	if dh.Bits&(1<<15) != 0 {
		return dns.MsgIgnore
	}
	opcode := int(dh.Bits>>11) & 0xF
	switch opcode {
	case dns.OpcodeQuery, dns.OpcodeUpdate:
		if dh.Qdcount != 1 {
			return dns.MsgReject
		}
		return dns.MsgAccept
	default:
		return dns.MsgRejectNotImplemented
	}
}

func nsOps(msg *dns.Msg) []string {
	if msg == nil {
		return nil
	}
	var ops []string
	for _, rr := range msg.Ns {
		h := rr.Header()
		kind := "add"
		if h.Class == dns.ClassANY {
			kind = "delete"
		}
		ops = append(ops, kind+" "+dns.TypeToString[h.Rrtype])
	}
	return ops
}

func TestRunNoopWhenRecordsMatch(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.10")
	v6 := netip.MustParseAddr("2001:db8::1")
	z := &fakeZone{a: []netip.Addr{v4}, aaaa: []netip.Addr{v6}}
	host, port := startServer(t, z)

	var buf strings.Builder
	err := Run(context.Background(), resolved(host, port, testSecret), Local{IPv4: v4, IPv6: netip.MustParseAddr("2001:0db8:0000::1")}, false, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if z.updates != 0 {
		t.Fatalf("updates = %d", z.updates)
	}
	if !strings.Contains(buf.String(), "already up to date") {
		t.Fatalf("output: %s", buf.String())
	}
}

func TestRunSendsOneUpdateWhenBothDiffer(t *testing.T) {
	z := &fakeZone{
		a:    []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		aaaa: []netip.Addr{netip.MustParseAddr("2001:db8::9")},
	}
	host, port := startServer(t, z)
	local := Local{
		IPv4: netip.MustParseAddr("192.0.2.10"),
		IPv6: netip.MustParseAddr("2001:db8::10"),
	}
	var buf strings.Builder
	err := Run(context.Background(), resolved(host, port, testSecret), local, false, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if z.updates != 1 {
		t.Fatalf("updates = %d", z.updates)
	}
	got := nsOps(z.last)
	want := []string{"delete A", "add A", "delete AAAA", "add AAAA"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ops %v", got)
	}
	if strings.Contains(buf.String(), testSecret) {
		t.Fatal("output contains the TSIG secret")
	}
}

func TestRunUpdatesOnlyChangedType(t *testing.T) {
	v6 := netip.MustParseAddr("2001:db8::1")
	z := &fakeZone{
		a:    []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		aaaa: []netip.Addr{v6},
	}
	host, port := startServer(t, z)
	err := Run(context.Background(), resolved(host, port, testSecret), Local{
		IPv4: netip.MustParseAddr("192.0.2.8"),
		IPv6: v6,
	}, false, ioDiscard())
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(nsOps(z.last), ",")
	if got != "delete A,add A" {
		t.Fatalf("ops %s", got)
	}
}

func TestRunDoesNotDeleteMissingFamily(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.10")
	z := &fakeZone{
		a:    []netip.Addr{v4},
		aaaa: []netip.Addr{netip.MustParseAddr("2001:db8::5")},
	}
	host, port := startServer(t, z)
	var buf strings.Builder
	err := Run(context.Background(), resolved(host, port, testSecret), Local{IPv4: v4}, false, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if z.updates != 0 {
		t.Fatalf("updates = %d, ops %v, out %s", z.updates, nsOps(z.last), buf.String())
	}
}

func TestRunDryRunSendsNothing(t *testing.T) {
	z := &fakeZone{}
	host, port := startServer(t, z)
	var buf strings.Builder
	err := Run(context.Background(), resolved(host, port, testSecret), Local{
		IPv4: netip.MustParseAddr("192.0.2.10"),
		IPv6: netip.MustParseAddr("2001:db8::10"),
	}, true, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if z.updates != 0 {
		t.Fatalf("updates = %d", z.updates)
	}
	out := buf.String()
	if !strings.Contains(out, "update add") || !strings.Contains(out, "[Dry-Run]") {
		t.Fatalf("output: %s", out)
	}
	if strings.Contains(out, testSecret) {
		t.Fatal("dry-run output contains the secret")
	}
}

func TestRunRejectsBadSecret(t *testing.T) {
	z := &fakeZone{}
	host, port := startServer(t, z)
	err := Run(context.Background(), resolved(host, port, otherSecret), Local{
		IPv4: netip.MustParseAddr("192.0.2.10"),
	}, false, ioDiscard())
	if err == nil {
		t.Fatal("expected TSIG failure")
	}
	if z.updates != 0 {
		t.Fatalf("updates = %d", z.updates)
	}
}

func TestRunReplacesRRsetThatIsNotExactlyOneAddress(t *testing.T) {
	want := netip.MustParseAddr("192.0.2.10")
	z := &fakeZone{a: []netip.Addr{want, netip.MustParseAddr("192.0.2.11")}}
	host, port := startServer(t, z)
	err := Run(context.Background(), resolved(host, port, testSecret), Local{IPv4: want}, false, ioDiscard())
	if err != nil {
		t.Fatal(err)
	}
	if z.updates != 1 {
		t.Fatalf("updates = %d", z.updates)
	}
}

func TestRunQueryFailure(t *testing.T) {
	z := &fakeZone{}
	host, port := startServer(t, z)
	z.mu.Lock()
	z.serveFail = true
	z.mu.Unlock()
	err := Run(context.Background(), resolved(host, port, testSecret), Local{
		IPv4: netip.MustParseAddr("192.0.2.10"),
	}, false, ioDiscard())
	if err == nil {
		t.Fatal("expected query error")
	}
	if z.updates != 0 {
		t.Fatalf("updates = %d", z.updates)
	}
}

func ioDiscard() *strings.Builder { return &strings.Builder{} }
