package update

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"dnsupdate/internal/config"
)

// Local holds the addresses to publish. An invalid address means that family is skipped.
type Local struct {
	IPv4 netip.Addr
	IPv6 netip.Addr
}

// Run queries A and AAAA, then sends one TSIG-signed TCP update when they differ.
func Run(ctx context.Context, cfg config.Resolved, local Local, dryRun bool, out io.Writer) error {
	if out == nil {
		out = io.Discard
	}
	if !usable(local.IPv4) && !usable(local.IPv6) {
		return fmt.Errorf("could not determine any local IP address (IPv4 or IPv6)")
	}

	addr := net.JoinHostPort(cfg.Server.String(), strconv.Itoa(cfg.Port))
	haveA, err := query(ctx, addr, cfg.Domain, dns.TypeA)
	if err != nil {
		return err
	}
	haveAAAA, err := query(ctx, addr, cfg.Domain, dns.TypeAAAA)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "Current local IPs:  IPv4=%s, IPv6=%s\n", formatOne(local.IPv4), formatOne(local.IPv6))
	fmt.Fprintf(out, "Current DNS records: IPv4=%s, IPv6=%s\n", formatMany(haveA), formatMany(haveAAAA))

	msg, summary, changed := build(cfg, local, haveA, haveAAAA, out)
	if !changed {
		fmt.Fprintln(out, "Both A and AAAA records are already up to date on DNS server. No update needed.")
		return nil
	}
	if dryRun {
		fmt.Fprintln(out, "--- [Dry-Run] nsupdate commands to be sent ---")
		fmt.Fprint(out, summary)
		fmt.Fprintln(out, "--- [Dry-Run] Finished ---")
		return nil
	}

	fmt.Fprintf(out, "Sending dynamic DNS update to %s using TSIG key %q (%s)...\n",
		addr, cfg.KeyName, strings.TrimSuffix(cfg.Algorithm, "."))

	msg.SetTsig(cfg.KeyName, cfg.Algorithm, 300, time.Now().Unix())
	client := &dns.Client{
		Net:        "tcp",
		Timeout:    10 * time.Second,
		TsigSecret: map[string]string{cfg.KeyName: cfg.Secret},
	}
	resp, _, err := client.ExchangeContext(ctx, msg, addr)
	if err != nil {
		return fmt.Errorf("dns update: %w", err)
	}
	if resp == nil {
		return fmt.Errorf("dns update: empty response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("dns update rejected: %s", dns.RcodeToString[resp.Rcode])
	}
	fmt.Fprintln(out, "DNS update completed successfully.")
	return nil
}

func build(cfg config.Resolved, local Local, haveA, haveAAAA []netip.Addr, out io.Writer) (*dns.Msg, string, bool) {
	var script strings.Builder
	fmt.Fprintf(&script, "server %s %d\n", cfg.Server, cfg.Port)
	fmt.Fprintf(&script, "zone %s\n", cfg.Zone)

	msg := new(dns.Msg)
	msg.SetUpdate(cfg.Zone)
	changed := false

	if usable(local.IPv4) {
		if sameSingle(haveA, local.IPv4) {
			fmt.Fprintf(out, "A record is unchanged (%s). Skipping.\n", local.IPv4)
		} else {
			changed = true
			fmt.Fprintf(out, "A record update required: %s -> %s\n", formatMany(haveA), local.IPv4)
			msg.RemoveRRset([]dns.RR{&dns.A{Hdr: dns.RR_Header{Name: cfg.Domain, Rrtype: dns.TypeA, Class: dns.ClassINET}}})
			msg.Insert([]dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: cfg.Domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: cfg.TTL},
				A:   local.IPv4.AsSlice(),
			}})
			fmt.Fprintf(&script, "update delete %s A\n", cfg.Domain)
			fmt.Fprintf(&script, "update add %s %d A %s\n", cfg.Domain, cfg.TTL, local.IPv4)
		}
	}

	if usable(local.IPv6) {
		if sameSingle(haveAAAA, local.IPv6) {
			fmt.Fprintf(out, "AAAA record is unchanged (%s). Skipping.\n", local.IPv6)
		} else {
			changed = true
			fmt.Fprintf(out, "AAAA record update required: %s -> %s\n", formatMany(haveAAAA), local.IPv6)
			msg.RemoveRRset([]dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: cfg.Domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET}}})
			msg.Insert([]dns.RR{&dns.AAAA{
				Hdr:  dns.RR_Header{Name: cfg.Domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: cfg.TTL},
				AAAA: local.IPv6.AsSlice(),
			}})
			fmt.Fprintf(&script, "update delete %s AAAA\n", cfg.Domain)
			fmt.Fprintf(&script, "update add %s %d AAAA %s\n", cfg.Domain, cfg.TTL, local.IPv6)
		}
	}
	script.WriteString("send\n")
	return msg, script.String(), changed
}

func query(ctx context.Context, addr, name string, qtype uint16) ([]netip.Addr, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	client := &dns.Client{Net: "tcp", Timeout: 10 * time.Second}
	resp, _, err := client.ExchangeContext(ctx, m, addr)
	if err != nil {
		return nil, fmt.Errorf("query %s %s: %w", name, dns.TypeToString[qtype], err)
	}
	if resp == nil {
		return nil, fmt.Errorf("query %s %s: empty response", name, dns.TypeToString[qtype])
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, nil
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("query %s %s: %s", name, dns.TypeToString[qtype], dns.RcodeToString[resp.Rcode])
	}
	return addrsOf(resp, name, qtype), nil
}

func addrsOf(msg *dns.Msg, name string, qtype uint16) []netip.Addr {
	want := dns.CanonicalName(name)
	var out []netip.Addr
	for _, rr := range msg.Answer {
		h := rr.Header()
		if h.Rrtype != qtype || dns.CanonicalName(h.Name) != want {
			continue
		}
		switch v := rr.(type) {
		case *dns.A:
			if ip, ok := netip.AddrFromSlice(v.A); ok {
				out = append(out, ip.Unmap())
			}
		case *dns.AAAA:
			if ip, ok := netip.AddrFromSlice(v.AAAA); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

func sameSingle(have []netip.Addr, want netip.Addr) bool {
	want = want.Unmap()
	return len(have) == 1 && have[0].Unmap() == want
}

func usable(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsValid() && !ip.IsUnspecified()
}

func formatOne(ip netip.Addr) string {
	if !usable(ip) {
		return "none"
	}
	return ip.Unmap().String()
}

func formatMany(ips []netip.Addr) string {
	if len(ips) == 0 {
		return "none"
	}
	parts := make([]string, len(ips))
	for i, ip := range ips {
		parts[i] = ip.String()
	}
	return strings.Join(parts, ",")
}
