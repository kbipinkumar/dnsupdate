# dnsupdate

Linux Go tool that publishes this host's A and AAAA records with one TSIG-signed RFC 2136 update. `dnsupdate.sh` is the original script; leave it in place unless asked to remove it.

## Layout

- `cmd/dnsupdate` — `setup`, `run`, `show`, `install`, `uninstall`
- `internal/config` — TOML load/save, BIND key file, validation
- `internal/update` — preflight queries and the TCP UPDATE (`miekg/dns`)
- `internal/ipaddr` — Linux address selection; `stub.go` builds elsewhere
- `internal/setup` — huh wizard and flag parsing
- `internal/install` — systemd unit render; install/uninstall are Linux-only

## Behavior to preserve

- Query A and AAAA over TCP, then skip the update when that RRset is already the single desired address. Compare with `netip.Addr`.
- Send one TCP UPDATE. Delete and add only the families that changed. Do not remove AAAA when the host has no IPv6, or A when it has no IPv4.
- IPv4 is the kernel route source toward the DNS server, then the first global-scope IPv4. Include private addresses (Linux scope global).
- IPv6 is the first global-scope address that is not temporary (`IFA_F_TEMPORARY`). Unique-local addresses count.
- A BIND key file overrides inline key name, algorithm, and secret. Default algorithm is `hmac-sha256`.
- `--dry-run` still queries and prints the update; it does not send it.
- Logs go to stdout and must not include the TSIG secret.

## Config and systemd

- Default path is `/etc/dnsupdate/config.toml`, else `DNSUPDATE_CONFIG` or `--config`.
- Directory mode `0700`, file mode `0600`. `run` and `show` refuse a group- or world-accessible file on Unix.
- Do not put secrets in source, unit files, logs, or examples. `show` redacts `key_secret`.
- `install` must be root. It writes `/etc/systemd/system/dnsupdate.service` and `dnsupdate.timer` (`OnBootSec=1min`, `OnUnitActiveSec` from `interval`, `Persistent=true`) and enables the timer.

## Build and test

```bash
go test ./...
GOOS=linux CGO_ENABLED=0 go build -o dnsupdate ./cmd/dnsupdate
```

Address detection and `install`/`uninstall` do not run off Linux. Test update behavior against the in-process DNS server in `internal/update`, and address selection with `SelectIPv4` / `SelectIPv6`.
