# dnsupdate

RFC 2136 dynamic DNS update client for Linux that publishes the host's A and AAAA records in a single atomic, TSIG-signed DNS transaction.

[![License: GPL-2.0](https://img.shields.io/badge/License-GPL%202.0-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/kbipinkumar/dnsupdate)](https://goreportcard.com/report/github.com/kbipinkumar/dnsupdate)

---

## Features

- **Atomic Dual-Stack Update**: Sends A and AAAA updates in a single RFC 2136 TCP transaction. Deletes and adds only the record families that have changed.
- **Smart IP Address Selection**:
  - **IPv4**: Kernel route source toward the DNS server, falling back to the first global-scope address (including private network scopes).
  - **IPv6**: First global-scope address that is not temporary (`IFA_F_TEMPORARY`), including Unique Local Addresses (ULA).
- **Pre-Flight Query**: Queries current A and AAAA records over TCP before sending updates; skips the update if existing records already match the host's desired addresses to avoid unnecessary zone churn.
- **TSIG Authentication**: Supports standard TSIG algorithms (`hmac-sha1`, `hmac-sha224`, `hmac-sha256`, `hmac-sha384`, `hmac-sha512`). Accepts inline base64 secrets or BIND `.key` key files.
- **Security by Default**: Enforces directory mode `0700` and config file mode `0600`. Refuses to run if configuration files are accessible by group or world. Secrets are strictly redacted in logs and CLI outputs (`dnsupdate show`).
- **Systemd Integration**: Includes service and timer units for automated periodic updates.

---

## Installation

### Option 1: Debian Package (.deb)

Pre-built Debian packages are available for `amd64`, `arm64`, and `armhf` on the [GitHub Releases](https://github.com/kbipinkumar/dnsupdate/releases) page.

```bash
# Download and install the Debian package (example for amd64)
sudo apt install ./dnsupdate_0.1.0-1_amd64.deb
```

The Debian package installs:
- Executable binary to `/usr/bin/dnsupdate`
- Systemd service to `/usr/lib/systemd/system/dnsupdate.service`
- Systemd timer to `/usr/lib/systemd/system/dnsupdate.timer` (enabled by default)
- Secure configuration directory `/etc/dnsupdate/` (mode `0700`)
- Examples and documentation to `/usr/share/doc/dnsupdate/examples/`

### Option 2: Build from Source

Requirements: Go 1.22+ and Linux.

```bash
# Clone the repository
git clone https://github.com/kbipinkumar/dnsupdate.git
cd dnsupdate

# Compile the binary
make build

# Optional: Install manually using the built-in installer
sudo ./dnsupdate install --bin /usr/local/bin/dnsupdate
```

---

## Usage Guide

### 1. Initial Configuration

#### Interactive Setup Wizard (Recommended)
Run the interactive setup wizard in a terminal:
```bash
sudo dnsupdate setup
```
The wizard prompts for:
- DNS Server IP and Port (default `53`)
- Zone (e.g. `example.com.`)
- Domain / Hostname (e.g. `host.example.com.`)
- Record TTL in seconds (default `3600`)
- Timer interval (default `5m`)
- TSIG Key Name, Algorithm, and Secret (or path to a BIND key file). Choose **Generate a random TSIG secret?** to mint a base64 secret sized for the selected algorithm. The new secret is printed once so it can be copied to the DNS server; `show` and later runs do not print it again.

The configuration is saved to `/etc/dnsupdate/config.toml` with strict `0600` permissions.

#### Non-Interactive Setup (Scripted)
You can configure `dnsupdate` without an interactive terminal using flags:
```bash
sudo dnsupdate setup --non-interactive \
  --server 192.168.1.1 \
  --port 53 \
  --zone example.com \
  --domain host.example.com \
  --key-name "local-ddns-key" \
  --key-algorithm "hmac-sha256" \
  --key-secret "BASE64_SECRET"
```

`--generate-key` mints the secret instead of `--key-secret`. It cannot be combined with `--key-secret` or `--key-file`. The generated secret is printed once after the file is written:

```bash
sudo dnsupdate setup --non-interactive \
  --server 192.168.1.1 \
  --port 53 \
  --zone example.com \
  --domain host.example.com \
  --key-name "local-ddns-key" \
  --key-algorithm "hmac-sha256" \
  --generate-key
```

### 2. Inspect Configuration
View the configuration file with the TSIG secret safely redacted:
```bash
dnsupdate show
```

### 3. Test with Dry-Run
Query the DNS server, detect local IP addresses, and display the update commands that would be sent without modifying records:
```bash
dnsupdate run --dry-run
```

### 4. Manual Execution
Perform a dynamic DNS update immediately:
```bash
sudo dnsupdate run
```

### 5. Check Version
Display the installed version:
```bash
dnsupdate version
```

---

## Systemd Timer & Customizing Intervals

The Debian package includes a systemd timer unit (`dnsupdate.timer`) configured to run every 5 minutes by default (`OnUnitActiveSec=5min`).

The associated service unit (`dnsupdate.service`) contains `ConditionPathExists=/etc/dnsupdate/config.toml`, meaning the timer runs cleanly and no-ops until you configure `/etc/dnsupdate/config.toml`.

### Setting Higher Intervals

To change the timer interval (e.g., to 15 minutes, 1 hour, or 12 hours) without modifying packaged vendor files, use a systemd drop-in override:

```bash
sudo systemctl edit dnsupdate.timer
```

Add the following configuration (systemd requires an empty `OnUnitActiveSec=` line first to reset the default trigger):
```ini
[Timer]
OnUnitActiveSec=
OnUnitActiveSec=1h
```

Save and exit. Then reload and restart the timer:
```bash
sudo systemctl daemon-reload
sudo systemctl restart dnsupdate.timer
```

You can verify the active schedule with:
```bash
systemctl list-timers dnsupdate.timer
```

An example template is also available in `examples/timer-interval.conf`.

---

## Building Debian Packages

You can build Debian packages directly on any Linux distribution using `make`:

```bash
# Build for host architecture
make deb

# Build for all supported architectures (amd64, arm64, armhf)
make deb-all

# Build a specific version or architecture
ARCH=arm64 VERSION=1.0.0-1 make deb
```

Generated packages are placed in the `dist/` directory.

---

## LLM Coding Disclosure

This software was designed and developed with the assistance of an AI coding assistant (Google DeepMind Antigravity). All code, tests, documentation, and packaging were collaboratively created, reviewed, and verified by human supervision.

---

## License

This project is licensed under the **GNU General Public License v2.0** (GPL-2.0). See the [LICENSE](LICENSE) file for the full license text.
