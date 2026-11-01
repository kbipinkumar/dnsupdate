#!/bin/bash
# ==============================================================================
# Dynamic DNS Update via RFC 2136 (TSIG) for Technitium DNS Server
# ==============================================================================
# This script updates local DNS records (A and AAAA) using standard RFC 2136 DNS
# UPDATE protocol signed with a TSIG key (RFC 2845) via `nsupdate`.
#
# Key Features:
# - Pre-flight check via `dig` prevents excessive zone churn when IPs have not changed.
# - Atomic update: A and AAAA updates are sent in a single DNS transaction.
# - Operates directly over standard DNS port (53) using TCP (-v).
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
SERVER_IP="192.168.1.1"
SERVER_PORT="53"
ZONE="example.com"
DOMAIN="example.com"
TTL=3600

# TSIG Key Configuration:
# Generate a 256-bit key with: openssl rand -base64 32
KEY_NAME="local-ddns-key"
KEY_ALGO="hmac-sha256"
KEY_SECRET="REPLACE_WITH_YOUR_BASE64_TSIG_SECRET"

# Optional: Path to a BIND-compatible TSIG key file.
# If KEY_FILE exists and is readable, it takes precedence over KEY_NAME/KEY_SECRET.
# Format:
#   key "local-ddns-key" {
#       algorithm hmac-sha256;
#       secret "base64secret...";
#   };
KEY_FILE=""

# ------------------------------------------------------------------------------
# Dependency Check
# ------------------------------------------------------------------------------
for cmd in ip dig nsupdate awk grep; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: Required command '$cmd' is not installed or not in PATH." >&2
        exit 1
    fi
done

# ------------------------------------------------------------------------------
# 1. Determine Local IP Addresses
# ------------------------------------------------------------------------------
# Resolve IPv4 address used to route to the DNS server
IPV4_ADDR=$(ip -4 route get "$SERVER_IP" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n 1)
if [ -z "$IPV4_ADDR" ]; then
    IPV4_ADDR=$(ip -4 addr show scope global | grep "inet " | awk '{print $2}' | cut -d/ -f1 | head -n 1)
fi

# Resolve primary global non-temporary IPv6 address
IPV6_ADDR=$(ip -6 addr show scope global 2>/dev/null | grep "inet6 " | grep -v "temporary" | awk '{print $2}' | cut -d/ -f1 | head -n 1 || true)

if [ -z "$IPV4_ADDR" ] && [ -z "$IPV6_ADDR" ]; then
    echo "Error: Could not determine any local IP address (IPv4 or IPv6)." >&2
    exit 1
fi

# Normalize IPv6 to lowercase
if [ -n "$IPV6_ADDR" ]; then
    IPV6_ADDR=$(echo "$IPV6_ADDR" | tr '[:upper:]' '[:lower:]')
fi

# ------------------------------------------------------------------------------
# 2. Check Existing Records in DNS (Pre-Flight Check)
# ------------------------------------------------------------------------------
CURRENT_A=$(dig @"$SERVER_IP" -p "$SERVER_PORT" +short "$DOMAIN" A 2>/dev/null | tail -n 1 || true)
CURRENT_AAAA=$(dig @"$SERVER_IP" -p "$SERVER_PORT" +short "$DOMAIN" AAAA 2>/dev/null | tail -n 1 | tr '[:upper:]' '[:lower:]' || true)

echo "Current local IPs:  IPv4=${IPV4_ADDR:-none}, IPv6=${IPV6_ADDR:-none}"
echo "Current DNS records: IPv4=${CURRENT_A:-none}, IPv6=${CURRENT_AAAA:-none}"

NEEDS_A_UPDATE=false
NEEDS_AAAA_UPDATE=false

if [ -n "$IPV4_ADDR" ] && [ "$IPV4_ADDR" != "$CURRENT_A" ]; then
    NEEDS_A_UPDATE=true
fi

if [ -n "$IPV6_ADDR" ] && [ "$IPV6_ADDR" != "$CURRENT_AAAA" ]; then
    NEEDS_AAAA_UPDATE=true
fi

if [ "$NEEDS_A_UPDATE" = false ] && [ "$NEEDS_AAAA_UPDATE" = false ]; then
    echo "Both A and AAAA records are already up to date on DNS server. No update needed."
    exit 0
fi

# ------------------------------------------------------------------------------
# 3. Build nsupdate Command Batch
# ------------------------------------------------------------------------------
NSUPDATE_INPUT="server $SERVER_IP $SERVER_PORT
zone $ZONE
"

if [ "$NEEDS_A_UPDATE" = true ]; then
    echo "A record update required: ${CURRENT_A:-<none>} -> $IPV4_ADDR"
    NSUPDATE_INPUT+="update delete $DOMAIN A
update add $DOMAIN $TTL A $IPV4_ADDR
"
else
    echo "A record is unchanged ($CURRENT_A). Skipping."
fi

if [ "$NEEDS_AAAA_UPDATE" = true ]; then
    echo "AAAA record update required: ${CURRENT_AAAA:-<none>} -> $IPV6_ADDR"
    NSUPDATE_INPUT+="update delete $DOMAIN AAAA
update add $DOMAIN $TTL AAAA $IPV6_ADDR
"
elif [ -n "$CURRENT_AAAA" ]; then
    echo "AAAA record is unchanged ($CURRENT_AAAA). Skipping."
fi

NSUPDATE_INPUT+="send
"

# ------------------------------------------------------------------------------
# 4. Execute nsupdate with TSIG Authentication
# ------------------------------------------------------------------------------
if [ "${1:-}" = "--dry-run" ]; then
    echo "--- [Dry-Run] nsupdate commands to be sent ---"
    echo "$NSUPDATE_INPUT"
    echo "--- [Dry-Run] Finished ---"
    exit 0
fi

if [ -n "$KEY_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "Sending dynamic DNS update to $SERVER_IP using keyfile $KEY_FILE..."
    echo "$NSUPDATE_INPUT" | nsupdate -v -k "$KEY_FILE"
else
    if [ "$KEY_SECRET" = "REPLACE_WITH_YOUR_BASE64_TSIG_SECRET" ]; then
        echo "Error: Please set KEY_SECRET in the script or provide a valid KEY_FILE." >&2
        echo "Generate a secret with: openssl rand -base64 32" >&2
        exit 1
    fi
    echo "Sending dynamic DNS update to $SERVER_IP using TSIG key '$KEY_NAME' ($KEY_ALGO)..."
    echo "$NSUPDATE_INPUT" | nsupdate -v -y "${KEY_ALGO}:${KEY_NAME}:${KEY_SECRET}"
fi

echo "DNS update completed successfully."
