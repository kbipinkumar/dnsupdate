#!/usr/bin/env bash
# ==============================================================================
# Build a Debian package (.deb) for dnsupdate
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Architecture determination
ARCH="${ARCH:-}"
if [ -z "${ARCH}" ]; then
    if command -v dpkg >/dev/null 2>&1; then
        ARCH="$(dpkg --print-architecture)"
    else
        UNAME_M="$(uname -m)"
        case "${UNAME_M}" in
            x86_64)  ARCH="amd64" ;;
            aarch64) ARCH="arm64" ;;
            armv7l)  ARCH="armhf" ;;
            i386|i686) ARCH="i386" ;;
            *)       ARCH="amd64" ;;
        esac
    fi
fi

# Map Debian ARCH to Go GOARCH/GOARM
GOARM=""
case "${ARCH}" in
    amd64)   GOARCH="amd64" ;;
    arm64)   GOARCH="arm64" ;;
    armhf)   GOARCH="arm"; GOARM="7" ;;
    armel)   GOARCH="arm"; GOARM="5" ;;
    i386)    GOARCH="386" ;;
    riscv64) GOARCH="riscv64" ;;
    *)       GOARCH="${ARCH}" ;;
esac

# Version determination
RAW_VERSION="${VERSION:-}"
if [ -z "${RAW_VERSION}" ]; then
    if git -C "${ROOT_DIR}" describe --tags --exact-match 2>/dev/null; then
        RAW_VERSION="$(git -C "${ROOT_DIR}" describe --tags --exact-match)"
    elif [ -f "${ROOT_DIR}/debian/changelog" ]; then
        RAW_VERSION="$(head -n 1 "${ROOT_DIR}/debian/changelog" | sed -n 's/.*(\(.*\)).*/\1/p')"
    fi
fi
RAW_VERSION="${RAW_VERSION:-0.1.0-1}"

# Strip leading 'v' if present
CLEAN_VERSION="${RAW_VERSION#v}"

# Determine Debian version and binary version
if [[ "${CLEAN_VERSION}" == *-* ]]; then
    DEB_VERSION="${CLEAN_VERSION}"
    BIN_VERSION="${CLEAN_VERSION%%-*}"
else
    DEB_VERSION="${CLEAN_VERSION}-1"
    BIN_VERSION="${CLEAN_VERSION}"
fi

OUTPUT_DIR="${OUTPUT_DIR:-${ROOT_DIR}/dist}"
BUILD_TMP="$(mktemp -d /tmp/dnsupdate-deb-XXXXXX)"
STAGING="${BUILD_TMP}/dnsupdate_${DEB_VERSION}_${ARCH}"

cleanup() {
    rm -rf "${BUILD_TMP}"
}
trap cleanup EXIT

echo "==> Building dnsupdate Debian package"
echo "    Debian Architecture: ${ARCH} (GOARCH=${GOARCH}${GOARM:+ GOARM=${GOARM}})"
echo "    Package Version:     ${DEB_VERSION}"
echo "    Binary Version:      ${BIN_VERSION}"

# 1. Create staging directory layout
mkdir -p "${STAGING}/usr/bin"
mkdir -p "${STAGING}/usr/lib/systemd/system"
mkdir -p "${STAGING}/etc/dnsupdate"
chmod 0700 "${STAGING}/etc/dnsupdate"
mkdir -p "${STAGING}/usr/share/doc/dnsupdate/examples"
mkdir -p "${STAGING}/DEBIAN"

# 2. Compile static Go binary
echo "==> Compiling Go binary..."
export CGO_ENABLED=0
export GOOS=linux
export GOARCH="${GOARCH}"
if [ -n "${GOARM}" ]; then
    export GOARM="${GOARM}"
fi

go build -trimpath \
    -ldflags="-s -w -X main.version=${BIN_VERSION}" \
    -o "${STAGING}/usr/bin/dnsupdate" \
    "${ROOT_DIR}/cmd/dnsupdate"

chmod 0755 "${STAGING}/usr/bin/dnsupdate"

# 3. Copy systemd units and documentation
echo "==> Staging systemd units and examples..."
cp "${ROOT_DIR}/debian/dnsupdate.service" "${STAGING}/usr/lib/systemd/system/"
cp "${ROOT_DIR}/debian/dnsupdate.timer" "${STAGING}/usr/lib/systemd/system/"
chmod 0644 "${STAGING}/usr/lib/systemd/system/"*

cp "${ROOT_DIR}/debian/copyright" "${STAGING}/usr/share/doc/dnsupdate/copyright"
chmod 0644 "${STAGING}/usr/share/doc/dnsupdate/copyright"

if [ -f "${ROOT_DIR}/README.md" ]; then
    cp "${ROOT_DIR}/README.md" "${STAGING}/usr/share/doc/dnsupdate/README.md"
    chmod 0644 "${STAGING}/usr/share/doc/dnsupdate/README.md"
fi

cp "${ROOT_DIR}/examples/config.toml.example" "${STAGING}/usr/share/doc/dnsupdate/examples/"
cp "${ROOT_DIR}/examples/timer-interval.conf" "${STAGING}/usr/share/doc/dnsupdate/examples/"
chmod 0644 "${STAGING}/usr/share/doc/dnsupdate/examples/"*

# Compress Debian changelog if present
if [ -f "${ROOT_DIR}/debian/changelog" ]; then
    gzip -9 -n -c "${ROOT_DIR}/debian/changelog" > "${STAGING}/usr/share/doc/dnsupdate/changelog.Debian.gz"
    chmod 0644 "${STAGING}/usr/share/doc/dnsupdate/changelog.Debian.gz"
fi

# 4. Copy and prepare maintainer scripts
echo "==> Staging maintainer scripts..."
for script in postinst prerm postrm; do
    if [ -f "${ROOT_DIR}/debian/${script}" ]; then
        cp "${ROOT_DIR}/debian/${script}" "${STAGING}/DEBIAN/${script}"
        chmod 0755 "${STAGING}/DEBIAN/${script}"
    fi
done

# 5. Generate DEBIAN/control
INSTALLED_SIZE="$(du -sk "${STAGING}" | cut -f1)"

cat <<EOF > "${STAGING}/DEBIAN/control"
Package: dnsupdate
Version: ${DEB_VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: Bipin Kumar <bipin@kbipinkumar.live>
Installed-Size: ${INSTALLED_SIZE}
Depends: systemd
Description: RFC 2136 dynamic DNS update client for Linux
 dnsupdate publishes the host's A and AAAA records using TSIG-signed
 RFC 2136 updates over TCP, with automated route-based IP detection
 and systemd timer integration.
EOF
chmod 0644 "${STAGING}/DEBIAN/control"

# 6. Package .deb
mkdir -p "${OUTPUT_DIR}"
DEB_PACKAGE="${OUTPUT_DIR}/dnsupdate_${DEB_VERSION}_${ARCH}.deb"

echo "==> Building package with dpkg-deb..."
dpkg-deb --root-owner-group --build "${STAGING}" "${DEB_PACKAGE}"

echo "==> Successfully created: ${DEB_PACKAGE}"
