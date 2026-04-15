#!/bin/bash
#
# Run the activation protocol capture proxy.
#
# Redirects Apple activation domains to localhost, starts the proxy
# which forwards to Apple's real servers while logging everything,
# then cleans up on exit.
#
# Usage: sudo ./run_capture.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORTAL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB_DIR="$PORTAL_DIR/lib"
CAPTURES_DIR="$PORTAL_DIR/captures"

# Marker for /etc/hosts entries
MARKER="# tr4mpass-capture"

# Apple domains to intercept
DOMAINS=(
    "albert.apple.com"
    "humb.apple.com"
    "captive.apple.com"
)

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Must run as root (need ports 80/443 and /etc/hosts)."
    echo "Usage: sudo $0"
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found."
    exit 1
fi

# ---------------------------------------------------------------------------
# Cleanup trap -- ALWAYS runs on exit
# ---------------------------------------------------------------------------
cleanup() {
    echo ""
    echo "[cleanup] Removing /etc/hosts redirects..."
    sed -i '' "/${MARKER}/d" /etc/hosts 2>/dev/null || true
    echo "[cleanup] Flushing DNS cache..."
    dscacheutil -flushcache 2>/dev/null || true
    killall -HUP mDNSResponder 2>/dev/null || true
    echo "[cleanup] Done. /etc/hosts restored."
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Add /etc/hosts entries
# ---------------------------------------------------------------------------
echo "[setup] Adding /etc/hosts redirects..."
for domain in "${DOMAINS[@]}"; do
    if ! grep -q "${domain}.*${MARKER}" /etc/hosts 2>/dev/null; then
        echo "127.0.0.1 ${domain} ${MARKER}" >> /etc/hosts
        echo "  + ${domain} -> 127.0.0.1"
    fi
done

echo "[setup] Flushing DNS cache..."
dscacheutil -flushcache 2>/dev/null || true
killall -HUP mDNSResponder 2>/dev/null || true

# Verify
echo "[setup] Verifying redirects:"
for domain in "${DOMAINS[@]}"; do
    resolved=$(python3 -c "import socket; print(socket.gethostbyname('${domain}'))" 2>/dev/null || echo "FAILED")
    echo "  ${domain} -> ${resolved}"
done
echo ""

# ---------------------------------------------------------------------------
# Start proxy
# ---------------------------------------------------------------------------
echo "[proxy] Starting activation protocol capture proxy..."
echo "[proxy] Captures will be saved to: ${CAPTURES_DIR}/"
echo "[proxy] Press Ctrl+C to stop."
echo ""

mkdir -p "${CAPTURES_DIR}"

python3 "${LIB_DIR}/http/activation_proxy.py"
