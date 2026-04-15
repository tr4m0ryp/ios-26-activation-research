#!/bin/bash
#
# Capture activation protocol traffic via USB -- no WiFi needed.
#
# Flow:
#   1. /etc/hosts redirects Apple domains to 127.0.0.1
#   2. Proxy starts on localhost (forwards to real Apple, logs both sides)
#   3. ideviceactivation triggers the activation flow over USB
#   4. The Mac's HTTP requests to Apple hit our proxy via /etc/hosts
#   5. Everything is captured in captures/
#
# Usage: sudo ./run_usb_capture.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORTAL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB_DIR="$PORTAL_DIR/lib"
CAPTURES_DIR="$PORTAL_DIR/captures"

MARKER="# tr4mpass-capture"

DOMAINS=(
    "albert.apple.com"
    "humb.apple.com"
)

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Must run as root."
    echo "Usage: sudo $0"
    exit 1
fi

# Check device is connected
UDID=$(idevice_id -l 2>/dev/null | head -1)
if [[ -z "$UDID" ]]; then
    echo "ERROR: No iOS device connected. Plug in via USB and trust."
    exit 1
fi

echo "Device: ${UDID}"
echo "iOS:    $(ideviceinfo -k ProductVersion 2>/dev/null || echo unknown)"
echo "State:  $(ideviceinfo -k ActivationState 2>/dev/null || echo unknown)"
echo ""

HAS_PMD3=$(command -v pymobiledevice3 2>/dev/null || true)

if [[ -z "$HAS_PMD3" ]]; then
    echo "ERROR: pymobiledevice3 not found. Install: pip3 install pymobiledevice3"
    exit 1
fi

# ---------------------------------------------------------------------------
# Cleanup trap
# ---------------------------------------------------------------------------
cleanup() {
    echo ""
    echo "[cleanup] Removing /etc/hosts redirects..."
    sed -i '' "/${MARKER}/d" /etc/hosts 2>/dev/null || true
    dscacheutil -flushcache 2>/dev/null || true
    killall -HUP mDNSResponder 2>/dev/null || true

    # Kill proxy if still running
    if [[ -n "${PROXY_PID:-}" ]]; then
        kill "$PROXY_PID" 2>/dev/null || true
        wait "$PROXY_PID" 2>/dev/null || true
    fi

    echo "[cleanup] Done."
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Add /etc/hosts entries
# ---------------------------------------------------------------------------
echo "[setup] Redirecting Apple domains to localhost..."
for domain in "${DOMAINS[@]}"; do
    if ! grep -q "${domain}.*${MARKER}" /etc/hosts 2>/dev/null; then
        echo "127.0.0.1 ${domain} ${MARKER}" >> /etc/hosts
        echo "  + ${domain} -> 127.0.0.1"
    fi
done

dscacheutil -flushcache 2>/dev/null || true
killall -HUP mDNSResponder 2>/dev/null || true
sleep 1

# Verify redirect
echo "[setup] Verifying:"
for domain in "${DOMAINS[@]}"; do
    resolved=$(python3 -c "import socket; print(socket.gethostbyname('${domain}'))" 2>/dev/null || echo "FAILED")
    echo "  ${domain} -> ${resolved}"
    if [[ "$resolved" != "127.0.0.1" ]]; then
        echo "  WARNING: redirect not working for ${domain}"
    fi
done
echo ""

# ---------------------------------------------------------------------------
# Start proxy in background
# ---------------------------------------------------------------------------
echo "[proxy] Starting capture proxy..."
mkdir -p "${CAPTURES_DIR}"

python3 "${LIB_DIR}/http/activation_proxy.py" &
PROXY_PID=$!
sleep 2

if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "ERROR: Proxy failed to start."
    exit 1
fi
echo "[proxy] Running (PID ${PROXY_PID})"
echo ""

# ---------------------------------------------------------------------------
# Trigger activation via USB
# ---------------------------------------------------------------------------
echo "============================================================"
echo "  Phase 1: Query current activation state"
echo "============================================================"
echo ""

echo "[state] Querying activation state..."
pymobiledevice3 activation state 2>&1 || true
echo ""

echo "============================================================"
echo "  Phase 2: Trigger activation flow (proxied through capture)"
echo "============================================================"
echo ""

echo "[activate] Running: pymobiledevice3 activation activate"
echo "[activate] HTTP requests to Apple will be intercepted by proxy..."
echo ""
pymobiledevice3 activation activate 2>&1 || true
echo ""

echo "[state] Post-attempt activation state:"
pymobiledevice3 activation state 2>&1 || true
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "  Capture Complete"
echo "============================================================"
echo ""
echo "Captures saved to: ${CAPTURES_DIR}/"
echo ""
ls -la "${CAPTURES_DIR}"/*.bin 2>/dev/null || echo "(no binary captures)"
echo ""
ls -la "${CAPTURES_DIR}"/*.json 2>/dev/null || echo "(no metadata captures)"
echo ""

# Give user a chance to review before cleanup
echo "Press Enter to stop proxy and clean up /etc/hosts..."
read -r
