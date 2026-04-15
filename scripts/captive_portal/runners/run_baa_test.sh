#!/bin/bash
#
# Run the VU#346053 BAA injection test.
#
# Prerequisites:
#   1. Internet Sharing enabled (Mac broadcasts WiFi hotspot)
#   2. iPhone connected to that hotspot during Setup Assistant
#
# This script:
#   - Detects the bridge IP from Internet Sharing
#   - Adds /etc/hosts redirects for Apple activation domains
#   - Starts the BAA test server on ports 80 + 443
#   - Waits for the iPhone to connect and hit the endpoints
#   - Cleans up on exit
#
# Usage: sudo ./run_baa_test.sh [scenario]
#   Scenarios: 1=AllowActivation, 2=Minimal, 3=FullProvisioning,
#              4=EmbeddedState, 5=EchoNonce
#
set -euo pipefail

SCENARIO="${1:-1}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORTAL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB_DIR="$PORTAL_DIR/lib"

MARKER="# baa-test-capture"

# Apple domains to intercept
DOMAINS=(
    "albert.apple.com"
    "humb.apple.com"
    "captive.apple.com"
    "gs.apple.com"
    "static.ips.apple.com"
    "mesu.apple.com"
)

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Must run as root."
    echo "Usage: sudo $0 [scenario]"
    exit 1
fi

# Detect bridge IP (from Internet Sharing)
BRIDGE_IP=""
for iface in bridge100 bridge0; do
    ip=$(ifconfig "$iface" 2>/dev/null | grep "inet " | awk '{print $2}')
    if [[ -n "$ip" ]]; then
        BRIDGE_IP="$ip"
        echo "Detected bridge: $iface -> $BRIDGE_IP"
        break
    fi
done

if [[ -z "$BRIDGE_IP" ]]; then
    echo "ERROR: No bridge interface found."
    echo "Enable Internet Sharing first:"
    echo "  System Settings > General > Sharing > Internet Sharing"
    echo "  Share from: Wi-Fi, To: Wi-Fi"
    exit 1
fi

echo ""
echo "============================================================"
echo "  VU#346053 BAA Injection Test"
echo "============================================================"
echo "  Bridge IP:  $BRIDGE_IP"
echo "  Scenario:   $SCENARIO"
echo "  Server:     $LIB_DIR/http/baa_test.py"
echo ""
echo "  iPhone instructions:"
echo "    1. Go to Setup Assistant WiFi selection"
echo "    2. Connect to the WiFi hotspot this Mac is broadcasting"
echo "    3. The device will hit our test server"
echo "============================================================"
echo ""

# ---------------------------------------------------------------------------
# Cleanup trap
# ---------------------------------------------------------------------------
cleanup() {
    echo ""
    echo "[cleanup] Removing /etc/hosts redirects..."
    sed -i '' "/${MARKER}/d" /etc/hosts 2>/dev/null || true
    dscacheutil -flushcache 2>/dev/null || true
    killall -HUP mDNSResponder 2>/dev/null || true
    echo "[cleanup] Done."
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Add /etc/hosts entries pointing Apple domains to bridge IP
# ---------------------------------------------------------------------------
echo "[setup] Redirecting Apple domains to $BRIDGE_IP..."
for domain in "${DOMAINS[@]}"; do
    if ! grep -q "${domain}.*${MARKER}" /etc/hosts 2>/dev/null; then
        echo "${BRIDGE_IP} ${domain} ${MARKER}" >> /etc/hosts
        echo "  + ${domain} -> ${BRIDGE_IP}"
    fi
done

echo "[setup] Flushing DNS cache..."
dscacheutil -flushcache 2>/dev/null || true
killall -HUP mDNSResponder 2>/dev/null || true
sleep 1

# Verify redirects
echo "[setup] Verifying:"
for domain in "${DOMAINS[@]}"; do
    resolved=$(python3 -c "import socket; print(socket.gethostbyname('${domain}'))" 2>/dev/null || echo "FAILED")
    echo "  ${domain} -> ${resolved}"
done
echo ""

# ---------------------------------------------------------------------------
# Start BAA test server
# ---------------------------------------------------------------------------
echo "[server] Starting BAA test server (scenario $SCENARIO)..."
python3 "${LIB_DIR}/http/baa_test.py" --scenario "$SCENARIO"
