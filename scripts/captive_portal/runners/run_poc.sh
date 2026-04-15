#!/usr/bin/env bash
#
# run_poc.sh -- VU#346053 Automated Captive Portal PoC launcher
#
# Validates prerequisites, kills conflicting processes, and launches
# poc_runner.py with the correct Python 3.12 (pymobiledevice3).
#
# Usage:
#   sudo ./run_poc.sh [options]
#
# Options are forwarded to poc_runner.py:
#   --gateway IP          Gateway IP (auto-detected)
#   --iface IFACE         Network interface (default: en0)
#   --timeout SECS        Monitoring timeout (default: 180)
#   --captive-window SECS WebSheet open duration (default: 25)
#   --no-restart          Skip device restart
#   --no-network          Skip ARP/DNS (if already running)
#   --udid UDID           Target device UDID
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORTAL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB_DIR="$PORTAL_DIR/lib"
CERTS_DIR="$PORTAL_DIR/certs"
PY312="/usr/local/opt/python@3.12/bin/python3.12"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
die() { echo "[FATAL] $*" >&2; exit 1; }

# ── Root check ──────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    die "Root required. Run: sudo $0 $*"
fi

# ── Python 3.12 check ──────────────────────────────────────────────
if [ ! -x "$PY312" ]; then
    die "Python 3.12 not found at $PY312"
fi

# pymobiledevice3 check
if ! "$PY312" -c "import pymobiledevice3" 2>/dev/null; then
    die "pymobiledevice3 not installed for Python 3.12. Run: $PY312 -m pip install pymobiledevice3"
fi

# scapy check (needed for ARP redirect)
if ! "$PY312" -c "import scapy" 2>/dev/null; then
    log "WARNING: scapy not installed -- ARP redirect will not work"
    log "Install with: $PY312 -m pip install scapy"
fi

log "Python 3.12: $PY312"
log "pymobiledevice3: OK"

# ── Generate certs if missing ──────────────────────────────────────
if [ ! -f "$CERTS_DIR/server.crt" ] || [ ! -f "$CERTS_DIR/server.key" ]; then
    log "Generating TLS certificates..."
    if [ -x "$CERTS_DIR/generate_ca.sh" ]; then
        (cd "$CERTS_DIR" && bash generate_ca.sh)
    else
        log "WARNING: No cert generator found. HTTPS server will be skipped."
    fi
else
    log "TLS certificates: OK"
fi

# ── Kill conflicting processes on ports 53, 80, 443 ───────────────
log "Checking for port conflicts..."
for port in 53 80 443; do
    pids=$(lsof -i ":$port" -t 2>/dev/null || true)
    if [ -n "$pids" ]; then
        log "  Killing processes on port $port: $pids"
        echo "$pids" | xargs kill 2>/dev/null || true
        sleep 1
    fi
done

# ── Check USB device ───────────────────────────────────────────────
log "Checking for USB device..."
DEVICE_CHECK=$("$PY312" -c "
import asyncio
from pymobiledevice3.usbmux import list_devices
d = asyncio.run(list_devices())
if d:
    print(f'{len(d)} device(s): {d[0].serial}')
else:
    print('none')
" 2>/dev/null || echo "error")

if [ "$DEVICE_CHECK" = "none" ] || [ "$DEVICE_CHECK" = "error" ]; then
    die "No USB device detected. Connect iPhone via USB cable."
fi
log "USB device: $DEVICE_CHECK"

# ── Launch PoC runner ──────────────────────────────────────────────
log "Launching PoC runner..."
echo ""
exec "$PY312" "$LIB_DIR/poc_runner.py" "$@"
