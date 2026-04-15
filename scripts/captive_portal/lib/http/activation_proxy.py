#!/usr/bin/env python3
"""
Transparent activation protocol proxy for security research.

Intercepts iOS activation traffic, logs both the device request and
Apple's real response, then forwards the response to the device.
This documents the unauthenticated protocol for bounty reporting.

Endpoints proxied:
  - albert.apple.com  /deviceservices/drmHandshake
  - albert.apple.com  /deviceservices/deviceActivation
  - humb.apple.com    /humbug/baa

All traffic is saved to the requests/ directory for analysis.

Usage:
    sudo python3 activation_proxy.py
"""

import os
import sys
import ssl
import json
import time
import socket
import struct
import plistlib
import logging
import threading
import subprocess
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
CERTS_DIR = os.path.join(PROJECT_DIR, "certs")
REQUESTS_DIR = os.path.join(SCRIPT_DIR, "requests")
CAPTURES_DIR = os.path.join(SCRIPT_DIR, "captures")
REPORT_FILE = os.path.join(CAPTURES_DIR, "protocol_report.json")

SERVER_CERT = os.path.join(CERTS_DIR, "server.crt")
SERVER_KEY = os.path.join(CERTS_DIR, "server.key")

os.makedirs(REQUESTS_DIR, exist_ok=True)
os.makedirs(CAPTURES_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s | %(name)-14s | %(levelname)-5s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("proxy")

# ---------------------------------------------------------------------------
# Domain -> real Apple server mapping
# ---------------------------------------------------------------------------
DOMAIN_MAP = {
    "/deviceservices/drmHandshake": "https://albert.apple.com/deviceservices/drmHandshake",
    "/deviceservices/deviceActivation": "https://albert.apple.com/deviceservices/deviceActivation",
    "/humbug/baa": "https://humb.apple.com/humbug/baa",
}

# ---------------------------------------------------------------------------
# Real Apple IP resolution (bypass /etc/hosts for outgoing proxy requests)
# ---------------------------------------------------------------------------
APPLE_DOMAINS = ["albert.apple.com", "humb.apple.com"]
REAL_IPS = {}

def _resolve_real_ips():
    """Resolve Apple domain IPs via external DNS (8.8.8.8), bypassing /etc/hosts."""
    for domain in APPLE_DOMAINS:
        try:
            result = subprocess.run(
                ["dig", "+short", "@8.8.8.8", domain],
                capture_output=True, text=True, timeout=5
            )
            lines = [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]
            # Filter to IPv4 addresses only
            ips = [l for l in lines if all(c.isdigit() or c == '.' for c in l)]
            if ips:
                REAL_IPS[domain] = ips[0]
                logger.info("Resolved %s -> %s (real Apple IP)", domain, ips[0])
            else:
                logger.error("Could not resolve real IP for %s", domain)
        except Exception as e:
            logger.error("DNS resolve failed for %s: %s", domain, e)

# Monkey-patch socket.getaddrinfo so urllib connects to real Apple IPs
_original_getaddrinfo = socket.getaddrinfo

def _patched_getaddrinfo(host, port, *args, **kwargs):
    if host in REAL_IPS:
        real_ip = REAL_IPS[host]
        logger.debug("DNS bypass: %s -> %s", host, real_ip)
        return _original_getaddrinfo(real_ip, port, *args, **kwargs)
    return _original_getaddrinfo(host, port, *args, **kwargs)

# ---------------------------------------------------------------------------
# Capture storage
# ---------------------------------------------------------------------------
_capture_counter = 0
_captures = []


def _save_capture(label, path, method, req_headers, req_body,
                  resp_code, resp_headers, resp_body):
    """Save a full request/response pair for analysis."""
    global _capture_counter
    _capture_counter += 1
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_path = path.strip("/").replace("/", "_") or "root"
    prefix = f"{ts}_{_capture_counter:03d}_{label}_{safe_path}"

    # Save request body
    req_file = os.path.join(CAPTURES_DIR, f"{prefix}_req.bin")
    with open(req_file, "wb") as f:
        f.write(req_body)

    # Save response body
    resp_file = os.path.join(CAPTURES_DIR, f"{prefix}_resp.bin")
    with open(resp_file, "wb") as f:
        f.write(resp_body)

    # Try to parse plists for human-readable logging
    req_parsed = _try_parse_plist(req_body)
    resp_parsed = _try_parse_plist(resp_body)

    # Save metadata
    meta = {
        "timestamp": ts,
        "counter": _capture_counter,
        "label": label,
        "path": path,
        "method": method,
        "request": {
            "headers": dict(req_headers) if req_headers else {},
            "body_file": req_file,
            "body_size": len(req_body),
            "body_type": "plist" if req_parsed else "raw",
            "plist_keys": list(req_parsed.keys()) if isinstance(req_parsed, dict) else None,
        },
        "response": {
            "code": resp_code,
            "headers": dict(resp_headers) if resp_headers else {},
            "body_file": resp_file,
            "body_size": len(resp_body),
            "body_type": "plist" if resp_parsed else "raw",
            "plist_keys": list(resp_parsed.keys()) if isinstance(resp_parsed, dict) else None,
        },
    }

    meta_file = os.path.join(CAPTURES_DIR, f"{prefix}_meta.json")
    with open(meta_file, "w") as f:
        json.dump(meta, f, indent=2, default=str)

    _captures.append(meta)

    logger.info("Captured: %s (%d req bytes, %d resp bytes, HTTP %s)",
                prefix, len(req_body), len(resp_body), resp_code)

    return meta


def _try_parse_plist(data):
    """Try to parse data as plist. Return dict or None."""
    if not data:
        return None
    try:
        return plistlib.loads(data)
    except Exception:
        pass
    # Try XML plist
    try:
        if data.startswith(b"<?xml") or data.startswith(b"<plist"):
            return plistlib.loads(data)
    except Exception:
        pass
    return None


def _plist_summary(data, max_val_len=100):
    """Create a human-readable summary of a plist dict."""
    parsed = _try_parse_plist(data)
    if not parsed or not isinstance(parsed, dict):
        return None
    summary = {}
    for k, v in parsed.items():
        if isinstance(v, bytes):
            summary[k] = f"<{len(v)} bytes>"
        elif isinstance(v, dict):
            summary[k] = {sk: f"<{len(sv)} bytes>" if isinstance(sv, bytes)
                          else str(sv)[:max_val_len]
                          for sk, sv in v.items()}
        elif isinstance(v, str) and len(v) > max_val_len:
            summary[k] = v[:max_val_len] + "..."
        else:
            summary[k] = v
    return summary


# ---------------------------------------------------------------------------
# Proxy handler
# ---------------------------------------------------------------------------
class ProxyHandler(BaseHTTPRequestHandler):
    """Transparent proxy: captures traffic, forwards to Apple, logs both."""

    def log_message(self, fmt, *args):
        logger.info("CLIENT %s %s %s", self.address_string(),
                     self.command, self.path)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def _send(self, code, content_type, body, extra_headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    # -- GET ---------------------------------------------------------------

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/hotspot-detect.html":
            self._handle_hotspot()
        elif path == "/":
            self._handle_status()
        elif path == "/captures":
            self._handle_captures_list()
        else:
            self._send(404, "text/plain", "Not Found")

    def _handle_hotspot(self):
        """Return captive portal page to keep WebSheet open."""
        logger.info("  >> Captive detection -- returning non-Success page")
        # Return anything OTHER than "<HTML><HEAD><TITLE>Success</TITLE>"
        # to keep the WebSheet captive portal window open
        html = (
            '<!DOCTYPE html><html><head>'
            '<title>Network Authentication</title>'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '</head><body style="font-family:-apple-system,sans-serif;'
            'text-align:center;padding:2em">'
            '<h2>Connecting...</h2>'
            '<p>Verifying network access.</p>'
            '</body></html>'
        )
        self._send(200, "text/html", html)

    def _handle_status(self):
        self._send(200, "text/html",
                   "<h1>Activation Proxy</h1>"
                   "<p>Running. <a href='/captures'>View captures</a></p>")

    def _handle_captures_list(self):
        """Show captured exchanges."""
        lines = ["<h1>Captured Exchanges</h1><pre>"]
        for c in _captures:
            lines.append(
                f"[{c['timestamp']}] {c['path']} "
                f"req={c['request']['body_size']}B "
                f"resp={c['response']['body_size']}B "
                f"HTTP {c['response']['code']}"
            )
        lines.append("</pre>")
        self._send(200, "text/html", "\n".join(lines))

    # -- POST --------------------------------------------------------------

    def do_POST(self):
        path = self.path.split("?")[0]
        body = self._read_body()

        # Log the device request
        req_summary = _plist_summary(body)
        if req_summary:
            logger.info("  >> Device request keys: %s", list(req_summary.keys()))
            for k, v in req_summary.items():
                if not isinstance(v, dict):
                    logger.info("     %s: %s", k, v)

        # Check if this is a known activation endpoint
        real_url = DOMAIN_MAP.get(path)

        if real_url:
            self._proxy_to_apple(path, body, real_url)
        else:
            logger.info("  >> Unknown POST path: %s", path)
            # Save request anyway
            _save_capture("unknown", path, "POST",
                          self.headers, body, 404, {}, b"Not Found")
            self._send(404, "text/plain", "Not Found")

    def _proxy_to_apple(self, path, device_body, real_url):
        """Forward request to Apple, capture response, return to device."""
        logger.info("  >> Proxying to: %s", real_url)

        # Build the request to Apple
        # Use the same content-type the device sent
        ct = self.headers.get("Content-Type", "application/x-apple-plist")
        ua = self.headers.get("User-Agent", "")

        headers = {
            "Content-Type": ct,
            "Accept": self.headers.get("Accept", "application/xml"),
            "User-Agent": ua,
        }

        # Add any other Apple-specific headers the device sent
        for key in ["X-Apple-Signature", "X-Apple-Sig-Key",
                     "Accept-Language", "Accept-Encoding"]:
            val = self.headers.get(key)
            if val:
                headers[key] = val

        try:
            req = Request(real_url, data=device_body, headers=headers,
                          method="POST")

            # Create SSL context that trusts Apple's real certs via certifi
            ssl_ctx = ssl.create_default_context()
            try:
                import certifi
                ssl_ctx.load_verify_locations(certifi.where())
            except ImportError:
                # Fallback: try common macOS CA paths
                for ca_path in ["/etc/ssl/cert.pem",
                                "/usr/local/etc/openssl@3/cert.pem"]:
                    if os.path.isfile(ca_path):
                        ssl_ctx.load_verify_locations(ca_path)
                        break

            resp = urlopen(req, context=ssl_ctx, timeout=30)
            resp_code = resp.getcode()
            resp_headers = dict(resp.headers)
            resp_body_raw = resp.read()

            # Decompress if gzipped (urllib doesn't auto-decompress)
            resp_body = resp_body_raw
            content_enc = resp_headers.get("Content-Encoding", "")
            if "gzip" in content_enc.lower():
                import gzip
                try:
                    resp_body = gzip.decompress(resp_body_raw)
                    logger.info("  << Decompressed gzip: %d -> %d bytes",
                                len(resp_body_raw), len(resp_body))
                except Exception:
                    pass  # Use raw if decompress fails

            logger.info("  << Apple responded: HTTP %d (%d bytes)",
                        resp_code, len(resp_body))

            # Log response summary
            resp_summary = _plist_summary(resp_body)
            if resp_summary:
                logger.info("  << Response keys: %s",
                            list(resp_summary.keys()))

            # Save the full exchange
            _save_capture("apple", path, "POST",
                          self.headers, device_body,
                          resp_code, resp_headers, resp_body)

            # Forward Apple's response to the device
            # Filter out hop-by-hop and transfer headers that conflict
            # with our proxy re-encoding (we send Content-Length, not chunked)
            skip_headers = {
                "transfer-encoding", "content-length", "content-encoding",
                "connection", "keep-alive",
            }
            clean_headers = {
                k: v for k, v in resp_headers.items()
                if k.lower() not in skip_headers
            }
            resp_ct = resp_headers.get("Content-Type",
                                        "application/x-apple-plist")
            self._send(resp_code, resp_ct, resp_body, clean_headers)

        except HTTPError as e:
            resp_body = e.read() if hasattr(e, 'read') else b""
            logger.error("  << Apple HTTP error: %d (%d bytes)",
                         e.code, len(resp_body))

            resp_summary = _plist_summary(resp_body)
            if resp_summary:
                logger.info("  << Error response keys: %s",
                            list(resp_summary.keys()))

            _save_capture("apple_error", path, "POST",
                          self.headers, device_body,
                          e.code, dict(e.headers) if e.headers else {},
                          resp_body)

            self._send(e.code, "application/x-apple-plist", resp_body)

        except URLError as e:
            logger.error("  << Connection to Apple failed: %s", e.reason)

            _save_capture("apple_fail", path, "POST",
                          self.headers, device_body,
                          0, {}, str(e.reason).encode())

            # Return a minimal error to the device
            self._send(503, "text/plain",
                       f"Proxy: upstream connection failed: {e.reason}")

        except Exception as e:
            logger.error("  << Proxy error: %s", e)
            self._send(500, "text/plain", f"Proxy error: {e}")


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------
def write_report():
    """Write a summary report of all captured exchanges."""
    if not _captures:
        return

    report = {
        "generated": datetime.now().isoformat(),
        "device": "Connected iOS device",
        "total_exchanges": len(_captures),
        "exchanges": [],
    }

    for cap in _captures:
        entry = {
            "timestamp": cap["timestamp"],
            "endpoint": cap["path"],
            "request_size": cap["request"]["body_size"],
            "request_type": cap["request"]["body_type"],
            "request_keys": cap["request"]["plist_keys"],
            "response_code": cap["response"]["code"],
            "response_size": cap["response"]["body_size"],
            "response_type": cap["response"]["body_type"],
            "response_keys": cap["response"]["plist_keys"],
        }
        report["exchanges"].append(entry)

    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2, default=str)

    logger.info("Report written to %s", REPORT_FILE)


# ---------------------------------------------------------------------------
# Server startup
# ---------------------------------------------------------------------------
def start_proxy(host="0.0.0.0", http_port=80, https_port=443):
    """Start HTTP and HTTPS proxy servers."""
    # HTTP server
    http_server = HTTPServer((host, http_port), ProxyHandler)

    # HTTPS server (if certs exist)
    https_server = None
    if os.path.isfile(SERVER_CERT) and os.path.isfile(SERVER_KEY):
        https_server = HTTPServer((host, https_port), ProxyHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        https_server.socket = ctx.wrap_socket(
            https_server.socket, server_side=True
        )
        logger.info("HTTPS proxy on %s:%d", host, https_port)
    else:
        logger.warning("No TLS certs found -- HTTPS disabled")
        logger.warning("Run: %s/certs/generate_ca.sh", PROJECT_DIR)

    http_thread = threading.Thread(
        target=http_server.serve_forever, daemon=True
    )
    http_thread.start()
    logger.info("HTTP proxy on %s:%d", host, http_port)

    https_thread = None
    if https_server:
        https_thread = threading.Thread(
            target=https_server.serve_forever, daemon=True
        )
        https_thread.start()

    return http_server, https_server, http_thread, https_thread


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    host = "0.0.0.0"
    http_port = int(os.environ.get("PROXY_PORT", 80))
    https_port = int(os.environ.get("PROXY_HTTPS_PORT", 443))

    # Resolve real Apple IPs via external DNS before /etc/hosts kicks in
    _resolve_real_ips()
    if not REAL_IPS:
        print("FATAL: Could not resolve any real Apple IPs. Check DNS.")
        sys.exit(1)

    # Install monkey-patch so urllib connects to real Apple IPs
    socket.getaddrinfo = _patched_getaddrinfo

    print("=" * 60)
    print("  Activation Protocol Proxy -- Traffic Capture Mode")
    print("=" * 60)
    print(f"  HTTP  : {host}:{http_port}")
    print(f"  HTTPS : {host}:{https_port}")
    print(f"  Saves : {CAPTURES_DIR}/")
    print()
    print("  Real Apple IPs (via 8.8.8.8):")
    for domain, ip in REAL_IPS.items():
        print(f"    {domain} -> {ip}")
    print()
    print("  Endpoints proxied:")
    for local, remote in DOMAIN_MAP.items():
        print(f"    {local} -> {remote}")
    print()
    print("  Press Ctrl+C to stop and generate report.")
    print("=" * 60)
    print()

    http_srv, https_srv, _, _ = start_proxy(host, http_port, https_port)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping proxy...")
        write_report()
        http_srv.shutdown()
        if https_srv:
            https_srv.shutdown()
        print("Done. Captures in: %s" % CAPTURES_DIR)


if __name__ == "__main__":
    main()
