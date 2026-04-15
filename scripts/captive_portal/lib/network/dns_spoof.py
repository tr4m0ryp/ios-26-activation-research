#!/usr/bin/env python3
"""
Minimal DNS server that redirects Apple activation domains to a local IP.
All other queries are forwarded to upstream DNS (8.8.8.8).

Usage:
    sudo python3 dns_spoof.py [local_ip]
"""

import os
import socket
import struct
import sys
import threading
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | dns | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("dns")

UPSTREAM_DNS = "8.8.8.8"
DNS_PORT = 53

# Domains to redirect
SPOOF_DOMAINS = {
    "albert.apple.com",
    "humb.apple.com",
    "captive.apple.com",
    "gs.apple.com",
    "static.ips.apple.com",
    "mesu.apple.com",
    "static.deviceservices.apple.com",
    "bag.itunes.apple.com",
    "setup.icloud.com",
    "gateway.icloud.com",
    "iprofiles.apple.com",
    "configuration.apple.com",
    "identity.apple.com",
    "gsa.apple.com",
    "gdmf.apple.com",
    "xp.apple.com",
    "init.ess.apple.com",
    "deviceservices.apple.com",
}


def parse_dns_name(data, offset):
    """Parse a DNS name from packet data, handling compression pointers."""
    labels = []
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            # Compression pointer
            ptr = struct.unpack("!H", data[offset:offset+2])[0] & 0x3FFF
            labels.append(parse_dns_name(data, ptr)[0])
            offset += 2
            break
        else:
            offset += 1
            labels.append(data[offset:offset+length].decode("ascii", errors="replace"))
            offset += length
    return ".".join(labels), offset


def build_dns_response(query, spoof_ip):
    """Build a DNS response that redirects to spoof_ip."""
    # Parse the query
    if len(query) < 12:
        return None

    txn_id = query[:2]
    flags = b"\x81\x80"  # Standard response, no error
    qdcount = struct.unpack("!H", query[4:6])[0]
    ancount = struct.pack("!H", qdcount)  # One answer per question

    # Copy the question section
    offset = 12
    questions = b""
    names = []
    for _ in range(qdcount):
        name, new_offset = parse_dns_name(query, offset)
        names.append(name)
        questions += query[offset:new_offset + 4]  # name + type + class
        offset = new_offset + 4

    # Build answer section
    ip_bytes = socket.inet_aton(spoof_ip)
    answers = b""
    for _ in range(qdcount):
        answers += b"\xc0\x0c"  # Pointer to name in question
        answers += b"\x00\x01"  # Type A
        answers += b"\x00\x01"  # Class IN
        answers += struct.pack("!I", 60)  # TTL 60s
        answers += struct.pack("!H", 4)   # Data length
        answers += ip_bytes

    response = txn_id + flags + query[4:6] + ancount + b"\x00\x00\x00\x00"
    response += questions + answers

    return response, names


def forward_to_upstream(query):
    """Forward DNS query to upstream and return response."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(query, (UPSTREAM_DNS, 53))
        response, _ = sock.recvfrom(4096)
        sock.close()
        return response
    except Exception:
        return None


def run_dns(local_ip, port=DNS_PORT):
    """Run the DNS server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    logger.info("DNS server on 0.0.0.0:%d, spoofing to %s", port, local_ip)
    logger.info("Spoofed domains: %s", ", ".join(sorted(SPOOF_DOMAINS)))

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            if len(data) < 12:
                continue

            # Parse query name
            name, _ = parse_dns_name(data, 12)

            name_lower = name.lower()
            should_spoof = (
                name_lower in SPOOF_DOMAINS
                or name_lower.endswith(".apple.com")
                or name_lower.endswith(".icloud.com")
                or name_lower.endswith(".aaplimg.com")
                or "apple" in name_lower
                or "icloud" in name_lower
                or name_lower.endswith(".cdn-apple.com")
                or "itunes-apple" in name_lower
            )
            if should_spoof:
                result = build_dns_response(data, local_ip)
                if result:
                    response, names = result
                    sock.sendto(response, addr)
                    logger.info("SPOOF %s -> %s (from %s)", name, local_ip, addr[0])
                continue

            # Forward other queries to upstream
            response = forward_to_upstream(data)
            if response:
                sock.sendto(response, addr)
                logger.info("FORWARD %s (from %s)", name, addr[0])

        except Exception as e:
            logger.error("Error: %s", e)


if __name__ == "__main__":
    ip = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("MAC_IP", "192.0.2.1")
    run_dns(ip)
