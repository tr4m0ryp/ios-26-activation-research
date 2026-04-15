# FDR Trust Object Fetched Over Plain HTTP -- Enables Trust Anchor Replacement via MITM

## Issue Description

Apple's FairPlay Data Recovery (FDR) library fetches its trust object from
`http://gg.apple.com/fdrtrustobject` over plain HTTP (port 80), not HTTPS.
The FDR trust object contains the SSL root certificates and trusted signing
keys that libFDR uses for all subsequent cryptographic trust decisions.

This creates a circular trust failure: the certificates used to validate
FDR server connections are themselves fetched over an unauthenticated channel.
A network-level MITM attacker can replace the trust object with one containing
their own CA certificates, causing libFDR to trust attacker-controlled servers
for all FDR operations including device personalization and activation.

Additionally, when the trust object is unavailable (e.g., if the attacker
blocks the HTTP request), `_AMFDRDecodeVerifyChain` logs "Skipping trust
root check (trustobject unset)" and continues certificate chain verification
without anchoring to any trusted root. Error flags are set (0x200100) but
execution continues through signature verification.

The trust object is a 2884-byte DER-encoded structure containing:
- "FDR Sealing Server CA 1" (RSA-4096, valid 2014-2029)
- "FDR-DC-SSL-ROOT" certificate
- SSL root CA certificates used for subsequent HTTPS connections

## Affected Component

- Component: libFDR.dylib (FDR trust object fetch)
- Endpoint: http://gg.apple.com/fdrtrustobject (port 80, no TLS)
- Platform: iOS/iPadOS 26.0 (restore and update ramdisks)
- Device: All iOS devices (universal)

## Proof of Concept

```bash
# 1. Verify the endpoint uses HTTP, not HTTPS
curl -v "http://gg.apple.com/fdrtrustobject" -o /tmp/fdrtrustobject.bin
# Returns HTTP 200, 2884 bytes

# Verify HTTPS version does NOT work
curl -v "https://gg.apple.com/fdrtrustobject" -o /dev/null
# Connection fails

# 2. Parse the trust object structure
strings /tmp/fdrtrustobject.bin
# Shows: "FDR Sealing Server CA 1", "Apple Inc.", "FDR-DC-SSL-ROOT"

# 3. Verify libFDR references this URL
strings /Volumes/ramdisk/usr/lib/libFDR.dylib | grep "gg.apple.com"
# Output: http://gg.apple.com/fdrtrustobject

# 4. Verify the trust root skip path
strings /Volumes/ramdisk/usr/lib/libFDR.dylib | grep "Skipping trust"
# Output: Skipping trust root check (trustobject unset)
# Output: Skipping revocation check (trustobject unset)

# 5. Verify SSL roots come FROM the trust object
strings /Volumes/ramdisk/usr/lib/libFDR.dylib | grep "SslRoots"
# Output: AMFDRDataCopySslRoots
```

## Reproduction Steps

1. On a macOS machine on the same network as an iOS device
2. Download the FDR trust object: `curl http://gg.apple.com/fdrtrustobject -o original.bin`
3. Verify it contains certificates: `openssl asn1parse -inform DER -in original.bin`
4. Set up DNS spoofing: point `gg.apple.com` to attacker machine
5. Serve a modified trust object containing attacker's CA certificate
6. During device restore, libFDR fetches the modified trust object
7. libFDR now trusts attacker's CA for all FDR SSL connections
8. Attacker can MITM subsequent HTTPS connections to FDR endpoints

## Exploit Conditions

- Prerequisites: Network position (same WiFi, DNS control, or ARP spoofing)
- Attack vector: Network (MITM during restore/provisioning)
- User interaction: None (trust object fetched automatically by libFDR)

## Impact

- Trust anchor replacement: attacker controls which certificates libFDR trusts
- SSL MITM: all subsequent FDR HTTPS connections use attacker-supplied roots
- FDR data manipulation: personalization tickets, activation records
- Device personalization bypass: attacker can serve crafted APTickets
- Affects ALL iOS devices during restore/provisioning flow

## Environment

- IPSW: iPad_Pro_A12X_A12Z_26.0_23A341_Restore.ipsw
- Endpoint: http://gg.apple.com/fdrtrustobject
- DNS: gg.apple.com resolves to gg.apple.com.v.aaplimg.com -> 17.171.47.4
- Tools: curl, strings, openssl

## Suggested Remediation

1. Switch the trust object endpoint from HTTP to HTTPS with certificate
   pinning. This eliminates the MITM vector entirely.
2. Embed a fallback trust anchor in libFDR itself (not fetched from network)
   so that the trust root skip path cannot be triggered by blocking HTTP.
3. When the trust object is unavailable, `_AMFDRDecodeVerifyChain` should
   FAIL CLOSED (return error) instead of continuing without root verification.
4. Sign the trust object and verify the signature using an embedded public
   key before accepting it.

## Attachments

- Trust object binary: /tmp/fdrtrustobject.bin (2884 bytes)
- libFDR.dylib strings analysis showing HTTP endpoint and skip paths
