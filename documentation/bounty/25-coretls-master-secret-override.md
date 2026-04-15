# CoreTLS Master Secret Override and Peer Trust Manipulation in Production Firmware

## Issue Description

Apple's libcoretls.dylib on the iOS restore ramdisk exports internal
functions that allow complete manipulation of TLS session security:

1. `_tls_handshake_internal_set_master_secret_function` -- Overrides the
   function that derives the TLS master secret. The master secret is the
   root of all session keys in TLS. Overriding this function allows an
   attacker to choose a known master secret, making all session traffic
   decryptable.

2. `_tls_handshake_set_peer_trust` -- Sets the trust evaluation result
   for a TLS peer. If called with a "trusted" value, any server
   certificate would be accepted regardless of its validity.

3. `_tls_handshake_internal_master_secret` -- Extracts the current TLS
   master secret from an active session.

4. `_tls_handshake_internal_client_random` /
   `_tls_handshake_internal_server_random` -- Extract the random values
   used in key derivation.

5. `_tls_handshake_internal_set_session_ticket` -- Sets arbitrary TLS
   session ticket data, enabling session hijacking.

Additionally, the binary contains `com.apple.coretls.insecureDHParams`
suggesting a path for accepting weak Diffie-Hellman parameters.

These functions are exported as public symbols accessible to any code
running within the same process. On the restore ramdisk, processes like
`restored_update` (which handles activation) load this library.

## Affected Component

- Component: libcoretls.dylib (coretls-186)
- Platform: iOS/iPadOS 26.0 (all ramdisks)
- Device: All iOS devices

## Proof of Concept

```bash
nm -g /Volumes/ramdisk/usr/lib/libcoretls.dylib | grep -i "master_secret\|peer_trust\|session_ticket"
# _tls_handshake_internal_set_master_secret_function
# _tls_handshake_internal_master_secret
# _tls_handshake_set_peer_trust
# _tls_handshake_internal_set_session_ticket

strings /Volumes/ramdisk/usr/lib/libcoretls.dylib | grep "insecure"
# com.apple.coretls.insecureDHParams
```

## Impact

- Complete TLS session interception from within process
- Master secret override enables decryption of all activation traffic
- Peer trust override enables server certificate forgery
- Combined with dylib injection on ramdisk: full MITM of activation
  server communications (albert.apple.com, humb.apple.com)
- Combined with finding #10 (FDR HTTP trust object): cascading trust
  chain compromise

## Environment

- IPSW: iPad_Pro_A12X_A12Z_26.0_23A341_Restore.ipsw
- Binary: /Volumes/ramdisk/usr/lib/libcoretls.dylib

## Suggested Remediation

1. Remove internal TLS manipulation functions from production firmware.
2. Mark these symbols as private/hidden in the library exports.
3. Gate internal functions behind a compile-time flag for debug builds.
