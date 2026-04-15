# 23 Apple Certificates Including TEST Certs in Production Firmware

## Issue Description

The `restored_update` binary in the iOS production restore ramdisk
contains 23 embedded X.509 certificates including test and development
certificates that should not be present in production firmware:

- `[TEST] Apple iPhone Activation` (RSA-1024, sha1WithRSAEncryption)
- `[TEST] Apple iPhone Device CA` (RSA-1024, sha1WithRSAEncryption)
- `TEST SEP ROOT CA`
- `TEST UCRT ATTESTATION ROOT CA`
- `img4 test secp384r1 Root Certificate Authority`
- `FDR-LOCAL-V1` (with matching private key in libFDR.dylib)
- `FDR-LOCAL`
- `Apple iPhone Activation` (production, RSA-1024, expired 2014)
- `Apple iPhone Certification Authority` (RSA-2048, expired 2022)
- `Apple iPhone Device CA`
- `FDR-CA1-ROOT-CM`
- Multiple SEP Root CAs and Attestation Root CAs

The TEST certificates enable alternative validation paths in the
factory activation flow. Their presence in production firmware
increases the attack surface for certificate-based authentication.

## Affected Component

- Component: restored_update (/usr/local/bin/restored_update)
- Platform: iOS/iPadOS 26.0 (restore ramdisk)
- Device: All iOS devices

## Proof of Concept

```bash
# Extract all certificates from the binary
strings restored_update | grep -E "^MI[A-Z]" | while read b64; do
    echo "$b64" | base64 -d 2>/dev/null | \
    openssl x509 -inform DER -noout -subject 2>/dev/null
done

# Key certificates found:
# CN=Apple iPhone Activation (RSA-1024, expired 2014)
# CN=[TEST] Apple iPhone Activation (RSA-1024)
# CN=[TEST] Apple iPhone Device CA
# CN=TEST SEP ROOT CA
# CN=TEST UCRT ATTESTATION ROOT CA
# CN=FDR-LOCAL-V1 (with private key in libFDR)
```

## Reproduction Steps

1. Download any IPSW from ipsw.me
2. Extract the restore ramdisk
3. Run `strings` on restored_update and filter for base64 cert data
4. Decode with openssl to see TEST and expired production certificates

## Impact

- TEST certificates enable alternative factory validation paths
- Expired production certificates still accepted (no expiry enforcement)
- FDR-LOCAL certificates have matching private keys in firmware
- Combined attack surface enables certificate-based bypass attempts

## Environment

- IPSW: iPad_Pro_A12X_A12Z_26.0_23A341_Restore.ipsw

## Suggested Remediation

1. Remove all TEST certificates from production firmware
2. Remove expired certificates
3. Enforce certificate expiry checking in activation paths
