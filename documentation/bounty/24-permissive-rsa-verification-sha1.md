# Permissive RSA Signature Verification + SHA-1 + RSA-1024 in Activation Path

## Issue Description

The iOS activation certificate verification path in restored_update uses
`_ccrsa_verify_pkcs1v15_allowshortsigs` from Apple's corecrypto library.
This is the PERMISSIVE variant of PKCS#1 v1.5 signature verification that
explicitly allows:
- Signatures shorter than the RSA modulus length
- Incomplete validation of trailing padding bytes after the DigestInfo

This creates attack surface for CVE-2006-4339-style padding oracle
attacks where the PKCS#1 v1.5 padding after the hash digest is not
fully validated to the modulus length.

Additionally, ALL embedded activation certificates use deprecated
cryptographic parameters:
- **SHA-1 signatures** (sha1WithRSAEncryption) -- SHA-1 collision
  attacks are practical since 2017 (SHAttered)
- **RSA-1024 leaf certificate** (Apple iPhone Activation) -- approaching
  practical factorability for well-resourced attackers
- **Expired certificates** -- Apple iPhone Activation cert expired
  April 2014 but is still accepted (no expiry enforcement observed)

Certificates found:
| Certificate | Key Size | Hash | Expired |
|---|---|---|---|
| Apple iPhone Activation | RSA-1024 | SHA-1 | Apr 2014 |
| Apple iPhone Certification Authority | RSA-2048 | SHA-1 | Apr 2022 |
| [TEST] Apple iPhone Activation | RSA-1024 | SHA-1 | Mar 2022 |
| [TEST] Apple iPhone Device CA | RSA-1024 | SHA-1 | - |

All use e=65537, ruling out classic e=3 forgery, but the combination
of `allowshortsigs` + SHA-1 + RSA-1024 creates a viable attack surface.

## Affected Component

- Component: restored_update (MASoftwareUpdate activation verification)
- Library: corecrypto (_ccrsa_verify_pkcs1v15_allowshortsigs)
- Platform: iOS/iPadOS 26.0 (restore ramdisk)
- Device: All iOS devices

## Proof of Concept

```bash
# 1. Verify the permissive function is used
strings /Volumes/ramdisk/usr/local/bin/restored_update | grep "allowshortsigs"
# _ccrsa_verify_pkcs1v15_allowshortsigs

# 2. Extract cert parameters
openssl x509 -in restored_cert_14.pem -noout -text | grep -E "Signature|Public-Key|Exponent"
# Public-Key: (1024 bit)
# Exponent: 65537
# Signature Algorithm: sha1WithRSAEncryption

# 3. Verify SHA-1 usage
openssl x509 -in restored_cert_14.pem -noout -text | grep "sha1"
# sha1WithRSAEncryption

# 4. Verify cert expiry
openssl x509 -in restored_cert_14.pem -noout -dates
# notAfter=Apr X 2014 (EXPIRED)
```

## Impact

- `allowshortsigs` + PKCS#1 v1.5: potential for padding-based
  signature forgery attacks
- SHA-1: collision attacks may enable certificate forgery
- RSA-1024: approaching factorability; compromised key would allow
  signing arbitrary activation records
- Expired certs: no temporal binding on activation certificate validity
- Combined: weakest link in the activation trust chain

## Environment

- IPSW: iPad_Pro_A12X_A12Z_26.0_23A341_Restore.ipsw
- Binary: /Volumes/ramdisk/usr/local/bin/restored_update
- Tools: strings, openssl

## Suggested Remediation

1. Replace `_ccrsa_verify_pkcs1v15_allowshortsigs` with the strict
   variant `_ccrsa_verify_pkcs1v15` or migrate to PSS padding.
2. Rotate activation certificates to SHA-256/SHA-384 with RSA-2048+
   or ECDSA P-256.
3. Enforce certificate expiry checking in the activation path.
4. Remove RSA-1024 certificates from production firmware.
