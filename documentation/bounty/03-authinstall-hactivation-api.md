# libauthinstall Hactivation and Relaxed Verification APIs in Production Firmware

## Issue Description

Apple's `libauthinstall.dylib` on iOS restore ramdisks exports internal
functions that enable hactivation policy, relaxed image verification, and
global signing. These functions are intended for Apple's internal factory
and test environments but are present in production firmware distributed
via publicly downloadable IPSW files.

Key exported functions:
- `AMAuthInstallApEnableLocalPolicyHactivation` -- enables local hactivation policy
- `AMAuthInstallApEnableRelaxedImageVerification` -- relaxes firmware image verification
- `AMAuthInstallApEnableGlobalSigning` -- enables global (non-personalized) signing
- `AMAuthInstallAddTrustedSSLCACert` -- adds a trusted SSL CA certificate

Additionally, the binary references an internal HTTP (not HTTPS) Apple
server: `http://treecko-dr.apple.com:8080/TREECKO/controller` -- an
unencrypted endpoint for device recovery operations.

## Affected Component

- Binary: `/usr/lib/libauthinstall.dylib` (restore and update ramdisks)
- IPSW: iPad_Pro_A12X_A12Z_26.0_23A341_Restore.ipsw

## Reproduction Steps

1. Download any IPSW from ipsw.me
2. Extract the restore ramdisk (IMG4P container)
3. Mount the APFS filesystem
4. List exported functions:
   ```bash
   nm -g /Volumes/ramdisk/usr/lib/libauthinstall.dylib | grep -iE "Hactivation|Relaxed|GlobalSigning|TrustedSSL"
   ```
5. Output:
   ```
   0000000000004c58 T _AMAuthInstallApEnableLocalPolicyHactivation
   0000000000076e38 T _AMAuthInstallApEnableRelaxedImageVerification
   0000000000004c90 T _AMAuthInstallApEnableGlobalSigning
   0000000000075ad0 T _AMAuthInstallAddTrustedSSLCACert
   ```

## Impact

1. The hactivation function enables a local policy that bypasses activation
   checks during restore operations. If triggered during a restore flow,
   it could bypass iCloud activation lock.

2. The relaxed verification function weakens firmware image validation,
   potentially allowing unsigned or modified firmware to be loaded.

3. The global signing function enables non-personalized signing, which
   could allow one device's signed firmware to be used on another.

4. The trusted CA function could add an attacker's Root CA to the device's
   trust store, enabling HTTPS MITM of activation endpoints.

5. The HTTP endpoint (treecko-dr.apple.com:8080) transmits recovery data
   over unencrypted HTTP, exposing it to network interception.

## Environment

- IPSW: iPad_Pro_A12X_A12Z_26.0_23A341_Restore.ipsw
- Device: iPad8,10 iOS 26.3
- Tools: nm, strings (standard macOS tools)
