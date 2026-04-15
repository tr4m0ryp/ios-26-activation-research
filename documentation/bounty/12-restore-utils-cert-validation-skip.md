# AppleRestoreUtils Certificate Validation Skip and FDR SSL Disable in Production Firmware

## Issue Description

Apple's AppleRestoreUtils.framework on the iOS restore ramdisk contains
options that completely disable certificate validation and SSL verification
during device restore operations. When the `AllowCertificateValidationFailed`
option is enabled, the framework logs "failed to validate %@, but
allowCertificateValidationFailed enabled, ignore this failure" and proceeds
with the restore operation despite the validation failure.

Additionally, the framework exports a `FDRDisableSSLValidation` option that
disables SSL certificate verification for all FDR server communications
during restore.

Other dangerous internal APIs discovered in the same framework:
- `setEntitlementOverrideConfig` -- overrides entitlement checking
- `setDummyWrappedFDRDataEncryptionKey` -- sets a dummy encryption key
- `simulateSelfTestFailure` -- simulates biometric test failure
- `aks_run_internal_test` -- internal AppleKeyStore test function
- References to `IOService:/IOResources/AppleKeyStoreTest` test interface

These APIs are intended for Apple's factory restore flow but are compiled
into production firmware accessible via IPSW downloads.

## Affected Component

- Component: AppleRestoreUtils.framework (restore ramdisk only)
- Platform: iOS/iPadOS 26.0
- Device: All iOS devices (present on restore ramdisk)

## Proof of Concept

```bash
# 1. Find the certificate validation skip
strings /Volumes/ramdisk/System/Library/PrivateFrameworks/AppleRestoreUtils.framework/AppleRestoreUtils | grep -i "AllowCertificate"
# Output: AllowCertificateValidationFailed
# Output: failed to validate %@, but allowCertificateValidationFailed enabled, ignore this failure

# 2. Find FDR SSL disable
strings /Volumes/ramdisk/System/Library/PrivateFrameworks/AppleRestoreUtils.framework/AppleRestoreUtils | grep -i "FDRDisableSSL"
# Output: FDRDisableSSLValidation

# 3. Find internal test APIs
strings /Volumes/ramdisk/System/Library/PrivateFrameworks/AppleRestoreUtils.framework/AppleRestoreUtils | grep -iE "KeyStoreTest|EntitlementOverride|DummyWrapped"
# Output: AppleKeyStoreTest
# Output: setEntitlementOverrideConfig
# Output: setDummyWrappedFDRDataEncryptionKey

# 4. Verify these are exported symbols
nm -g /Volumes/ramdisk/System/Library/PrivateFrameworks/AppleRestoreUtils.framework/AppleRestoreUtils 2>/dev/null | grep -i "ARU"
# Shows ARUContextSetRestoreOptions and related symbols
```

## Reproduction Steps

1. Download any IPSW from ipsw.me
2. Extract the restore ramdisk (not the update ramdisk)
3. Mount the APFS filesystem
4. Run `strings` on AppleRestoreUtils.framework binary
5. Search for "AllowCertificateValidationFailed" and "FDRDisableSSLValidation"
6. Both options are present in production firmware

## Exploit Conditions

- Prerequisites: Control over restore options dictionary (during DFU restore)
- Attack vector: Local USB (during device restore)
- User interaction: None (during automated restore flow)

## Impact

- Certificate validation bypass: Any certificate accepted during restore,
  including self-signed or expired certificates
- FDR SSL disable: All FDR server communications proceed without TLS
  verification, enabling MITM during restore
- Entitlement override: Security entitlement checks can be bypassed
- Combined with FDR trust object MITM (finding #10): complete control
  over device personalization and activation during restore

## Environment

- IPSW: iPad_Pro_A12X_A12Z_26.0_23A341_Restore.ipsw
- Binary: /Volumes/ramdisk/System/Library/PrivateFrameworks/AppleRestoreUtils.framework/AppleRestoreUtils
- Tools: strings, nm

## Suggested Remediation

1. Remove `AllowCertificateValidationFailed` and `FDRDisableSSLValidation`
   from production firmware builds entirely.
2. Gate all internal test APIs (`setEntitlementOverrideConfig`,
   `setDummyWrappedFDRDataEncryptionKey`, `simulateSelfTestFailure`)
   behind hardware fuse checks.
3. The `AppleKeyStoreTest` reference should not exist in production
   restore tools.
4. Consider separating factory and production restore ramdisks if
   factory APIs cannot be removed from the production build pipeline.

## Attachments

- strings output from AppleRestoreUtils.framework
- nm -g symbol listing
