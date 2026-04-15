# restored_update Has SEP Manager, NVRAM Write, and No-Sandbox Entitlements

## Issue Description

The `restored_update` binary on the iOS production restore ramdisk holds
an extremely permissive set of entitlements that grant it full access to
the Secure Enclave, NVRAM, boot policy, firmware update, and attestation
services -- all without sandbox restrictions.

Critical entitlements:
- `com.apple.private.applesepmanager.allow` -- Full access to all 40
  AppleSEPUserClient external methods, including nonce generation,
  invalidation, and XART slot management
- `com.apple.private.iokit.system-nvram-allow` -- Write access to
  system NVRAM variables, including boot-nonce
- `com.apple.private.security.no-sandbox` -- Runs completely unsandboxed
- `com.apple.private.security.bootpolicy` -- Can modify boot policy
- `com.apple.private.security.AppleImage4.user-client` -- Image4
  personalization and manifest manipulation
- `com.apple.private.img4.nonce.cryptex1.boot` -- Cryptex1 boot nonce
- `com.apple.aop.durant.user-client` with `gen-boot-nonce` -- Can
  generate boot nonce via the AOP (Always-On Processor)
- `com.apple.afu.userclientaccess` -- Firmware update user client
- `com.apple.security.attestation.access` -- Attestation access
- `com.apple.diskimages.attach` -- Disk image mounting

Combined with the fact that during DFU restore, the host computer
controls ALL restore options sent to `restored_update` via USB, this
creates a powerful attack surface:

1. Host sends restore options with bypass flags (ShouldHactivate,
   FDRSkipSealing, AllowCertificateValidationFailed)
2. `restored_update` has entitlements to access AppleSEPUserClient
3. It can call DispatchUserClientGenerateNonceAndSlot repeatedly
4. After 16 calls, XART slots are exhausted (finding #09)
5. Nonce becomes predictable all-0xFF
6. NVRAM write allows setting the boot-nonce directly
7. No sandbox means unrestricted filesystem and network access

## Affected Component

- Component: restored_update (/usr/local/bin/restored_update)
- Platform: iOS/iPadOS 26.0 (restore ramdisk)
- Device: All iOS devices

## Proof of Concept

```bash
# 1. Extract entitlements
codesign -d --entitlements - /Volumes/ramdisk/usr/local/bin/restored_update

# Key entitlements found:
# com.apple.private.applesepmanager.allow: true
# com.apple.private.iokit.system-nvram-allow: true
# com.apple.private.security.no-sandbox: true
# com.apple.private.security.bootpolicy: true
# com.apple.private.security.AppleImage4.user-client: true
# com.apple.private.img4.nonce.cryptex1.boot: true
# com.apple.aop.durant.user-client > gen-boot-nonce

# 2. Verify these entitlements match kernel service requirements
strings kernelcache.macho | grep "applesepmanager.allow"
# com.apple.private.applesepmanager.allow (required by AppleSEPUserClient)

# 3. Verify host controls restore options
strings /Volumes/ramdisk/usr/local/bin/restored_update | grep "RestoreOption"
# copy_restore_options, allow_restore_option
```

## Exploit Conditions

- Prerequisites: Physical access + USB during DFU restore
- Attack vector: Local USB (host controls restore flow)
- User interaction: None (automated restore process)

## Impact

- Full SEP nonce manipulation from restore context
- NVRAM write access enables boot-nonce setting
- Unsandboxed execution with attestation and boot policy access
- Combined with XART slot exhaustion: predictable nonce generation
- Combined with host-controlled restore options: full option injection
- This set of entitlements is sufficient to bypass personalization
  binding if the nonce can be made predictable

## Environment

- IPSW: iPad_Pro_A12X_A12Z_26.0_23A341_Restore.ipsw
- Binary: /Volumes/ramdisk/usr/local/bin/restored_update
- Tools: codesign, strings

## Suggested Remediation

1. Apply least-privilege to restored_update. Most SEP operations
   should not require direct AppleSEPUserClient access -- use
   higher-level APIs instead.
2. Remove `gen-boot-nonce` from the AOP user-client entitlement
   unless specifically needed for the restore flow.
3. Validate restore options against a strict allowlist that excludes
   security-weakening options like FDRSkipSealing and
   AllowCertificateValidationFailed.
4. Consider sandboxing restored_update with a restrictive profile
   that only allows necessary operations.
