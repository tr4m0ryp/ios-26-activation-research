# 20+ FDR Security Bypass Options Compiled into Production Firmware

## Issue Description

Apple's libFDR.dylib in production iOS firmware contains over 20 named
bypass options that disable critical security checks. These options are
intended for factory and test environments but are present and functional
in firmware distributed via public IPSW downloads.

When set, these options disable trust verification, manifest checking,
signature validation, property verification, and certificate revocation.
Any process that calls `AMFDRCreateWithOptions` or `AMFDRSetOption` can
enable these bypasses in-memory.

Key bypass options discovered:

| Option | Effect |
|--------|--------|
| APTicketAllowUntrusted | Skips ALL APTicket trust verification |
| APTicketAllowDigestMismatch | Allows boot manifest hash mismatch |
| SkipManifest | Skips entire manifest verification |
| SkipVerifySik | Skips SIK (System Integrity Key) verification |
| SkipProperties | Skips property verification |
| CopyAllowUnsealed | Allows access to unsealed FDR data |
| CopyAllowOfflineSigning | Enables offline signing mode |
| AllowPropertyMismatch | Ignores property verification failures |
| AllowVersionMismatch | Ignores version check failures |
| AllowCSRForbidden | Bypasses CSR restrictions |
| AllowIncompleteData | Proceeds with missing FDR data |
| AllowSikPubMissingWhenUnseal | Unseals without SIK public key |
| SealingManifestOverride | Overrides sealing manifest |
| SealingPropertiesOverride | Overrides sealing properties |
| AllowSealingWithMLBSerialNumber | Alternative sealing identifier |
| kAMFDROptionOfflineSigning | Offline signing mode flag |

Additionally, `kAMFDROptionApTicketAllowUntrusted` when set to TRUE causes
`AMFDRDataApTicketIsTrusted` to immediately return success (error = 0)
without ANY verification. The code at offset 0x5aa24 sets the return value
to 0 and returns immediately after logging "kAMFDROptionApTicketAllowUntrusted
is TRUE, implicitly trusting ticket."

A related option, `APTicketAllowDigestMismatch`, allows the APTicket digest
to not match the boot manifest hash. In recovery/NeRD mode, this mismatch
is allowed automatically without any option flag.

## Affected Component

- Component: libFDR.dylib (FairPlay Data Recovery library)
- Platform: iOS/iPadOS 26.0 (all restore and update ramdisks)
- Device: All iOS devices (universal)

## Proof of Concept

```bash
# 1. Extract all bypass options from libFDR
strings /Volumes/ramdisk/usr/lib/libFDR.dylib | grep -iE "Allow|Skip|Override"

# Output includes:
# APTicketAllowUntrusted
# APTicketAllowDigestMismatch
# SkipManifest
# SkipVerifySik
# SkipProperties
# CopyAllowUnsealed
# CopyAllowOfflineSigning
# AllowPropertyMismatch
# AllowVersionMismatch
# AllowCSRForbidden
# AllowIncompleteData
# AllowSikPubMissingWhenUnseal
# SealingManifestOverride
# SealingPropertiesOverride

# 2. Verify APTicketAllowUntrusted immediate-return path
strings /Volumes/ramdisk/usr/lib/libFDR.dylib | grep "implicitly trusting"
# Output: kAMFDROptionApTicketAllowUntrusted is TRUE, implicitly trusting ticket.

# 3. Verify NeRD/recovery auto-bypass
strings /Volumes/ramdisk/usr/lib/libFDR.dylib | grep "NeRD"
# Output: NeRD OS detected, digest mismatch is allowed

# 4. Verify these are read via CFDictionary (API-level options)
nm -g /Volumes/ramdisk/usr/lib/libFDR.dylib | grep -i option
# Shows: AMFDRSetOption, AMFDRGetOptions, AMFDRCreateWithOptions
```

## Reproduction Steps

1. Download any IPSW from ipsw.me
2. Extract and mount the restore ramdisk
3. Run `strings` on libFDR.dylib to enumerate bypass options
4. Run `nm -g` to confirm AMFDRSetOption and AMFDRCreateWithOptions exports
5. Disassemble AMFDRDataApTicketIsTrusted to confirm the immediate-return
   path when APTicketAllowUntrusted is TRUE

## Exploit Conditions

- Prerequisites: Code execution within a process that loads libFDR
- Attack vector: Local (API-level option setting)
- User interaction: None

## Impact

- APTicketAllowUntrusted: Complete bypass of APTicket trust chain.
  Any APTicket is accepted regardless of signer.
- SkipManifest: Boot manifest verification disabled entirely.
  Device boots with any manifest.
- CopyAllowUnsealed: Unsealed FDR data accessible. Personalization
  data not bound to specific hardware.
- Combined: An attacker controlling a process that uses libFDR
  (e.g., restored, mobileactivationd) can disable ALL cryptographic
  verification of firmware personalization.

## Environment

- IPSW: iPad_Pro_A12X_A12Z_26.0_23A341_Restore.ipsw
- Binary: /Volumes/ramdisk/usr/lib/libFDR.dylib
- Tools: strings, nm, otool

## Suggested Remediation

1. Remove all bypass options from production firmware builds. These
   should only exist in internal/factory builds.
2. If options must remain for field repair scenarios, gate them behind
   a hardware fuse check (production vs. development fusing).
3. At minimum, the `APTicketAllowUntrusted` option should be completely
   removed from production code -- there is no legitimate reason for
   production firmware to skip APTicket trust verification.
4. The NeRD auto-bypass of digest mismatch should verify the device
   is actually in a legitimate recovery mode, not just check
   `os_variant_is_recovery`.

## Attachments

- Full list of bypass options extracted from libFDR.dylib
- Disassembly of AMFDRDataApTicketIsTrusted function at offset 0x5a97c
