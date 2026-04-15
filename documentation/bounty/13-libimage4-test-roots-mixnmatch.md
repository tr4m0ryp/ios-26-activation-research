# Test Root CAs and Mix-N-Match God Mode in Production libimage4

## Issue Description

Apple's libimage4.dylib in production iOS firmware contains embedded test
root certificate authorities and debug policy flags that weaken Image4
secure boot verification. Specifically:

1. Two test root CAs are compiled into the production binary:
   - `.img4 test secp256r1 Root Certificate Authority1`
   - `.img4 test secp384r1 Root Certificate Authority1`
   - `TEST UCRT ATTESTATION ROOT CA1`

2. Policy override flags in the binary:
   - `factory-prerelease-global-trust` -- enables global trust for factory/prerelease
   - `allow mix-n-match` -- allows mixing firmware components from different builds
   - `mix-n-match god mode` -- disables ALL mix-n-match policy enforcement
   - `allow-ecid-mismatch` -- allows ECID mismatch (device identity bypass)

3. Factory mode strings for SEP components:
   - `Savage - Factory`
   - `Yonkers - Factory`
   - `certificate-production-status`
   - `effective-production-status-ap`

4. Kernel test interface reference:
   - `security.mac.image4.kmod.test_firebloom`

Image4 is the fundamental cryptographic verification mechanism for all
firmware loaded on iOS devices. Test roots and policy overrides in
production code weaken the entire secure boot chain.

## Affected Component

- Component: libimage4.dylib
- Platform: iOS/iPadOS 26.0 (all ramdisks)
- Device: All iOS devices (universal)

## Proof of Concept

```bash
# 1. Find test root CAs
strings /Volumes/ramdisk/usr/lib/libimage4.dylib | grep -i "test.*root"
# Output:
# .img4 test secp256r1 Root Certificate Authority1
# .img4 test secp384r1 Root Certificate Authority1
# TEST UCRT ATTESTATION ROOT CA1

# 2. Find mix-n-match flags
strings /Volumes/ramdisk/usr/lib/libimage4.dylib | grep -i "mix-n-match"
# Output:
# allow mix-n-match
# mix-n-match god mode

# 3. Find ECID mismatch flag
strings /Volumes/ramdisk/usr/lib/libimage4.dylib | grep -i "ecid"
# Output: allow-ecid-mismatch

# 4. Find factory flags
strings /Volumes/ramdisk/usr/lib/libimage4.dylib | grep -i "factory"
# Output:
# factory-prerelease-global-trust
# Savage - Factory
# Yonkers - Factory

# 5. Find production status queries
strings /Volumes/ramdisk/usr/lib/libimage4.dylib | grep -i "production-status"
# Output:
# certificate-production-status
# effective-production-status-ap
# effective-production-status-sep
```

## Reproduction Steps

1. Download any IPSW from ipsw.me
2. Extract and mount any ramdisk
3. Run `strings` on libimage4.dylib
4. Search for "test.*Root", "mix-n-match", "ecid-mismatch"
5. All test roots and policy flags are present in production firmware

## Exploit Conditions

- Prerequisites: Ability to set Image4 manifest properties or load
  firmware with specific Image4 tags
- Attack vector: Local (during boot or restore)
- User interaction: None

## Impact

- Test root CAs: If code paths exist that accept these test roots,
  firmware signed by test keys would be accepted on production devices
- Mix-n-match god mode: Allows combining firmware components from
  different iOS versions, potentially loading vulnerable older components
- ECID mismatch: Allows firmware personalized for one device to be
  loaded on a different device, bypassing the personalization binding
- Factory flags: Could trick production devices into accepting
  factory-mode firmware or certificates

## Environment

- IPSW: iPad_Pro_A12X_A12Z_26.0_23A341_Restore.ipsw
- Binary: /Volumes/ramdisk/usr/lib/libimage4.dylib
- Tools: strings, nm

## Suggested Remediation

1. Remove test root CAs from production libimage4 builds entirely.
   Test roots should only exist in internal/development builds.
2. Remove `mix-n-match god mode` from production code. If mix-n-match
   is needed for specific update scenarios, enforce it via signed
   manifest properties, not in-library flags.
3. Remove `allow-ecid-mismatch` from production code. ECID binding
   is fundamental to personalization security.
4. Gate factory mode paths behind hardware fuse checks.

## Attachments

- Full strings output from libimage4.dylib
- Cross-reference with libimage4 symbol table
