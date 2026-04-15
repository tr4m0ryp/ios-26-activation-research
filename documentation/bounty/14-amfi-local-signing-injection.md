# AMFI Local Signing Key Injection and Boot Argument Signature Bypass

## Issue Description

Apple's AppleMobileFileIntegrity (AMFI) library on iOS production firmware
exports functions that allow injection of local code signing keys and
boot-argument-based code signature bypasses. These APIs are intended for
developer mode and internal testing but are compiled into production
ramdisk firmware.

Key exported functions and capabilities:

1. `amfi_interface_set_local_signing_public_key` -- Injects a public key
   that AMFI will accept for local code signing validation. Any code signed
   with the corresponding private key would pass AMFI checks.

2. `amfi_interface_get_local_signing_private_key` -- Extracts the local
   signing private key from AMFI. If accessible, provides the key needed
   to sign arbitrary code.

3. `amfi_interface_authorize_local_signing` -- Authorizes local signing
   without Apple's certificate chain.

4. Boot argument bypass: `"boot-args allow process with invalid signature: %@"`
   indicates that specific boot arguments can override AMFI signature
   enforcement for named processes.

5. Additional security mode controls:
   - `AMFIArmSecurityBootMode` / `AMFICompleteSecurityBootMode`
   - `AMFIDemoModeSetState` -- demo mode toggle
   - `AMFIDeveloperModeCommit` / `AMFIIsDeveloperModeEnabled`
   - `AMFISupervisedModeSetState` -- supervised mode toggle
   - `amfi_restricted_execution_mode_enable/status`

## Affected Component

- Component: AppleMobileFileIntegrity.framework / libAMFI.dylib
- Platform: iOS/iPadOS 26.0 (restore and update ramdisks)
- Device: All iOS devices (universal)

## Proof of Concept

```bash
# 1. Find local signing key injection
strings /Volumes/ramdisk/usr/lib/libAMFI.dylib | grep -i "local_signing"
# Output:
# amfi_interface_set_local_signing_public_key
# amfi_interface_get_local_signing_private_key
# amfi_interface_authorize_local_signing

# 2. Find boot argument signature bypass
strings /Volumes/ramdisk/usr/lib/libAMFI.dylib | grep -i "invalid signature"
# Output: boot-args allow process with invalid signature: %@

# 3. Find security mode controls
strings /Volumes/ramdisk/usr/lib/libAMFI.dylib | grep -i "AMFIDeveloper\|DemoMode\|SupervisedMode"
# Output:
# AMFIDeveloperModeCommit
# AMFIIsDeveloperModeEnabled
# AMFIDemoModeSetState
# AMFISupervisedModeSetState

# 4. Verify exported symbols
nm -g /Volumes/ramdisk/usr/lib/libAMFI.dylib 2>/dev/null | grep -i "amfi_interface"
```

## Reproduction Steps

1. Download any IPSW from ipsw.me
2. Extract and mount any ramdisk
3. Run `strings` on libAMFI.dylib or equivalent AMFI library
4. Search for "local_signing", "invalid signature", "DemoMode"
5. Verify the local signing key injection interface exists

## Exploit Conditions

- Prerequisites: Code execution on the device (e.g., during restore,
  or via another vulnerability)
- Attack vector: Local
- User interaction: None

## Impact

- Local signing key injection: An attacker who can call
  `amfi_interface_set_local_signing_public_key` can make AMFI trust
  any code they sign, bypassing Apple's code signing requirement.
- Private key extraction: If `get_local_signing_private_key` returns
  a valid key, it could be used to sign malicious code.
- Boot argument bypass: Processes named in boot arguments can run
  without valid code signatures.
- Combined with other findings: These primitives make exploitation
  chains significantly easier by removing code signing as a barrier.

## Environment

- IPSW: iPad_Pro_A12X_A12Z_26.0_23A341_Restore.ipsw
- Binary: AMFI library on restore/update ramdisk
- Tools: strings, nm

## Suggested Remediation

1. Remove `amfi_interface_set_local_signing_public_key` and
   `amfi_interface_get_local_signing_private_key` from production
   firmware. These should only exist in development builds.
2. The boot argument signature bypass path should be gated behind
   development fusing, not just boot-args (which can be set via
   NVRAM on some device configurations).
3. Security mode toggle functions (DemoMode, SupervisedMode) should
   require authentication or be removed from ramdisk firmware.

## Attachments

- AMFI library strings analysis
- Symbol table from nm -g
