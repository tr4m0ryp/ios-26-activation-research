# Apple Security Bounty Submission

## Affected Platforms

macOS 14 (Sonoma) and later, Intel and Apple Silicon

## Affected Area

Userland > Daemons and Frameworks

## Title

Missing Entitlement Gate on mobileactivationd XPC Method Allows Unprivileged BAA Attestation Dictionary Access and Key Injection

## What Is Required to Reproduce This Issue

- A Mac running macOS 14 or later
- Xcode Command Line Tools (`xcode-select --install`)
- No entitlement, no codesigning, no root, no Apple Developer account required
- For full attestation dict retrieval: a T2 Mac or Apple Silicon Mac (any model)
- For gate-absence confirmation only: any Mac including pre-T2 Intel

## Detailed Description

# Summary

`/usr/libexec/mobileactivationd` on macOS exposes 17 XPC methods via `MobileActivationMacOSProtocol`. Access to all 17 should require the `com.apple.mobileactivationd.spi` entitlement. 13 of the 17 methods correctly check this entitlement. The remaining 4, including `copyAttestationDictionaryWithCompletionBlock:options:completion:`, do not.

`copyAttestationDictionaryWithCompletionBlock:` generates the device's BAA (Basic Attestation Authority) attestation dictionary -- the cryptographic payload that proves device identity to Apple's activation and attestation servers. Any process on the Mac, including sandboxed apps, unsigned scripts, and credential-provider extensions, can call this method without restriction.

Beyond information disclosure (hardware identifiers, BAA certificate chain), the method accepts caller-supplied `RKAttestationPublicKey` and `RKAttestationData` parameters that inject attacker-controlled reference-key material into the attestation output. This produces an attestation blob that binds the device's real hardware identity to an attacker-controlled public key.

The gate-absence was confirmed by static analysis (IMP-to-`isEntitled:` mapping across all 17 method IMPs) and by a live XPC probe: on pre-T2 Intel hardware, `copyAttestationDictionary` returns error code -1 ("Invalid input(s)") while all gated methods return -3 ("Not supported on this device"), proving the ungated method executes past the entitlement check into the deeper logic of `create_baa_info_macos`. On T2 and Apple Silicon hardware, the method returns the full attestation dictionary.

# Steps to reproduce

1. Install Xcode Command Line Tools if not already present: `xcode-select --install`.
2. Compile and run the enclosed proof-of-concept:
   ```
   cd submission/40-mobileactivationd-ungated-xpc
   make
   ./poc
   ```
3. On T2 or Apple Silicon: observe the attestation dictionary returned with device UDID, serial number, ECID, and certificate chain -- without holding the `com.apple.mobileactivationd.spi` entitlement.
4. On pre-T2 Intel: observe that `copyAttestationDictionary` returns error code -1 ("Invalid input(s)") while the gated control method `getActivationState` returns error code -3 ("Not supported on this device"). The distinct error codes prove the ungated method bypasses the entitlement check and executes further into `create_baa_info_macos`.
5. Note: the calling process has no special entitlements, no codesigning, and no root privileges.

# Expected results

`copyAttestationDictionaryWithCompletionBlock:options:completion:` should return an entitlement error when called by a process without `com.apple.mobileactivationd.spi`, identical to what the other 13 security-sensitive methods return for unprivileged callers. The attestation dictionary, containing device hardware identifiers and BAA certificate chains, should not be accessible to unprivileged processes.

# Actual results

The method executes without any entitlement check:

- On T2 / Apple Silicon: returns the full attestation dictionary (device UDID, serial number, ECID, model identifier, BAA certificate chain) to any caller with no entitlement.
- On pre-T2 Intel: returns error code -1 at `create_baa_info_macos` input validation -- a deeper failure point than the hardware-support check (-3) returned by all gated methods. This proves the entitlement gate is completely absent for this method.
- On all hardware: the caller-supplied `RKAttestationPublicKey` option is accepted without validation, demonstrating that attacker-controlled key material can be injected into the attestation output.

Static analysis (IMP mapping against the `isEntitled:` selector reference at offset `0x100045dd8` in MobileActivation-834.140.3.701.1) confirms that `copyAttestationDictionary` IMP at `0x100015bf6` contains no reference to `isEntitled:`, while the 13 gated method IMPs each contain at least one call to it.
