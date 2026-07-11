# Missing Entitlement Gate on macOS mobileactivationd Allows Unprivileged BAA Attestation Dictionary Access

## What This Vulnerability Is

`/usr/libexec/mobileactivationd` on macOS is the daemon responsible for device activation and identity management. It holds the device's cryptographic identity -- its attestation certificates, hardware identifiers (UDID, serial number, ECID), and the attestation chains used to prove device ownership to Apple's servers.

Access to this daemon's capabilities is supposed to be gated by a code-signing entitlement (`com.apple.mobileactivationd.spi`). Only processes that hold this entitlement -- a restricted set of Apple system binaries -- are supposed to be able to call its XPC methods. The daemon exposes 17 methods. 13 of them correctly check the entitlement before doing any work. 4 of them do not.

The security-relevant ungated method is `copyAttestationDictionaryWithCompletionBlock:options:completion:`. This method generates the device's BAA (Basic Attestation Authority) attestation dictionary -- the full cryptographic payload that proves device identity to Apple's activation and attestation infrastructure. Any process on the Mac, including sandboxed apps and unsigned scripts, can call this method without holding the entitlement. The service accepts the connection without any audit-token or entitlement check at the connection level either.

## Why It Is Dangerous

**Device identity disclosure.** The attestation dictionary contains the device's UDID, serial number, ECID, and model identifier, along with the device's BAA certificate chain. These identifiers are otherwise restricted to entitled processes. An unprivileged app or script can fingerprint the Mac without triggering any permission dialogs or entitlement checks.

**Attestation-parameter injection.** The method accepts caller-supplied option keys, specifically `RKAttestationPublicKey` and `RKAttestationData`. These keys inject attacker-controlled reference-key material into the attestation output. The attestation blob that results mixes the real device's hardware identity with an attacker-controlled public key. If Apple's server-side validation does not strictly verify that the reference-key material corresponds to a SEP-bound key, this blob could be used to register the device's identity against an attacker-controlled key -- a prerequisite for activation-record replay attacks.

**Bypasses the entitlement architecture.** The 13 gated methods demonstrate that Apple intended all 17 methods to require the entitlement. The 4 ungated ones are a code defect (missed gate during a refactor) rather than an intentional design. The fix is surgical and clear.

**Chain enabler.** Combined with the `BAAOverrideURL` and `UseQACertificates` option keys settable via entitled processes (finding #39), the chain is: (1) unprivileged process obtains device attestation via this ungated method, (2) an entitled process (Setup Assistant, mdmclient) is exploited to redirect the activation server to an attacker-controlled endpoint, (3) the attacker presents the device attestation with injected key material to perform activation-record spoofing.

## Technical Explanation

The `MobileActivationMacOSProtocol` XPC service has the following architecture:

- The listener IMP at offset `0x10000ed0b` (MobileActivation-834.140.3.701.1) unconditionally returns `YES` to `shouldAcceptNewConnection:` -- any process can connect.
- Each method IMP is then supposed to call `[self isEntitled:@"com.apple.mobileactivationd.spi"]` before performing work.

Cycle-009 analysis mapped all 17 method IMPs against the `isEntitled:` selector reference at `0x100045dd8`. Result:

| Method | Entitlement check |
|---|---|
| issueDCRT, copyDCRT, getActivationState, activate, deactivate, copyActivationRecord, copyActivationState, copyDeviceInfo, copyBAAInfo, copyUCRT, issueDCRTWithOptions, copyDCRTWithOptions, copyLocalPolicy | YES (13 methods) |
| **copyAttestationDictionaryWithCompletionBlock:options:completion:** | **NO** |
| copyAutomaticTimeEnabledWithCompletion, copyRTCResetCountWithCompletionBlock, copyMonotonicClockWithCompletionBlock | NO (harmless getters) |

The ungated method IMP at `0x100015bf6` calls `create_baa_info_macos` directly with the caller-supplied options dictionary. No entitlement check, no audit-token check, no connection-level gate.

**Runtime confirmation (cycle-010, pre-T2 Intel Mac):**

On pre-T2 Intel hardware (attestation hardware absent), all methods return error code -3 ("Not supported on this device") at the hardware-capability check level -- EXCEPT `copyAttestationDictionary`, which returns error code -1 ("Invalid input(s)"). This difference proves `copyAttestationDictionary` bypasses the hardware-support gate and reaches deeper into `create_baa_info_macos` before failing. On T2 Macs and Apple Silicon (attestation hardware present), the method executes fully and returns the attestation dictionary.

## Evidence

- **Level:** RUNTIME-CONFIRMED
- **Static analysis:** cycle-009 (IMP-to-gate mapping)
- **Runtime probe:** cycle-010 (live XPC probe, pre-T2 Intel Mac)
- **Platform:** macOS 14+ (MobileActivation-834.140.3.701.1)
- **Runtime output:** `copyAttestationDictionary` returns code -1 (executes deeper) vs code -3 (hardware-support gate) for all gated methods
- **Log file:** `logs/cycle-009-010_runtime_verification.log`

## How to Reproduce

### Requirements

- A Mac running macOS 14 or later
- Xcode Command Line Tools: `xcode-select --install`
- No entitlement, no codesigning, no root required

### Build the Proof of Concept

```bash
cd submission/40-mobileactivationd-ungated-xpc
make
```

### Run the Proof of Concept

```bash
./poc
```

Or with log capture:

```bash
make run
```

### What to Expect

On **T2 or Apple Silicon** (full attestation hardware):
```
[UNGATED] Attestation dict received (8 keys):
  UDID: __NSCFData
  SerialNumber: __NSCFString
  ...
FINDING CONFIRMED (T2/Apple Silicon): received attestation dict without entitlement
```

On **pre-T2 Intel** (attestation hardware absent):
```
[UNGATED] copyAttestationDictionary -> code -1 (Invalid input(s))
[GATED  ] getActivationState        -> code -3 (Not supported on this device)

FINDING CONFIRMED (pre-T2 Intel): ungated method returned different error code
  ungated copyAttestationDictionary: code -1
  gated   getActivationState:        code -3
  Difference proves entitlement gate is absent for copyAttestationDictionary.
  Run on T2 or Apple Silicon for full attestation dict retrieval.
```

### What the PoC Does Internally

1. Opens an XPC connection to `com.apple.mobileactivationd` using `NSXPCConnection`.
2. Calls `copyAttestationDictionaryWithCompletionBlock:options:completion:` with attacker-controlled option keys (`OIDSToInclude`, `RKAttestationPublicKey`) -- no entitlement in the calling process.
3. In parallel, calls `getActivationState:completion:` as a gated control -- this has the same hardware availability requirement but adds an entitlement check.
4. Compares error codes. If `copyAttestationDictionary` succeeds (returns a dict): FINDING CONFIRMED. If it returns a different error code than the gated method: CONFIRMED (gate absent, hardware-capability check is the only obstacle).

## Expected Behavior

`copyAttestationDictionaryWithCompletionBlock:options:completion:` should return an entitlement error (equivalent to what an unprivileged call to `getActivationState` returns) when called by a process without `com.apple.mobileactivationd.spi`. The 13 other methods demonstrate this is the intended behavior.

## Actual Behavior

The method executes without any entitlement check. On capable hardware, it returns the device's full attestation dictionary to any caller. On pre-T2 Intel hardware, the method advances further into `create_baa_info_macos` than gated methods, proven by a distinct error code at a deeper failure point.

## Suggested Fix

1. Add `[self isEntitled:@"com.apple.mobileactivationd.spi"]` to the IMP of `copyAttestationDictionaryWithCompletionBlock:options:completion:`. The other 13 methods already have this -- the gate is a one-line addition.

2. Move the entitlement check to `listener:shouldAcceptNewConnection:` to eliminate the entire class of per-method missed-gate bugs. Reject connections from processes that do not hold the SPI entitlement.

3. Validate that `RKAttestationPublicKey` material corresponds to a SEP-bound key before incorporating it into the attestation output. Caller-supplied key material in a device identity attestation is a structural risk regardless of the entitlement gate.

## Affected Versions

- Confirmed: macOS 14+ (MobileActivation-834.140.3.701.1), Intel and Apple Silicon
- All Mac models where `mobileactivationd` is present
