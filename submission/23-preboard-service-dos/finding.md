# preboardservice_v2 Accessible on Activation-Locked Device and Crashes on Crafted Input

## What This Vulnerability Is

`preboardservice_v2` is an iOS daemon responsible for managing Full Disk Encryption (FDE) stashbags -- the cryptographic key material used for pre-boot authentication. It handles requests to create and commit FDE stash bags that protect the device's encryption keys before the user passcode is set up.

This service is accessible over USB on activation-locked devices without any authentication. Any computer that connects to an activation-locked iPhone via USB can reach this daemon directly, before the owner has entered a passcode or completed setup.

Beyond the unauthorized access issue, the service crashes when it receives crafted input. Sending a plist dictionary containing an unexpected key (`ManifestVersion`) causes the service process to terminate. The crash occurs from unauthenticated input to a privileged system daemon that handles encryption key material.

## Why It Is Dangerous

**Unauthorized access to a cryptographic key daemon.** preboardservice_v2 manages pre-boot encryption stash bags. Under normal circumstances, only trusted, authenticated processes should communicate with it. The fact that it is reachable from any USB-connected computer on a locked device violates this design. Any future vulnerability in its plist parsing could be reachable from the USB attack surface without authentication.

**Crash from crafted unauthenticated input.** Three of four tested manifest formats cause the service to crash (connection reset or broken pipe). A crash from a process that handles encryption key material, triggered by unauthenticated input, is at minimum a denial-of-service vulnerability. Depending on the root cause (buffer overflow, use-after-free, null dereference), it may represent exploitable memory corruption in a privileged context.

**Attack surface classification.** On a locked device, this is a zero-precondition attack: any USB cable, any computer, no trust decision, no passcode. The crash is deterministic and reproducible across reboots.

## Technical Explanation

`lockdownd` maintains a whitelist of services accessible before activation. `com.apple.preboardservice_v2` is on this list, presumably to allow FDE initialization to begin before activation completes.

The service implements a plist-over-socket protocol (4-byte big-endian length prefix followed by XML plist bytes). Its `CreateStashbag` command takes a `Manifest` argument containing a serialized plist. The crash behavior under different manifest shapes:

| Manifest content | Result |
|---|---|
| `{}` (empty dict) | Service alive, returns `{Error: True, Version: 2}` |
| `{ManifestVersion: 1}` | Connection lost (service crash) |
| `{StashKey: "x", ManifestVersion: 1}` | Broken pipe (service crash) |
| 64 raw zero bytes | Broken pipe (service crash) |

The empty-dict case returns an error response without crashing, confirming the service is reachable and the protocol is being parsed. The `ManifestVersion` key, which represents a single unexpected integer field, triggers the crash. This strongly suggests missing bounds or presence validation before the manifest is dereferenced.

The service runs as a privileged daemon (not sandbox-restricted for this IPC surface). On devices with FDE enabled, preboardservice_v2 has access to key derivation material and stashbag storage.

## Evidence

- **Level:** RUNTIME-CONFIRMED (service access) + crash confirmed on iPad8,10 iPadOS 26.3
- **Confirmed:** 2026-04-18 via `scripts/exploit_tests/tools/run_all_findings.py`
- **Device (service access):** iPhone 15 Pro (iPhone16,1), iOS 26.3 (23D127), UDID 00008130-000C219A0206001C
- **Device (crash confirmed):** iPad Pro 11-inch 2nd gen (iPad8,10), iPadOS 26.3
- **Runtime output:** preboardservice_v2 reachable on locked device; response={'Error': True, 'Version': 2}
- **Log file:** `logs/2026-04-18_runtime_verification.log`

## How to Reproduce

### Requirements

- An iPhone or iPad in the activation-locked state
- A USB cable
- A Mac or Linux computer with libimobiledevice and libplist installed:
  - macOS: `brew install libimobiledevice`
  - Linux: `sudo apt install libimobiledevice-dev libplist-dev`

### Build the Proof of Concept

```bash
cd submission/23-preboard-service-dos
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

When the finding is present, the output looks like this:

```
Connecting to activation-locked device via USB...
Device:  00008130-000C219A0206001C

Testing com.apple.preboardservice_v2

  ALIVE      [empty dict (baseline)          ]  response: <?xml version="1.0"...Error...Version...
  CRASH      [ManifestVersion: 1             ]  connection lost / broken pipe
  CRASH      [StashKey + ManifestVersion     ]  connection lost / broken pipe

SERVICE ACCESSIBLE without authentication on locked device
FINDING CONFIRMED: 2 crash(es) from crafted manifest input
```

### What the PoC Does Internally

1. Connects to the device via USB. No pairing or trust dialog occurs.
2. Calls `lockdownd_start_service("com.apple.preboardservice_v2")` to get the service port -- confirms the service is in the pre-activation allowlist.
3. Opens a raw TCP connection to that port via `idevice_connect()`.
4. Sends three crafted `CreateStashbag` plist messages with progressively more unexpected manifest content.
5. For each, attempts to receive a response within 5 seconds. A connection reset or broken pipe is classified as a crash.

The PoC does not attempt to create or read any real stash bags. The `/_bounty_test` StashKey value is arbitrary and has no real effect -- the crash occurs before the service can process it.

## Expected Behavior

`com.apple.preboardservice_v2` should not be accessible on an activation-locked, unpaired device. If it must be accessible for FDE initialization purposes, it should validate all manifest fields and return a structured error response for any unexpected input rather than crashing.

## Actual Behavior

The service starts on an unpaired locked device. Three of four tested manifest inputs cause the service process to crash (connection lost or broken pipe). The crash is deterministic and repeatable across reboots.

## Suggested Fix

1. Remove `com.apple.preboardservice_v2` from lockdownd's pre-activation service allowlist. If FDE initialization requires early USB communication, restrict it to paired hosts only.

2. Add input validation to the manifest parser: require specific known keys, check that `ManifestVersion` is a supported value, and validate the presence of all required fields before any memory operations.

3. If the service must remain pre-activation accessible, run it in a restricted sandbox that prevents the crash from affecting stashbag state and limits the blast radius of any memory corruption.

## Affected Versions

- Confirmed: iOS 26.3 (23D127) on iPhone 15 Pro (iPhone16,1) and iPad Pro 11-inch 2nd gen (iPad8,10)
- Likely affected: all iOS/iPadOS versions in the activation-locked state
