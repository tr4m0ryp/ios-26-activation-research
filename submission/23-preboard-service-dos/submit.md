# Apple Security Bounty Submission

## Affected Platforms

iOS 26.3, iPadOS 26.3

## Affected Area

Authentication > Activation Lock

## Title

preboardservice_v2 Accessible and Crashes on Crafted Input on Activation-Locked iOS Device

## What Is Required to Reproduce This Issue

- An iPhone or iPad in the activation-locked state (Setup Assistant / "Hello" activation screen visible)
- A USB cable
- A Mac or Linux computer with libimobiledevice and libplist installed
  - macOS: `brew install libimobiledevice`
  - Linux: `sudo apt install libimobiledevice-dev libplist-dev`
- Xcode Command Line Tools (macOS) or gcc/clang (Linux)
- No device pairing, no passcode, no Apple ID credentials required

## Detailed Description

# Summary

The `com.apple.preboardservice_v2` service -- which manages Full Disk Encryption stashbag creation and commit operations -- is accessible over USB on activation-locked iOS devices without any authentication. Any computer connected via USB to an activation-locked device can communicate with this daemon directly.

Beyond the unauthorized access, the service crashes when it receives crafted plist input. Sending a manifest dictionary containing a `ManifestVersion` key causes the service process to terminate with a connection reset or broken pipe. The crash is deterministic and reproducible. Three of four tested manifest formats trigger the crash; only an empty dict returns a normal error response.

This represents: (1) unauthorized USB access to a privileged daemon that handles encryption key material, and (2) a denial-of-service vulnerability from unauthenticated input. Depending on the root cause of the crash (the unexpected key causing a null dereference, bounds violation, or type confusion in the manifest parser), it may also represent exploitable memory corruption.

Confirmed on iPhone 15 Pro (iPhone16,1) running iOS 26.3 (23D127) and iPad Pro 11-inch 2nd gen (iPad8,10) running iPadOS 26.3.

# Steps to reproduce

1. Obtain a device in the activation-locked state (activation lock screen is visible).
2. Connect the device to a Mac or Linux computer via USB.
3. Compile and run the enclosed proof-of-concept:
   ```
   cd submission/23-preboard-service-dos
   make
   ./poc
   ```
4. Observe that the service starts successfully with no authentication (`lockdownd_start_service` returns success for `com.apple.preboardservice_v2`).
5. Observe that the empty-dict baseline manifest receives a structured response (`{Error: True, Version: 2}`), confirming the service is alive and parsing.
6. Observe that a manifest containing `{ManifestVersion: 1}` causes the connection to terminate immediately (service crash).
7. Observe that a manifest containing `{StashKey: "test", ManifestVersion: 1}` also causes a crash.

# Expected results

`com.apple.preboardservice_v2` should return `InvalidService` on an unpaired, activation-locked device -- it should not be accessible without a paired trust relationship. If it must be accessible before activation, it should validate all input fields and return a structured error for unexpected manifest content rather than crashing.

# Actual results

The service starts successfully on an activation-locked, unpaired device. An empty manifest returns a normal error response. Three crafted manifests cause the service process to crash (connection reset / broken pipe):

- `{ManifestVersion: 1}` -- CRASH (connection lost)
- `{StashKey: "x", ManifestVersion: 1}` -- CRASH (broken pipe)
- 64 raw zero bytes -- CRASH (broken pipe)

The crash is deterministic and reproducible after each device reboot. The service is reachable from any USB-connected computer with no pairing or authentication.
