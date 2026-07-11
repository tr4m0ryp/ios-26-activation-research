# Apple Security Bounty Submission

## Affected Platforms

iOS 26.3, iPadOS 26.3

## Affected Area

Authentication > Activation Lock

## Title

Multiple Sensitive Services Accessible on Activation-Locked iOS Device Without Authentication

## What Is Required to Reproduce This Issue

- An iPhone or iPad in the activation-locked state (Setup Assistant visible, showing the "Hello" / activation screen)
- A USB cable (USB-A to USB-C or USB-C to USB-C)
- A Mac or Linux computer with libimobiledevice installed
  - macOS: `brew install libimobiledevice`
  - Linux: `sudo apt install libimobiledevice-dev libplist-dev`
- Xcode Command Line Tools (macOS) or gcc/clang (Linux)
- No device pairing, no passcode, no Apple ID credentials are required

## Detailed Description

# Summary

An activation-locked iOS device exposes six security-sensitive USB services to any connected computer without pairing, passcode, or any authentication. The most impactful are: AFC (Apple File Conduit), which provides full read and write access to the device's photo library, books, and media databases; pcapd, which captures all WiFi network traffic; and diagnostics_relay, which can force the device to reboot on demand. This is accessible from any computer that plugs in a USB cable -- no trust dialog appears, no pairing is required.

The practical impact on a stolen device is immediate and severe: an attacker can exfiltrate the entire photo library (DCIM/, typically several gigabytes of personal photos and videos), capture any WiFi traffic the locked device generates, and prevent the owner from remotely erasing the device via Find My by loop-rebooting it. Additionally, AFC write access allows placing crafted files into directories that system daemons will process when the device is eventually recovered and unlocked.

This was confirmed on iPhone 15 Pro (iPhone16,1) running iOS 26.3 (23D127) and independently on iPad Pro 11-inch 2nd gen (iPad8,10) running iPadOS 26.3.

# Steps to reproduce

1. Obtain a device in the activation-locked state (the activation lock screen / Setup Assistant is visible).
2. Connect the device to a Mac or Linux computer via USB.
3. Compile and run the enclosed proof-of-concept:
   ```
   cd submission/02-sensitive-services-locked-device
   make
   ./poc
   ```
4. Observe that six services start successfully with no authentication: com.apple.afc, com.apple.pcapd, com.apple.syslog_relay, com.apple.os_trace_relay, com.apple.mobile.notification_proxy, com.apple.mobile.diagnostics_relay.
5. Observe the AFC write confirmation: the PoC creates and deletes a test file on the device's media partition without any pairing or authentication.
6. Observe that control services (com.apple.afc2, com.apple.webinspector, com.apple.mobile.installation_proxy) are correctly blocked, confirming the test is valid.

# Expected results

Only com.apple.mobileactivationd should be reachable on an activation-locked, unpaired device. All six services tested should return an "Invalid Service" error. AFC in particular should require the device to be both activated and paired before allowing file system access. No service should start without a pairing trust decision.

# Actual results

All six services start immediately on an activation-locked, unpaired device:

- com.apple.afc: OPEN -- full read/write access to /var/mobile/Media/ confirmed (photos, books, downloads, music databases). Write access confirmed: test file created and deleted without authentication.
- com.apple.pcapd: OPEN -- WiFi packet capture ready.
- com.apple.syslog_relay: OPEN -- live system log streaming starts immediately.
- com.apple.os_trace_relay: OPEN -- OS trace streaming starts immediately.
- com.apple.mobile.notification_proxy: OPEN -- notification dispatch accessible.
- com.apple.mobile.diagnostics_relay: OPEN -- device reboot/shutdown/sleep commands accepted without authentication.

The device shows no UI indication that any of these connections are active. The activation lock screen remains visible throughout.
