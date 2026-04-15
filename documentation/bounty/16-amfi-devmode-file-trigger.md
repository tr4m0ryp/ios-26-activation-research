# AMFI Developer Mode Trigger via World-Writable Directory

## Issue Description

Apple Mobile File Integrity (AMFI) checks for the existence of the file
`/private/var/tmp/show_dev_mode` to determine whether developer mode
services should be loaded. The directory `/private/var/tmp/` is
world-writable (`drwxrwxrwt`) on both restore and update ramdisks.

If any process with filesystem write access can create this file, AMFI
will load developer mode daemons from
`/System/Library/DeveloperModeLaunchDaemons/`. This includes debug
services that have reduced security restrictions.

Additionally, AMFI exports these functions for mode manipulation:
- `AMFIDemoModeSetState` -- set demo mode
- `AMFIMDMModeEnroll` / `AMFIMDMModeRemove` -- MDM enrollment
- `AMFISupervisedModeSetState` -- supervised mode toggle
- `AMFIProfileSetTeamIDTrustWithOptions` -- trust arbitrary team IDs
- `initiateDeveloperModeDaemons` -- start developer mode daemons

## Affected Component

- Component: AMFI (AppleMobileFileIntegrity)
- Path: /private/var/tmp/show_dev_mode
- Platform: iOS/iPadOS 26.0 (restore and update ramdisks)
- Device: All iOS devices

## Proof of Concept

```bash
# 1. Verify the directory is world-writable on ramdisk
ls -la /Volumes/ramdisk/private/var/tmp/
# drwxrwxrwt

# 2. Verify AMFI checks for the file
strings /Volumes/ramdisk/usr/lib/libAMFI.dylib | grep "show_dev_mode"
# /private/var/tmp/show_dev_mode

# 3. Verify dev mode daemon loading
strings /Volumes/ramdisk/usr/lib/libAMFI.dylib | grep "DeveloperMode"
# initiateDeveloperModeDaemons
# /System/Library/DeveloperModeLaunchDaemons/
```

## Reproduction Steps

1. Download any IPSW and extract the restore ramdisk
2. Verify `/private/var/tmp/` has `drwxrwxrwt` permissions
3. Run strings on the AMFI library to confirm the file check
4. During a restore flow, any process that can write to /private/var/tmp/
   can create the file to enable developer mode

## Exploit Conditions

- Prerequisites: Filesystem write access to /private/var/tmp/
- Attack vector: Local (during restore or via exploit)
- User interaction: None

## Impact

- Developer mode services load with reduced security restrictions
- Debug daemons become available for interaction
- Combined with other vulnerabilities (AFC file write, restore option
  injection), this could enable a chain to code execution

## Environment

- IPSW: iPad_Pro_A12X_A12Z_26.0_23A341_Restore.ipsw
- Tools: strings, ls

## Suggested Remediation

1. Do not use a world-writable directory for security-critical sentinel
   files. Use a directory with restricted permissions.
2. Gate developer mode on a hardware fuse check or SEP attestation,
   not a filesystem sentinel.
3. Remove the file-based trigger from production firmware entirely.
