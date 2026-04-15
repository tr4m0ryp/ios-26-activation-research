# keystorectl Escrow Bag Manipulation and Test Keys in Production Firmware

## Issue Description

The `keystorectl` binary on iOS restore ramdisks exposes dangerous
keybag manipulation operations including escrow bag creation, passcode
recovery via escrow, SE nonce setting, and obliteration. These operations
are intended for factory provisioning but are compiled into production
firmware.

Critical capabilities:
- `create_escrow_bag` -- creates an escrow keybag for backup
- `aks_recover_with_escrow_bag` -- recovers (changes/removes) passcode
  using an escrow bag
- `do_se_set_nonce` -- sets the Secure Element nonce
- `aks_system_key_operation_obliterate` with confirmation string
  `obliterate-really-please`
- `allow tests keys` / `-t use test keys and verify beacon` -- test key
  infrastructure for bypassing production key requirements

Additionally, the binary references:
- Test infrastructure: `Test Apple Root CA - G3`,
  `crl-uat.corp.apple.com/testapplerootcag3.crl`
- Hardcoded SIK identifier: `~sik-00008110-001258A23A40011E-...`
- Predictable test files: `/tmp/testA`, `/tmp/testB`
- keybag state flags: `keybag_state_allow_test_keys`,
  `keybag_state_stash_unlocked`, `keybag_state_escrow_unwrap_required`

## Affected Component

- Component: keystorectl (/usr/local/bin/keystorectl)
- Platform: iOS/iPadOS 26.0 (restore ramdisk only)
- Device: All iOS devices

## Proof of Concept

```bash
# 1. Verify escrow bag operations
strings /Volumes/ramdisk/usr/local/bin/keystorectl | grep -i "escrow"
# create_escrow_bag
# load and unlock escrow bag
# aks_recover_with_escrow_bag

# 2. Verify test key infrastructure
strings /Volumes/ramdisk/usr/local/bin/keystorectl | grep -i "test"
# -t use test keys and verify beacon
# allow tests keys
# Test Apple Root CA - G3
# /tmp/testA
# /tmp/testB

# 3. Verify obliteration capability
strings /Volumes/ramdisk/usr/local/bin/keystorectl | grep -i "obliterate"
# aks_system_key_operation_obliterate
# obliterate-really-please

# 4. Verify SE nonce manipulation
strings /Volumes/ramdisk/usr/local/bin/keystorectl | grep -i "nonce"
# do_se_set_nonce
```

## Reproduction Steps

1. Download any IPSW and extract the restore ramdisk
2. Find keystorectl at /usr/local/bin/
3. Run strings to enumerate dangerous operations
4. Verify escrow bag, test key, and obliteration capabilities

## Exploit Conditions

- Prerequisites: Code execution on restore ramdisk or access to
  keystorectl during restore flow
- Attack vector: Local (during DFU restore)
- User interaction: None

## Impact

- Escrow bag recovery: Could change or remove device passcode
- Test keys: Could bypass production key requirements for keybag
  operations
- SE nonce setting: Could influence boot nonce for firmware downgrade
- Obliteration: Could destroy keying material (denial of service)
- Combined with restore flow option injection: if keystorectl can
  be invoked with test key flags during restore, keybag security
  is fundamentally compromised

## Environment

- IPSW: iPad_Pro_A12X_A12Z_26.0_23A341_Restore.ipsw
- Binary: /Volumes/ramdisk/usr/local/bin/keystorectl
- Tools: strings

## Suggested Remediation

1. Remove escrow bag creation and recovery operations from production
   firmware. These should only exist in factory provisioning builds.
2. Remove the test key infrastructure entirely from production builds.
3. Gate obliteration behind hardware fuse checks.
4. Remove hardcoded SIK identifiers and test file paths.
