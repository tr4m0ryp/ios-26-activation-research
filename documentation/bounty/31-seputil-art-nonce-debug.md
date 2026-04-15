# seputil ART Clear/Set and SEP Debug Variable Manipulation in Production

## Issue Description

The `seputil` binary on the iOS production restore ramdisk provides
complete command-line control over the Secure Enclave Processor's
Anti-Replay Token (ART) and nonce systems:

ART manipulation:
- `--art get` -- Dump current ART from SEP memory
- `--art clear` -- CLEAR the persisted ART entirely
- `--art-set <value>` -- Set an arbitrary ART value
- `--art ctrtest` -- Counter self-test

Nonce manipulation:
- `--get-nonce` -- Read current SEP/OS nonce
- `--new-nonce` -- Request new SEP/OS nonce
- `--new-rom-nonce` -- Request new ROM nonce
- `--slot <id>` -- Select nonce slot for SEP firmware loading
- `--commit-hash` / `--commit-hash-ap` -- Commit firmware hashes

SEP debug variables:
- `--set-var <app>:<name>:<value>` -- Set debug variables on SEP apps
- `--get-var <app>:<name>` -- Read debug variables
- `--list-var <app>` -- List all debug variables

The ART is the cryptographic mechanism preventing replay of old SEP
commands. Clearing or setting it to a known value could enable replay
of old activation records or SHSH blobs. The SEP debug variable setter
could modify activation-related behavior if appropriate variables exist.

## Affected Component

- Component: seputil (/usr/local/bin/seputil)
- Platform: iOS/iPadOS 26.0 (restore ramdisk)
- Device: All iOS devices with SEP

## Proof of Concept

```bash
strings /Volumes/ramdisk/usr/local/bin/seputil | grep "art"
# --art get, --art clear, --art-set, --art ctrtest

strings /Volumes/ramdisk/usr/local/bin/seputil | grep "nonce"
# --get-nonce, --new-nonce, --new-rom-nonce, kill-nonce

strings /Volumes/ramdisk/usr/local/bin/seputil | grep "set-var"
# --set-var <app>:<name>:<value>
```

## Impact

- ART clear: removes anti-replay protection, enables old command replay
- ART set: sets arbitrary anti-replay token value
- Nonce manipulation: combined with XART slot exhaustion for predictable nonce
- Debug variable setting: could modify SEP app behavior
- All accessible during DFU restore via restored_update (has SEP entitlements)

## Environment

- IPSW: iPad_Pro_A12X_A12Z_26.0_23A341_Restore.ipsw
- Binary: /Volumes/ramdisk/usr/local/bin/seputil

## Suggested Remediation

1. Remove ART clear/set from production firmware
2. Remove debug variable setter from production builds
3. Gate nonce manipulation behind hardware fuse checks
