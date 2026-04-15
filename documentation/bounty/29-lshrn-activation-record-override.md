# LSHRNSupport setActivationRecordOverride -- Unguarded Activation Record Override

## Issue Description

CoreServices on the iOS ramdisk contains `+[LSHRNSupport setActivationRecordOverride:]`
which writes directly to an unguarded static global variable with NO entitlement
check. When set, this overrides the return value of `MAECopyActivationRecordWithError`
which is lazily loaded via `dlopen`/`dlsym` from MobileActivation.framework.

The function stores a BOOL flag at a fixed memory offset (`[x9, #0x8a0]`).
Value `-1` means "no override", value `1` means "override active". The
companion `setActivationRecordOverrideNil` resets to sentinel value `0xFFFFFFFFFFFFFFFE`.

Any process that loads CoreServices and can call this class method can
override the activation record check without authentication or entitlement.

## Affected Component

- Component: CoreServices (LSHRNSupport class)
- Platform: iOS/iPadOS 26.0 (restore ramdisk)
- Device: All iOS devices

## Proof of Concept

```bash
nm -g /Volumes/ramdisk/System/Library/Frameworks/CoreServices.framework/CoreServices | grep "LSHRNSupport"
# +[LSHRNSupport setActivationRecordOverride:]
# +[LSHRNSupport setActivationRecordOverrideNil]

strings CoreServices | grep "MAECopy"
# MAECopyActivationRecordWithError (loaded via dlsym)
```

## Impact

- Activation record override without entitlement check
- Any process loading CoreServices can set the override
- Combined with code execution in a CoreServices-loading daemon:
  complete activation record bypass
- The lazy dlopen/dlsym pattern means the override intercepts
  before the real MobileActivation check

## Suggested Remediation

1. Add entitlement check to setActivationRecordOverride
2. Remove the override mechanism from production firmware
3. Use a secure IPC pattern instead of a static global variable
