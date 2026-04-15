# AppleEffaceableStorageUserClient Uses Root Trust Check Instead of Entitlement

## Issue Description

The AppleEffaceableStorageUserClient IOKit service in the production iOS
kernel uses a "root trust state" check instead of a named entitlement for
access control. This is a weaker security gate than the entitlement-based
checks used by most other sensitive IOKit services.

The effaceable storage contains critical device keys including the device
encryption key (dkey). The service exposes methods for:
- `getLocker` / `setLocker` / `setLockerWithID` -- read/write key lockers
- `effaceLocker` -- destroy a key locker
- `getBytes` / `setBytes` -- raw byte access (kernel debug only)
- `generateNonce` -- nonce generation
- `getCapacity` / `isFormatted` / `lockerSpace` -- storage queries

Error strings in the kernel reveal the security model:
- "failed to determine root trust state" -- trust check fails open
- "getBytes is only allowed when kernel debug is enabled"
- "setBytes is only allowed when kernel debug is enabled"
- "wipe attempt from untrusted root" -- wipe blocked for untrusted
- "wipe effaceable dkey" -- confirms device key is stored here

The "root trust" check is weaker than entitlements because:
- Entitlements are signed into the binary and verified by AMFI
- Root trust state can potentially be spoofed via race conditions
  or confused deputy attacks
- Root trust doesn't distinguish between different root processes

## Affected Component

- Component: AppleEffaceableStorageUserClient
- Platform: iOS/iPadOS 26.0
- Device: All iOS devices

## Proof of Concept

```bash
strings kernelcache.macho | grep -i "effaceable"
# AppleEffaceableStorageUserClient
# getLocker, setLocker, effaceLocker
# wipe effaceable dkey
# D-key effaceable locker does not exist

strings kernelcache.macho | grep "root trust"
# failed to determine root trust state
```

## Impact

- If root trust check is bypassed, device encryption keys (dkey) in
  lockers become readable
- Nonce generation capability
- Device wipe capability (denial of service)
- Locker modification could corrupt encryption state

## Environment

- Kernel: xnu-12377.2.8 RELEASE_ARM64_T8020

## Suggested Remediation

1. Replace root trust check with explicit named entitlement.
2. Ensure the "failed to determine root trust state" path fails
   CLOSED (deny access) instead of potentially open.
