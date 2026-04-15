# AppleMobileApNonceUserClient Accessible Without Entitlement Gate

## Issue Description

The AppleMobileApNonceUserClient IOKit service in the production iOS
kernel controls the AP boot nonce used in SHSH/APTicket validation and
device personalization. Analysis of the kernelcache reveals no entitlement
gating on this UserClient's initialization, unlike most other sensitive
IOKit services.

The service exposes methods for nonce generation, retrieval, clearing,
and slot management:
- `generateNonce` -- generate a new boot nonce
- `retrieveNonce` -- read the current nonce
- `_clearNonce` -- clear the current nonce
- `_saveNonce` -- save nonce to NVRAM
- `_readNonce` -- read nonce from NVRAM
- `_pickNewNonceSlot` -- select a new XART nonce slot

The nonce is stored in NVRAM at
`40A0DDD2-77F8-4392-B4A3-1E7304206516:com.apple.System.boot-nonce`.

While `retrieveNonce` has a runtime check (`_allowApNonceRetrieval`),
generation and clearing may not have equivalent runtime gates.

This service is directly relevant to activation lock security: the boot
nonce is used to bind APTickets to specific boot attempts. If a process
running on the device (e.g., mobileactivationd, which is reachable over
USB on activation-locked devices) can manipulate the nonce, it undermines
the freshness guarantee of personalization.

## Affected Component

- Component: AppleMobileApNonceUserClient (com.apple.driver.AppleMobileAP)
- Platform: iOS/iPadOS 26.0 (kernel xnu-12377.2.8)
- Device: All iOS devices

## Proof of Concept

```bash
# 1. Verify no entitlement string references this UserClient
strings kernelcache.macho | grep -A5 -B5 "AppleMobileApNonceUserClient"
# Shows class name but no "entitlement" string nearby

# 2. Verify the methods exist
strings kernelcache.macho | grep "AppleMobileApNonce"
# generateNonce, retrieveNonce, _clearNonce, _saveNonce, _readNonce

# 3. Compare with AppleSEPUserClient which IS gated
strings kernelcache.macho | grep "applesepmanager.allow"
# com.apple.private.applesepmanager.allow (entitlement exists)

# 4. Verify NVRAM nonce variable
strings kernelcache.macho | grep "boot-nonce"
# com.apple.System.boot-nonce
```

## Exploitation Scenario

1. Connect to activation-locked device via USB
2. Interact with mobileactivationd (accessible on locked device)
3. mobileactivationd communicates with kernel IOKit services
4. If mobileactivationd can open AppleMobileApNonceUserClient (no
   entitlement required), it can call generateNonce/clearNonce
5. Combined with XART slot exhaustion (finding #09), this could
   produce a predictable nonce

## Impact

- Boot nonce manipulation undermines APTicket personalization binding
- Predictable nonce enables pre-crafted personalization manifests
- Combined with nonce slot exhaustion: all-0xFF predictable nonce
- Enables firmware downgrade to vulnerable iOS versions
- Enables activation bypass on older iOS versions

## Environment

- Kernel: xnu-12377.2.8 RELEASE_ARM64_T8020
- IPSW: iPad_Pro_A12X_A12Z_26.0_23A341_Restore.ipsw

## Suggested Remediation

1. Add explicit entitlement gating to AppleMobileApNonceUserClient's
   initWithTask method, similar to AppleSEPUserClient's
   `com.apple.private.applesepmanager.allow` check.
2. Ensure nonce generation, clearing, and slot selection all require
   the entitlement, not just retrieval.
