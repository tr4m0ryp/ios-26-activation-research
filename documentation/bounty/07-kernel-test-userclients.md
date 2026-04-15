# Test IOKit UserClients Compiled into Production Kernel

## Issue Description

The iOS production kernelcache contains multiple test and debug IOKit
UserClient classes that should not be present in release builds:

- `AppleKeyStoreTestUserClient` -- Test interface for the keystore
  with no visible entitlement check string (unlike the production
  AppleKeyStoreUserClient which has 30+ entitlement gates)
- `CoreAnalyticsTestUserClient` -- Test analytics interface
- `IOTimeSyncClockTestUserClient` -- Test time synchronization
- `VictimUserClient` -- Named "Victim" (likely for exploit testing)
- `AppleSEPDebugService` -- SEP debug service that can send messages
  directly to the Secure Enclave
- `AppleSEPTestingService` -- SEP testing service

Test UserClients typically have reduced security checks compared to
their production counterparts. AppleKeyStoreTestUserClient is
particularly concerning as it may expose key management operations
without the 30+ entitlement checks that gate the production variant.

## Affected Component

- Component: XNU kernelcache (multiple IOKit kexts)
- Platform: iOS/iPadOS 26.0 (kernel xnu-12377.2.8)
- Device: All iOS devices

## Proof of Concept

```bash
strings kernelcache.macho | grep "TestUserClient"
# AppleKeyStoreTestUserClient
# CoreAnalyticsTestUserClient
# IOTimeSyncClockTestUserClient

strings kernelcache.macho | grep "VictimUserClient"
# VictimUserClient

strings kernelcache.macho | grep "SEPDebugService\|SEPTestingService"
# AppleSEPDebugService
# AppleSEPTestingService
```

## Reproduction Steps

1. Download any IPSW and extract/decompress the kernelcache
2. Run `strings` to find test UserClient class names
3. Verify these are compiled into the production RELEASE kernel

## Impact

- Test UserClients may lack entitlement checks present on production
- AppleKeyStoreTestUserClient could expose key operations
- AppleSEPDebugService sends messages directly to SEP
- VictimUserClient suggests deliberate exploit testing surface

## Environment

- Kernel: xnu-12377.2.8 RELEASE_ARM64_T8020

## Suggested Remediation

Remove all test UserClients from production kernel builds using
compile-time flags. These should only exist in DEVELOPMENT builds.
