# AppleBasebandPCIUserClient Exposes Physical Memory Read/Write to Userspace

## Issue Description

The iOS production kernel contains AppleBasebandPCIUserClient which
exposes `read(mach_vm_address_t, mach_vm_size_t)` and
`write(mach_vm_address_t, mach_vm_size_t)` methods that take raw
virtual addresses from userspace. These methods interact with DMA
hardware for baseband communication.

Three related UserClients are exposed:
- AppleBasebandPCIUserClient -- main read/write interface
- AppleBasebandPCIControlUserClient -- control plane
- AppleBasebandPCITraceUserClient -- tracing (softer entitlement gate)

The DMA address validation relies on DART callbacks
(DARTErrorHandlerCallback) rather than bounds checking at the UserClient
dispatch layer. If DART does not cover kernel virtual addresses that are
also physical-mapped, out-of-bounds DMA writes become possible.

Additionally, `_mapSharedMemory` / `_unmapSharedMemory` create shared
DMA memory regions between userspace and baseband hardware with
`sendImage(mach_vm_address_t, UInt32)` for firmware loading.

## Affected Component

- Component: AppleBasebandPCI kext (IOKit kernel extension)
- Platform: iOS/iPadOS 26.0 (kernel xnu-12377.2.8)
- Device: All iOS devices with cellular baseband

## Proof of Concept

```bash
strings kernelcache.macho | grep "AppleBasebandPCI"
# AppleBasebandPCIUserClient
# AppleBasebandPCIControlUserClient
# AppleBasebandPCITraceUserClient

strings kernelcache.macho | grep -E "mapSharedMemory|unmapSharedMemory|sendImage|DARTError"
# _mapSharedMemory
# _unmapSharedMemory
# sendImage
# DARTErrorHandlerCallback
```

## Reproduction Steps

1. Download any cellular-capable IPSW from ipsw.me
2. Extract and decompress the kernelcache
3. Run strings to find the UserClient classes and methods
4. Verify read/write methods take mach_vm_address_t from userspace
5. Verify DART error handling via callback (not inline rejection)

## Impact

- Userspace-to-kernel DMA with raw virtual addresses
- Potential kernel memory read/write via baseband DMA engine
- Shared memory regions between userspace and hardware
- Firmware image loading to baseband coprocessor
- If DART bypass is achievable: full kernel compromise

## Environment

- Kernel: xnu-12377.2.8 RELEASE_ARM64_T8020

## Suggested Remediation

1. Validate mach_vm_address_t arguments against safe ranges before DMA
2. Add inline bounds checking at the UserClient dispatch layer
3. Restrict AppleBasebandPCITraceUserClient to the same entitlement
   level as the main UserClient
