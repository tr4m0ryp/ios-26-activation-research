# Predictable All-Ones Boot Nonce via SEP XART Slot Exhaustion (A12/A12X)

## Issue Description

The iOS kernel's AppleSEPManager kext contains a fail-open fallback in
`AppleSEPUserClient::getOrGenerateNonce()` that returns a deterministic
20-byte all-0xFF nonce when SEP XART nonce slots are exhausted, while
reporting `kIOReturnSuccess (0)` to the caller.

The XART nonce slot mechanism uses 4-bit slot IDs (maximum 16 slots).
When `_pickNewNonceSlot()` fails to find a free slot, the function logs
"GenerateNonce called without slot on Sandcat device, returning dummy
all-ones value" and writes `memset(nonce_buffer, 0xFF, 20)` before
returning success. The caller cannot distinguish this dummy nonce from
a genuine SEP-generated nonce.

This affects the Sandcat SEP generation, which corresponds to A12 and
A12X Bionic chips (e.g., iPhone XS, iPad Pro 3rd gen).

If an attacker can exhaust all 16 XART nonce slots, every subsequent
nonce request produces a predictable value. The SHA-384 hash of
`0xFF * 20` is pre-computable, potentially enabling pre-generated
APTickets and personalization manifests for boot policy manipulation.

## Affected Component

- Component: AppleSEPManager kext (`AppleSEPUserClient::getOrGenerateNonce`)
- Platform: iOS/iPadOS 26.0 (kernel xnu-12377.2.8, RELEASE_ARM64_T8020)
- Device: A12/A12X Bionic (Sandcat SEP generation)

## Proof of Concept

```bash
# 1. Decompress kernelcache from IPSW
img4tool -e kernelcache.im4p -o kernelcache.macho

# 2. Search for the vulnerability string
strings kernelcache.macho | grep "GenerateNonce called without slot"
# Output: "%s: GenerateNonce called without slot on Sandcat device, returning dummy all-ones value"

# 3. Verify slot ID is 4-bit (max 16 slots)
strings kernelcache.macho | grep "slot_id"
# Output: "assert: 0 == slot_id >> 4"

# 4. Find the slot exhaustion error
strings kernelcache.macho | grep "free nonce slot"
# Output: "Couldn't find a free nonce slot to use: %08x"

# 5. Verify external methods exist for nonce generation
strings kernelcache.macho | grep "DispatchUserClient.*Nonce"
# Output: DispatchUserClientGenerateNonceAndSlot
# Output: DispatchUserClientInvalidateNonce
```

The vulnerable function at VA 0xfffffff009665840 unconditionally calls
`memset(nonce_buffer, 0xFF, 20)` and returns `kIOReturnSuccess (0)`
when the slot allocation fails.

## Reproduction Steps

1. Download any IPSW for A12/A12X device from ipsw.me
2. Extract and decompress the kernelcache (LZFSE compressed)
3. Search for the string "GenerateNonce called without slot on Sandcat"
4. Disassemble the containing function with `otool -tV`
5. Verify the memset(buf, 0xFF, 20) + return 0 pattern
6. Verify the 4-bit slot ID constraint (assert: 0 == slot_id >> 4)
7. Note that AppleSEPUserClient has 40 external methods including
   DispatchUserClientGenerateNonceAndSlot

## Exploit Conditions

- Prerequisites: Code execution with `com.apple.private.applesepmanager.allow` entitlement
- Attack vector: Local (requires process with appropriate entitlement)
- User interaction: None (after initial code execution)

## Impact

- A process that can exhaust nonce slots makes all subsequent nonce
  requests return a predictable value (0xFF * 20)
- The SHA-384 hash of this predictable nonce is pre-computable
- This could enable pre-generated APTickets for boot policy manipulation
- Combined with other vulnerabilities, could enable unsigned firmware loading
- Affects all A12/A12X devices (Sandcat SEP generation)

## Environment

- IPSW: iPad_Pro_A12X_A12Z_26.0_23A341_Restore.ipsw
- Kernel: xnu-12377.2.8 RELEASE_ARM64_T8020
- Tools: strings, otool, img4tool

## Suggested Remediation

1. Remove the fail-open fallback entirely. When slot allocation fails,
   `getOrGenerateNonce` should return an error code, not success with
   a dummy value.
2. If a fallback is needed for internal testing on Sandcat devices,
   gate it behind a fuse check (production vs. development) rather
   than compiling it into production kernels.
3. Consider increasing the nonce slot count beyond 16 if slot exhaustion
   is a realistic concern.

## Attachments

- Kernelcache: iPad_Pro_A12X_A12Z_26.0_23A341_Restore.ipsw (decompressed to 59MB arm64e Mach-O)
- Disassembly of getOrGenerateNonce function at VA 0xfffffff009665840
