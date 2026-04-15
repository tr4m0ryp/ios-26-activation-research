# PPL pmap_cs_allow_invalid_internal + OOP-JIT Type Confusion

## Issue Description

The Page Protection Layer (PPL) in the iOS production kernel contains
`pmap_cs_allow_invalid_internal` -- an internal function that explicitly
allows invalid code signatures. The OOP-JIT (Out-of-Process JIT) path
in PMAP_CS validates a uint32_t type field but handles invalid types
with an "Anomaly" log rather than a hard rejection, suggesting execution
continues.

Key evidence:
- `pmap_cs_allow_invalid_internal` -- allows invalid code signatures
- `PMAP_CS: Anomaly, invalid OOP-JIT type suuplied` -- soft error (note typo)
- `PMAP_CS: attempted to create an overlapping association with the JIT region`
- `pmap_ppl_unlockdown_page_locked` / `pmap_ppl_lockdown_page_with_prot` -- PPL pages can be unlocked
- `PMAP_CS: enabling developer mode incorrectly` -- soft log, not panic

## Affected Component

- Component: PPL / PMAP_CS (kernel Page Protection Layer)
- Platform: iOS/iPadOS 26.0
- Device: All arm64e iOS devices

## Impact

- PPL bypass enables modification of code-signed pages
- OOP-JIT type confusion may allow injecting unsigned code
- Combined with kernel r/w: complete code signing bypass
- Highest-impact kernel primitive on arm64e platform

## Environment

- Kernel: xnu-12377.2.8 RELEASE_ARM64_T8020

## Suggested Remediation

1. `pmap_cs_allow_invalid_internal` should panic or hard-fail on invalid types
2. OOP-JIT type validation should reject unknown types with kIOReturnError
3. `pmap_ppl_unlockdown_page_locked` should only be callable from PPL context
