# AppleAVD Video Decoder Integer Overflow and OOB Write

## Issue Description

The AppleAVD (Apple Video Decoder) kernel extension contains 15+
separate integer overflow and out-of-bounds check strings, indicating
a large attack surface in video frame decoding. The `decryptFrame_CTRMode`
path takes user-controlled `initialClearBytes` and `dataLength` parameters
with potential signed/unsigned confusion leading to out-of-bounds writes.

User-to-kernel video data is submitted via
`AppleAVDUserClient::createAndSubmitDecodeCMD`, which has no entitlement
requirement to open.

Historical precedent: CVE-2022-32788 was an AppleAVD integer overflow
used in the NSO Pegasus exploit chain for zero-click kernel code execution.

## Affected Component

- Component: AppleAVD.kext (com.apple.driver.AppleAVD)
- Platform: iOS/iPadOS 26.0
- Device: All iOS devices with hardware video decoder

## Proof of Concept

```bash
strings kernelcache.macho | grep -iE "AppleAVD.*overflow\|AppleAVD.*bounds\|decryptFrame"
# Shows 15+ overflow/bounds check strings
# decryptFrame_CTRMode with initialClearBytes/dataLength parameters

strings kernelcache.macho | grep "AppleAVDUserClient"
# createAndSubmitDecodeCMD -- no entitlement required
```

## Impact

- Kernel heap corruption via crafted video decode commands
- No entitlement needed to access AppleAVDUserClient
- OOB write primitive from integer overflow in size calculations
- Reachable from any process that can submit video decode requests

## Environment

- Kernel: xnu-12377.2.8 RELEASE_ARM64_T8020

## Suggested Remediation

1. Add integer overflow checks with safe math to all size calculations
   in the video decode path.
2. Validate `initialClearBytes` and `dataLength` against buffer bounds
   before DMA operations.
3. Add entitlement gating to AppleAVDUserClient.
