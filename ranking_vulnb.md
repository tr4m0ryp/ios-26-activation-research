# iCloud Activation Lock Research -- Findings and Reward Estimates

Research target: iCloud Activation Lock bypass / unauthorized sensitive-data access on iOS 26.3
and macOS 14+. Test device: iPhone 15 Pro (iPhone16,1, 23D127), personally owned and
intentionally locked. Responsible disclosure target: Apple Security Bounty Program.

Last updated: 2026-04-18 (cycle-001 autonomous-loop findings appended)

---

## Evidence Levels

| Level | Definition |
|-------|-----------|
| RUNTIME-CONFIRMED | Code path triggered on real device with direct observable evidence. Qualifies for submission. |
| COMPONENT | Code path triggered; chain blocked by a specific documented barrier. Not independently submittable. |

---

## Submittable Findings

All three are RUNTIME-CONFIRMED and have a complete submission package in `submission/`.
To submit: open `submit.md` in the relevant directory and paste into https://security.apple.com/bounty/.

| # | Finding | Platform | Apple Band | Reward Estimate | Submission |
|---|---------|----------|------------|-----------------|------------|
| 02 | Multiple Sensitive Services Accessible on Activation-Locked Device Without Authentication | iOS / iPadOS | Unauthorized access to sensitive data from lock-screen | **$100,000 -- $250,000** | [02-sensitive-services-locked-device](submission/02-sensitive-services-locked-device/) |
| 23 | preboardservice_v2 Accessible and Crashes on Crafted Input on Activation-Locked Device | iOS / iPadOS | Other bypass / non-kernel memory corruption | **$25,000 -- $100,000** | [23-preboard-service-dos](submission/23-preboard-service-dos/) |
| 40 | Missing Entitlement Gate on macOS mobileactivationd Allows Unprivileged BAA Attestation Dictionary Access | macOS 14+ | Unauthorized access to iCloud account / high-privilege service | **DEGRADED PENDING REWRITE** -- see cycle-001 | [40-mobileactivationd-ungated-xpc](submission/40-mobileactivationd-ungated-xpc/) |

**Submitted range (after cycle-001 degradation of #40): $125,000 -- $350,000**

### #40 cycle-001 correction

Cycle-001 (2026-04-18) static + runtime analysis shows the `copyAttestationDictionary` IMP contains `[self isEntitled:@"com.apple.mobileactivationd.spi"]` at 0x100019548 (arm64e) / 0x100015e43 (x86_64). The submission's original PoC returns `-1 "Invalid input(s)"` from an input-validation check that fires BEFORE the entitlement gate, not from reaching deeper ungated logic. The existing PoC also has two build defects (wrong `getActivationState:` selector; missing `dlopen` of MobileActivationMacOS framework). Before Apple submission, either (a) retract and supersede with the GATED_LATE finding (H1), or (b) re-run on T2/Apple Silicon with fixed PoC to determine actual runtime behavior when the pre-gate validation passes. See `scripts/apple_bb:loop/cycles/cycle-001/consolidated-results.md`.

---

## Chain Components (Not Independently Submittable)

These findings are RUNTIME-CONFIRMED in isolation but require additional steps to close into a
full activation-bypass chain. If the blocker is resolved, the combined chain qualifies for the
$500,000 -- $1,000,000 activation-lock bypass band.

| # | Finding | Evidence | Blocker | If Closed |
|---|---------|----------|---------|-----------|
| H1 | GATED_LATE pre-gate attack surface in MobileActivationMacOSDaemon (14 methods do 91-192 pre-gate instructions on caller input) | BINARY static (cycle-001) | Runtime primitive (crash, hang, info leak) not yet demonstrated | Could become a submittable primitive once a specific pre-gate defect is runtime-confirmed |
| H2 | com.apple.mobile.insecure_notification_proxy accessible pre-pair on iOS 26.3 activation-locked iPhone16,1 | COMPONENT (cycle-001) -- service starts without session, accepts Darwin ObserveNotification | Need to enumerate which specific notifications leak state or are post-able on a locked device | Extended finding of #02 band, $50K-$250K depending on information disclosure severity |
| 04 | SkipNonceCheck Option in CreateActivationInfoRequest | COMPONENT -- confirmed on iPad8,10; blocked on iPhone16,1 without SIM | Requires a SIM-capable device or Apple SRD to complete session establishment | Part of activation-bypass chain with #15 |
| 15 | Session-Based Factory Cert Activation Nonce Bypass | COMPONENT -- nonce check bypassed (error changes from "Invalid nonce" to "Failed to verify account token signature") | Apple factory HSM private key required for AccountTokenSignature | Closes the chain with #04 |
| 24 | Permissive RSA Verification + SHA-1 + RSA-1024 in Activation | COMPONENT -- factory cert path triggered by 256-byte stub sig | Same cert+sig barrier as #15 | Supporting evidence for #15 |
| 01 | FDR-LOCAL Private Keys in Production Firmware | COMPONENT -- RSA-2048 + EC P-256 keys extracted from libFDR.dylib | FDR-LOCAL cert rejected as AccountTokenCertificate on iOS 26.3 | Informational; stand-alone submission as key-material-in-firmware |

**If chain #04 + #15 is closed: $500,000 -- $1,000,000 (activation-lock bypass, full chain)**

---

## macOS Chain Component

| Chain | Components | Evidence | Blocker | Reward if Closed |
|-------|-----------|----------|---------|-----------------|
| chain-01: macOS activation-lock bypass via BAA QA cert substitution | #40 (DEGRADED -- method IS gated per cycle-001) + BAAOverrideURL (COMPONENT) + UseQACertificates (COMPONENT) | All three components now COMPONENT-level; chain not viable without an unprivileged path into one of the 10 `mobileactivationd.spi`-entitled helper processes | QA BAA root private key AND an unprivileged -> entitled-helper IPC primitive | $500,000 -- $1,000,000 (requires new chain component first) |

---

## Reward Summary

| Scenario | Estimated Reward |
|---------|-----------------|
| Two currently-submittable findings (#02, #23) | $125,000 -- $350,000 |
| + #40 rewritten or verified on T2/Apple Silicon | + $25,000 -- $100,000 (if CONFIRMED on other hardware) |
| + H2 insecure_notification_proxy elevated to CONFIRMED extended finding | + $50,000 -- $250,000 |
| + iOS chain (#04 + #15) closed and submitted | + $500,000 -- $1,000,000 |
| + macOS chain-01 closed and submitted (requires new unprivileged-to-entitled primitive) | + $500,000 -- $1,000,000 |
| Maximum (all closures + submissions) | up to $2,000,000+ |

Payout bands are Apple's published 2024 figures. Actual awards are at Apple's discretion.
The iOS activation-bypass chain (#04 + #15) is the highest-priority target: one of the two
blockers (SIM requirement for #04) is a hardware constraint, not a cryptographic one.

---

## Next Steps

1. **Submit #02, #23** -- both are ready. Run `make zip` in each submission directory
   and attach to the Apple portal form using `submit.md` as the paste text. **#40 is on hold** pending cycle-001 correction (either rewrite or T2/Apple Silicon re-verification).

1a. **#40 remediation** -- cycle-001 found that `copyAttestationDictionary` IS gated on the current build. Before submitting:
   - Fix `poc.c` selector name `getActivationState:completion:` -> `getActivationState:withCompletionBlock:`
   - Add `dlopen("/System/Library/PrivateFrameworks/MobileActivationMacOS.framework/MobileActivationMacOS", RTLD_LAZY)` at the top of `main()`; without it the protocol is not visible on a fresh host.
   - Run on a T2 or Apple Silicon Mac. If the returned `NSError code` is `-7` ("Client is missing required entitlement"), the gate holds and the submission must be retracted or rewritten as the GATED_LATE finding (H1). If instead an attestation dictionary is returned without entitlement, the original claim holds and the submission is valid.
   - See `scripts/apple_bb:loop/cycles/cycle-001/consolidated-results.md` for full details.

2. **Test #04 on a SIM-capable device** -- finding is CONFIRMED on iPad8,10 but blocked on
   iPhone16,1 without SIM. A SIM-active device or Apple SRD would close this gap and allow
   the #04 + #15 chain submission at the $500K-$1M band.

3. **Investigate #01 as standalone** -- FDR-LOCAL private key material is extractable from
   production IPSW. This is submittable as a low-impact informational finding ($5K-$25K) with
   a simple `strings` / `openssl` PoC requiring no live device.

---

## Submission Checklist

For each finding in `submission/`:

- [ ] `make` -- builds without errors
- [ ] `./poc` -- prints FINDING CONFIRMED on the test device
- [ ] `make run` -- saves run output to `logs/`
- [ ] `make zip` -- produces zip for attachment
- [ ] `submit.md` -- paste into https://security.apple.com/bounty/
