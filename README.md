# iOS 26 Activation Lock -- Documented Vulnerabilities

Documentation repository for **31 firmware-level vulnerabilities** identified in iOS 26.3 affecting the activation lock subsystem, prepared as Apple Security Bounty submission material and published for the security research community.

The repository is documentation-first: every finding has a self-contained writeup with vulnerability description, evidence, reproducer steps, and suggested patch direction. A working proof-of-concept for **VU#346053** (the unauthenticated `humb.apple.com/humbug/baa` BAA injection vector) is included as supporting material.

---

## Where to find the vulnerabilities

**Start here:** [`ranking_vulnb.md`](ranking_vulnb.md) -- all 31 findings ranked across 6 tiers from most critical to least critical, with severity, verification status, and one-line summaries.

**Per-finding writeups:** [`documentation/bounty/`](documentation/bounty/) -- 28 numbered Markdown files (`NN-<topic>.md`). Each is self-contained -- no need to read them in order.

### Headline (Tier 1 -- CRITICAL, kernel RCE / arbitrary memory access)

| # | Finding | Status |
|---|---------|--------|
| 21 | [IPv6 extension-header double-free in kernel](documentation/bounty/21-ipv6-double-free-kernel.md) -- network-reachable, no precondition | Confirmed |
| 22 | [AppleAVD video decoder integer overflow](documentation/bounty/22-appeavd-integer-overflow.md) -- matches CVE-2022-32788 (NSO Pegasus) | Confirmed |
| 27 | [PPL `pmap_cs_allow_invalid_internal` + OOP-JIT type confusion](documentation/bounty/27-ppl-oopjit-type-confusion.md) -- arm64e PPL bypass | Confirmed |
| 28 | [`AppleBasebandPCIUserClient` raw physical memory R/W](documentation/bounty/28-baseband-pci-physical-rw.md) | Confirmed |

See [`ranking_vulnb.md`](ranking_vulnb.md) for Tiers 2-6 (the remaining 27 findings).

---

## Repository layout

```
ranking_vulnb.md            -- ranked index of all 31 findings (start here)
documentation/bounty/       -- 28 per-finding writeups
scripts/captive_portal/     -- VU#346053 BAA injection PoC implementation
scripts/exploit_tests/      -- fuzzers and supporting test scripts
```

---

## Test environment

Findings reproduced on iPhone 15 Pro (iPhone16,1), iOS 26.3 (build 23D127), USB-paired and activation-locked. UDIDs, ECIDs, and host network addresses are redacted across the committed materials.

---

## References

- [VU#346053 -- iOS Activation Flaw (CERT/CC)](https://kb.cert.org/vuls/id/346053)
- [Original full disclosure (Jun 2025)](https://seclists.org/fulldisclosure/2025/Jun/27)
- [Apple Security Bounty program](https://security.apple.com/bounty/)

---

## Disclaimer

Authorized security research only (Apple Security Bounty program). Test devices owned by the researcher. Reproducing the PoC against devices you do not own is illegal in most jurisdictions.
