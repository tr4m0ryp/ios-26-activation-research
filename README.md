# iOS 26 Activation Lock Research -- VU#346053 + Bounty Findings

> Apple Security Bounty research workspace for iOS 26.3 activation lock. **31 documented firmware vulnerabilities** + a working PoC for **VU#346053** (the unauthenticated `humb.apple.com/humbug/baa` BAA injection).

**For security researchers and Apple Security Bounty submitters.** This is a research workspace -- not a one-click bypass tool. The matching open-source tool lives in the companion repo: [tr4mpass](https://github.com/tr4m0ryp/tr4mpass).

---

## Headline findings

Full ranked index in [`ranking_vulnb.md`](ranking_vulnb.md). Top 6:

| # | Severity | Status | Finding |
|---|----------|--------|---------|
| 21 | CRITICAL | Confirmed | IPv6 extension-header double-free in kernel -- network-reachable, no precondition |
| 22 | CRITICAL | Confirmed | AppleAVD video decoder integer overflow -- matches NSO Pegasus pattern (CVE-2022-32788) |
| 27 | CRITICAL | Confirmed | PPL `pmap_cs_allow_invalid_internal` + OOP-JIT type confusion -- arm64e PPL bypass |
| 28 | CRITICAL | Confirmed | `AppleBasebandPCIUserClient` raw physical memory R/W from userspace |
| 04 | CRITICAL | Confirmed | `CreateActivationInfoRequest{SkipNonceCheck:True}` returns full activation info without DRM session |
| 15 | CRITICAL | Confirmed | Session-based factory cert activation nonce bypass via `HandleActivationInfoWithSessionRequest` |

**VU#346053 -- the primary vector:** Apple's `humb.apple.com/humbug/baa` accepts unsigned plist payloads with no authentication. A captive portal returns a forged `BAAResponse` -- working implementation in [`scripts/captive_portal/`](scripts/captive_portal/).

---

## Quick start

```bash
# Smoke-test the captive portal on localhost (no device, no sudo)
bash scripts/captive_portal/runners/test_local.sh

# VU#346053 BAA injection against a paired device
export MAC_IP=192.0.2.1                  # your Mac's LAN IP
sudo -E bash scripts/captive_portal/runners/run_baa_test.sh

# Full activation-bypass orchestrator
sudo -E bash scripts/captive_portal/runners/run_bypass.sh
```

Python deps: `pip install pymobiledevice3 mitmproxy`

---

## What's in here

```
ranking_vulnb.md            # 31 findings, ranked across 6 tiers
documentation/bounty/       # 28 per-finding writeups
scripts/captive_portal/     # VU#346053 implementation
  runners/                  # entry-point shell wrappers (test_local, run_baa_test, run_bypass, ...)
  lib/{http,network,usb}/   # backend services grouped by role
scripts/exploit_tests/      # bounty-finding fuzzers + captured outputs
```

---

## Reproducing

Per-vulnerability reproduction commands and the full directory walkthrough live in [`ranking_vulnb.md`](ranking_vulnb.md) and the bounty docs. The captive portal scripts use `MAC_IP` (and `GATEWAY` for `run_mitm.sh`) env vars -- no hardcoded IPs. Device UDID auto-detects via `pymobiledevice3` or `DEVICE_UDID` env var.

---

## Companion repo

[**tr4mpass**](https://github.com/tr4m0ryp/tr4mpass) -- the public open-source tool (C99). Two bypass paths: A5-A11 via checkm8, A12+ via session activation. This research repo extends that work with the iOS 26.3 firmware vulnerability inventory + VU#346053 PoC.

---

## References

- [VU#346053 -- iOS Activation Flaw (CERT/CC)](https://kb.cert.org/vuls/id/346053)
- [Original disclosure (Full Disclosure, Jun 2025)](https://seclists.org/fulldisclosure/2025/Jun/27)
- [Apple Security Bounty](https://security.apple.com/bounty/)
- Test device: iPhone 15 Pro (iPhone16,1), iOS 26.3 (build 23D127), USB-paired, activation-locked

---

## Disclaimer

Authorized security research only (Apple Security Bounty program). Test devices are owned by the researcher. The captive portal infrastructure runs on a controlled lab network -- deploying it against devices you don't own is illegal in most jurisdictions.
