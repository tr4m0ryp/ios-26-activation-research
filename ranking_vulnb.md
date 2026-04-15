# Vulnerability Ranking -- iCloud Activation Lock Research

All 31 findings ranked from most critical to least critical. Per-finding details: [`documentation/bounty/NN-*.md`](documentation/bounty/).

**Ranking factors** (in priority order):
1. **Severity** -- Apple's classification (CRITICAL > High > Medium-High > Medium > Low).
2. **Verification status** -- CONFIRMED > LIKELY BUG > GRAY AREA (needs hardware verification).
3. **Reachability** -- network / no-precondition bugs ranked above bugs requiring prior code execution.

| Tier | Severity | Bug count |
|------|----------|-----------|
| **1** | CRITICAL (kernel RCE / arbitrary memory access) | 4 |
| **2** | CRITICAL (activation / crypto bypass primitives) | 7 |
| **3** | CRITICAL (targeted bypasses) | 3 |
| **4** | High | 11 |
| **5** | Medium-High / Medium | 5 |
| **6** | Low | 1 |

27 confirmed, 2 likely, 2 gray area.

---

## Tier 1 -- CRITICAL (kernel RCE / arbitrary memory access)

Kernel-level memory corruption / arbitrary memory access. Network- or media-reachable, no prior code execution required.

| # | Finding | Status | Why critical | Doc |
|---|---------|--------|--------------|-----|
| 21 | IPv6 Extension Header Double-Free in Kernel | CONFIRMED | Network-reachable kernel heap corruption via crafted IPv6 (USB-Ethernet path). Four double-free paths + mbuf double-free. Matches CVE-2023-40404 / CVE-2024-27826 patterns. | [`21-ipv6-double-free-kernel.md`](documentation/bounty/21-ipv6-double-free-kernel.md) |
| 22 | AppleAVD Video Decoder Integer Overflow | CONFIRMED | Kernel UAF via crafted media (no precondition). Matches CVE-2022-32788 used in NSO Pegasus. `AppleAVDUserClient` has no entitlement gate. | [`22-appeavd-integer-overflow.md`](documentation/bounty/22-appeavd-integer-overflow.md) |
| 27 | PPL pmap_cs_allow_invalid_internal + OOP-JIT Type Confusion | CONFIRMED | PPL bypass on arm64e: invalid code signatures accepted, OOP-JIT type validation falls back to log-only "Anomaly", PPL pages can be unlocked. The chain killer for code-signing on Apple silicon. | [`27-ppl-oopjit-type-confusion.md`](documentation/bounty/27-ppl-oopjit-type-confusion.md) |
| 28 | AppleBasebandPCIUserClient Physical Memory R/W | CONFIRMED | `read(mach_vm_address_t)` / `write(...)` take raw user-supplied virtual addresses. DMA validated by DART callbacks, not the dispatch layer. Direct kernel R/W primitive. | [`28-baseband-pci-physical-rw.md`](documentation/bounty/28-baseband-pci-physical-rw.md) |

---

## Tier 2 -- CRITICAL (activation / crypto bypass primitives)

Activation-lock bypass primitives + crypto downgrade. The core of the project's research.

| # | Finding | Status | Why critical | Doc |
|---|---------|--------|--------------|-----|
| 15 | Session-Based Factory Cert Activation Nonce Bypass | CONFIRMED | `HandleActivationInfoWithSessionRequest` with the Apple iPhone Activation cert bypasses the activation nonce check entirely. The nonce IS the cryptographic activation barrier. | [`15-session-factory-nonce-bypass.md`](documentation/bounty/15-session-factory-nonce-bypass.md) |
| 29 | LSHRNSupport Activation Record Override Without Entitlement | CONFIRMED | `+[LSHRNSupport setActivationRecordOverride:]` writes an unguarded static global with no entitlement check. Override propagates through `MAECopyActivationRecordWithError`. | [`29-lshrn-activation-record-override.md`](documentation/bounty/29-lshrn-activation-record-override.md) |
| 09 | Predictable Nonce via SEP XART Slot Exhaustion (A12/A12X) | CONFIRMED | When 16 XART slots are exhausted, `AppleSEPUserClient::getOrGenerateNonce()` returns `memset(buf, 0xFF, 20)` + `kIOReturnSuccess`. Caller cannot distinguish dummy from real. | [`09-kernel-nonce-slot-exhaustion.md`](documentation/bounty/09-kernel-nonce-slot-exhaustion.md) |
| 18 | AppleMobileApNonceUserClient Without Entitlement Gate | CONFIRMED | No entitlement string references this UserClient anywhere in the kernel. Exposes `generateNonce`, `retrieveNonce`, `clearNonce`, `saveNonce` for the AP boot nonce. Combined with #09: full predictable nonce. | [`18-ap-nonce-userclient-no-entitlement.md`](documentation/bounty/18-ap-nonce-userclient-no-entitlement.md) |
| 20 | restored_update SEP/NVRAM/No-Sandbox Entitlement Bundle | CONFIRMED | Production restore binary holds: `applesepmanager.allow` (40 SEP methods), `system-nvram-allow`, `no-sandbox`, `gen-boot-nonce`, `bootpolicy`. Combined with #09 = predictable nonce + restore. | [`20-restored-update-sep-nvram-entitlements.md`](documentation/bounty/20-restored-update-sep-nvram-entitlements.md) |
| 24 | Permissive RSA Verification + SHA-1 + RSA-1024 in Activation | CONFIRMED | `_ccrsa_verify_pkcs1v15_allowshortsigs` (PKCS#1 v1.5 permissive), all activation certs use SHA-1, leaf is RSA-1024 (approaching factorability), expired since 2014 yet still accepted. CVE-2006-4339-class surface. | [`24-permissive-rsa-verification-sha1.md`](documentation/bounty/24-permissive-rsa-verification-sha1.md) |
| 25 | CoreTLS Master Secret Override and Peer Trust Bypass | CONFIRMED | `_tls_handshake_internal_set_master_secret_function`, `_tls_handshake_set_peer_trust`, `_tls_handshake_internal_master_secret` exported in production `libcoretls.dylib`. Combined with code execution = full TLS interception. | [`25-coretls-master-secret-override.md`](documentation/bounty/25-coretls-master-secret-override.md) |

---

## Tier 3 -- CRITICAL (targeted bypasses)

Critical-severity bypasses targeting specific subsystems.

| # | Finding | Status | Why critical | Doc |
|---|---------|--------|--------------|-----|
| 04 | SkipNonceCheck Option in CreateActivationInfoRequest | CONFIRMED | `Options: {SkipNonceCheck: True, FactoryActivation: True}` returns full activation info without DRM session. Bypasses the FairPlay nonce requirement entirely. | [`04-skipnoncecheck-option.md`](documentation/bounty/04-skipnoncecheck-option.md) |
| 10 | FDR Trust Object Fetched Over Plain HTTP | CONFIRMED | `http://gg.apple.com/fdrtrustobject` returns 2884 bytes over HTTP (not HTTPS). MITM replaces the trust anchor for *all* FDR SSL connections. | [`10-fdr-trust-object-http.md`](documentation/bounty/10-fdr-trust-object-http.md) |
| 26 | FairPlay SAP Bypass via NSUserDefaults in Production | CONFIRMED | `BypassFairPlaySAPSignatureVerification`, `DisableFairPlaySAP`, `FairPlaySAPServer` (URL override), `DisableCertVerification` -- all NSUserDefaults keys in production `MFAAuthentication.framework`. | [`26-fairplay-sap-userdefaults-bypass.md`](documentation/bounty/26-fairplay-sap-userdefaults-bypass.md) |

---

## Tier 4 -- High

High-severity enabling primitives, key material exposure, and configuration-level bypasses.

| # | Finding | Status | Summary | Doc |
|---|---------|--------|---------|-----|
| 19 | AppleEffaceableStorageUserClient Root Trust Only | CONFIRMED | Uses root-trust state check instead of an entitlement. Contains device encryption key (dkey) lockers + `generateNonce`. "failed to determine root trust state" suggests fail-open. | [`19-effaceable-storage-root-trust.md`](documentation/bounty/19-effaceable-storage-root-trust.md) |
| 31 | seputil ART Clear/Set and SEP Debug Variables in Production | CONFIRMED | `--art clear` removes anti-replay, `--art-set` sets arbitrary ART, `--set-var` writes SEP debug vars, `--new-nonce/kill-nonce`. All on production ramdisk. | [`31-seputil-art-nonce-debug.md`](documentation/bounty/31-seputil-art-nonce-debug.md) |
| 13 | Test Root CAs and Mix-N-Match God Mode in libimage4 | **GRAY AREA** | "img4 test secp256r1/secp384r1 Root CA1", "mix-n-match god mode", "allow-ecid-mismatch", "factory-prerelease-global-trust" strings in production `libimage4.dylib`. Need to verify if test roots are accepted. | [`13-libimage4-test-roots-mixnmatch.md`](documentation/bounty/13-libimage4-test-roots-mixnmatch.md) |
| 01 | FDR-LOCAL Private Keys in Firmware | CONFIRMED | RSA-2048 + EC P-256 private keys embedded in `libFDR.dylib`, identical across all IPSW ramdisks. | [`01-fdr-local-key-exposure.md`](documentation/bounty/01-fdr-local-key-exposure.md) |
| 05 | Factory Activation Path via AccountTokenXML | CONFIRMED | Using `AccountTokenXML` key triggers the factory cert validation path, bypassing the activation nonce check entirely. | [`bounty/`](documentation/bounty/) (no per-finding doc -- folded into #04 / #15) |
| 08 | Dummy All-Ones Nonce on Slot Exhaustion | **GRAY AREA** | Kernel string: "GenerateNonce called without slot on Sandcat device, returning dummy all-ones value". 16 XART slots, 4-bit ID. Predecessor finding to #09. | (folded into #09) |
| 11 | 20+ FDR Bypass Options in Production Firmware | CONFIRMED | `APTicketAllowUntrusted`, `SkipManifest`, `SkipVerifySik`, `CopyAllowUnsealed`, `AllowECIDMismatch`, +15 more. `AMFDRSetOption` enables in-process. `kAMFDROptionApTicketAllowUntrusted` returns success without verification. | [`11-fdr-bypass-options-production.md`](documentation/bounty/11-fdr-bypass-options-production.md) |
| 12 | AppleRestoreUtils Certificate Validation Skip | CONFIRMED | `AllowCertificateValidationFailed` + `FDRDisableSSLValidation` in production restore ramdisk. Also `setEntitlementOverrideConfig`, `setDummyWrappedFDRDataEncryptionKey`. | [`12-restore-utils-cert-validation-skip.md`](documentation/bounty/12-restore-utils-cert-validation-skip.md) |
| 14 | AMFI Local Signing Key Injection | CONFIRMED | `amfi_interface_set_local_signing_public_key`, `amfi_interface_get_local_signing_private_key`, "boot-args allow process with invalid signature" in production AMFI. | [`14-amfi-local-signing-injection.md`](documentation/bounty/14-amfi-local-signing-injection.md) |
| 17 | keystorectl Escrow Bag + Test Keys in Production | CONFIRMED | `create_escrow_bag`, `aks_recover_with_escrow_bag` (passcode recovery), `do_se_set_nonce`, hardcoded SIK, `obliterate-really-please`. | [`17-keystorectl-escrow-test-keys.md`](documentation/bounty/17-keystorectl-escrow-test-keys.md) |
| 30 | LocalAuthenticationCore bypassEntitlements Property | CONFIRMED | `bypassEntitlements` / `setBypassEntitlements:` on `LACDTOMutableKVStore`. Settable boolean skips per-request entitlement checks. `LACPolicyDoublePressBypass` + `FallbackToNoAuth`. | (no per-finding doc -- find in [`bounty/`](documentation/bounty/)) |

---

## Tier 5 -- Medium-High / Medium

Surface-area exposure, capability leaks, and triggers requiring additional access.

| # | Finding | Status | Summary | Doc |
|---|---------|--------|---------|-----|
| 16 | AMFI Developer Mode File Trigger in World-Writable Directory | CONFIRMED | `/private/var/tmp/show_dev_mode` triggers developer mode loading; directory is `drwxrwxrwt` on production ramdisks. `AMFIDemoModeSetState`, `AMFISupervisedModeSetState` exported. | [`16-amfi-devmode-file-trigger.md`](documentation/bounty/16-amfi-devmode-file-trigger.md) |
| 03 | libauthinstall Hactivation/Relaxed Verification APIs | CONFIRMED | `AMAuthInstallApEnableLocalPolicyHactivation`, `AMAuthInstallApEnableRelaxedImageVerification`, `AMAuthInstallAddTrustedSSLCACert` exported in production firmware. | [`03-authinstall-hactivation-api.md`](documentation/bounty/03-authinstall-hactivation-api.md) |
| 07 | Kernel Test UserClients in Production | CONFIRMED | `AppleKeyStoreTestUserClient`, `CoreAnalyticsTestUserClient`, `IOTimeSyncClockTestUserClient`, `VictimUserClient` compiled into production kernelcache. | [`07-kernel-test-userclients.md`](documentation/bounty/07-kernel-test-userclients.md) |
| 02 | Sensitive Services on Activation-Locked Device | **LIKELY** | `pcapd`, `diagnostics_relay` (reboot), AFC read/write, syslog all reachable on a locked device. | [`02-sensitive-services-locked-device.md`](documentation/bounty/02-sensitive-services-locked-device.md) |
| 06 | 23 Apple Certificates in Production Firmware | **LIKELY** | 23 certs extracted from `restored_update` including `[TEST] Apple iPhone Activation`, SEP Root CAs, Test CAs, FDR-CA1-ROOT-CM. | [`06-apple-certs-in-firmware.md`](documentation/bounty/06-apple-certs-in-firmware.md) |

---

## Tier 6 -- Low

| # | Finding | Status | Summary | Doc |
|---|---------|--------|---------|-----|
| 23 | Preboard Service Accessible on Locked Device (Skip Behavior) | **LIKELY** | `preboardservice_v2` reachable on locked device, always returns `{Skip: True, Version: 2}` for all manifest formats. | [`23-preboard-service-crash.md`](documentation/bounty/23-preboard-service-crash.md) |

---

## Notes

- **Findings #05 and #08** were folded into adjacent entries (#04 and #09 respectively) during writeup -- they don't have their own per-finding files. The numbering gap is intentional.
- **Finding #30** (`LocalAuthenticationCore bypassEntitlements`) does not have a dedicated per-finding doc in `documentation/bounty/` either; it's covered in the registry only.
- **GRAY AREA** entries (#08, #13) need additional verification (live device + hardware) before formal submission. They are listed in their tier but should be flagged in submission cover-letter.
