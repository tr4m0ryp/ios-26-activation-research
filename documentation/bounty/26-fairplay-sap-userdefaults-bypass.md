# FairPlay SAP Signature Verification Controlled by NSUserDefaults in Production

## Issue Description

Apple's MFAAuthentication.framework on the iOS production restore ramdisk
contains security-critical FairPlay SAP (Secure Association Protocol)
bypass controls exposed as NSUserDefaults keys:

- `MFAAUserDefaultsKey_BypassFairPlaySAPSignatureVerification` -- Completely
  bypasses the FairPlay SAP signature verification
- `MFAAUserDefaultsKey_DisableFairPlaySAP` -- Disables FairPlay SAP entirely
- `MFAAUserDefaultsKey_ForceFairPlaySAPFailure` -- Forces SAP to fail
- `MFAAUserDefaultsKey_BypassCertificateExpirationCheck` -- Bypasses cert
  expiry checking
- `MFAAUserDefaultsKey_FairPlaySAPServer` -- Overrides the FairPlay SAP
  server URL (enables MITM)

Additional accessory authentication bypasses:
- `ACCUserDefaultsKey_DisableCertVerification` -- Disables certificate
  verification for all accessory communication
- `ACCUserDefaultsKey_AllowMFi4DevCertsOnProdDevice` -- Allows development
  certificates on production devices
- `ACCUserDefaultsKey_ACCAuthProtocolPretendAuth` -- Pretends authentication
  succeeded

These are NSUserDefaults keys, meaning they can be set by writing to the
appropriate preferences plist file or via any process that can call
`NSUserDefaults setObject:forKey:` in the relevant domain.

## Affected Component

- Component: MFAAuthentication.framework
- Platform: iOS/iPadOS 26.0 (all ramdisks)
- Device: All iOS devices

## Proof of Concept

```bash
# 1. Find the bypass keys
strings /Volumes/ramdisk/System/Library/PrivateFrameworks/MFAAuthentication.framework/MFAAuthentication | grep "Bypass\|Disable.*FairPlay\|Force.*Failure"
# BypassFairPlaySAPSignatureVerification
# DisableFairPlaySAP
# ForceFairPlaySAPFailure
# BypassCertificateExpirationCheck
# DisableCertVerification

# 2. Verify they are UserDefaults keys
nm -g MFAAuthentication | grep "UserDefaultsKey_Bypass"
# _MFAAUserDefaultsKey_BypassFairPlaySAPSignatureVerification
# _MFAAUserDefaultsKey_BypassCertificateExpirationCheck
```

## Impact

- FairPlay SAP signature bypass via preferences
- Server URL override enables complete MITM of SAP protocol
- Certificate verification can be fully disabled
- Combined with filesystem access (during restore): write preferences
  plist to disable all FairPlay security
- Development certificates accepted on production hardware

## Environment

- IPSW: iPad_Pro_A12X_A12Z_26.0_23A341_Restore.ipsw

## Suggested Remediation

1. Remove all UserDefaults-controlled security bypass keys from
   production firmware.
2. Use compile-time flags or hardware fuse checks instead of
   runtime preferences for security controls.
3. Never allow server URL overrides for security-critical protocols.
