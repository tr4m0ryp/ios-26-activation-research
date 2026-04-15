# SkipNonceCheck Option in Production mobileactivationd

## Issue Description

The mobileactivationd service on iOS 26.3 accepts a `SkipNonceCheck`
option in the `CreateActivationInfoRequest` command's Options dictionary.
When set to `True` alongside `FactoryActivation: True`, the service
returns full device activation information (ActivationInfoXML,
FairPlayCertChain, FairPlaySignature, ActivationInfoComplete) without
requiring a DRM handshake session.

This bypasses the FairPlay nonce requirement, which is the primary
cryptographic freshness guarantee for activation. The option is intended
for factory provisioning and should not be present in production firmware.

## Affected Component

- Component: mobileactivationd (CreateActivationInfoRequest command)
- Platform: iOS/iPadOS 26.3 (build 23D127)
- Device: iPad8,10 (A12Z Bionic), likely all iOS devices

## Proof of Concept

```python
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.mobile_activation import MobileActivationService

l = await create_using_usbmux()
ma = MobileActivationService(l)

# Send CreateActivationInfoRequest with factory bypass options
result = await ma.send_command("CreateActivationInfoRequest",
    {'Options': {'SkipNonceCheck': True, 'FactoryActivation': True}})

# Returns: ActivationInfoXML (13KB), FairPlayCertChain, FairPlaySignature
# WITHOUT requiring a DRM session establishment
```

Tested on iPad8,10 running iPadOS 26.3 (23D127) over USB.

## Reproduction Steps

1. Connect any iOS device via USB and pair with pymobiledevice3
2. Send CreateActivationInfoRequest with Options dict containing
   SkipNonceCheck: True and FactoryActivation: True
3. The service returns full activation info without DRM session
4. Compare with normal flow which requires drmHandshake first

## Exploit Conditions

- Prerequisites: USB access, paired device
- Attack vector: Local USB
- User interaction: None

## Impact

- FairPlay DRM nonce requirement bypassed entirely
- Device attestation info obtainable without server handshake
- Enables offline generation of activation requests
- Removes freshness guarantee from the activation protocol

## Environment

- Device: iPad Pro 11-inch 3rd Gen (iPad8,10)
- OS: iPadOS 26.3 (23D127)
- Tools: pymobiledevice3 9.8.2

## Suggested Remediation

Remove the SkipNonceCheck and FactoryActivation options from production
mobileactivationd. Gate them behind hardware fuse checks if needed for
factory provisioning.
