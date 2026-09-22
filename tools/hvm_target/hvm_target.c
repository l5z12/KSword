/*
 * hvm_target.exe: Observable target for R-1 handling and injection.
 *
 * The rationale is that "from the outside, success looks identical to nothing happening." Both handling and injection operate on a
 * On the guest physical page, selecting the wrong page (an address that will never be executed) results in the driver appearing
 * normal, entries in the table, and a count that remains zero. When using a ready-made process like Notepad as a target, it is
 * impossible to distinguish between 'no reaction' caused by the mechanism failing versus one caused by selecting the wrong page.
 *
 * So this program reveals the answer itself:
 *   1. Print the **guest linear address** where the main loop resides; the handler is pinned to that page;
 *   2. Print a dedicated target page address for injection: it is executable, gets executed on every
 *      heartbeat, and is all zeros except for the first few bytes. Injection requires a 'gap' to hold
 *      the shellcode and payload, whereas in real modules, that gap is section padding with
 *      uncontrolled position and length. Using a page of known blank space for the initial verification
 *      separates the concerns of 'is the shellcode encoding correct' and 'does this page have a gap'.
 *   3. Print the address of a marker variable and echo its value in every heartbeat. As long as the payload
 *      writes a number to this address, it becomes visible immediately outside—this is the only reliable
 *      evidence that "the payload is actually running," far stronger than "the process hasn't crashed";
 *   4. Emit a numbered heartbeat line every 200ms and flush to disk immediately.
 *
 * Thus, the various outcomes are distinguishable externally:
 *   Frozen: heartbeat stops at a specific sequence number while the process remains active and interception count continues to grow; after undoing, execution
 *          resumes from the next sequence number (not a restart), providing direct evidence that instructions have not retired and state remains unchanged.
 *   End: process disappeared.
 *   The injection marker value changes from 0 to the payload written, while the heartbeat continues to
 *          advance normally—the latter is equally critical: it proves the borrowed thread was returned intact.
 *   Not effective: heartbeat continues normally, marker remains 0, count is zero.
 *
 * Use static linking (/MT) to match other tools in the same directory: A fresh
 * Windows install lacks VC++ redistributables, causing dynamically linked EXEs to
 * fail silently in the guest with no output, which looks like a different bug.
 */

#include <windows.h>
#include <stdio.h>

/*
 * Observation point for injection effects.
 *
 * volatile: the payload is written by the hypervisor on a different execution stream. Without volatile, the
 * compiler has no way of knowing this and is free to optimize every read into the same cached value. In that
 * case, even if the payload executes, the heartbeat will always show 0, appearing exactly as if nothing happened.
 */
static volatile unsigned int gInjectionMarker = 0U;

/*
 * Heartbeat loop in a separate function with inlining disabled.
 *
 * Use its function address as the "page to be rejected for execution." While the address
 * can be obtained in main, the optimizer might move the loop elsewhere, causing the
 * printed address to differ from the actual executing page — another silent failure.
 */
#pragma optimize("", off)
static void __declspec(noinline) heartbeatLoop(void (*probe)(void))
{
    unsigned long long tick = 0ULL;

    for (;;) {
        /* Execute the target page on every tick to ensure the injection is triggered quickly after being installed. */
        probe();
        printf("tick %llu marker %08X\n", tick, gInjectionMarker);
        fflush(stdout);
        tick += 1ULL;
        Sleep(200);
    }
}
#pragma optimize("", on)

int main(void)
{
    /*
     * Target page: a full executable page with a 'ret' instruction at the start and zeros elsewhere.
     *
     * The all-zero portion is the gap reserved for injection. Real modules also have such gaps (section tail padding), but their
     * position and length depend on the linking result; the initial verification should not bet on this condition simultaneously.
     */
    unsigned char* probePage = (unsigned char*)VirtualAlloc(
        NULL,
        4096U,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (probePage == NULL) {
        printf("probe-page-alloc-failed %lu\n", GetLastError());
        fflush(stdout);
        return 1;
    }
    /* VirtualAlloc guarantees zeroing; here we only write the ret instruction. */
    probePage[0] = 0xC3U;

    /* Allow PowerShell inside the guest to capture these four values in a single run. */
    printf("pid %lu\n", GetCurrentProcessId());
    printf("loop 0x%016llX\n", (unsigned long long)(ULONG_PTR)&heartbeatLoop);
    printf("probe 0x%016llX\n", (unsigned long long)(ULONG_PTR)probePage);
    printf("marker 0x%016llX\n",
           (unsigned long long)(ULONG_PTR)&gInjectionMarker);
    fflush(stdout);
    heartbeatLoop((void (*)(void))probePage);
    /* The loop does not return; this line merely ensures the compiler sees a complete return path. */
    return 0;
}
