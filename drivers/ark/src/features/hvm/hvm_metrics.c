/* Bounded transition timing and invalidation/resource accounting. */
#include "hvm_metrics.h"
#include "hvm_internal.h"
#include "hvm_ept.h"
#if defined(_M_AMD64)
#include "hvm_svm.h"
#endif

/* Static storage outlives resident contexts and permits queries after stop. */
static KSWORD_ARK_HVM_METRICS_RESPONSE gHvmTiming;
/* Odd sequences identify a transition whose stamps are still being written. */
static volatile LONG gHvmTimingSequence;
/* These counters survive resource teardown and reset only at driver load. */
static volatile LONG64 gHvmInveptAttempts, gHvmInveptSucceeded, gHvmInveptFailed;
static volatile LONG64 gHvmRuleAllocations, gHvmRuleFrees;
static volatile LONG64 gHvmReplacementAllocations, gHvmReplacementFrees;

VOID kswordArkHvmMetricsBegin(ULONG command)
{
    /* The caller owns runtime control serialization before entering here. */
    KswHvmRuntime* runtime = kswordArkHvmGetRuntime();
    LARGE_INTEGER frequency;
    ULONG index;
    /* Mark the snapshot incomplete before changing any measured field. */
    (void)InterlockedIncrement(&gHvmTimingSequence);
    /* Keep allocator and invalidation counters separate from transition reset. */
    RtlZeroMemory(&gHvmTiming, sizeof(gHvmTiming));
    /* Capture the actual platform QPC frequency alongside its first reading. */
    gHvmTiming.commandBeginQpc = (ULONGLONG)KeQueryPerformanceCounter(&frequency).QuadPart;
    /* Store the frequency rather than assuming Hyper-V's usual 10 MHz clock. */
    gHvmTiming.qpcFrequency = (ULONGLONG)frequency.QuadPart;
    /* Preserve the exact control verb whose interval is being measured. */
    gHvmTiming.command = command;
    /* Clamp every reported processor to the protocol's fixed capacity. */
    gHvmTiming.processorCount = min(runtime->processorCount, KSWORD_ARK_HVM_MAX_PROCESSORS);
    /* Capture stable processor identities before entering the rendezvous. */
    for (index = 0UL; runtime->processors != NULL && index < gHvmTiming.processorCount; ++index) {
        /* Record the Windows processor group without assuming group zero. */
        gHvmTiming.processors[index].group = runtime->processors[index].row.processorGroup;
        /* Record the group-relative processor number used by the runtime. */
        gHvmTiming.processors[index].number = runtime->processors[index].row.processorNumber;
    }
}

VOID kswordArkHvmMetricsEnd(NTSTATUS status)
{
    /* Preserve failure intervals as well as successful transitions. */
    gHvmTiming.lastStatus = (ULONG)status;
    /* Finish the measured control body before advertising completeness. */
    gHvmTiming.commandEndQpc = (ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;
    /* Interlocked publication orders every earlier CPU stamp before readers. */
    (void)InterlockedIncrement(&gHvmTimingSequence);
}

VOID kswordArkHvmMetricsStamp(ULONG stage)
{
    /* Ignore automatic callbacks outside an instrumented control operation. */
    if ((InterlockedCompareExchange(&gHvmTimingSequence, 0L, 0L) & 1L) == 0L ||
        stage >= KSW_HVM_TIME_GLOBAL_STAGES) { return; }
    /* Keep the first interval boundary when a start needs a rollback rendezvous. */
    if ((gHvmTiming.globalValidMask & (1UL << stage)) != 0UL) { return; }
    /* Capture a single QPC reading at this exact boundary. */
    gHvmTiming.globalQpc[stage] = (ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;
    /* Publish its validity after its complete 64-bit value. */
    gHvmTiming.globalValidMask |= 1UL << stage;
}

VOID kswordArkHvmMetricsCpuStamp(ULONG index, ULONG stage)
{
    /* Every processor writes only its own fixed row during the rendezvous. */
    KSWORD_ARK_HVM_METRICS_CPU* cpu;
    /* Reject incomplete intervals and indices before touching their storage. */
    if ((InterlockedCompareExchange(&gHvmTimingSequence, 0L, 0L) & 1L) == 0L ||
        index >= gHvmTiming.processorCount || stage >= KSW_HVM_TIME_CPU_STAGES) { return; }
    /* Resolve this processor's preallocated timing row. */
    cpu = &gHvmTiming.processors[index];
    /* Do not overwrite failed-start evidence with the cleanup callback. */
    if ((cpu->validMask & (1UL << stage)) != 0UL) { return; }
    /* Capture the boundary without allocating or publishing event-ring records. */
    cpu->qpc[stage] = (ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;
    /* Publish availability after storing the timestamp. */
    cpu->validMask |= 1UL << stage;
}

VOID kswordArkHvmMetricsAllocation(BOOLEAN replacement, BOOLEAN free)
{
    /* Count each successful allocation or actual free exactly once. */
    volatile LONG64* counter = replacement
        ? (free ? &gHvmReplacementFrees : &gHvmReplacementAllocations)
        : (free ? &gHvmRuleFrees : &gHvmRuleAllocations);
    /* Pair ledger updates even on pre-publication failure cleanup. */
    (void)InterlockedIncrement64(counter);
}

NTSTATUS kswordArkHvmMetricsQuery(KSWORD_ARK_HVM_METRICS_RESPONSE* response)
{
    /* Snapshot boundaries describe the observation's own duration. */
    ULONGLONG begin;
    LONG before, after;
    LARGE_INTEGER frequency;
    /* Never copy a fixed response to a missing validated output buffer. */
    if (response == NULL) { return STATUS_INVALID_PARAMETER; }
    /* timestamp the beginning before reading any counters or transition data. */
    begin = (ULONGLONG)KeQueryPerformanceCounter(&frequency).QuadPart;
    /* Read the writer sequence before copying its state. */
    before = InterlockedCompareExchange(&gHvmTimingSequence, 0L, 0L);
    /* Copy fixed storage; the subsequent sequence check decides coherence. */
    RtlCopyMemory(response, &gHvmTiming, sizeof(*response));
    /* Re-read after the copy to detect an intervening transition. */
    after = InterlockedCompareExchange(&gHvmTimingSequence, 0L, 0L);
    /* Identify this independently versioned response. */
    response->version = KSWORD_ARK_HVM_METRICS_VERSION;
    /* Report the exact buffer contract used by the driver. */
    response->size = sizeof(*response);
    /* Queries before the first transition still carry the counter's units. */
    response->qpcFrequency = (ULONGLONG)frequency.QuadPart;
    /* A never-started or concurrently changing record is explicitly incomplete. */
    response->transitionCoherent = before != 0L && before == after && (after & 1L) == 0L;
    /* Allow callers to require the same measured transition across queries. */
    response->transitionSequence = (ULONG)after;
    /* Read independently atomic counters without claiming a simultaneous snapshot. */
    response->inveptAttempts = (ULONGLONG)InterlockedCompareExchange64(&gHvmInveptAttempts, 0LL, 0LL);
    /* Count instructions that actually returned success. */
    response->inveptSucceeded = (ULONGLONG)InterlockedCompareExchange64(&gHvmInveptSucceeded, 0LL, 0LL);
    /* Include failed instructions and exceptional returns. */
    response->inveptFailed = (ULONGLONG)InterlockedCompareExchange64(&gHvmInveptFailed, 0LL, 0LL);
    /* Export the rule-object allocation ledger independently of active slots. */
    response->ruleAllocations = (ULONGLONG)InterlockedCompareExchange64(&gHvmRuleAllocations, 0LL, 0LL);
    /* Export actual rule-object frees, including rejected preparations. */
    response->ruleFrees = (ULONGLONG)InterlockedCompareExchange64(&gHvmRuleFrees, 0LL, 0LL);
    /* Export actual successful replacement-page allocations. */
    response->replacementAllocations = (ULONGLONG)InterlockedCompareExchange64(&gHvmReplacementAllocations, 0LL, 0LL);
    /* Export actual replacement-page reclamation. */
    response->replacementFrees = (ULONGLONG)InterlockedCompareExchange64(&gHvmReplacementFrees, 0LL, 0LL);
    /* Prevent resource destruction while copying static per-CPU cache counters. */
    kswordArkAcquirePushLockShared(&kswordArkHvmGetRuntime()->lock);
    /* CPU writers still run, so this does not claim a simultaneous snapshot. */
    response->backend = kswordArkHvmGetRuntime()->backendId;
#if defined(_M_AMD64)
    /* AMD exit IDs are sparse 64-bit values and require their own snapshot. */
    if (response->backend == KSWORD_ARK_HVM_BACKEND_SVM) { kswordSvmMetrics(kswordArkHvmGetRuntime(), response); }
    /* Existing VMX telemetry retains its original decoder. */
    else
#endif
    { kswordArkHvmResidentMetrics(response); }
    /* Release before returning to user mode. */
    kswordArkReleasePushLockShared(&kswordArkHvmGetRuntime()->lock);
    /* Preserve the first timestamp and close the snapshot's observation interval. */
    response->snapshotBeginQpc = begin;
    /* Capture the final timestamp after every independently sampled value. */
    response->snapshotEndQpc = (ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;
    /* Incoherent timing remains a successful query with explicit validity. */
    return STATUS_SUCCESS;
}

#if defined(_M_AMD64)
/* The assembly leaf alone executes INVEPT; every caller uses this wrapper. */
extern UCHAR KswordARKHvmAsmInveptSingleRaw(ULONGLONG eptPointer);

UCHAR kswordArkHvmAsmInveptSingle(ULONGLONG eptPointer)
{
    /* An exception is a failed attempt even if no VM-instruction code returns. */
    UCHAR result = 0xFFU;
    /* Count attempts before entering the instruction, including exceptions. */
    (void)InterlockedIncrement64(&gHvmInveptAttempts);
    /* Preserve the original caller's exception handling and return contract. */
    __try {
        /* Execute precisely one single-context INVEPT. */
        result = KswordARKHvmAsmInveptSingleRaw(eptPointer);
    } __finally {
        /* Finalize accounting on both regular and abnormal instruction returns. */
        (void)InterlockedIncrement64(result == 0U ? &gHvmInveptSucceeded : &gHvmInveptFailed);
    }
    /* Forward the architecture's success/failure result unchanged. */
    return result;
}
#endif
