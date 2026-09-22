#include "ark/ark_driver.h"

/*++

Module Name:

    bugcheck_shield.c

Abstract:

    PatchGuard-safe bugcheck buffer backend.

    Motivation and design boundaries
    --------------------------------
    Publicly circulated reverse-engineering of private-slot
    "Disable-PatchGuard" style samples shows the same recipe: enumerate
    ntoskrnl by signature, overwrite undocumented function-pointer slots
    and permanently wait on an unsignaled event so the intercepted
    bug-check path never completes. That approach fails Windows kernel
    integrity checks (HVCI, PatchGuard, WHQL) and leaves the kernel in a
    non-recoverable state. It is presented as an example of what not to
    ship in a signed driver.

    The Shield keeps the "extend the window before the machine leaves the
    bug-check screen" observation from those samples but implements it
    only through documented callbacks:

      * KeRegisterBugCheckCallback for the earliest phase.
      * KeRegisterBugCheckReasonCallback for KbCallbackSecondaryDumpData,
        KbCallbackDumpIo and KbCallbackAddPages.

    Every callback performs a bounded KeStallExecutionProcessor loop that
    respects a global remaining-budget accumulator. The Shield never
    writes to ntoskrnl code, private KPCR/KPRCB/KTHREAD offsets, CR0, CR4,
    CR8, MSRs, SSDT, IDT or GDT. It never waits on an unsignaled event.
    It always yields back to Windows so the normal dump path can run.

    DriverEntry only initializes synchronization state. Callbacks are
    installed only after an IOCTL with the KSHL confirmation token and
    UI-confirmed flag arrives. Driver unload drains any in-flight
    callback invocations before deregistering the records.

Environment:

    Kernel-mode Driver Framework

--*/

// x64 only: the driver as a whole is x64-only; the Shield reuses the same
// gate so a mistaken 32-bit build does not silently link against the wrong
// ULONG_PTR/pointer semantics used inside the timeline ring.
#if !defined(_WIN64)
#error The bugcheck Shield only supports x64 builds.
#endif

// KSHL is derived from the shared header. Redefining it locally would allow
// R0 and R3 to drift; instead we assert the token matches at compile time so
// any accidental change trips the build before anyone reaches a real machine.
C_ASSERT(KSWORD_ARK_BUGCHECK_SHIELD_CONFIRMATION_TOKEN == 0x4C48534BUL);

// Fixed component name shown by the kernel when logging callback failures.
static UCHAR gKswordArkBugcheckShieldComponent[] = "KswordBugcheckShield";

// State is fully static and lives in nonpaged BSS. The Shield never allocates
// at callback time; every field it touches on the crash path is a member of
// this structure.
typedef struct KswordArkBugcheckShieldState
{
    // ControlLock serializes IOCTL enable/disable transitions at
    // PASSIVE_LEVEL. It is never acquired by callback code, which can run at
    // HIGH_LEVEL on the crashing processor.
    FAST_MUTEX controlLock;
    // Enabled is set to 1 after all requested reason callbacks registered
    // successfully. Callbacks bail out cheaply when Enabled is 0.
    volatile LONG enabled;
    // Fired is set to 1 on the first callback observed after enable so R3
    // can distinguish "installed but never fired" from "actually invoked".
    volatile LONG fired;
    // FireCount tracks how many callback executions have completed. It is
    // decremented after each callback returns so unload can drain safely.
    volatile LONG fireCount;
    // Executions counts nesting per callback entry; used to prevent unload
    // from deregistering while another CPU is inside a Shield callback.
    volatile LONG executions;
    // TimelineNextIndex is monotonically incremented; entries beyond the
    // ring size are dropped to keep the response bounded.
    volatile LONG timelineNextIndex;
    // TimelineCommittedCount is the visible size for R3 snapshots.
    volatile LONG timelineCommittedCount;
    // RemainingBudgetMs is a global buffer budget shared across callbacks
    // so multiple stages cannot exceed TotalSeconds. It is set on enable
    // and drained by callbacks; it never goes negative.
    volatile LONG remainingBudgetMs;
    // Configured knobs mirror the last successful enable request; used for
    // both response serialization and callback stall duration.
    ULONG reasonMask;
    ULONG stageSeconds;
    ULONG totalSeconds;
    // Registration bookkeeping for KeDeregister* on disable/unload.
    KBUGCHECK_CALLBACK_RECORD classicRecord;
    KBUGCHECK_REASON_CALLBACK_RECORD secondaryRecord;
    KBUGCHECK_REASON_CALLBACK_RECORD dumpIoRecord;
    KBUGCHECK_REASON_CALLBACK_RECORD addPagesRecord;
    // The kernel keeps a pointer to the callback buffer; we hand it a
    // ULONG per callback record. The value itself is not used by Windows,
    // it only needs to remain valid until the record is deregistered.
    ULONG classicBuffer;
    ULONG reasonBuffer;
    BOOLEAN classicRegistered;
    BOOLEAN secondaryRegistered;
    BOOLEAN dumpIoRegistered;
    BOOLEAN addPagesRegistered;
    // Last kernel status reported to R3 for diagnostics.
    NTSTATUS lastStatus;
    // Timeline ring is fixed size; entries are visible only after they are
    // fully written and TimelineCommittedCount is bumped.
    KSWORD_ARK_BUGCHECK_SHIELD_TIMELINE_ENTRY
        timeline[KSWORD_ARK_BUGCHECK_SHIELD_TIMELINE_ENTRIES];
} KswordArkBugcheckShieldState;

// Single global state; the Shield is not per-device.
static KswordArkBugcheckShieldState gKswordArkBugcheckShield;

// Forward declarations for the four callback entry points.
static VOID
kswordArkBugcheckShieldClassicCallback(
    _In_ PVOID buffer,
    _In_ ULONG length
    );

static VOID
kswordArkBugcheckShieldReasonCallback(
    _In_ KBUGCHECK_CALLBACK_REASON reason,
    _In_ struct _KBUGCHECK_REASON_CALLBACK_RECORD* record,
    _In_ PVOID reasonSpecificData,
    _In_ ULONG reasonSpecificDataLength
    );

// KeQueryInterruptTime returns 100ns units. This helper converts a
// millisecond count to interrupt-time units so we can compare against a
// KeQueryInterruptTime baseline without integer overflow risk on the
// bug-check path.
static ULONGLONG
kswordArkBugcheckShieldMsToInterruptUnits(
    _In_ ULONG milliseconds
    )
{
    // 10 000 100ns ticks per millisecond; guard against overflow by taking
    // ULONGLONG on both operands even though ULONG * 10000 fits in 64-bit.
    return (ULONGLONG)milliseconds * 10000ULL;
}

// Compute how long this callback is allowed to stall. The per-stage cap is
// bounded by the global remaining budget; when the global budget is empty
// the callback returns immediately so downstream Windows work is not
// starved.
static ULONG
kswordArkBugcheckShieldClaimStallBudgetMs(
    _In_ ULONG stageSeconds
    )
{
    LONG desired;
    LONG remaining;
    LONG claim;
    LONG updated;

    // Convert stage seconds to milliseconds; the shared header caps the
    // value at KSWORD_ARK_BUGCHECK_SHIELD_STAGE_MAX_SECONDS so this cannot
    // wrap.
    desired = (LONG)(stageSeconds * 1000UL);
    for (;;) {
        // Read the current remaining budget. Loop until CAS succeeds so we
        // are correct even if multiple callbacks race on different CPUs.
        remaining = InterlockedCompareExchange(
            &gKswordArkBugcheckShield.remainingBudgetMs,
            0L,
            0L);
        if (remaining <= 0L) {
            // Global budget is exhausted; no further stall permitted.
            return 0UL;
        }
        claim = remaining < desired ? remaining : desired;
        // Publish the new remaining value only if nobody else changed it.
        updated = InterlockedCompareExchange(
            &gKswordArkBugcheckShield.remainingBudgetMs,
            remaining - claim,
            remaining);
        if (updated == remaining) {
            return (ULONG)claim;
        }
    }
}

// Stall the current processor for approximately the requested duration.
// The loop uses 50µs KeStallExecutionProcessor steps and re-checks elapsed
// time on every iteration so the stall never significantly overshoots.
static VOID
kswordArkBugcheckShieldStallMs(
    _In_ ULONG milliseconds
    )
{
    ULONGLONG deadline;
    ULONGLONG now;

    if (milliseconds == 0UL) {
        // Empty stall — fall through so the timeline still records the hit.
        return;
    }
    // KeQueryInterruptTime is callable at any IRQL and monotonic across
    // processors, which is the property we need on the crash path.
    now = KeQueryInterruptTime();
    deadline = now + kswordArkBugcheckShieldMsToInterruptUnits(milliseconds);
    while (now < deadline) {
        // 50µs per step keeps the loop responsive without spinning too
        // tightly on the memory subsystem.
        KeStallExecutionProcessor(50UL);
        now = KeQueryInterruptTime();
    }
}

// Publish a timeline entry describing the callback that just ran. Called
// after the stall completes so the recorded duration is accurate.
static VOID
kswordArkBugcheckShieldRecordTimeline(
    _In_ ULONG reason,
    _In_ ULONG stalledMilliseconds
    )
{
    LONG index;
    ULONG cpu;

    // Reserve the next ring slot; drop the entry when the ring is full so
    // the crash response never grows beyond its fixed layout.
    index = InterlockedIncrement(
        &gKswordArkBugcheckShield.timelineNextIndex) - 1L;
    if (index < 0L ||
        (ULONG)index >= KSWORD_ARK_BUGCHECK_SHIELD_TIMELINE_ENTRIES) {
        return;
    }
    // KeGetCurrentProcessorNumberEx is documented for any IRQL and returns
    // the processor that is actually running the callback.
    cpu = KeGetCurrentProcessorNumberEx(NULL);
    gKswordArkBugcheckShield.timeline[index].reason = reason;
    // Bug-check code is not exposed to reason callbacks; leave it 0 so
    // R3 renders it as "unknown".  We keep the field for wire-format
    // compatibility if a future kernel exposes the value.
    gKswordArkBugcheckShield.timeline[index].bugcheckCode = 0UL;
    gKswordArkBugcheckShield.timeline[index].cpu = cpu;
    gKswordArkBugcheckShield.timeline[index].stalledMilliseconds =
        stalledMilliseconds;
    // Publish the entry only after all fields are written so a reader
    // observing TimelineCommittedCount can trust every visible slot.
    KeMemoryBarrier();
    InterlockedIncrement(&gKswordArkBugcheckShield.timelineCommittedCount);
}

// Core buffer body shared by every callback entry point. Handles the
// enable check, stall budget, timeline recording and bookkeeping so the
// callback shims can stay a couple of lines each.
static VOID
kswordArkBugcheckShieldOnCallback(
    _In_ ULONG reason
    )
{
    ULONG stallMs;
    ULONG stageSeconds;

    // The Executions counter guards against unload deregistering the
    // record while a CPU is still inside this function.
    InterlockedIncrement(&gKswordArkBugcheckShield.executions);
    if (InterlockedCompareExchange(
            &gKswordArkBugcheckShield.enabled,
            0L,
            0L) == 0L) {
        // Disabled after registration; still record the reason so R3 can
        // see a callback fired but no buffer was applied.
        kswordArkBugcheckShieldRecordTimeline(reason, 0UL);
        InterlockedDecrement(&gKswordArkBugcheckShield.executions);
        return;
    }
    // Flag the first-ever invocation for R3 UI feedback. The order matters:
    // set Fired before consuming budget so a query racing the first hit
    // never sees "budget consumed, Fired = 0".
    InterlockedCompareExchange(&gKswordArkBugcheckShield.fired, 1L, 0L);
    InterlockedIncrement(&gKswordArkBugcheckShield.fireCount);
    // Snapshot StageSeconds locally; the field itself is written only
    // under ControlLock at PASSIVE_LEVEL so a plain read is safe here.
    stageSeconds = gKswordArkBugcheckShield.stageSeconds;
    stallMs = kswordArkBugcheckShieldClaimStallBudgetMs(stageSeconds);
    kswordArkBugcheckShieldStallMs(stallMs);
    kswordArkBugcheckShieldRecordTimeline(reason, stallMs);
    InterlockedDecrement(&gKswordArkBugcheckShield.executions);
}

// Classic BugCheck callback: fires early during bug-check processing on the
// crashing processor before dump generation.
static VOID
kswordArkBugcheckShieldClassicCallback(
    _In_ PVOID buffer,
    _In_ ULONG length
    )
{
    // The buffer is our own ULONG scratch and is not used to communicate
    // state back to Windows; acknowledge the parameters and drop into the
    // shared body.
    UNREFERENCED_PARAMETER(buffer);
    UNREFERENCED_PARAMETER(length);
    kswordArkBugcheckShieldOnCallback(
        KSWORD_ARK_BUGCHECK_SHIELD_REASON_CLASSIC);
}

// Reason callback: fires for SECONDARY_DUMP_DATA, DUMP_IO and ADD_PAGES.
// The Shield does not attempt to inject dump data or extra pages; we only
// stall for the buffer budget and return to let Windows continue.
static VOID
kswordArkBugcheckShieldReasonCallback(
    _In_ KBUGCHECK_CALLBACK_REASON reason,
    _In_ struct _KBUGCHECK_REASON_CALLBACK_RECORD* record,
    _In_ PVOID reasonSpecificData,
    _In_ ULONG reasonSpecificDataLength
    )
{
    ULONG reasonBit;

    UNREFERENCED_PARAMETER(record);
    UNREFERENCED_PARAMETER(reasonSpecificData);
    UNREFERENCED_PARAMETER(reasonSpecificDataLength);
    // Map the kernel reason enum to the shared bitmask so R3 sees a
    // single, wire-stable value even if Windows renumbers the enum.
    switch (reason) {
    case KbCallbackSecondaryDumpData:
        reasonBit = KSWORD_ARK_BUGCHECK_SHIELD_REASON_SECONDARY_DUMP_DATA;
        break;
    case KbCallbackDumpIo:
        reasonBit = KSWORD_ARK_BUGCHECK_SHIELD_REASON_DUMP_IO;
        break;
    case KbCallbackAddPages:
        reasonBit = KSWORD_ARK_BUGCHECK_SHIELD_REASON_ADD_PAGES;
        break;
    default:
        // The Shield only registers the three reasons above; any other
        // reason means the kernel invoked us for a callback we did not
        // subscribe to. Record and exit without stalling.
        reasonBit = 0UL;
        break;
    }
    if (reasonBit == 0UL) {
        // Skip the stall for reasons we did not request but still record
        // the invocation so anomalies are visible in the timeline.
        kswordArkBugcheckShieldRecordTimeline(0UL, 0UL);
        return;
    }
    kswordArkBugcheckShieldOnCallback(reasonBit);
}

// Assemble the current state bitmap for R3 responses. Runs at PASSIVE_LEVEL
// under ControlLock so registration state is a coherent snapshot.
static ULONG
kswordArkBugcheckShieldStateFlagsLocked(VOID)
{
    ULONG flags = 0UL;

    if (InterlockedCompareExchange(
            &gKswordArkBugcheckShield.enabled,
            0L,
            0L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_SHIELD_STATE_ACTIVE;
    }
    if (InterlockedCompareExchange(
            &gKswordArkBugcheckShield.fired,
            0L,
            0L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_SHIELD_STATE_FIRED;
    }
    if (gKswordArkBugcheckShield.classicRegistered) {
        flags |= KSWORD_ARK_BUGCHECK_SHIELD_STATE_CLASSIC_REGISTERED;
    }
    if (gKswordArkBugcheckShield.secondaryRegistered) {
        flags |= KSWORD_ARK_BUGCHECK_SHIELD_STATE_SECONDARY_REGISTERED;
    }
    if (gKswordArkBugcheckShield.dumpIoRegistered) {
        flags |= KSWORD_ARK_BUGCHECK_SHIELD_STATE_DUMPIO_REGISTERED;
    }
    if (gKswordArkBugcheckShield.addPagesRegistered) {
        flags |= KSWORD_ARK_BUGCHECK_SHIELD_STATE_ADDPAGES_REGISTERED;
    }
    return flags;
}

// Deregister every previously registered callback record. Returns TRUE only
// when all records were successfully deregistered; a FALSE return means at
// least one callback was in flight and the caller must retry or refuse the
// disable so we do not free the record while Windows is calling us.
static BOOLEAN
kswordArkBugcheckShieldDeregisterAllLocked(VOID)
{
    BOOLEAN allDeregistered = TRUE;

    // Deregister the reason callbacks first so no additional executions
    // can enter after Enabled is dropped.
    if (gKswordArkBugcheckShield.addPagesRegistered) {
        if (KeDeregisterBugCheckReasonCallback(
                &gKswordArkBugcheckShield.addPagesRecord)) {
            gKswordArkBugcheckShield.addPagesRegistered = FALSE;
        }
        else {
            allDeregistered = FALSE;
        }
    }
    if (gKswordArkBugcheckShield.dumpIoRegistered) {
        if (KeDeregisterBugCheckReasonCallback(
                &gKswordArkBugcheckShield.dumpIoRecord)) {
            gKswordArkBugcheckShield.dumpIoRegistered = FALSE;
        }
        else {
            allDeregistered = FALSE;
        }
    }
    if (gKswordArkBugcheckShield.secondaryRegistered) {
        if (KeDeregisterBugCheckReasonCallback(
                &gKswordArkBugcheckShield.secondaryRecord)) {
            gKswordArkBugcheckShield.secondaryRegistered = FALSE;
        }
        else {
            allDeregistered = FALSE;
        }
    }
    if (gKswordArkBugcheckShield.classicRegistered) {
        if (KeDeregisterBugCheckCallback(
                &gKswordArkBugcheckShield.classicRecord)) {
            gKswordArkBugcheckShield.classicRegistered = FALSE;
        }
        else {
            allDeregistered = FALSE;
        }
    }
    return allDeregistered;
}

// Reset runtime accumulators back to their pre-enable defaults. Only called
// after all callback records are deregistered.
static VOID
kswordArkBugcheckShieldResetRuntimeLocked(VOID)
{
    InterlockedExchange(&gKswordArkBugcheckShield.enabled, 0L);
    InterlockedExchange(&gKswordArkBugcheckShield.fired, 0L);
    InterlockedExchange(&gKswordArkBugcheckShield.fireCount, 0L);
    InterlockedExchange(&gKswordArkBugcheckShield.timelineNextIndex, 0L);
    InterlockedExchange(&gKswordArkBugcheckShield.timelineCommittedCount, 0L);
    InterlockedExchange(&gKswordArkBugcheckShield.remainingBudgetMs, 0L);
    gKswordArkBugcheckShield.reasonMask = 0UL;
    gKswordArkBugcheckShield.stageSeconds = 0UL;
    gKswordArkBugcheckShield.totalSeconds = 0UL;
    // Zero the timeline ring so a subsequent enable presents a clean slate.
    RtlZeroMemory(
        gKswordArkBugcheckShield.timeline,
        sizeof(gKswordArkBugcheckShield.timeline));
}

// Try to deregister every record and reset runtime state. Returns success
// only when both the deregister and the drain succeed.
static NTSTATUS
kswordArkBugcheckShieldDisableLocked(VOID)
{
    // Flip Enabled off before touching the records so any concurrent
    // callback observes the drop immediately and skips further stalls.
    InterlockedExchange(&gKswordArkBugcheckShield.enabled, 0L);
    if (!kswordArkBugcheckShieldDeregisterAllLocked()) {
        // Restore Enabled=1 if any record could not be dropped; the driver
        // has not actually disabled and must reflect that to R3.
        InterlockedExchange(&gKswordArkBugcheckShield.enabled, 1L);
        return STATUS_DEVICE_BUSY;
    }
    // The kernel deregister APIs synchronize with in-flight callbacks on
    // the current CPU; verify Executions is 0 before publishing success.
    if (InterlockedCompareExchange(
            &gKswordArkBugcheckShield.executions,
            0L,
            0L) != 0L) {
        return STATUS_DEVICE_BUSY;
    }
    kswordArkBugcheckShieldResetRuntimeLocked();
    return STATUS_SUCCESS;
}

// Register a single reason callback. The caller flips the matching
// registered flag in the state struct on success so the disable path
// knows which records to undo.
static NTSTATUS
kswordArkBugcheckShieldRegisterReasonLocked(
    _Inout_ PKBUGCHECK_REASON_CALLBACK_RECORD record,
    _In_ KBUGCHECK_CALLBACK_REASON reason
    )
{
    KeInitializeCallbackRecord(record);
    if (!KeRegisterBugCheckReasonCallback(
            record,
            kswordArkBugcheckShieldReasonCallback,
            reason,
            gKswordArkBugcheckShieldComponent)) {
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

// Register every requested reason atomically. If any registration fails we
// roll back the ones that already succeeded so the driver never presents a
// partial installation to Windows.
static NTSTATUS
kswordArkBugcheckShieldEnableLocked(
    _In_ ULONG reasonMask,
    _In_ ULONG stageSeconds,
    _In_ ULONG totalSeconds
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    // The enable path is only valid from a clean state. If a previous
    // enable is still active or draining we reject the request instead of
    // stacking registrations.
    if (InterlockedCompareExchange(
            &gKswordArkBugcheckShield.enabled,
            0L,
            0L) != 0L ||
        gKswordArkBugcheckShield.classicRegistered ||
        gKswordArkBugcheckShield.secondaryRegistered ||
        gKswordArkBugcheckShield.dumpIoRegistered ||
        gKswordArkBugcheckShield.addPagesRegistered) {
        return STATUS_ALREADY_REGISTERED;
    }
    // Wipe accumulators so a re-enable presents a fresh timeline.
    kswordArkBugcheckShieldResetRuntimeLocked();
    gKswordArkBugcheckShield.reasonMask = reasonMask;
    gKswordArkBugcheckShield.stageSeconds = stageSeconds;
    gKswordArkBugcheckShield.totalSeconds = totalSeconds;
    // Seed the global remaining budget for this enable so callbacks share
    // one bounded pool regardless of how many reasons were requested.
    InterlockedExchange(
        &gKswordArkBugcheckShield.remainingBudgetMs,
        (LONG)(totalSeconds * 1000UL));
    if ((reasonMask & KSWORD_ARK_BUGCHECK_SHIELD_REASON_CLASSIC) != 0UL) {
        // Classic callbacks use the legacy KeRegisterBugCheckCallback entry;
        // it is the earliest hook Windows offers to a driver during a bug
        // check and has been stable since Windows XP.
        KeInitializeCallbackRecord(&gKswordArkBugcheckShield.classicRecord);
        if (!KeRegisterBugCheckCallback(
                &gKswordArkBugcheckShield.classicRecord,
                kswordArkBugcheckShieldClassicCallback,
                &gKswordArkBugcheckShield.classicBuffer,
                sizeof(gKswordArkBugcheckShield.classicBuffer),
                gKswordArkBugcheckShieldComponent)) {
            status = STATUS_UNSUCCESSFUL;
            goto Rollback;
        }
        gKswordArkBugcheckShield.classicRegistered = TRUE;
    }
    if ((reasonMask &
            KSWORD_ARK_BUGCHECK_SHIELD_REASON_SECONDARY_DUMP_DATA) != 0UL) {
        status = kswordArkBugcheckShieldRegisterReasonLocked(
            &gKswordArkBugcheckShield.secondaryRecord,
            KbCallbackSecondaryDumpData);
        if (!NT_SUCCESS(status)) {
            goto Rollback;
        }
        gKswordArkBugcheckShield.secondaryRegistered = TRUE;
    }
    if ((reasonMask & KSWORD_ARK_BUGCHECK_SHIELD_REASON_DUMP_IO) != 0UL) {
        status = kswordArkBugcheckShieldRegisterReasonLocked(
            &gKswordArkBugcheckShield.dumpIoRecord,
            KbCallbackDumpIo);
        if (!NT_SUCCESS(status)) {
            goto Rollback;
        }
        gKswordArkBugcheckShield.dumpIoRegistered = TRUE;
    }
    if ((reasonMask & KSWORD_ARK_BUGCHECK_SHIELD_REASON_ADD_PAGES) != 0UL) {
        // KbCallbackAddPages is supported from Windows 8; a failure here is
        // still fatal to enable so R3 sees an explicit reject rather than
        // a silently degraded set of registrations.
        status = kswordArkBugcheckShieldRegisterReasonLocked(
            &gKswordArkBugcheckShield.addPagesRecord,
            KbCallbackAddPages);
        if (!NT_SUCCESS(status)) {
            goto Rollback;
        }
        gKswordArkBugcheckShield.addPagesRegistered = TRUE;
    }
    // Publish Enabled last so a callback that fires the moment the final
    // record was registered still observes a fully installed Shield.
    InterlockedExchange(&gKswordArkBugcheckShield.enabled, 1L);
    return STATUS_SUCCESS;

Rollback:
    // Roll back every record that did register; the drain path is safe to
    // reuse because we never set Enabled=1 on this attempt.
    (VOID)kswordArkBugcheckShieldDeregisterAllLocked();
    kswordArkBugcheckShieldResetRuntimeLocked();
    return status;
}

// Validate the fixed-length request. Returns TRUE only when every field is
// well formed for the current protocol version. The caller guarantees the
// pointer is non-null because WdfRequestRetrieveInputBuffer succeeded.
static BOOLEAN
kswordArkBugcheckShieldRequestValid(
    _In_ const KSWORD_ARK_BUGCHECK_SHIELD_REQUEST* request
    )
{
    if (request->size != sizeof(*request) ||
        request->version != KSWORD_ARK_BUGCHECK_SHIELD_PROTOCOL_VERSION) {
        return FALSE;
    }
    // Reserved fields exist so future versions can repurpose them; refuse
    // any non-zero value so a v1 driver never accidentally interprets v2
    // request extensions as valid data.
    if (request->reserved0 != 0UL || request->reserved1 != 0UL) {
        return FALSE;
    }
    // Only the confirmed flag is defined today; reject unknown bits.
    if ((request->flags & ~KSWORD_ARK_BUGCHECK_SHIELD_FLAG_UI_CONFIRMED) !=
            0UL) {
        return FALSE;
    }
    // Any of the three actions is acceptable.
    if (request->action != KSWORD_ARK_BUGCHECK_SHIELD_ACTION_QUERY &&
        request->action != KSWORD_ARK_BUGCHECK_SHIELD_ACTION_ENABLE &&
        request->action != KSWORD_ARK_BUGCHECK_SHIELD_ACTION_DISABLE) {
        return FALSE;
    }
    return TRUE;
}

// Fill the fixed-length response, including the currently visible slice of
// the timeline ring.
static VOID
kswordArkBugcheckShieldFillResponseLocked(
    _Out_ KSWORD_ARK_BUGCHECK_SHIELD_RESPONSE* response,
    _In_ ULONG protocolStatus
    )
{
    LONG committed;
    LONG index;

    // Zero the response first so failure paths never leak stale kernel
    // stack data back to R3.
    RtlZeroMemory(response, sizeof(*response));
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_BUGCHECK_SHIELD_PROTOCOL_VERSION;
    response->status = protocolStatus;
    response->stateFlags = kswordArkBugcheckShieldStateFlagsLocked();
    response->reasonMask = gKswordArkBugcheckShield.reasonMask;
    response->stageSeconds = gKswordArkBugcheckShield.stageSeconds;
    response->totalSeconds = gKswordArkBugcheckShield.totalSeconds;
    response->fireCount = (ULONG)InterlockedCompareExchange(
        &gKswordArkBugcheckShield.fireCount, 0L, 0L);
    committed = InterlockedCompareExchange(
        &gKswordArkBugcheckShield.timelineCommittedCount, 0L, 0L);
    if (committed < 0L) {
        committed = 0L;
    }
    if ((ULONG)committed > KSWORD_ARK_BUGCHECK_SHIELD_TIMELINE_ENTRIES) {
        committed = (LONG)KSWORD_ARK_BUGCHECK_SHIELD_TIMELINE_ENTRIES;
    }
    response->timelineCount = (ULONG)committed;
    response->lastStatus = (LONG)gKswordArkBugcheckShield.lastStatus;
    // Copy the committed prefix; the remainder was already zeroed above.
    for (index = 0; index < committed; ++index) {
        response->timeline[index] =
            gKswordArkBugcheckShield.timeline[index];
    }
}

// Public initialization entry called from DriverEntry. It only prepares the
// synchronization primitives; no callback is registered until an IOCTL
// arrives with an explicit enable request.
VOID
kswordArkBugcheckShieldInitialize(
    VOID
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    // Diagnostics disabled at compile time: nothing to do.
    return;
#else
    // Zero the state so a fresh driver load starts with an inactive Shield.
    RtlZeroMemory(
        &gKswordArkBugcheckShield,
        sizeof(gKswordArkBugcheckShield));
    ExInitializeFastMutex(&gKswordArkBugcheckShield.controlLock);
    gKswordArkBugcheckShield.lastStatus = STATUS_SUCCESS;
#endif
}

// Public uninitialize entry. Called from EvtDriverUnload after the control
// device becomes invisible to user space, so no additional IOCTLs can race.
VOID
kswordArkBugcheckShieldUninitialize(
    VOID
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    return;
#else
    NTSTATUS status;

    // ControlLock is the same one the IOCTL path uses; acquiring it here
    // guarantees the disable path serializes with any final query racing
    // driver unload from user space.
    ExAcquireFastMutex(&gKswordArkBugcheckShield.controlLock);
    status = kswordArkBugcheckShieldDisableLocked();
    gKswordArkBugcheckShield.lastStatus = status;
    ExReleaseFastMutex(&gKswordArkBugcheckShield.controlLock);
#endif
}

// IOCTL configure entry point registered in ioctl_registry.c. All input and
// output are fixed-length METHOD_BUFFERED packets, so buffer retrieval and
// bounds checks are trivial and never dereference user-mode pointers
// directly.
NTSTATUS
kswordArkBugcheckShieldIoctlConfigure(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    // Fail closed when the entire diagnostics stack is disabled.
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    if (BytesReturned != NULL) {
        *BytesReturned = 0U;
    }
    return STATUS_NOT_SUPPORTED;
#else
    KSWORD_ARK_BUGCHECK_SHIELD_REQUEST* input = NULL;
    KSWORD_ARK_BUGCHECK_SHIELD_RESPONSE* output = NULL;
    NTSTATUS status;
    ULONG protocolStatus = KSWORD_ARK_BUGCHECK_SHIELD_STATUS_INVALID_REQUEST;
    ULONG stageSeconds;
    ULONG totalSeconds;

    UNREFERENCED_PARAMETER(device);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    // Retrieve the fixed-length input buffer; the framework handles all
    // copy-in and access-mode checks for METHOD_BUFFERED.
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(*input),
        (PVOID*)&input,
        NULL);
    if (!NT_SUCCESS(status) || inputBufferLength < sizeof(*input)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }
    // Retrieve the fixed-length output buffer; refusing here keeps the
    // response layout stable and unambiguous for R3.
    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(*output),
        (PVOID*)&output,
        NULL);
    if (!NT_SUCCESS(status) || outputBufferLength < sizeof(*output)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    // Serialize the transition. All state mutation happens under this lock
    // so a concurrent query cannot observe a torn snapshot.
    ExAcquireFastMutex(&gKswordArkBugcheckShield.controlLock);
    if (!kswordArkBugcheckShieldRequestValid(input)) {
        // Bad header: fail closed and expose the last kernel status so R3
        // can render a precise reason.
        gKswordArkBugcheckShield.lastStatus = STATUS_INVALID_PARAMETER;
        protocolStatus = KSWORD_ARK_BUGCHECK_SHIELD_STATUS_INVALID_REQUEST;
    }
    else if (input->action == KSWORD_ARK_BUGCHECK_SHIELD_ACTION_QUERY) {
        // Query is idempotent and never touches the callback state.
        protocolStatus = InterlockedCompareExchange(
            &gKswordArkBugcheckShield.enabled,
            0L,
            0L) != 0L
            ? KSWORD_ARK_BUGCHECK_SHIELD_STATUS_ACTIVE
            : KSWORD_ARK_BUGCHECK_SHIELD_STATUS_INACTIVE;
    }
    else if (input->action == KSWORD_ARK_BUGCHECK_SHIELD_ACTION_DISABLE) {
        // Attempt to deregister every callback; the drain path may report
        // BUSY if a callback is still executing on another CPU.
        status = kswordArkBugcheckShieldDisableLocked();
        gKswordArkBugcheckShield.lastStatus = status;
        protocolStatus = NT_SUCCESS(status)
            ? KSWORD_ARK_BUGCHECK_SHIELD_STATUS_INACTIVE
            : KSWORD_ARK_BUGCHECK_SHIELD_STATUS_BUSY;
    }
    else if (input->action == KSWORD_ARK_BUGCHECK_SHIELD_ACTION_ENABLE) {
        if ((input->flags &
                KSWORD_ARK_BUGCHECK_SHIELD_FLAG_UI_CONFIRMED) == 0UL ||
            input->confirmationToken !=
                KSWORD_ARK_BUGCHECK_SHIELD_CONFIRMATION_TOKEN) {
            // Enable requires the explicit UI-side confirmation contract.
            gKswordArkBugcheckShield.lastStatus = STATUS_ACCESS_DENIED;
            protocolStatus =
                KSWORD_ARK_BUGCHECK_SHIELD_STATUS_CONFIRMATION_NEEDED;
        }
        else if ((input->reasonMask &
                    ~KSWORD_ARK_BUGCHECK_SHIELD_REASON_ALL) != 0UL ||
                 input->reasonMask == 0UL) {
            // Reason mask must select at least one supported reason and
            // must not include unknown bits.
            gKswordArkBugcheckShield.lastStatus = STATUS_INVALID_PARAMETER;
            protocolStatus =
                KSWORD_ARK_BUGCHECK_SHIELD_STATUS_INVALID_REQUEST;
        }
        else {
            // Apply defaults for zero values so R3 can send a minimal
            // request; then clamp both knobs to the shared caps.
            stageSeconds = input->stageSeconds == 0UL
                ? KSWORD_ARK_BUGCHECK_SHIELD_DEFAULT_STAGE_SECONDS
                : input->stageSeconds;
            totalSeconds = input->totalSeconds == 0UL
                ? KSWORD_ARK_BUGCHECK_SHIELD_DEFAULT_TOTAL_SECONDS
                : input->totalSeconds;
            if (stageSeconds >
                    KSWORD_ARK_BUGCHECK_SHIELD_STAGE_MAX_SECONDS) {
                stageSeconds =
                    KSWORD_ARK_BUGCHECK_SHIELD_STAGE_MAX_SECONDS;
            }
            if (totalSeconds >
                    KSWORD_ARK_BUGCHECK_SHIELD_TOTAL_MAX_SECONDS) {
                totalSeconds =
                    KSWORD_ARK_BUGCHECK_SHIELD_TOTAL_MAX_SECONDS;
            }
            // Enforce total >= stage so at least one full stage fits.
            if (stageSeconds > totalSeconds) {
                stageSeconds = totalSeconds;
            }
            status = kswordArkBugcheckShieldEnableLocked(
                input->reasonMask,
                stageSeconds,
                totalSeconds);
            gKswordArkBugcheckShield.lastStatus = status;
            if (status == STATUS_SUCCESS) {
                protocolStatus = KSWORD_ARK_BUGCHECK_SHIELD_STATUS_ACTIVE;
            }
            else if (status == STATUS_ALREADY_REGISTERED) {
                protocolStatus = KSWORD_ARK_BUGCHECK_SHIELD_STATUS_ACTIVE;
            }
            else if (status == STATUS_NOT_SUPPORTED) {
                protocolStatus =
                    KSWORD_ARK_BUGCHECK_SHIELD_STATUS_UNSUPPORTED;
            }
            else {
                protocolStatus =
                    KSWORD_ARK_BUGCHECK_SHIELD_STATUS_REGISTRATION_FAILED;
            }
        }
    }

    // Serialize the response snapshot under the same lock so state and
    // timeline agree with each other for this reply.
    kswordArkBugcheckShieldFillResponseLocked(output, protocolStatus);
    ExReleaseFastMutex(&gKswordArkBugcheckShield.controlLock);
    *bytesReturned = sizeof(*output);
    return STATUS_SUCCESS;
#endif
}
