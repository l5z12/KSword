/*++

Module Name:

    process_protect_kernel.c

Abstract:

    Kernel protection layer for the process protection feature. Where the
    object-callback layer strips access on individual handle operations, this
    layer stamps EPROCESS.Protection (PP/PPL) on matching processes and keeps
    it stamped: it applies at process-create time so a restarted target is
    protected again, and a background scan restores the byte whenever something
    outside this driver clears it.

Environment:

    Kernel-mode Driver Framework

--*/

#include "process_protect_internal.h"

#include "ark/ark_process.h"
#include "../process/process_extended.h"

NTKERNELAPI
LONGLONG
NTAPI
PsGetProcessCreateTimeQuadPart(
    _In_ PEPROCESS process
    );

// A resolved decision on "what to apply to this process".
typedef struct KswordArkProcessProtectKernelDecision
{
    BOOLEAN matched;
    BOOLEAN selfHeal;
    UCHAR protection;
    ULONG ruleId;
    ULONG ruleIndex;
    ULONG hardenFlags;
} KswordArkProcessProtectKernelDecision;

static VOID
kswordArkProcessProtectResolveKernelDecision(
    _In_ KswordArkProcessProtectState* state,
    _In_ ULONG processId,
    _In_opt_z_ PCWSTR imagePath,
    _Out_ KswordArkProcessProtectKernelDecision* decisionOut
    )
/*++

Routine Description:

    Pick the first enabled rule that both matches the process and carries a
    non-zero kernelProtection. Matching reuses the object-callback layer's
    comparison helper so one rule cannot mean two different things across the
    two layers.

--*/
{
    ULONG ruleIndex = 0UL;

    RtlZeroMemory(decisionOut, sizeof(*decisionOut));

    kswordArkAcquirePushLockShared(&state->configLock);

    if ((state->globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_ENABLED) == 0UL ||
        (state->globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_KERNEL_PROTECTION) == 0UL) {
        kswordArkReleasePushLockShared(&state->configLock);
        return;
    }

    for (ruleIndex = 0UL; ruleIndex < state->ruleCount; ++ruleIndex) {
        const KSWORD_ARK_PROCESS_PROTECT_RULE* protectRule = &state->rules[ruleIndex];

        if ((protectRule->flags & KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_ENABLED) == 0UL ||
            protectRule->kernelProtection == 0UL) {
            continue;
        }
        if (!kswordArkProcessProtectIdentityMatchPublic(
                protectRule->targetKind,
                protectRule->targetProcessId,
                protectRule->targetImage,
                processId,
                imagePath)) {
            continue;
        }

        decisionOut->matched = TRUE;
        decisionOut->selfHeal =
            ((protectRule->flags & KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_SELF_HEAL) != 0UL) ? TRUE : FALSE;
        decisionOut->protection = (UCHAR)(protectRule->kernelProtection & 0xFFUL);
        decisionOut->ruleId = protectRule->ruleId;
        decisionOut->ruleIndex = ruleIndex;
        decisionOut->hardenFlags = protectRule->hardenFlags;
        break;
    }

    kswordArkReleasePushLockShared(&state->configLock);
}

static VOID
kswordArkProcessProtectTrackProcess(
    _In_ KswordArkProcessProtectState* state,
    _In_ ULONG processId,
    _In_ LONGLONG createTimeQuadPart,
    _In_ const KswordArkProcessProtectKernelDecision* decision
    )
/*++

Routine Description:

    Insert or refresh the tracking entry that the self-heal scan walks.
    Identity is (PID, creation time): PID alone is reusable, and re-stamping a
    recycled PID would put PP on an unrelated process.

--*/
{
    ULONG entryIndex = 0UL;
    BOOLEAN replaced = FALSE;

    kswordArkAcquirePushLockExclusive(&state->trackedLock);

    for (entryIndex = 0UL; entryIndex < state->trackedCount; ++entryIndex) {
        KswordArkProcessProtectTrackedEntry* entry = &state->tracked[entryIndex];
        if (entry->processId != processId) {
            continue;
        }
        entry->createTimeQuadPart = createTimeQuadPart;
        entry->ruleId = decision->ruleId;
        entry->ruleIndex = decision->ruleIndex;
        entry->expectedProtection = decision->protection;
        entry->hardenFlags = decision->hardenFlags;
        replaced = TRUE;
        break;
    }

    if (!replaced && state->trackedCount < KSWORD_ARK_PROCESS_PROTECT_MAX_TRACKED) {
        KswordArkProcessProtectTrackedEntry* entry = &state->tracked[state->trackedCount];
        RtlZeroMemory(entry, sizeof(*entry));
        entry->processId = processId;
        entry->createTimeQuadPart = createTimeQuadPart;
        entry->ruleId = decision->ruleId;
        entry->ruleIndex = decision->ruleIndex;
        entry->expectedProtection = decision->protection;
        entry->hardenFlags = decision->hardenFlags;
        state->trackedCount += 1UL;
        replaced = TRUE;
    }

    kswordArkReleasePushLockExclusive(&state->trackedLock);

    if (!replaced) {
        // The ledger is full: protection is already applied, but it is no longer included in self-healing inspections. It is better to explain this than to silently drop it.
        kswordArkProcessProtectLogFormat(
            state,
            "Warn",
            "Process protection tracking table full (%lu), pid=%lu keeps its protection but is not scanned.",
            (unsigned long)KSWORD_ARK_PROCESS_PROTECT_MAX_TRACKED,
            (unsigned long)processId);
    }
}

VOID
kswordArkProcessProtectKernelUntrackProcess(
    _In_ ULONG processId
    )
/*++

Routine Description:

    Drop a process from the self-heal table on exit. The scan would eventually
    notice too, but removing eagerly keeps the table from filling up with dead
    PIDs on machines that churn short-lived protected processes.

--*/
{
    KswordArkProcessProtectState* state = kswordArkProcessProtectGetState();
    ULONG entryIndex = 0UL;

    if (state == NULL || processId == 0UL) {
        return;
    }

    kswordArkAcquirePushLockExclusive(&state->trackedLock);
    for (entryIndex = 0UL; entryIndex < state->trackedCount; ++entryIndex) {
        if (state->tracked[entryIndex].processId != processId) {
            continue;
        }
        if (entryIndex + 1UL < state->trackedCount) {
            state->tracked[entryIndex] = state->tracked[state->trackedCount - 1UL];
        }
        state->trackedCount -= 1UL;
        RtlZeroMemory(&state->tracked[state->trackedCount], sizeof(state->tracked[0]));
        break;
    }
    kswordArkReleasePushLockExclusive(&state->trackedLock);
}

static VOID
kswordArkProcessProtectApplyHarden(
    _In_ KswordArkProcessProtectState* state,
    _In_ PEPROCESS processObject,
    _In_ ULONG processId,
    _In_ ULONG hardenFlags
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if ((hardenFlags & KSWORD_ARK_PROCESS_PROTECT_HARDEN_CLEAR_DEBUG_PORT) == 0UL) {
        return;
    }

    status = kswordArkProcessClearDebugPortByObject(processObject);
    if (NT_SUCCESS(status)) {
        (VOID)InterlockedIncrement64(&state->hardenApplyCount);
        return;
    }

    // Missing DebugPort offset indicates 'incomplete DynData on this machine', not a configuration error; log only once.
    kswordArkProcessProtectLogFormat(
        state,
        "Warn",
        "Process protection harden(clear debug port) failed, pid=%lu, status=0x%08lX.",
        (unsigned long)processId,
        (unsigned long)status);
}

static BOOLEAN
kswordArkProcessProtectStampProcess(
    _In_ KswordArkProcessProtectState* state,
    _In_ PEPROCESS processObject,
    _In_ ULONG processId,
    _In_ const KswordArkProcessProtectKernelDecision* decision
    )
/*++

Routine Description:

    Write the decided PS_PROTECTION byte onto the process and fold the outcome
    into the counters.

Return Value:

    TRUE when the byte was written and verified.

--*/
{
    const NTSTATUS kStatus = kswordArkDriverApplyProcessProtectionToObject(
        processObject,
        decision->protection);

    if (!NT_SUCCESS(kStatus)) {
        (VOID)InterlockedIncrement64(&state->kernelApplyFailureCount);
        (VOID)InterlockedExchange(&state->lastKernelApplyStatus, (LONG)kStatus);
        return FALSE;
    }

    (VOID)InterlockedIncrement64(&state->kernelApplyCount);
    if (decision->ruleIndex < KSWORD_ARK_PROCESS_PROTECT_MAX_RULES) {
        (VOID)InterlockedIncrement64(&state->ruleKernelApplyCounts[decision->ruleIndex]);
    }
    kswordArkProcessProtectApplyHarden(state, processObject, processId, decision->hardenFlags);
    return TRUE;
}

VOID
kswordArkProcessProtectKernelApplyToProcess(
    _In_ PEPROCESS processObject,
    _In_ ULONG processId,
    _In_opt_z_ PCWSTR imagePath
    )
{
    KswordArkProcessProtectState* state = kswordArkProcessProtectGetState();
    KswordArkProcessProtectKernelDecision decision;

    if (state == NULL || processObject == NULL || processId == 0UL) {
        return;
    }

    kswordArkProcessProtectResolveKernelDecision(state, processId, imagePath, &decision);
    if (!decision.matched) {
        return;
    }

    if (!kswordArkProcessProtectStampProcess(state, processObject, processId, &decision)) {
        return;
    }

    if (decision.selfHeal) {
        kswordArkProcessProtectTrackProcess(
            state,
            processId,
            PsGetProcessCreateTimeQuadPart(processObject),
            &decision);
    }

    kswordArkProcessProtectLogFormat(
        state,
        "Info",
        "Process protection applied, pid=%lu, protection=0x%02lX, ruleId=%lu, harden=0x%08lX.",
        (unsigned long)processId,
        (unsigned long)decision.protection,
        (unsigned long)decision.ruleId,
        (unsigned long)decision.hardenFlags);
}

VOID
kswordArkProcessProtectNotifyProcessCreate(
    _In_ PEPROCESS processObject,
    _In_ ULONG processId,
    _In_opt_ PCUNICODE_STRING imageFileName
    )
{
    WCHAR imagePathBuffer[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS] = { 0 };
    USHORT copyChars = 0U;

    if (processObject == NULL || processId == 0UL) {
        return;
    }

    // The notification provides a UNICODE_STRING that may not be null-terminated; first create a fixed-length string with a NUL terminator.
    if (imageFileName != NULL && imageFileName->Buffer != NULL && imageFileName->Length != 0U) {
        copyChars = (USHORT)(imageFileName->Length / sizeof(WCHAR));
        if (copyChars >= KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS) {
            copyChars = (USHORT)(KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS - 1U);
        }
        RtlCopyMemory(imagePathBuffer, imageFileName->Buffer, (SIZE_T)copyChars * sizeof(WCHAR));
    }
    imagePathBuffer[copyChars] = L'\0';

    kswordArkProcessProtectKernelApplyToProcess(processObject, processId, imagePathBuffer);
}

VOID
kswordArkProcessProtectNotifyProcessExit(
    _In_ ULONG processId
    )
{
    kswordArkProcessProtectKernelUntrackProcess(processId);
}

static VOID
kswordArkProcessProtectRecordTamper(
    _In_ KswordArkProcessProtectState* state,
    _In_ const KswordArkProcessProtectTrackedEntry* entry,
    _In_ UCHAR observedProtection,
    _In_opt_z_ PCWSTR imagePath
    )
{
    LARGE_INTEGER nowUtc = { 0 };

    KeQuerySystemTimePrecise(&nowUtc);

    kswordArkAcquirePushLockExclusive(&state->lastTamperLock);
    state->lastTamperUtc100ns = nowUtc;
    state->lastTamperProcessId = entry->processId;
    state->lastTamperObservedProtection = (ULONG)observedProtection;
    state->lastTamperExpectedProtection = (ULONG)entry->expectedProtection;
    state->lastTamperRuleId = entry->ruleId;
    kswordArkProcessProtectCopyFixedWideText(
        state->lastTamperImage,
        KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS,
        imagePath);
    kswordArkReleasePushLockExclusive(&state->lastTamperLock);
}

static VOID
kswordArkProcessProtectScanOnce(
    _In_ KswordArkProcessProtectState* state,
    _Inout_updates_(KSWORD_ARK_PROCESS_PROTECT_MAX_TRACKED)
        KswordArkProcessProtectTrackedEntry* snapshot,
    _Inout_updates_(KSWORD_ARK_PROCESS_PROTECT_MAX_TRACKED) ULONG* staleProcessIds
    )
/*++

Routine Description:

    One self-heal pass. The tracked table is snapshotted under a shared lock and
    then walked without holding it: PsLookupProcessByProcessId plus an EPROCESS
    write per entry is far too long to keep process creation waiting on the
    exclusive lock.

--*/
{
    ULONG snapshotCount = 0UL;
    ULONG staleCount = 0UL;
    ULONG entryIndex = 0UL;

    kswordArkAcquirePushLockShared(&state->trackedLock);
    snapshotCount = state->trackedCount;
    if (snapshotCount > KSWORD_ARK_PROCESS_PROTECT_MAX_TRACKED) {
        snapshotCount = KSWORD_ARK_PROCESS_PROTECT_MAX_TRACKED;
    }
    if (snapshotCount != 0UL) {
        RtlCopyMemory(snapshot, state->tracked, (SIZE_T)snapshotCount * sizeof(snapshot[0]));
    }
    kswordArkReleasePushLockShared(&state->trackedLock);

    for (entryIndex = 0UL; entryIndex < snapshotCount; ++entryIndex) {
        const KswordArkProcessProtectTrackedEntry* entry = &snapshot[entryIndex];
        PEPROCESS processObject = NULL;
        UCHAR observedProtection = 0U;
        NTSTATUS status = STATUS_SUCCESS;

        status = PsLookupProcessByProcessId(ULongToHandle(entry->processId), &processObject);
        if (!NT_SUCCESS(status) || processObject == NULL) {
            staleProcessIds[staleCount++] = entry->processId;
            continue;
        }

        // PID reuse detection: A mismatch in creation time indicates this PID now belongs to another process.
        if (PsGetProcessCreateTimeQuadPart(processObject) != entry->createTimeQuadPart) {
            staleProcessIds[staleCount++] = entry->processId;
            ObDereferenceObject(processObject);
            continue;
        }

        status = kswordArkProcessReadProtectionByte(processObject, &observedProtection);
        if (NT_SUCCESS(status) && observedProtection != entry->expectedProtection) {
            KswordArkProcessProtectKernelDecision healDecision;
            WCHAR imagePathBuffer[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS] = { 0 };

            RtlZeroMemory(&healDecision, sizeof(healDecision));
            healDecision.matched = TRUE;
            healDecision.protection = entry->expectedProtection;
            healDecision.ruleId = entry->ruleId;
            healDecision.ruleIndex = entry->ruleIndex;
            healDecision.hardenFlags = entry->hardenFlags;

            (VOID)kswordArkResolveProcessImagePath(
                processObject,
                imagePathBuffer,
                RTL_NUMBER_OF(imagePathBuffer),
                NULL);
            kswordArkProcessProtectRecordTamper(state, entry, observedProtection, imagePathBuffer);

            if (kswordArkProcessProtectStampProcess(
                    state,
                    processObject,
                    entry->processId,
                    &healDecision)) {
                (VOID)InterlockedIncrement64(&state->selfHealCount);
                kswordArkProcessProtectLogFormat(
                    state,
                    "Warn",
                    "Process protection self-healed, pid=%lu, observed=0x%02lX, restored=0x%02lX, ruleId=%lu.",
                    (unsigned long)entry->processId,
                    (unsigned long)observedProtection,
                    (unsigned long)entry->expectedProtection,
                    (unsigned long)entry->ruleId);
            }
        }

        ObDereferenceObject(processObject);
    }

    for (entryIndex = 0UL; entryIndex < staleCount; ++entryIndex) {
        kswordArkProcessProtectKernelUntrackProcess(staleProcessIds[entryIndex]);
    }
}

static KSTART_ROUTINE kswordArkProcessProtectScanThread;

static VOID
kswordArkProcessProtectScanThread(
    _In_ PVOID startContext
    )
{
    KswordArkProcessProtectState* state = (KswordArkProcessProtectState*)startContext;
    KswordArkProcessProtectTrackedEntry* snapshot = NULL;
    ULONG* staleProcessIds = NULL;

    // Snapshot buffer is allocated once: placing 256 items on the stack per round would exhaust the kernel stack.
    snapshot = (KswordArkProcessProtectTrackedEntry*)kswordArkAllocateNonPaged(
        sizeof(KswordArkProcessProtectTrackedEntry) * KSWORD_ARK_PROCESS_PROTECT_MAX_TRACKED,
        KSWORD_ARK_PROCESS_PROTECT_TAG_STATE);
    staleProcessIds = (ULONG*)kswordArkAllocateNonPaged(
        sizeof(ULONG) * KSWORD_ARK_PROCESS_PROTECT_MAX_TRACKED,
        KSWORD_ARK_PROCESS_PROTECT_TAG_STATE);

    if (snapshot == NULL || staleProcessIds == NULL) {
        kswordArkProcessProtectLogFormat(
            state,
            "Warn",
            "Process protection scan thread cannot allocate its buffers; self-heal is disabled.");
    }

    while (InterlockedCompareExchange(&state->scanStopping, 0L, 0L) == 0L) {
        LARGE_INTEGER waitTimeout;
        ULONG intervalMs = 0UL;
        BOOLEAN scanEnabled = FALSE;

        kswordArkAcquirePushLockShared(&state->configLock);
        intervalMs = state->scanIntervalMs;
        scanEnabled =
            ((state->globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_ENABLED) != 0UL &&
             (state->globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_KERNEL_PROTECTION) != 0UL &&
             (state->globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_SELF_HEAL_SCAN) != 0UL)
            ? TRUE
            : FALSE;
        kswordArkReleasePushLockShared(&state->configLock);

        if (intervalMs < KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_MIN_MS ||
            intervalMs > KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_MAX_MS) {
            intervalMs = KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_DEFAULT_MS;
        }

        if (scanEnabled && snapshot != NULL && staleProcessIds != NULL) {
            kswordArkProcessProtectScanOnce(state, snapshot, staleProcessIds);
        }

        // Negative value indicates a relative timeout in units of 100ns. Upon stop, the event immediately interrupts the wait.
        waitTimeout.QuadPart = -((LONGLONG)intervalMs * 10000LL);
        (VOID)KeWaitForSingleObject(
            &state->scanWakeEvent,
            Executive,
            KernelMode,
            FALSE,
            &waitTimeout);
    }

    if (snapshot != NULL) {
        ExFreePoolWithTag(snapshot, KSWORD_ARK_PROCESS_PROTECT_TAG_STATE);
    }
    if (staleProcessIds != NULL) {
        ExFreePoolWithTag(staleProcessIds, KSWORD_ARK_PROCESS_PROTECT_TAG_STATE);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS
kswordArkProcessProtectKernelStart(
    _In_ KswordArkProcessProtectState* state
    )
{
    HANDLE threadHandle = NULL;
    OBJECT_ATTRIBUTES threadAttributes;
    NTSTATUS status = STATUS_SUCCESS;

    if (state == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (state->scanThread != NULL) {
        return STATUS_SUCCESS;
    }

    InitializeObjectAttributes(&threadAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        &threadAttributes,
        NULL,
        NULL,
        kswordArkProcessProtectScanThread,
        state);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Wait for thread exit during unloading, so save via object reference instead; close the handle immediately.
    status = ObReferenceObjectByHandle(
        threadHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID*)&state->scanThread,
        NULL);
    ZwClose(threadHandle);
    if (!NT_SUCCESS(status)) {
        // The thread has started, but without a reference, it is unsafe to wait for it to exit.
        // Let it finish based on the stop flag; record this startup as failed.
        state->scanThread = NULL;
        (VOID)InterlockedExchange(&state->scanStopping, 1L);
        KeSetEvent(&state->scanWakeEvent, IO_NO_INCREMENT, FALSE);
        return status;
    }
    return STATUS_SUCCESS;
}

VOID
kswordArkProcessProtectKernelStop(
    _In_ KswordArkProcessProtectState* state
    )
{
    if (state == NULL) {
        return;
    }

    (VOID)InterlockedExchange(&state->scanStopping, 1L);
    KeSetEvent(&state->scanWakeEvent, IO_NO_INCREMENT, FALSE);

    if (state->scanThread != NULL) {
        (VOID)KeWaitForSingleObject(state->scanThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(state->scanThread);
        state->scanThread = NULL;
    }
}

VOID
kswordArkProcessProtectKernelResetTracking(
    _In_ KswordArkProcessProtectState* state
    )
{
    if (state == NULL) {
        return;
    }

    // After switching tables, expected values in the old ledger may no longer belong to any rule. Continuing self-healing would enforce
    // protection based on deleted rules. Clearing them allows reconstruction via the next process creation or user re-deployment.
    kswordArkAcquirePushLockExclusive(&state->trackedLock);
    RtlZeroMemory(state->tracked, sizeof(state->tracked));
    state->trackedCount = 0UL;
    kswordArkReleasePushLockExclusive(&state->trackedLock);
}
