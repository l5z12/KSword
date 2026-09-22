/*++

Module Name:

    callback_runtime.c

Abstract:

    Callback interception runtime bootstrap and IOCTL entry wrappers.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_internal.h"
#include "ark/ark_push_lock.h"
#include "ark/ark_startup.h"

NTSYSAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS process
    );

NTSYSAPI
ULONG
NTAPI
PsGetProcessSessionId(
    _In_ PEPROCESS process
    );

typedef PVOID
(NTAPI* KswordArkExAllocatePooL2)(
    _In_ POOL_FLAGS flags,
    _In_ SIZE_T numberOfBytes,
    _In_ ULONG tag
    );

static EX_PUSH_LOCK gKswordArkCallbackRuntimeLock;
static KswordArkCallbackRuntime* gKswordArkCallbackRuntime = NULL;
static KswordArkExAllocatePooL2 gKswordArkExAllocatePool2 = NULL;
static volatile LONG gKswordArkPoolAllocatorResolved = 0;

KswordArkCallbackRuntime*
kswordArkCallbackGetRuntime(
    VOID
    )
{
    return gKswordArkCallbackRuntime;
}

PVOID
kswordArkAllocateNonPaged(
    _In_ SIZE_T bytes,
    _In_ ULONG poolTag
    )
{
    if (bytes == 0U) {
        return NULL;
    }

    if (InterlockedCompareExchange(&gKswordArkPoolAllocatorResolved, 1L, 0L) == 0L) {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ExAllocatePool2");
        gKswordArkExAllocatePool2 =
            (KswordArkExAllocatePooL2)MmGetSystemRoutineAddress(&routineName);
    }

    if (gKswordArkExAllocatePool2 != NULL) {
        return gKswordArkExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, poolTag);
    }

#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(NonPagedPool, bytes, poolTag);
#pragma warning(pop)
}

VOID
kswordArkCallbackLogFrameForRuntime(
    _In_opt_ KswordArkCallbackRuntime* runtime,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR messageText
    )
{
    // The caller holds the runtime under construction during the initialization phase, before global publication has occurred.
    if (runtime == NULL || runtime->device == WDF_NO_HANDLE) {
        return;
    }

    (VOID)kswordArkDriverEnqueueLogFrame(
        runtime->device,
        levelText != NULL ? levelText : "Info",
        messageText != NULL ? messageText : "");
}

VOID
kswordArkCallbackLogFormatForRuntime(
    _In_opt_ KswordArkCallbackRuntime* runtime,
    _In_z_ PCSTR levelText,
    _In_z_ _Printf_format_string_ PCSTR formatText,
    ...
    )
{
    CHAR logBuffer[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list argList;

    if (formatText == NULL) {
        kswordArkCallbackLogFrameForRuntime(runtime, levelText, "");
        return;
    }

    va_start(argList, formatText);
    (VOID)RtlStringCbVPrintfA(logBuffer, sizeof(logBuffer), formatText, argList);
    va_end(argList);

    kswordArkCallbackLogFrameForRuntime(runtime, levelText, logBuffer);
}

VOID
kswordArkCallbackLogFrame(
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR messageText
    )
{
    // The steady-state path continues to use the global runtime; callers during startup must switch to the ForRuntime version.
    kswordArkCallbackLogFrameForRuntime(kswordArkCallbackGetRuntime(), levelText, messageText);
}

VOID
kswordArkCallbackLogFormat(
    _In_z_ PCSTR levelText,
    _In_z_ _Printf_format_string_ PCSTR formatText,
    ...
    )
{
    CHAR logBuffer[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list argList;

    if (formatText == NULL) {
        kswordArkCallbackLogFrame(levelText, "");
        return;
    }

    va_start(argList, formatText);
    (VOID)RtlStringCbVPrintfA(logBuffer, sizeof(logBuffer), formatText, argList);
    va_end(argList);

    kswordArkCallbackLogFrame(levelText, logBuffer);
}

VOID
kswordArkGetSystemTimeUtc100ns(
    _Out_ LARGE_INTEGER* utcOut
    )
{
    if (utcOut == NULL) {
        return;
    }
    KeQuerySystemTimePrecise(utcOut);
}

VOID
kswordArkCopyUnicodeToFixedBuffer(
    _In_opt_ PCUNICODE_STRING sourceText,
    _Out_writes_(destinationChars) PWCHAR destinationBuffer,
    _In_ USHORT destinationChars
    )
{
    USHORT sourceChars = 0;
    USHORT copyChars = 0;

    if (destinationBuffer == NULL || destinationChars == 0U) {
        return;
    }

    destinationBuffer[0] = L'\0';
    if (sourceText == NULL || sourceText->Buffer == NULL || sourceText->Length == 0U) {
        return;
    }

    sourceChars = (USHORT)(sourceText->Length / sizeof(WCHAR));
    copyChars = sourceChars;
    if (copyChars >= destinationChars) {
        copyChars = (USHORT)(destinationChars - 1U);
    }

    if (copyChars > 0U) {
        RtlCopyMemory(destinationBuffer, sourceText->Buffer, copyChars * sizeof(WCHAR));
    }
    destinationBuffer[copyChars] = L'\0';
}

VOID
kswordArkCopyWideStringToFixedBuffer(
    _In_opt_z_ PCWSTR sourceText,
    _Out_writes_(destinationChars) PWCHAR destinationBuffer,
    _In_ USHORT destinationChars
    )
{
    size_t sourceChars = 0;
    size_t copyChars = 0;

    if (destinationBuffer == NULL || destinationChars == 0U) {
        return;
    }

    destinationBuffer[0] = L'\0';
    if (sourceText == NULL) {
        return;
    }

    if (!NT_SUCCESS(RtlStringCchLengthW(sourceText, destinationChars, &sourceChars))) {
        sourceChars = destinationChars - 1U;
    }

    copyChars = sourceChars;
    if (copyChars >= destinationChars) {
        copyChars = destinationChars - 1U;
    }

    if (copyChars > 0U) {
        RtlCopyMemory(destinationBuffer, sourceText, copyChars * sizeof(WCHAR));
    }
    destinationBuffer[copyChars] = L'\0';
}

BOOLEAN
kswordArkResolveProcessImagePath(
    _In_opt_ PEPROCESS processObject,
    _Out_writes_(destinationChars) PWCHAR destinationBuffer,
    _In_ USHORT destinationChars,
    _Out_opt_ BOOLEAN* pathUnavailableOut
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PUNICODE_STRING imagePath = NULL;
    BOOLEAN localUnavailable = TRUE;
    PEPROCESS targetProcess = processObject;

    if (destinationBuffer == NULL || destinationChars == 0U) {
        return FALSE;
    }

    destinationBuffer[0] = L'\0';
    if (targetProcess == NULL) {
        targetProcess = PsGetCurrentProcess();
    }

    status = SeLocateProcessImageName(targetProcess, &imagePath);
    if (NT_SUCCESS(status) && imagePath != NULL && imagePath->Buffer != NULL && imagePath->Length > 0U) {
        kswordArkCopyUnicodeToFixedBuffer(imagePath, destinationBuffer, destinationChars);
        ExFreePool(imagePath);
        localUnavailable = FALSE;
    }
    else {
        PCHAR shortImageName = PsGetProcessImageFileName(targetProcess);
        if (shortImageName != NULL && shortImageName[0] != '\0') {
            (VOID)RtlStringCbPrintfW(destinationBuffer, destinationChars * sizeof(WCHAR), L"%S", shortImageName);
            localUnavailable = TRUE;
        }
    }

    if (pathUnavailableOut != NULL) {
        *pathUnavailableOut = localUnavailable;
    }
    return (destinationBuffer[0] != L'\0') ? TRUE : FALSE;
}

ULONG
kswordArkGetProcessSessionIdSafe(
    _In_opt_ PEPROCESS processObject
    )
{
    PEPROCESS targetProcess = processObject;
    if (targetProcess == NULL) {
        targetProcess = PsGetCurrentProcess();
    }
    return PsGetProcessSessionId(targetProcess);
}

BOOLEAN
kswordArkGuidEquals(
    _In_ const KSWORD_ARK_GUID128* leftGuid,
    _In_ const KSWORD_ARK_GUID128* rightGuid
    )
{
    if (leftGuid == NULL || rightGuid == NULL) {
        return FALSE;
    }

    return (RtlCompareMemory(leftGuid->bytes, rightGuid->bytes, sizeof(leftGuid->bytes)) ==
        sizeof(leftGuid->bytes))
        ? TRUE
        : FALSE;
}

VOID
kswordArkGuidGenerate(
    _Out_ KSWORD_ARK_GUID128* guidOut
    )
{
    KswordArkCallbackRuntime* runtime = kswordArkCallbackGetRuntime();
    LARGE_INTEGER nowUtc = { 0 };
    ULONGLONG sequenceValue = 0;
    ULONG pidValue = HandleToULong(PsGetCurrentProcessId());
    ULONG tidValue = HandleToULong(PsGetCurrentThreadId());

    if (guidOut == NULL) {
        return;
    }

    kswordArkGetSystemTimeUtc100ns(&nowUtc);
    if (runtime != NULL) {
        sequenceValue = (ULONGLONG)InterlockedIncrement64(&runtime->eventSequence);
    }

    RtlZeroMemory(guidOut, sizeof(*guidOut));
    RtlCopyMemory(&guidOut->bytes[0], &nowUtc.QuadPart, sizeof(nowUtc.QuadPart));
    RtlCopyMemory(&guidOut->bytes[8], &sequenceValue, sizeof(sequenceValue));
    guidOut->bytes[0] ^= (UCHAR)(pidValue & 0xFFU);
    guidOut->bytes[1] ^= (UCHAR)((pidValue >> 8) & 0xFFU);
    guidOut->bytes[2] ^= (UCHAR)(tidValue & 0xFFU);
    guidOut->bytes[3] ^= (UCHAR)((tidValue >> 8) & 0xFFU);
}

static VOID
kswordArkCallbackDestroyRuntime(
    _In_opt_ KswordArkCallbackRuntime* runtime
    )
{
    KswordArkCallbackRuleSnapshot* oldSnapshot = NULL;

    if (runtime == NULL) {
        return;
    }

    // First close new AskUser wait items, then wake existing waiters to prevent wait threads from blocking during driver unloading.
    (VOID)InterlockedExchange(&runtime->stopping, 1L);
    // Synchronously close read-only telemetry; subsequent callbacks executing within the unregistration window will no longer write to the ring.
    (VOID)InterlockedExchange(&runtime->monitorCategoryMask, 0L);
    (VOID)kswordArkCallbackCancelAllPendingForRuntime(runtime);
    kswordArkMinifilterCallbackUnregister(runtime);
    // Only unregister callbacks that were successfully registered. Items not registered during a
    // downgrade boot must be skipped as-is; otherwise, it triggers a doomed kernel unregistration call.
    if ((runtime->registeredCallbacksMask & KSWORD_ARK_CALLBACK_REGISTERED_OBJECT) != 0U) {
        kswordArkObjectCallbackUnregister(runtime);
    }
    if ((runtime->registeredCallbacksMask & KSWORD_ARK_CALLBACK_REGISTERED_IMAGE) != 0U) {
        kswordArkImageCallbackUnregister(runtime);
    }
    if ((runtime->registeredCallbacksMask & KSWORD_ARK_CALLBACK_REGISTERED_THREAD) != 0U) {
        kswordArkThreadCallbackUnregister(runtime);
    }
    if ((runtime->registeredCallbacksMask & KSWORD_ARK_CALLBACK_REGISTERED_PROCESS) != 0U) {
        kswordArkProcessCallbackUnregister(runtime);
    }
    if ((runtime->registeredCallbacksMask & KSWORD_ARK_CALLBACK_REGISTERED_REGISTRY) != 0U) {
        kswordArkRegistryCallbackUnregister(runtime);
    }
    kswordArkCallbackWaiterUninitialize(runtime);

    kswordArkAcquirePushLockExclusive(&runtime->snapshotLock);
    oldSnapshot = runtime->activeSnapshot;
    runtime->activeSnapshot = NULL;
    kswordArkReleasePushLockExclusive(&runtime->snapshotLock);

    if (oldSnapshot != NULL) {
        ExWaitForRundownProtectionRelease(&oldSnapshot->rundownRef);
        kswordArkCallbackFreeSnapshot(oldSnapshot);
    }

    ExFreePoolWithTag(runtime, KSWORD_ARK_CALLBACK_TAG_RUNTIME);
}

static NTSTATUS
kswordArkCallbackRegisterOne(
    _In_ KswordArkCallbackRuntime* runtime,
    _In_ ULONG capabilityBit,
    _In_z_ PCSTR capabilityName,
    _In_ NTSTATUS registerStatus
    )
/*++

Routine Description:

    Fold one callback registration result into the runtime. Success sets the
    capability bit; failure only records the raw NTSTATUS and leaves the bit
    clear, so a single unavailable kernel callback can no longer take the whole
    driver down with it.

Arguments:

    runtime - Runtime being built. It is not published yet.
    capabilityBit - KSWORD_ARK_CALLBACK_REGISTERED_* bit for this callback.
    capabilityName - Short name used in the R3-visible log line.
    registerStatus - Raw NTSTATUS returned by the registration API.

Return Value:

    The registerStatus argument, unmodified.

--*/
{
    if (NT_SUCCESS(registerStatus)) {
        runtime->registeredCallbacksMask |= capabilityBit;
        return registerStatus;
    }

    // Common causes: altitude conflict, callback slot full, insufficient resources, or duplicate registration.
    kswordArkCallbackLogFormatForRuntime(
        runtime,
        "Warn",
        "%s callback unavailable, status=0x%08lX. Driver continues without this capability.",
        capabilityName,
        (unsigned long)registerStatus);
    return registerStatus;
}

ULONG
kswordArkCallbackGetRegisteredMask(
    VOID
    )
/*++

Routine Description:

    Report which callback capabilities are currently registered. DriverEntry
    persists this into the startup breadcrumb so a degraded start is visible
    without querying the driver.

Arguments:

    None.

Return Value:

    KSWORD_ARK_CALLBACK_REGISTERED_* bitmask, or zero when no runtime exists.

--*/
{
    KswordArkCallbackRuntime* runtime = kswordArkCallbackGetRuntime();
    return (runtime != NULL) ? runtime->registeredCallbacksMask : 0UL;
}

NTSTATUS
kswordArkCallbackInitialize(
    _In_ WDFDEVICE device
    )
/*++

Routine Description:

    Build and publish the callback runtime. Every kernel callback here is an
    optional capability: registration failures are recorded and the affected
    feature is disabled, but the runtime is still published so the rest of the
    driver keeps working.

Arguments:

    Device - Control device that owns the runtime and its log channel.

Return Value:

    STATUS_SUCCESS when every callback registered. The first registration
    failure otherwise, purely as a diagnostic signal — the caller must treat a
    failure status as "degraded", not as a reason to fail the load.

--*/
{
    KswordArkCallbackRuntime* runtime = NULL;
    NTSTATUS firstFailureStatus = STATUS_SUCCESS;
    NTSTATUS status = STATUS_SUCCESS;

    if (device == WDF_NO_HANDLE) {
        return STATUS_INVALID_PARAMETER;
    }

    kswordArkAcquirePushLockExclusive(&gKswordArkCallbackRuntimeLock);
    if (gKswordArkCallbackRuntime != NULL) {
        kswordArkReleasePushLockExclusive(&gKswordArkCallbackRuntimeLock);
        return STATUS_SUCCESS;
    }

    kswordArkStartupStage(kKswordArkStartStageCallbackRuntimeAllocate);
    runtime = (KswordArkCallbackRuntime*)kswordArkAllocateNonPaged(
        sizeof(KswordArkCallbackRuntime),
        KSWORD_ARK_CALLBACK_TAG_RUNTIME);
    if (runtime == NULL) {
        kswordArkReleasePushLockExclusive(&gKswordArkCallbackRuntimeLock);
        // Runtime allocation failure only closes the callback module; the core driver continues loading.
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(runtime, sizeof(*runtime));
    runtime->device = device;
    runtime->waitQueue = WDF_NO_HANDLE;
    runtime->obRegistrationHandle = NULL;
    runtime->miniFilterHandle = NULL;
    runtime->miniFilterStarted = FALSE;
    runtime->miniFilterRegisterStatus = STATUS_NOT_SUPPORTED;
    runtime->miniFilterStartStatus = STATUS_NOT_SUPPORTED;
    runtime->miniFilterBypassPidCount = 0U;
    RtlZeroMemory(runtime->miniFilterBypassPids, sizeof(runtime->miniFilterBypassPids));
    runtime->registeredCallbacksMask = 0U;
    runtime->monitorWriterLock = 0L;
    runtime->monitorCategoryMask = 0L;
    runtime->monitorLatestSequence = 0LL;
    runtime->monitorDroppedCount = 0LL;
    runtime->monitorLastStatus = STATUS_SUCCESS;
    runtime->initialized = FALSE;
    // Explicitly declare that the runtime can accept wait items before publishing; the teardown path atomically transitions to the stopped state.
    runtime->stopping = 0L;
    ExInitializePushLock(&runtime->snapshotLock);
    ExInitializePushLock(&runtime->pendingLock);
    ExInitializePushLock(&runtime->miniFilterBypassPidLock);
    InitializeListHead(&runtime->pendingDecisionList);

    // If the AskUser wait queue fails, only the "Ask User" capability is disabled; other callbacks are registered normally.
    kswordArkStartupStage(kKswordArkStartStageCallbackWaitQueue);
    status = kswordArkCallbackWaiterInitialize(runtime);
    runtime->waitQueueStatus = status;
    if (!NT_SUCCESS(status)) {
        kswordArkCallbackLogFormatForRuntime(
            runtime,
            "Warn",
            "AskUser wait queue unavailable, status=0x%08lX. Ask rules fall back to their default decision.",
            (unsigned long)status);
        firstFailureStatus = status;
    }

    // Registry callbacks use a fixed altitude of 385201.5141; another instance with the
    // same altitude will cause it to return STATUS_FLT_INSTANCE_ALTITUDE_COLLISION.
    kswordArkStartupStage(kKswordArkStartStageRegistryCallback);
    runtime->registryRegisterStatus = kswordArkCallbackRegisterOne(
        runtime,
        KSWORD_ARK_CALLBACK_REGISTERED_REGISTRY,
        "Registry",
        kswordArkRegistryCallbackRegister(runtime));
    if (!NT_SUCCESS(runtime->registryRegisterStatus) && NT_SUCCESS(firstFailureStatus)) {
        firstFailureStatus = runtime->registryRegisterStatus;
    }

    // Process creation callbacks return STATUS_INVALID_PARAMETER when registered repeatedly or when the system callback limit is reached.
    kswordArkStartupStage(kKswordArkStartStageProcessCallback);
    runtime->processRegisterStatus = kswordArkCallbackRegisterOne(
        runtime,
        KSWORD_ARK_CALLBACK_REGISTERED_PROCESS,
        "Process",
        kswordArkProcessCallbackRegister(runtime));
    if (!NT_SUCCESS(runtime->processRegisterStatus) && NT_SUCCESS(firstFailureStatus)) {
        firstFailureStatus = runtime->processRegisterStatus;
    }

    kswordArkStartupStage(kKswordArkStartStageThreadCallback);
    runtime->threadRegisterStatus = kswordArkCallbackRegisterOne(
        runtime,
        KSWORD_ARK_CALLBACK_REGISTERED_THREAD,
        "Thread",
        kswordArkThreadCallbackRegister(runtime));
    if (!NT_SUCCESS(runtime->threadRegisterStatus) && NT_SUCCESS(firstFailureStatus)) {
        firstFailureStatus = runtime->threadRegisterStatus;
    }

    // There are at most 64 image load callbacks system-wide; machines with multiple EDR/anti-cheat suites may exhaust these slots first.
    kswordArkStartupStage(kKswordArkStartStageImageCallback);
    runtime->imageRegisterStatus = kswordArkCallbackRegisterOne(
        runtime,
        KSWORD_ARK_CALLBACK_REGISTERED_IMAGE,
        "Image",
        kswordArkImageCallbackRegister(runtime));
    if (!NT_SUCCESS(runtime->imageRegisterStatus) && NT_SUCCESS(firstFailureStatus)) {
        firstFailureStatus = runtime->imageRegisterStatus;
    }

    // Object callbacks use a fixed altitude of 385201.5142; conflicts, resource exhaustion, and
    // parameter errors are now downgraded to STATUS_ACCESS_DENIED only, with no special distinction.
    kswordArkStartupStage(kKswordArkStartStageObjectCallback);
    runtime->objectRegisterStatus = kswordArkCallbackRegisterOne(
        runtime,
        KSWORD_ARK_CALLBACK_REGISTERED_OBJECT,
        "Object",
        kswordArkObjectCallbackRegister(runtime));
    if (!NT_SUCCESS(runtime->objectRegisterStatus) && NT_SUCCESS(firstFailureStatus)) {
        firstFailureStatus = runtime->objectRegisterStatus;
    }

    runtime->initialized = TRUE;
    gKswordArkCallbackRuntime = runtime;
    kswordArkReleasePushLockExclusive(&gKswordArkCallbackRuntimeLock);

    kswordArkCallbackLogFormat(
        "Info",
        "Callback runtime initialized, registeredMask=0x%08lX, firstFailure=0x%08lX.",
        (unsigned long)runtime->registeredCallbacksMask,
        (unsigned long)firstFailureStatus);
    return firstFailureStatus;
}

VOID
kswordArkCallbackUninitialize(
    VOID
    )
{
    KswordArkCallbackRuntime* runtime = NULL;

    kswordArkAcquirePushLockExclusive(&gKswordArkCallbackRuntimeLock);
    runtime = gKswordArkCallbackRuntime;
    // First revoke the global dispatch to reject new external lookups; destroy path uses explicit runtime pointer to cancel wait items.
    gKswordArkCallbackRuntime = NULL;
    kswordArkReleasePushLockExclusive(&gKswordArkCallbackRuntimeLock);

    if (runtime != NULL) {
        kswordArkCallbackDestroyRuntime(runtime);
    }
}

NTSTATUS
kswordArkCallbackSetMinifilterBypassPids(
    _In_reads_opt_(pidCount) const ULONG* processIds,
    _In_ ULONG pidCount
    )
/*++

Routine Description:

    Replace the in-memory minifilter bypass PID list used by the hot-path
    pre-operation callback. PID zero is ignored because it is not a user-mode
    process identity that should be allowlisted from the UI.

Arguments:

    ProcessIds - Optional caller-owned PID array. It may be NULL only when
        PidCount is zero.
    PidCount - Number of input PID slots to inspect.

Return Value:

    STATUS_SUCCESS when the runtime list has been replaced. An NTSTATUS error
    is returned for invalid packet shape, over-limit counts or missing runtime.

--*/
{
    KswordArkCallbackRuntime* runtime = kswordArkCallbackGetRuntime();
    ULONG uniquePids[KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT];
    ULONG readIndex = 0UL;
    ULONG scanIndex = 0UL;
    ULONG writeIndex = 0UL;

    if (pidCount > KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT) {
        return STATUS_INVALID_PARAMETER;
    }

    if (pidCount != 0UL && processIds == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (runtime == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    RtlZeroMemory(uniquePids, sizeof(uniquePids));
    for (readIndex = 0UL; readIndex < pidCount; ++readIndex) {
        BOOLEAN duplicatePid = FALSE;
        ULONG candidatePid = processIds[readIndex];

        if (candidatePid == 0UL) {
            continue;
        }

        for (scanIndex = 0UL; scanIndex < writeIndex; ++scanIndex) {
            if (uniquePids[scanIndex] == candidatePid) {
                duplicatePid = TRUE;
                break;
            }
        }

        if (!duplicatePid && writeIndex < KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT) {
            uniquePids[writeIndex] = candidatePid;
            ++writeIndex;
        }
    }

    kswordArkAcquirePushLockExclusive(&runtime->miniFilterBypassPidLock);
    RtlZeroMemory(runtime->miniFilterBypassPids, sizeof(runtime->miniFilterBypassPids));
    if (writeIndex != 0UL) {
        RtlCopyMemory(runtime->miniFilterBypassPids, uniquePids, (SIZE_T)writeIndex * sizeof(ULONG));
    }
    runtime->miniFilterBypassPidCount = writeIndex;
    kswordArkReleasePushLockExclusive(&runtime->miniFilterBypassPidLock);

    kswordArkCallbackLogFormat(
        "Info",
        "Minifilter bypass PID whitelist updated, count=%lu.",
        (unsigned long)writeIndex);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkCallbackQueryMinifilterBypassPids(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Copy the current minifilter bypass PID list into the shared R3/R0 response
    structure. The copy is protected by the runtime push lock so user mode sees
    one consistent snapshot.

Arguments:

    OutputBuffer - Caller output buffer that receives the fixed response packet.
    OutputBufferLength - Output buffer size supplied by WDF.
    BytesWrittenOut - Receives sizeof(KSWORD_ARK_MINIFILTER_BYPASS_PID_RESPONSE).

Return Value:

    STATUS_SUCCESS when the response packet was written; otherwise an NTSTATUS
    validation or runtime availability error.

--*/
{
    KswordArkCallbackRuntime* runtime = kswordArkCallbackGetRuntime();
    KSWORD_ARK_MINIFILTER_BYPASS_PID_RESPONSE* response = NULL;
    ULONG pidCount = 0UL;

    if (bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;

    if (outputBuffer == NULL ||
        outputBufferLength < sizeof(KSWORD_ARK_MINIFILTER_BYPASS_PID_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (runtime == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    response = (KSWORD_ARK_MINIFILTER_BYPASS_PID_RESPONSE*)outputBuffer;
    RtlZeroMemory(response, sizeof(*response));
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;

    kswordArkAcquirePushLockShared(&runtime->miniFilterBypassPidLock);
    pidCount = runtime->miniFilterBypassPidCount;
    if (pidCount > KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT) {
        pidCount = KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT;
    }
    response->pidCount = pidCount;
    if (pidCount != 0UL) {
        RtlCopyMemory(response->processIds, runtime->miniFilterBypassPids, (SIZE_T)pidCount * sizeof(ULONG));
    }
    kswordArkReleasePushLockShared(&runtime->miniFilterBypassPidLock);

    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}

BOOLEAN
kswordArkCallbackIsMinifilterBypassPid(
    _In_ ULONG processId
    )
/*++

Routine Description:

    Check whether a requestor PID is present in the minifilter bypass whitelist.
    The minifilter calls this before callback rules, redirect rewriting and file
    monitor capture so allowlisted requests pass through to the filesystem stack.

Arguments:

    ProcessId - Requestor process identifier from FltGetRequestorProcessId.

Return Value:

    TRUE when ProcessId is allowlisted; FALSE otherwise.

--*/
{
    KswordArkCallbackRuntime* runtime = kswordArkCallbackGetRuntime();
    ULONG pidIndex = 0UL;
    ULONG pidCount = 0UL;
    BOOLEAN matchedPid = FALSE;

    if (processId == 0UL || runtime == NULL) {
        return FALSE;
    }

    kswordArkAcquirePushLockShared(&runtime->miniFilterBypassPidLock);
    pidCount = runtime->miniFilterBypassPidCount;
    if (pidCount > KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT) {
        pidCount = KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT;
    }
    for (pidIndex = 0UL; pidIndex < pidCount; ++pidIndex) {
        if (runtime->miniFilterBypassPids[pidIndex] == processId) {
            matchedPid = TRUE;
            break;
        }
    }
    kswordArkReleasePushLockShared(&runtime->miniFilterBypassPidLock);

    return matchedPid;
}

NTSTATUS
kswordArkCallbackIoctlSetRules(
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _Out_ size_t* completeBytesOut
    )
{
    KswordArkCallbackRuleSnapshot* snapshot = NULL;
    PVOID inputBuffer = NULL;
    size_t inputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    if (completeBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *completeBytesOut = 0U;

    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_CALLBACK_RULE_BLOB_HEADER),
        &inputBuffer,
        &inputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (inputBufferLength < sizeof(KSWORD_ARK_CALLBACK_RULE_BLOB_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = kswordArkCallbackBuildSnapshotFromBlob(inputBuffer, inputLength, &snapshot);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = kswordArkCallbackSwapSnapshot(snapshot);
    if (!NT_SUCCESS(status)) {
        kswordArkCallbackFreeSnapshot(snapshot);
        return status;
    }

    *completeBytesOut = inputLength;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkCallbackIoctlGetRuntimeState(
    _In_ WDFREQUEST request,
    _In_ size_t outputBufferLength,
    _Out_ size_t* completeBytesOut
    )
{
    KSWORD_ARK_CALLBACK_RUNTIME_STATE* stateBuffer = NULL;
    size_t stateBufferLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    if (completeBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *completeBytesOut = 0U;

    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_CALLBACK_RUNTIME_STATE),
        (PVOID*)&stateBuffer,
        &stateBufferLength);
    if (!NT_SUCCESS(status)) {
        UNREFERENCED_PARAMETER(outputBufferLength);
        return status;
    }

    kswordArkCallbackQueryRuntimeState(stateBuffer);
    *completeBytesOut = sizeof(KSWORD_ARK_CALLBACK_RUNTIME_STATE);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkCallbackIoctlSetMinifilterBypassPids(
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _Out_ size_t* completeBytesOut
    )
/*++

Routine Description:

    Validate the R3 minifilter bypass PID packet and replace the runtime PID
    whitelist. The actual storage update is delegated to the callback runtime
    helper so dispatch remains thin.

Arguments:

    Request - WDF request that carries KSWORD_ARK_MINIFILTER_BYPASS_PID_REQUEST.
    InputBufferLength - Caller supplied input buffer length.
    CompleteBytesOut - Receives the consumed input byte count on success.

Return Value:

    STATUS_SUCCESS when the whitelist is updated; otherwise an NTSTATUS
    validation or WDF buffer retrieval error.

--*/
{
    KSWORD_ARK_MINIFILTER_BYPASS_PID_REQUEST* requestPacket = NULL;
    PVOID inputBuffer = NULL;
    size_t inputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (completeBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *completeBytesOut = 0U;

    if (inputBufferLength < sizeof(KSWORD_ARK_MINIFILTER_BYPASS_PID_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_MINIFILTER_BYPASS_PID_REQUEST),
        &inputBuffer,
        &inputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (inputLength < sizeof(KSWORD_ARK_MINIFILTER_BYPASS_PID_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    requestPacket = (KSWORD_ARK_MINIFILTER_BYPASS_PID_REQUEST*)inputBuffer;
    if (requestPacket->size < sizeof(KSWORD_ARK_MINIFILTER_BYPASS_PID_REQUEST) ||
        requestPacket->version != KSWORD_ARK_CALLBACK_PROTOCOL_VERSION ||
        requestPacket->pidCount > KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT) {
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkCallbackSetMinifilterBypassPids(
        requestPacket->processIds,
        requestPacket->pidCount);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *completeBytesOut = sizeof(KSWORD_ARK_MINIFILTER_BYPASS_PID_REQUEST);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkCallbackIoctlQueryMinifilterBypassPids(
    _In_ WDFREQUEST request,
    _In_ size_t outputBufferLength,
    _Out_ size_t* completeBytesOut
    )
/*++

Routine Description:

    Retrieve the caller output buffer and return the current minifilter bypass
    PID whitelist as one fixed shared-protocol response packet.

Arguments:

    Request - WDF request that owns the output buffer.
    OutputBufferLength - Caller supplied output buffer length.
    CompleteBytesOut - Receives the response byte count on success.

Return Value:

    STATUS_SUCCESS when the response is filled; otherwise an NTSTATUS
    validation or WDF buffer retrieval error.

--*/
{
    KSWORD_ARK_MINIFILTER_BYPASS_PID_RESPONSE* responsePacket = NULL;
    size_t outputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (completeBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *completeBytesOut = 0U;

    if (outputBufferLength < sizeof(KSWORD_ARK_MINIFILTER_BYPASS_PID_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_MINIFILTER_BYPASS_PID_RESPONSE),
        (PVOID*)&responsePacket,
        &outputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return kswordArkCallbackQueryMinifilterBypassPids(
        responsePacket,
        outputLength,
        completeBytesOut);
}

NTSTATUS
kswordArkCallbackIoctlWaitEvent(
    _In_ WDFREQUEST request,
    _In_ size_t outputBufferLength,
    _Out_ size_t* completeBytesOut
    )
{
    return kswordArkCallbackIoctlWaitEventInternal(
        request,
        outputBufferLength,
        completeBytesOut);
}

NTSTATUS
kswordArkCallbackIoctlAnswerEvent(
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _Out_ size_t* completeBytesOut
    )
{
    return kswordArkCallbackIoctlAnswerEventInternal(
        request,
        inputBufferLength,
        completeBytesOut);
}

NTSTATUS
kswordArkCallbackIoctlCancelAllPending(
    _Out_ size_t* completeBytesOut
    )
{
    NTSTATUS status = kswordArkCallbackCancelAllPendingInternal();
    if (completeBytesOut != NULL) {
        *completeBytesOut = 0U;
    }
    return status;
}
