/*++

Module Name:

    process_flags.c

Abstract:

    Process BreakOnTermination and ETHREAD APC insertion controls.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../platform/process_resolver.h"
#include "process_crossview.h"

/* Note: PsLookupProcessByProcessId is used to reference the target EPROCESS. */
NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE processId,
    _Outptr_ PEPROCESS* process
    );

/* Note: Exposes a kernel routine returning the stable creation time of the target EPROCESS. */
NTKERNELAPI
LONGLONG
NTAPI
PsGetProcessCreateTimeQuadPart(
    _In_ PEPROCESS process
    );

NTKERNELAPI
NTSTATUS
ObOpenObjectByPointer(
    _In_ PVOID object,
    _In_ ULONG handleAttributes,
    _In_opt_ PACCESS_STATE passedAccessState,
    _In_opt_ ACCESS_MASK desiredAccess,
    _In_opt_ POBJECT_TYPE objectType,
    _In_ KPROCESSOR_MODE accessMode,
    _Out_ PHANDLE handle
    );

extern POBJECT_TYPE* PsProcessType;

/* Note: ProcessBreakOnTermination is information class 29 for ZwSetInformationProcess. */
#define KSWORD_ARK_PROCESS_INFORMATION_BREAK_ON_TERMINATION 29UL
/* Note: In EPROCESS.Flags, BreakOnTermination corresponds to bit 13, and SKT64 uses the same bit. */
#define KSWORD_ARK_EPROCESS_FLAGS_BREAK_ON_TERMINATION_MASK 0x00002000UL
/* Note: EPROCESS structure offsets must come from DynData/PDB; exceeding this limit indicates an anomalous profile. */
#define KSWORD_ARK_EPROCESS_FLAGS_OFFSET_MAX 0x3000UL
/* Note: Conservative offset candidate for Windows x64 ETHREAD.CrossThreadFlags/ApcQueueable. */
#define KSWORD_ARK_ETHREAD_APC_QUEUEABLE_OFFSET_X64 0x74UL
/* Note: The ApcQueueable bit in CrossThreadFlags typically corresponds to bit 18. */
#define KSWORD_ARK_ETHREAD_APC_QUEUEABLE_MASK 0x00040000UL

#ifndef PROCESS_SET_INFORMATION
/* Note: Older WDK headers may lack user-mode constants with the same name; supplement them using ntifs/winnt definitions. */
#define PROCESS_SET_INFORMATION 0x0200
#endif

/* Note: psGetNextProcessThread is used to stably traverse the target process's thread objects. */
typedef PETHREAD(NTAPI* KswordPsGetNextProcessThreadFn)(
    _In_ PEPROCESS process,
    _In_opt_ PETHREAD thread
    );

typedef struct KswordProcessFlagsCidMatchContext
{
    const KswDynState* dynState;
    ULONG processId;
    PEPROCESS processObject;
    ULONG uniqueProcessId;
    NTSTATUS lastStatus;
} KswordProcessFlagsCidMatchContext;

/* Note: Resolves psGetNextProcessThread at runtime to avoid link-time dependency differences. */
static KswordPsGetNextProcessThreadFn
kswordArkProcessFlagsResolvePsGetNextProcessThread(
    VOID
    )
{
    UNICODE_STRING routineName;

    /* Note: Name comes from the ntoskrnl export table; if missing, APC functionality is disabled and unsupported is returned. */
    RtlInitUnicodeString(&routineName, L"PsGetNextProcessThread");
    /* Note: The caller checks for NULL; no state is recorded within the resolver. */
    return (KswordPsGetNextProcessThreadFn)MmGetSystemRoutineAddress(&routineName);
}

static VOID
kswordArkProcessFlagsCidMatchCallback(
    _In_ const KswCrossviewCidEntry* entry,
    _Inout_opt_ PVOID context
    )
{
    KswordProcessFlagsCidMatchContext* matchContext =
        (KswordProcessFlagsCidMatchContext*)context;
    PVOID uniqueProcessIdPointer = NULL;
    ULONG uniqueProcessId = 0UL;

    if (matchContext == NULL ||
        matchContext->processObject != NULL ||
        entry == NULL ||
        !entry->referenced ||
        entry->object == NULL) {
        return;
    }

    uniqueProcessId = HandleToULong(PsGetProcessId((PEPROCESS)entry->object));
    if (matchContext->dynState != NULL &&
        kswordArkCrossViewOffsetPresent(matchContext->dynState->kernel.epUniqueProcessId)) {
        NTSTATUS readStatus = kswordArkCrossViewReadPointerField(
            entry->object,
            matchContext->dynState->kernel.epUniqueProcessId,
            &uniqueProcessIdPointer);
        if (NT_SUCCESS(readStatus)) {
            uniqueProcessId = HandleToULong(uniqueProcessIdPointer);
        }
        else if (NT_SUCCESS(matchContext->lastStatus)) {
            matchContext->lastStatus = readStatus;
        }
    }

    if (entry->cidValue != matchContext->processId &&
        uniqueProcessId != matchContext->processId &&
        HandleToULong(PsGetProcessId((PEPROCESS)entry->object)) != matchContext->processId) {
        return;
    }

    ObReferenceObject(entry->object);
    matchContext->processObject = (PEPROCESS)entry->object;
    matchContext->uniqueProcessId = uniqueProcessId;
    matchContext->lastStatus = STATUS_SUCCESS;
}

static NTSTATUS
kswordArkProcessFlagsReferenceProcessByCidTable(
    _In_ const KswDynState* dynState,
    _In_ ULONG processId,
    _Outptr_ PEPROCESS* processObjectOut
    )
{
    KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS fieldOffsets;
    KswordProcessFlagsCidMatchContext matchContext;
    PVOID pspCidTableAddress = NULL;
    ULONG64 missingCapabilityMask = 0ULL;
    ULONG visitedEntries = 0UL;
    BOOLEAN usedDynDataGlobal = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (dynState == NULL || processObjectOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *processObjectOut = NULL;
    if (PsProcessType == NULL || *PsProcessType == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    RtlZeroMemory(&fieldOffsets, sizeof(fieldOffsets));
    RtlZeroMemory(&matchContext, sizeof(matchContext));
    kswordArkCrossViewFillFieldOffsets(dynState, &fieldOffsets);
    status = kswordArkCrossViewResolvePspCidTableAddress(
        dynState,
        &fieldOffsets,
        &pspCidTableAddress,
        &missingCapabilityMask,
        &usedDynDataGlobal);
    UNREFERENCED_PARAMETER(missingCapabilityMask);
    UNREFERENCED_PARAMETER(usedDynDataGlobal);
    if (!NT_SUCCESS(status) || pspCidTableAddress == NULL) {
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    matchContext.dynState = dynState;
    matchContext.processId = processId;
    matchContext.lastStatus = STATUS_NOT_FOUND;
    status = kswordArkCrossViewWalkCidTable(
        dynState,
        pspCidTableAddress,
        *PsProcessType,
        0x00100000UL,
        kswordArkProcessFlagsCidMatchCallback,
        &matchContext,
        &visitedEntries);
    UNREFERENCED_PARAMETER(visitedEntries);

    if (matchContext.processObject != NULL) {
        *processObjectOut = matchContext.processObject;
        return STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) {
        return status;
    }
    return matchContext.lastStatus;
}

static NTSTATUS
kswordArkProcessFlagsValidateReferencedIdentity(
    _Inout_ PEPROCESS* processObjectInOut,
    _In_ ULONG64 expectedCreateTime100ns
    )
/*++

Routine Description:

    Validate a referenced EPROCESS against the optional R3 snapshot creation
    time. Note: On failure, this function releases the reference and clears the output; the caller will not access an invalid object.

Arguments:

    ProcessObjectInOut - Referenced target object owned by the caller.
    ExpectedCreateTime100ns - Optional stable identity timestamp.

Return Value:

    STATUS_SUCCESS when identity matches, otherwise STATUS_INVALID_CID.

--*/
{
    ULONG64 observedCreateTime100ns = 0ULL;

    /* Note: Null output indicates the resolver did not return a valid object as agreed. */
    if (processObjectInOut == NULL || *processObjectInOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Note: Zero values are used for compatibility with legacy callers lacking a stable snapshot. */
    if (expectedCreateTime100ns == 0ULL) {
        return STATUS_SUCCESS;
    }

    /* Note: Read the timestamp from the object resolved by the driver to avoid being misled by hidden links via R3 OpenProcess. */
    observedCreateTime100ns =
        (ULONG64)PsGetProcessCreateTimeQuadPart(*processObjectInOut);
    if (observedCreateTime100ns == expectedCreateTime100ns) {
        return STATUS_SUCCESS;
    }

    /* Note: Immediately release the reference if the identity does not match to prevent subsequent BreakOnTermination/APC writes. */
    ObDereferenceObject(*processObjectInOut);
    *processObjectInOut = NULL;
    return STATUS_INVALID_CID;
}

static NTSTATUS
kswordArkProcessFlagsReferenceProcessObject(
    _In_ ULONG processId,
    _In_ ULONG64 expectedCreateTime100ns,
    _Outptr_ PEPROCESS* processObjectOut
    )
{
    KswDynState dynState;
    ULONG uniqueProcessId = 0UL;
    ULONG visitedEntries = 0UL;
    NTSTATUS cidStatus = STATUS_SUCCESS;
    NTSTATUS activeStatus = STATUS_SUCCESS;
    NTSTATUS lookupStatus = STATUS_SUCCESS;

    if (processObjectOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *processObjectOut = NULL;
    RtlZeroMemory(&dynState, sizeof(dynState));
    kswordArkDynDataSnapshot(&dynState);

    cidStatus = kswordArkProcessFlagsReferenceProcessByCidTable(
        &dynState,
        processId,
        processObjectOut);
    if (NT_SUCCESS(cidStatus)) {
        return kswordArkProcessFlagsValidateReferencedIdentity(
            processObjectOut,
            expectedCreateTime100ns);
    }

    activeStatus = kswordArkCrossViewReferenceProcessByActiveList(
        &dynState,
        processId,
        0x00100000UL,
        processObjectOut,
        &uniqueProcessId,
        &visitedEntries);
    UNREFERENCED_PARAMETER(uniqueProcessId);
    UNREFERENCED_PARAMETER(visitedEntries);
    if (NT_SUCCESS(activeStatus)) {
        return kswordArkProcessFlagsValidateReferencedIdentity(
            processObjectOut,
            expectedCreateTime100ns);
    }

    lookupStatus = PsLookupProcessByProcessId(ULongToHandle(processId), processObjectOut);
    if (NT_SUCCESS(lookupStatus)) {
        return kswordArkProcessFlagsValidateReferencedIdentity(
            processObjectOut,
            expectedCreateTime100ns);
    }
    if (cidStatus != STATUS_PROCEDURE_NOT_FOUND &&
        cidStatus != STATUS_NOT_FOUND &&
        cidStatus != STATUS_NOT_SUPPORTED) {
        return cidStatus;
    }
    if (activeStatus != STATUS_PROCEDURE_NOT_FOUND &&
        activeStatus != STATUS_NOT_FOUND &&
        activeStatus != STATUS_NOT_SUPPORTED) {
        return activeStatus;
    }
    return lookupStatus;
}

/* Note: Opens the target process handle, intended solely for the official ZwSetInformationProcess entry point. */
static NTSTATUS
kswordArkProcessFlagsOpenProcessHandleByObject(
    _In_ PEPROCESS processObject,
    _In_ ACCESS_MASK desiredAccess,
    _Out_ HANDLE* processHandleOut
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    /* Note: Clear output parameters first; the failure branch will not leave an invalid handle. */
    if (processHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *processHandleOut = NULL;

    if (processObject == NULL || PsProcessType == NULL || *PsProcessType == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Note: PROCESS_SET_INFORMATION is sufficient to set BreakOnTermination. */
    status = ObOpenObjectByPointer(
        processObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        desiredAccess,
        *PsProcessType,
        KernelMode,
        processHandleOut);
    return status;
}

/* Note: Set or clear BreakOnTermination via ZwSetInformationProcess. */
static NTSTATUS
kswordArkProcessFlagsSetBreakOnTerminationByZw(
    _In_ PEPROCESS processObject,
    _In_ BOOLEAN enableBreakOnTermination
    )
{
    HANDLE processHandle = NULL;
    ULONG breakValue = enableBreakOnTermination ? 1UL : 0UL;
    KswordZwSetInformationProcessFn zwSetInformationProcess = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Note: Do not attempt hardcoded writes to EPROCESS.Flags when dynamic resolution fails. */
    zwSetInformationProcess = kswordArkDriverResolveZwSetInformationProcess();
    if (zwSetInformationProcess == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    /* Note: The official entry point requires a process handle to avoid relying on undocumented EPROCESS bit layouts. */
    status = kswordArkProcessFlagsOpenProcessHandleByObject(
        processObject,
        PROCESS_SET_INFORMATION,
        &processHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Note: After ZwSetInformationProcess succeeds, the target process's critical flag takes effect immediately. */
    status = zwSetInformationProcess(
        processHandle,
        KSWORD_ARK_PROCESS_INFORMATION_BREAK_ON_TERMINATION,
        &breakValue,
        sizeof(breakValue));

    /* Note: The kernel handle must be closed regardless of whether the setting succeeded. */
    ZwClose(processHandle);
    return status;
}

/* Note: Resolves EPROCESS.Flags offset; prefers PDB, but signature-based sources require re-validation. */
static NTSTATUS
kswordArkProcessFlagsResolveEprocessFlagsOffset(
    _In_ PEPROCESS processObject,
    _Out_ ULONG* flagsOffsetOut
    )
{
    KswDynState dynState;
    LONG runtimeOffset = -1;

    if (processObject == NULL || flagsOffsetOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *flagsOffsetOut = 0UL;

    /*
     * Note: Guessing offsets based on Windows version is prohibited here. A precise PDB profile takes priority;
     * if a PDB is missing, only runtime patterns decoded from the exported routine PsGetProcessExitProcessCalled
     * and re-validated with bit-level semantics against the current target EPROCESS are accepted.
     */
    RtlZeroMemory(&dynState, sizeof(dynState));
    kswordArkDynDataSnapshot(&dynState);
    if (dynState.kernel.epFlags == KSW_DYN_OFFSET_UNAVAILABLE ||
        dynState.kernel.epFlags == 0UL ||
        dynState.kernel.epFlags > KSWORD_ARK_EPROCESS_FLAGS_OFFSET_MAX ||
        (dynState.kernelSources.epFlags != KSW_DYN_FIELD_SOURCE_PDB_PROFILE &&
         dynState.kernelSources.epFlags != KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN)) {
        return STATUS_NOT_SUPPORTED;
    }

    if (dynState.kernelSources.epFlags == KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN) {
        runtimeOffset = kswordArkDriverResolveProcessFlagsOffset(processObject);
        if (runtimeOffset <= 0 || (ULONG)runtimeOffset != dynState.kernel.epFlags) {
            return STATUS_REVISION_MISMATCH;
        }
    }

    *flagsOffsetOut = dynState.kernel.epFlags;
    return STATUS_SUCCESS;
}

/* Note: Sets BreakOnTermination as a fallback by directly writing to EPROCESS.Flags. */
static NTSTATUS
kswordArkProcessFlagsSetBreakOnTerminationByEprocess(
    _In_ PEPROCESS processObject,
    _In_ BOOLEAN enableBreakOnTermination
    )
{
    ULONG flagsOffset = 0UL;
    volatile LONG* flagsAddress = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (processObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Note: Do not guess when offset resolution fails to avoid writing to other EPROCESS fields. */
    status = kswordArkProcessFlagsResolveEprocessFlagsOffset(processObject, &flagsOffset);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (flagsOffset == 0UL || flagsOffset > KSWORD_ARK_EPROCESS_FLAGS_OFFSET_MAX) {
        return STATUS_NOT_SUPPORTED;
    }

    __try {
        flagsAddress = (volatile LONG*)((PUCHAR)processObject + flagsOffset);
        if (enableBreakOnTermination) {
            (VOID)InterlockedOr(
                flagsAddress,
                (LONG)KSWORD_ARK_EPROCESS_FLAGS_BREAK_ON_TERMINATION_MASK);
        }
        else {
            (VOID)InterlockedAnd(
                flagsAddress,
                (LONG)(~KSWORD_ARK_EPROCESS_FLAGS_BREAK_ON_TERMINATION_MASK));
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
}

/* Note: First use official ZwSetInformationProcess; fall back to EPROCESS.Flags on failure. */
static NTSTATUS
kswordArkProcessFlagsSetBreakOnTermination(
    _In_ ULONG processId,
    _In_ ULONG64 expectedCreateTime100ns,
    _In_ BOOLEAN enableBreakOnTermination
    )
{
    PEPROCESS processObject = NULL;
    NTSTATUS zwStatus = STATUS_SUCCESS;
    NTSTATUS directStatus = STATUS_SUCCESS;

    zwStatus = kswordArkProcessFlagsReferenceProcessObject(
        processId,
        expectedCreateTime100ns,
        &processObject);
    if (!NT_SUCCESS(zwStatus)) {
        return zwStatus;
    }

    zwStatus = kswordArkProcessFlagsSetBreakOnTerminationByZw(
        processObject,
        enableBreakOnTermination);
    if (NT_SUCCESS(zwStatus)) {
        ObDereferenceObject(processObject);
        return zwStatus;
    }

    /* Note: PPL/restricted handle paths may reject ZwOpenProcess, so R0 direct write is used as a fallback. */
    directStatus = kswordArkProcessFlagsSetBreakOnTerminationByEprocess(
        processObject,
        enableBreakOnTermination);
    ObDereferenceObject(processObject);
    if (NT_SUCCESS(directStatus)) {
        return directStatus;
    }

    /* Note: Prefer preserving the official path failure reason; if the official entry is missing, return the fallback reason. */
    if (zwStatus == STATUS_PROCEDURE_NOT_FOUND || zwStatus == STATUS_NOT_SUPPORTED) {
        return directStatus;
    }
    return zwStatus;
}

/* Note: Currently, only the ETHREAD offset verified by common builds for x64 is used. */
static NTSTATUS
kswordArkProcessFlagsResolveApcQueueableOffset(
    _Out_ ULONG* offsetOut
    )
{
    /* Note: The output is a ULONG offset; the caller will further limit the write size. */
    if (offsetOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *offsetOut = 0UL;

#if defined(_M_X64)
    /* Note: This offset comes from ETHREAD.CrossThreadFlags; not used on unknown architectures. */
    *offsetOut = KSWORD_ARK_ETHREAD_APC_QUEUEABLE_OFFSET_X64;
    return STATUS_SUCCESS;
#else
    /* Note: ARM64/x86 do not maintain offset tables; reject execution to avoid writing to thread objects. */
    return STATUS_NOT_SUPPORTED;
#endif
}

/* Note: Clear the ApcQueueable bit for a single ETHREAD; return an error code if an exception occurs. */
static NTSTATUS
kswordArkProcessFlagsClearThreadApcQueueable(
    _In_ PETHREAD threadObject,
    _In_ ULONG apcQueueableOffset,
    _Out_ BOOLEAN* changedOut
    )
{
    volatile LONG* fieldAddress = NULL;
    LONG oldValue = 0;
    LONG newValue = 0;

    /* Note: ChangedOut indicates to the caller whether the value actually transitioned from 1 to 0. */
    if (threadObject == NULL || changedOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *changedOut = FALSE;

    /* Note: An offset that is too large indicates an untrustworthy layout; reject immediately. */
    if (apcQueueableOffset > 0x1000UL) {
        return STATUS_NOT_SUPPORTED;
    }

    __try {
        /* Note: Clear the field atomically at the LONG bit level to avoid overwriting other bits set concurrently. */
        fieldAddress = (volatile LONG*)((PUCHAR)threadObject + apcQueueableOffset);
        oldValue = InterlockedAnd(fieldAddress, (LONG)(~KSWORD_ARK_ETHREAD_APC_QUEUEABLE_MASK));
        newValue = oldValue & (LONG)(~KSWORD_ARK_ETHREAD_APC_QUEUEABLE_MASK);
        *changedOut = ((oldValue ^ newValue) & (LONG)KSWORD_ARK_ETHREAD_APC_QUEUEABLE_MASK) != 0 ? TRUE : FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

/* Note: Iterate over target process threads and clear the ApcQueueable bit on each thread. */
static NTSTATUS
kswordArkProcessFlagsDisableApcInsertion(
    _In_ ULONG processId,
    _In_ ULONG64 expectedCreateTime100ns,
    _Out_ ULONG* touchedThreadCountOut
    )
{
    PEPROCESS processObject = NULL;
    PETHREAD threadCursor = NULL;
    ULONG apcQueueableOffset = 0UL;
    ULONG touchedThreadCount = 0UL;
    KswordPsGetNextProcessThreadFn psGetNextProcessThread = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS lastFailureStatus = STATUS_SUCCESS;

    /* Note: Output thread count is used for UI to display the scope of impact. */
    if (touchedThreadCountOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *touchedThreadCountOut = 0UL;

    /* Note: Resolve the offset first; do not enter the object write path on unknown platforms. */
    status = kswordArkProcessFlagsResolveApcQueueableOffset(&apcQueueableOffset);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Note: Thread enumeration relies on psGetNextProcessThread; no PID guessing or scanning is performed. */
    psGetNextProcessThread = kswordArkProcessFlagsResolvePsGetNextProcessThread();
    if (psGetNextProcessThread == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    /* Note: Reference the target EPROCESS to ensure the process object remains valid during thread enumeration. */
    status = kswordArkProcessFlagsReferenceProcessObject(
        processId,
        expectedCreateTime100ns,
        &processObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Note: psGetNextProcessThread returns an ETHREAD with a reference; it must be released within the loop. */
    threadCursor = psGetNextProcessThread(processObject, NULL);
    while (threadCursor != NULL) {
        PETHREAD nextThread = psGetNextProcessThread(processObject, threadCursor);
        BOOLEAN changed = FALSE;
        NTSTATUS threadStatus = STATUS_SUCCESS;

        /* Note: Independent SEH per thread; single-thread exceptions do not block processing of remaining threads. */
        threadStatus = kswordArkProcessFlagsClearThreadApcQueueable(
            threadCursor,
            apcQueueableOffset,
            &changed);
        if (NT_SUCCESS(threadStatus)) {
            if (changed && touchedThreadCount != MAXULONG) {
                touchedThreadCount += 1UL;
            }
        }
        else {
            lastFailureStatus = threadStatus;
        }

        /* Note: Advance to the next item after releasing the current thread reference. */
        ObDereferenceObject(threadCursor);
        threadCursor = nextThread;
    }

    /* Note: Release the process reference; thread enumeration has completed. */
    ObDereferenceObject(processObject);
    *touchedThreadCountOut = touchedThreadCount;

    /* Note: Return the last failure status if all threads fail; partial success is indicated by the response status. */
    if (touchedThreadCount == 0UL && !NT_SUCCESS(lastFailureStatus)) {
        return lastFailureStatus;
    }
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverSetProcessSpecialFlags(
    _In_ ULONG processId,
    _In_ ULONG action,
    _In_ ULONG flags,
    _In_ ULONG64 expectedCreateTime100ns,
    _Out_ ULONG* operationStatusOut,
    _Out_ ULONG* appliedFlagsOut,
    _Out_ ULONG* touchedThreadCountOut
    )
/*++

Routine Description:

    Apply dangerous process special flags from R3. Note: Currently supports toggling BreakOnTermination
    and clearing APC insertion permissions from existing threads of the target process.

Arguments:

    ProcessId - target PID.
    Action - KSWORD_ARK_PROCESS_SPECIAL_ACTION_*。
    Flags - Reserved policy bits; currently only recorded without changing semantics.
    ExpectedCreateTime100ns: Optional process creation time; if non-zero, it must match exactly.
    OperationStatusOut - Returned protocol status.
    AppliedFlagsOut - Returns the semantic flags that have been applied.
    TouchedThreadCountOut: returns the actual number of threads modified when APCs were disabled.

Return Value:

    STATUS_SUCCESS indicates completion; failure returns the underlying NTSTATUS.

--*/
{
    ULONG touchedThreadCount = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Note: Flags are currently reserved; explicitly marked to suppress W4 unreferenced parameter warnings. */
    UNREFERENCED_PARAMETER(flags);

    if (operationStatusOut == NULL ||
        appliedFlagsOut == NULL ||
        touchedThreadCountOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *operationStatusOut = KSWORD_ARK_PROCESS_SPECIAL_STATUS_UNKNOWN;
    *appliedFlagsOut = 0UL;
    *touchedThreadCountOut = 0UL;

    if (processId == 0UL || processId <= 4UL) {
        *operationStatusOut = KSWORD_ARK_PROCESS_SPECIAL_STATUS_LOOKUP_FAILED;
        return STATUS_INVALID_PARAMETER;
    }

    if (action == KSWORD_ARK_PROCESS_SPECIAL_ACTION_ENABLE_BREAK_ON_TERMINATION ||
        action == KSWORD_ARK_PROCESS_SPECIAL_ACTION_DISABLE_BREAK_ON_TERMINATION) {
        const BOOLEAN kEnableBreak =
            (action == KSWORD_ARK_PROCESS_SPECIAL_ACTION_ENABLE_BREAK_ON_TERMINATION) ? TRUE : FALSE;

        /* Note: Prefer ZwSetInformationProcess; fall back to EPROCESS.Flags on failure. */
        status = kswordArkProcessFlagsSetBreakOnTermination(
            processId,
            expectedCreateTime100ns,
            kEnableBreak);
        if (NT_SUCCESS(status)) {
            *operationStatusOut = KSWORD_ARK_PROCESS_SPECIAL_STATUS_APPLIED;
            if (kEnableBreak) {
                *appliedFlagsOut |= KSWORD_ARK_PROCESS_SPECIAL_FLAG_BREAK_ON_TERMINATION;
            }
        }
        else if (status == STATUS_PROCEDURE_NOT_FOUND || status == STATUS_NOT_SUPPORTED) {
            *operationStatusOut = KSWORD_ARK_PROCESS_SPECIAL_STATUS_UNSUPPORTED;
        }
        else {
            *operationStatusOut = KSWORD_ARK_PROCESS_SPECIAL_STATUS_OPERATION_FAILED;
        }
        return status;
    }

    if (action == KSWORD_ARK_PROCESS_SPECIAL_ACTION_DISABLE_APC_INSERTION) {
        /* Note: Disabling APC insertion is a thread-level batch write; return the count of changed threads for R3 auditing. */
        status = kswordArkProcessFlagsDisableApcInsertion(
            processId,
            expectedCreateTime100ns,
            &touchedThreadCount);
        *touchedThreadCountOut = touchedThreadCount;
        if (NT_SUCCESS(status)) {
            *operationStatusOut = KSWORD_ARK_PROCESS_SPECIAL_STATUS_APPLIED;
            *appliedFlagsOut |= KSWORD_ARK_PROCESS_SPECIAL_FLAG_APC_INSERT_DISABLED;
        }
        else if (status == STATUS_PROCEDURE_NOT_FOUND || status == STATUS_NOT_SUPPORTED) {
            *operationStatusOut = KSWORD_ARK_PROCESS_SPECIAL_STATUS_UNSUPPORTED;
        }
        else {
            *operationStatusOut = KSWORD_ARK_PROCESS_SPECIAL_STATUS_OPERATION_FAILED;
        }
        return status;
    }

    *operationStatusOut = KSWORD_ARK_PROCESS_SPECIAL_STATUS_OPERATION_FAILED;
    return STATUS_INVALID_PARAMETER;
}
