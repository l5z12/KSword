/*++

Module Name:

    process_terminate.c

Abstract:

    Process termination pipeline for KswordARK.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../platform/process_resolver.h"
#include "process_crossview.h"
#include "process_extended.h"
#include <ntstrsafe.h>
#include <stdarg.h>

// Note: This file hosts the multi-stage backend for process termination to prevent process_actions.c from growing further.
// Note: Public entry point accepts optional creation time to prevent PID/CID reuse from causing false positives after parsing EPROCESS.

NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE processId,
    _Outptr_ PEPROCESS* process
    );

NTSYSAPI
PETHREAD
NTAPI
PsGetNextProcessThread(
    _In_ PEPROCESS process,
    _In_opt_ PETHREAD thread
    );

NTSYSAPI
NTSTATUS
NTAPI
PsLookupThreadByThreadId(
    _In_ HANDLE threadId,
    _Outptr_ PETHREAD* thread
    );

NTSYSAPI
PEPROCESS
NTAPI
PsGetThreadProcess(
    _In_ PETHREAD thread
    );

// Note: Exposes a kernel routine returning the stable creation time of the target EPROCESS.
NTKERNELAPI
LONGLONG
NTAPI
PsGetProcessCreateTimeQuadPart(
    _In_ PEPROCESS process
    );

extern NTKERNELAPI PEPROCESS PsInitialSystemProcess;

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

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE (0x0001)
#endif

#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE (0x0001)
#endif

#ifndef STATUS_PROCESS_IS_TERMINATING
#define STATUS_PROCESS_IS_TERMINATING ((NTSTATUS)0xC000010AL)
#endif

#ifndef STATUS_THREAD_IS_TERMINATING
#define STATUS_THREAD_IS_TERMINATING ((NTSTATUS)0xC000004BL)
#endif

#define KSWORD_ARK_ENUM_PID_STEP 4UL
#define KSWORD_ARK_TERMINATE_WAIT_MAX_MS 500UL
#define KSWORD_ARK_TERMINATE_WAIT_FALLBACK_MS 800UL
#define KSWORD_ARK_TERMINATE_SCAN_CALL_MAX_BYTES 0x240UL
#define KSWORD_ARK_THREAD_SCAN_MAX_ID 0x00800000UL
#define KSWORD_ARK_TERMINATE_CID_WALK_MAX_NODES 0x00100000UL

#ifndef STATUS_TIMEOUT
#define STATUS_TIMEOUT ((NTSTATUS)0x00000102L)
#endif

#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif

typedef PETHREAD(NTAPI* KswordPsGetNextProcessThreadFn)(
    _In_ PEPROCESS process,
    _In_opt_ PETHREAD thread
    );

typedef NTSTATUS(NTAPI* KswordPspTerminateThreadByPointerFn)(
    _In_ PETHREAD thread,
    _In_ NTSTATUS exitStatus,
    _In_ BOOLEAN selfTerminate,
    _In_opt_ PVOID reserved
    );

typedef NTSTATUS(NTAPI* KswordZwOrNtTerminateThreadFn)(
    _In_opt_ HANDLE threadHandle,
    _In_ NTSTATUS exitStatus
    );

typedef enum KswordArkTerminateProcessResolveSource
{
    kKswordArkTerminateResolveUnknown = 0,
    kKswordArkTerminateResolveDirectCid = 1,
    kKswordArkTerminateResolveCidTableCid = 2,
    kKswordArkTerminateResolveCidTableUniquePid = 3,
    kKswordArkTerminateResolveActiveList = 4
} KswordArkTerminateProcessResolveSource;

typedef struct KswordArkTerminateProcessTarget
{
    PEPROCESS processObject;
    ULONG requestedProcessId;
    ULONG cidProcessId;
    ULONG uniqueProcessId;
    KswordArkTerminateProcessResolveSource resolveSource;
} KswordArkTerminateProcessTarget;

typedef struct KswordArkTerminateCidMatchContext
{
    const KswDynState* dynState;
    ULONG requestedProcessId;
    PEPROCESS processObject;
    ULONG cidProcessId;
    ULONG uniqueProcessId;
    KswordArkTerminateProcessResolveSource resolveSource;
    NTSTATUS lastStatus;
} KswordArkTerminateCidMatchContext;

static VOID
kswordArkDriverLogTerminateMessageV(
    _In_opt_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    _In_ va_list arguments
    )
{
    CHAR messageBuffer[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };

    if (device == NULL || levelText == NULL || formatText == NULL) {
        return;
    }

    if (NT_SUCCESS(RtlStringCbVPrintfA(
        messageBuffer,
        sizeof(messageBuffer),
        formatText,
        arguments))) {
        (void)kswordArkDriverEnqueueLogFrame(device, levelText, messageBuffer);
    }
}

VOID
kswordArkDriverLogTerminateMessage(
    _In_opt_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
{
    va_list arguments;

    va_start(arguments, formatText);
    kswordArkDriverLogTerminateMessageV(device, levelText, formatText, arguments);
    va_end(arguments);
}

static BOOLEAN
kswordArkDriverIsResolverMissingStatus(
    _In_ NTSTATUS status
    )
{
    return (status == STATUS_PROCEDURE_NOT_FOUND ||
        status == STATUS_NOT_IMPLEMENTED ||
        status == STATUS_NOT_FOUND) ? TRUE : FALSE;
}

static VOID
kswordArkDriverMergeTerminateFailure(
    _In_ NTSTATUS candidateStatus,
    _Inout_ NTSTATUS* aggregateStatus
    )
{
    if (aggregateStatus == NULL) {
        return;
    }
    if (NT_SUCCESS(candidateStatus)) {
        return;
    }
    if (candidateStatus == STATUS_PROCESS_IS_TERMINATING ||
        candidateStatus == STATUS_THREAD_IS_TERMINATING) {
        return;
    }

    if (NT_SUCCESS(*aggregateStatus) || *aggregateStatus == STATUS_UNSUCCESSFUL) {
        *aggregateStatus = candidateStatus;
        return;
    }

    if (kswordArkDriverIsResolverMissingStatus(*aggregateStatus) &&
        !kswordArkDriverIsResolverMissingStatus(candidateStatus)) {
        *aggregateStatus = candidateStatus;
        return;
    }
}

static KswordPsGetNextProcessThreadFn
kswordArkDriverResolvePsGetNextProcessThread(
    VOID
    )
{
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"PsGetNextProcessThread");
    return (KswordPsGetNextProcessThreadFn)MmGetSystemRoutineAddress(&routineName);
}

static PUCHAR
kswordArkDriverResolveKernelRoutineAddress(
    _In_z_ PCWSTR routineNameArg
    )
/*++

Routine Description:

    Resolve one optional ntoskrnl routine by name.

Arguments:

    RoutineName - NUL-terminated routine name.

Return Value:

    Routine address on success; NULL when the routine is not exported.

--*/
{
    UNICODE_STRING routineName;

    if (routineNameArg == NULL) {
        return NULL;
    }
    RtlInitUnicodeString(&routineName, routineNameArg);
    return (PUCHAR)MmGetSystemRoutineAddress(&routineName);
}

static BOOLEAN
kswordArkDriverCallSiteHasR8TrueHint(
    _In_reads_bytes_(routineOffset) const UCHAR* routineAddress,
    _In_ ULONG routineOffset
    )
/*++

Routine Description:

    Check whether bytes before a CALL look like "SelfTerminate = TRUE" setup.
    Note: PsTerminateSystemThread typically sets r8/r8b to 1 before calling PspTerminateThreadByPointer;
    this weak feature is used only to prioritize candidate targets across multiple CALLs.

Arguments:

    RoutineAddress - Base of the routine being scanned.
    RoutineOffset - Offset of the candidate CALL opcode.

Return Value:

    TRUE when a nearby mov r8{b,d},1 pattern is present; otherwise FALSE.

--*/
{
    ULONG windowStart = 0UL;
    ULONG index = 0UL;

    if (routineAddress == NULL || routineOffset == 0UL) {
        return FALSE;
    }

    windowStart = (routineOffset > 48UL) ? (routineOffset - 48UL) : 0UL;
    for (index = windowStart; index < routineOffset; ++index) {
        if (index + 3UL <= routineOffset &&
            routineAddress[index] == 0x41U &&
            routineAddress[index + 1UL] == 0xB0U &&
            routineAddress[index + 2UL] == 0x01U) {
            return TRUE;
        }
        if (index + 6UL <= routineOffset &&
            routineAddress[index] == 0x41U &&
            routineAddress[index + 1UL] == 0xB8U &&
            routineAddress[index + 2UL] == 0x01U &&
            routineAddress[index + 3UL] == 0x00U &&
            routineAddress[index + 4UL] == 0x00U &&
            routineAddress[index + 5UL] == 0x00U) {
            return TRUE;
        }
    }
    return FALSE;
}

static KswordPspTerminateThreadByPointerFn
kswordArkDriverScanRoutineForTerminateThreadCall(
    _In_z_ PCWSTR routineName,
    _In_ BOOLEAN preferSelfTerminateHint,
    _In_ BOOLEAN preferLastCandidate
    )
/*++

Routine Description:

    Scan one exported routine for a near CALL target that is likely
    PspTerminateThreadByPointer. Note: Some systems do not export Nt/ZwTerminateThread;
    PsTerminateSystemThread is still typically exported and internally calls the same private termination routine.

Arguments:

    RoutineName - Exported routine to scan.
    PreferSelfTerminateHint - TRUE to prefer CALL sites preceded by r8=1.
    PreferLastCandidate - TRUE to keep scanning and return the last plausible
        CALL when no stronger hint was found.

Return Value:

    Candidate private routine pointer or NULL.

--*/
{
    PUCHAR routineAddress = kswordArkDriverResolveKernelRoutineAddress(routineName);
    KswordPspTerminateThreadByPointerFn selectedRoutine = NULL;
    ULONG scanOffset = 0UL;

    if (routineAddress == NULL) {
        return NULL;
    }

    for (scanOffset = 0UL; scanOffset + 5UL < KSWORD_ARK_TERMINATE_SCAN_CALL_MAX_BYTES; ++scanOffset) {
        LONG relativeOffset = 0;
        PUCHAR targetAddress = NULL;
        ULONG_PTR routineValue = (ULONG_PTR)routineAddress;
        ULONG_PTR targetValue = 0;
        ULONG_PTR delta = 0;

        if (routineAddress[scanOffset] == 0xC3U || routineAddress[scanOffset] == 0xCCU) {
            break;
        }
        if (routineAddress[scanOffset] != 0xE8U) {
            continue;
        }

        RtlCopyMemory(
            &relativeOffset,
            routineAddress + scanOffset + 1UL,
            sizeof(relativeOffset));

        targetAddress = routineAddress + scanOffset + 5UL + relativeOffset;
        targetValue = (ULONG_PTR)targetAddress;
        delta = (targetValue > routineValue)
            ? (targetValue - routineValue)
            : (routineValue - targetValue);
        if (delta > 0x400000UL) {
            continue;
        }
        if (!MmIsAddressValid(targetAddress)) {
            continue;
        }

        if (preferSelfTerminateHint &&
            kswordArkDriverCallSiteHasR8TrueHint(routineAddress, scanOffset)) {
            return (KswordPspTerminateThreadByPointerFn)targetAddress;
        }

        selectedRoutine = (KswordPspTerminateThreadByPointerFn)targetAddress;
        if (!preferLastCandidate) {
            return selectedRoutine;
        }
    }

    return selectedRoutine;
}

static KswordPspTerminateThreadByPointerFn
kswordArkDriverResolvePspTerminateThreadByPointer(
    VOID
    )
{
    static KswordPspTerminateThreadByPointerFn cachedRoutine = NULL;
    static BOOLEAN hasResolved = FALSE;
    UNICODE_STRING routineName;

    if (hasResolved) {
        return cachedRoutine;
    }
    hasResolved = TRUE;

    // Try direct lookup first (some private symbols can surface on test kernels).
    RtlInitUnicodeString(&routineName, L"PspTerminateThreadByPointer");
    cachedRoutine = (KswordPspTerminateThreadByPointerFn)MmGetSystemRoutineAddress(&routineName);
    if (cachedRoutine != NULL) {
        return cachedRoutine;
    }

    // Dynamic locate fallback #1: scan Nt/ZwTerminateThread when exported.
    cachedRoutine = kswordArkDriverScanRoutineForTerminateThreadCall(
        L"NtTerminateThread",
        FALSE,
        FALSE);
    if (cachedRoutine != NULL) {
        return cachedRoutine;
    }
    cachedRoutine = kswordArkDriverScanRoutineForTerminateThreadCall(
        L"ZwTerminateThread",
        FALSE,
        FALSE);
    if (cachedRoutine != NULL) {
        return cachedRoutine;
    }

    // Dynamic locate fallback #2: PsTerminateSystemThread is commonly exported.
    cachedRoutine = kswordArkDriverScanRoutineForTerminateThreadCall(
        L"PsTerminateSystemThread",
        TRUE,
        TRUE);

    return cachedRoutine;
}

static KswordZwOrNtTerminateThreadFn
kswordArkDriverResolveZwOrNtTerminateThread(
    VOID
    )
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"ZwTerminateThread");
    {
        KswordZwOrNtTerminateThreadFn routineAddress =
            (KswordZwOrNtTerminateThreadFn)MmGetSystemRoutineAddress(&routineName);
        if (routineAddress != NULL) {
            return routineAddress;
        }
    }

    RtlInitUnicodeString(&routineName, L"NtTerminateThread");
    return (KswordZwOrNtTerminateThreadFn)MmGetSystemRoutineAddress(&routineName);
}

static PCSTR
kswordArkDriverTerminateResolveSourceText(
    _In_ KswordArkTerminateProcessResolveSource resolveSource
    )
/*++

Routine Description:

    Convert the internal terminate-target resolver source into a compact log
    string. Note: this text is used only for R0 logs; the IOCTL protocol retains PID input semantics.

Arguments:

    ResolveSource - Internal resolver source enum.

Return Value:

    Static NUL-terminated string.

--*/
{
    switch (resolveSource) {
    case kKswordArkTerminateResolveDirectCid:
        return "DirectCid";
    case kKswordArkTerminateResolveCidTableCid:
        return "CidTableCid";
    case kKswordArkTerminateResolveCidTableUniquePid:
        return "CidTableUniquePid";
    case kKswordArkTerminateResolveActiveList:
        return "ActiveList";
    default:
        return "Unknown";
    }
}

static NTSTATUS
kswordArkDriverReadTerminateUniqueProcessId(
    _In_opt_ const KswDynState* dynState,
    _In_ PEPROCESS processObject,
    _Out_ ULONG* uniqueProcessIdOut
    )
/*++

Routine Description:

    Read _EPROCESS.UniqueProcessId from a process object for termination target
    matching. Note: In hide scenarios, the PID passed from R3 may be a fake UniqueProcessId written by the
    adversary; this function only reads fields and does not restore the linked list or modify objects.

Arguments:

    DynState - Optional DynData snapshot that contains EpUniqueProcessId.
    ProcessObject - Referenced candidate EPROCESS.
    UniqueProcessIdOut - Receives the current UniqueProcessId value.

Return Value:

    STATUS_SUCCESS when the field was read; otherwise a validation/DynData/read
    status.

--*/
{
    PVOID uniqueProcessId = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (processObject == NULL || uniqueProcessIdOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *uniqueProcessIdOut = 0UL;

    if (dynState == NULL ||
        !dynState->initialized ||
        !kswordArkCrossViewOffsetPresent(dynState->kernel.epUniqueProcessId)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    status = kswordArkCrossViewReadPointerField(
        processObject,
        dynState->kernel.epUniqueProcessId,
        &uniqueProcessId);
    if (NT_SUCCESS(status)) {
        *uniqueProcessIdOut = HandleToULong(uniqueProcessId);
    }
    return status;
}

static VOID
kswordArkDriverTerminateCidMatchCallback(
    _In_ const KswCrossviewCidEntry* entry,
    _Inout_opt_ PVOID context
    )
/*++

Routine Description:

    CID-table walker callback used by the terminate resolver. Note: The callback accepts only process objects already
    validated and referenced by the walker via PsProcessType; upon a match, it increments the reference count once
    more to ensure the termination chain retains the object after the walker releases its temporary reference.

Arguments:

    Entry - Read-only CID walker payload.
    Context - KswordArkTerminateCidMatchContext.

Return Value:

    None. The walker continues scanning; later callbacks are ignored after the
    first match.

--*/
{
    KswordArkTerminateCidMatchContext* matchContext =
        (KswordArkTerminateCidMatchContext*)context;
    PEPROCESS processObject = NULL;
    ULONG publicUniqueProcessId = 0UL;
    ULONG privateUniqueProcessId = 0UL;
    NTSTATUS privatePidStatus = STATUS_SUCCESS;
    BOOLEAN matched = FALSE;
    KswordArkTerminateProcessResolveSource resolveSource =
        kKswordArkTerminateResolveUnknown;

    if (matchContext == NULL ||
        matchContext->processObject != NULL ||
        entry == NULL ||
        !entry->referenced ||
        entry->object == NULL) {
        return;
    }

    processObject = (PEPROCESS)entry->object;
    publicUniqueProcessId = HandleToULong(PsGetProcessId(processObject));
    privateUniqueProcessId = publicUniqueProcessId;
    privatePidStatus = kswordArkDriverReadTerminateUniqueProcessId(
        matchContext->dynState,
        processObject,
        &privateUniqueProcessId);
    if (!NT_SUCCESS(privatePidStatus) &&
        privatePidStatus != STATUS_PROCEDURE_NOT_FOUND &&
        NT_SUCCESS(matchContext->lastStatus)) {
        matchContext->lastStatus = privatePidStatus;
    }

    if (entry->cidValue == matchContext->requestedProcessId) {
        matched = TRUE;
        resolveSource = kKswordArkTerminateResolveCidTableCid;
    }
    else if (publicUniqueProcessId == matchContext->requestedProcessId ||
        privateUniqueProcessId == matchContext->requestedProcessId) {
        matched = TRUE;
        resolveSource = kKswordArkTerminateResolveCidTableUniquePid;
    }

    if (!matched) {
        return;
    }

    ObReferenceObject(processObject);
    matchContext->processObject = processObject;
    matchContext->cidProcessId = entry->cidValue;
    matchContext->uniqueProcessId = privateUniqueProcessId;
    matchContext->resolveSource = resolveSource;
    matchContext->lastStatus = STATUS_SUCCESS;
}

static VOID
kswordArkDriverReleaseTerminateTarget(
    _Inout_ KswordArkTerminateProcessTarget* target
    )
/*++

Routine Description:

    Release the process reference held by a terminate target descriptor.

Arguments:

    Target - Mutable target descriptor.

Return Value:

    None. The descriptor is zeroed after dereferencing.

--*/
{
    if (target == NULL) {
        return;
    }
    if (target->processObject != NULL) {
        ObDereferenceObject(target->processObject);
    }
    RtlZeroMemory(target, sizeof(*target));
}

static NTSTATUS
kswordArkDriverResolveTerminateTargetByCidTable(
    _In_opt_ WDFDEVICE device,
    _In_ ULONG processId,
    _Out_ KswordArkTerminateProcessTarget* target
    )
/*++

Routine Description:

    Resolve a termination target through PspCidTable when direct lookup by the
    Caller-supplied PID fails. Note: This path covers the hidden scenario where the CID table still
    retains the original PID, but EPROCESS.UniqueProcessId has been changed to a fake PID; it only
    reads the CID table and references the matched EPROCESS without touching ActiveProcessLinks.

Arguments:

    Device - Optional device used for diagnostic logging.
    ProcessId - PID-like identity supplied through the existing IOCTL.
    Target - Receives a referenced process object and resolved identities.

Return Value:

    STATUS_SUCCESS when a process object was found; otherwise lookup/walk status.

--*/
{
    KswDynState dynState;
    KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS fieldOffsets;
    KswordArkTerminateCidMatchContext matchContext;
    PVOID pspCidTableAddress = NULL;
    ULONG64 missingCapabilityMask = 0ULL;
    ULONG visitedEntries = 0UL;
    BOOLEAN usedDynDataGlobal = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (target == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&dynState, sizeof(dynState));
    RtlZeroMemory(&fieldOffsets, sizeof(fieldOffsets));
    RtlZeroMemory(&matchContext, sizeof(matchContext));
    kswordArkDynDataSnapshot(&dynState);
    kswordArkCrossViewFillFieldOffsets(&dynState, &fieldOffsets);

    if (PsProcessType == NULL || *PsProcessType == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    status = kswordArkCrossViewResolvePspCidTableAddress(
        &dynState,
        &fieldOffsets,
        &pspCidTableAddress,
        &missingCapabilityMask,
        &usedDynDataGlobal);
    if (!NT_SUCCESS(status) || pspCidTableAddress == NULL) {
        kswordArkDriverLogTerminateMessage(
            device,
            "Warn",
            "R0 terminate CID resolver unavailable: requestPid=%lu, status=0x%08X, missingCaps=0x%I64X.",
            (unsigned long)processId,
            (unsigned int)status,
            missingCapabilityMask);
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    matchContext.dynState = &dynState;
    matchContext.requestedProcessId = processId;
    matchContext.lastStatus = STATUS_NOT_FOUND;
    status = kswordArkCrossViewWalkCidTable(
        &dynState,
        pspCidTableAddress,
        *PsProcessType,
        KSWORD_ARK_TERMINATE_CID_WALK_MAX_NODES,
        kswordArkDriverTerminateCidMatchCallback,
        &matchContext,
        &visitedEntries);

    kswordArkDriverLogTerminateMessage(
        device,
        matchContext.processObject != NULL ? "Info" : "Warn",
        "R0 terminate CID resolver scan: requestPid=%lu, pspCid=%p, usedDyn=%u, visited=%lu, status=0x%08X, match=%p, cid=%lu, unique=%lu, source=%s.",
        (unsigned long)processId,
        pspCidTableAddress,
        usedDynDataGlobal ? 1U : 0U,
        (unsigned long)visitedEntries,
        (unsigned int)status,
        matchContext.processObject,
        (unsigned long)matchContext.cidProcessId,
        (unsigned long)matchContext.uniqueProcessId,
        kswordArkDriverTerminateResolveSourceText(matchContext.resolveSource));

    if (matchContext.processObject == NULL) {
        if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) {
            return status;
        }
        return matchContext.lastStatus;
    }

    target->processObject = matchContext.processObject;
    target->requestedProcessId = processId;
    target->cidProcessId = matchContext.cidProcessId;
    target->uniqueProcessId = matchContext.uniqueProcessId;
    target->resolveSource = matchContext.resolveSource;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkDriverResolveTerminateTargetByActiveList(
    _In_opt_ WDFDEVICE device,
    _In_ ULONG processId,
    _Out_ KswordArkTerminateProcessTarget* target
    )
/*++

Routine Description:

    Resolve a termination target through ActiveProcessLinks. Note: When the target hooks or
    tampering with NtOpenProcess, ZwOpenProcess, PsLookupProcessByProcessId, or PspCidTable evidence
    is incomplete, this path can still obtain an EPROCESS reference from the active process list.

Arguments:

    Device - Optional device used for diagnostic logging.
    ProcessId - PID-like identity supplied through the existing IOCTL.
    Target - Receives a referenced process object and resolved identities.

Return Value:

    STATUS_SUCCESS when a process object was found; otherwise list-walk status.

--*/
{
    KswDynState dynState;
    PEPROCESS processObject = NULL;
    ULONG uniqueProcessId = 0UL;
    ULONG visitedEntries = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (target == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&dynState, sizeof(dynState));
    kswordArkDynDataSnapshot(&dynState);

    status = kswordArkCrossViewReferenceProcessByActiveList(
        &dynState,
        processId,
        KSWORD_ARK_TERMINATE_CID_WALK_MAX_NODES,
        &processObject,
        &uniqueProcessId,
        &visitedEntries);

    kswordArkDriverLogTerminateMessage(
        device,
        NT_SUCCESS(status) ? "Info" : "Warn",
        "R0 terminate active-list resolver: requestPid=%lu, visited=%lu, status=0x%08X, match=%p, unique=%lu.",
        (unsigned long)processId,
        (unsigned long)visitedEntries,
        (unsigned int)status,
        processObject,
        (unsigned long)uniqueProcessId);

    if (!NT_SUCCESS(status) || processObject == NULL) {
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    target->processObject = processObject;
    target->requestedProcessId = processId;
    target->cidProcessId = HandleToULong(PsGetProcessId(processObject));
    target->uniqueProcessId = uniqueProcessId;
    target->resolveSource = kKswordArkTerminateResolveActiveList;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkDriverResolveTerminateTarget(
    _In_opt_ WDFDEVICE device,
    _In_ ULONG processId,
    _Out_ KswordArkTerminateProcessTarget* target
    )
/*++

Routine Description:

    Resolve the process object used by the whole R0 termination pipeline.
    Note: Prioritize direct lookup by CID/PID. If the caller passes a fake PID written to
    UniqueProcessId, fall back to a full walk of the CID table to reverse-lookup the object.

Arguments:

    Device - Optional device used for diagnostic logging.
    ProcessId - PID-like value from R3.
    Target - Receives the referenced process object.

Return Value:

    STATUS_SUCCESS when Target owns a reference; otherwise lookup status.

--*/
{
    PEPROCESS processObject = NULL;
    ULONG uniqueProcessId = 0UL;
    KswDynState dynState;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS cidTableStatus = STATUS_SUCCESS;
    NTSTATUS activeListStatus = STATUS_SUCCESS;
    NTSTATUS directLookupStatus = STATUS_SUCCESS;

    if (target == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(target, sizeof(*target));

    cidTableStatus = kswordArkDriverResolveTerminateTargetByCidTable(
        device,
        processId,
        target);
    if (NT_SUCCESS(cidTableStatus)) {
        return STATUS_SUCCESS;
    }

    /*
     * Note:
     * - Termination is a low-frequency, high-risk action; prioritize completing the PspCidTable evidence chain.
     * - Falls back only when the CID table resolver lacks DynData, is restricted by the system, or fails to match.
     *   PsLookupProcessByProcessId；
     * - This ensures that when PsLookup is inline hooked, the main path is unaffected, with impact limited at most to the final fallback.
     */
    kswordArkDriverLogTerminateMessage(
        device,
        "Warn",
        "R0 terminate CID-first resolver failed: requestPid=%lu, status=0x%08X; falling back to ActiveProcessLinks.",
        (unsigned long)processId,
        (unsigned int)cidTableStatus);

    activeListStatus = kswordArkDriverResolveTerminateTargetByActiveList(
        device,
        processId,
        target);
    if (NT_SUCCESS(activeListStatus)) {
        return STATUS_SUCCESS;
    }

    kswordArkDriverLogTerminateMessage(
        device,
        "Warn",
        "R0 terminate active-list resolver failed: requestPid=%lu, status=0x%08X; falling back to PsLookup.",
        (unsigned long)processId,
        (unsigned int)activeListStatus);

    directLookupStatus = PsLookupProcessByProcessId(ULongToHandle(processId), &processObject);
    if (NT_SUCCESS(directLookupStatus)) {
        RtlZeroMemory(&dynState, sizeof(dynState));
        kswordArkDynDataSnapshot(&dynState);
        status = kswordArkDriverReadTerminateUniqueProcessId(
            &dynState,
            processObject,
            &uniqueProcessId);
        if (!NT_SUCCESS(status)) {
            uniqueProcessId = HandleToULong(PsGetProcessId(processObject));
        }

        target->processObject = processObject;
        target->requestedProcessId = processId;
        target->cidProcessId = processId;
        target->uniqueProcessId = uniqueProcessId;
        target->resolveSource = kKswordArkTerminateResolveDirectCid;
        return STATUS_SUCCESS;
    }

    kswordArkDriverLogTerminateMessage(
        device,
        "Warn",
        "R0 terminate direct CID lookup failed: requestPid=%lu, status=0x%08X; returning best resolver failure.",
        (unsigned long)processId,
        (unsigned int)directLookupStatus);

    status = directLookupStatus;
    if (!kswordArkDriverIsResolverMissingStatus(cidTableStatus)) {
        return cidTableStatus;
    }
    if (!kswordArkDriverIsResolverMissingStatus(activeListStatus)) {
        return activeListStatus;
    }
    return status;
}

static NTSTATUS
kswordArkDriverOpenProcessHandleForTerminate(
    _In_ PEPROCESS processObject,
    _Out_ HANDLE* processHandleOut
    )
/*++

Routine Description:

    Open a terminate handle from an already resolved EPROCESS object.
    Note: Stop calling ZwOpenProcess(CLIENT_ID) to avoid the handle open path
    re-dependencing on an untrusted PID after UniqueProcessId is modified.

Arguments:

    ProcessObject - Referenced target EPROCESS.
    ProcessHandleOut - Receives a kernel process handle.

Return Value:

    STATUS_SUCCESS or ObOpenObjectByPointer status.

--*/
{
    HANDLE processHandle = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (processObject == NULL || processHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *processHandleOut = NULL;

    status = ObOpenObjectByPointer(
        processObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_TERMINATE | SYNCHRONIZE,
        *PsProcessType,
        KernelMode,
        &processHandle);
    if (NT_SUCCESS(status)) {
        *processHandleOut = processHandle;
    }
    return status;
}

static NTSTATUS
kswordArkDriverWaitProcessExitByObject(
    _In_ PEPROCESS processObject,
    _In_ ULONG timeoutMs
    )
/*++

Routine Description:

    Wait for a process object to become signaled instead of polling by PID.
    Note: A hidden process's PID field may be unreliable. Waiting on the
    object itself detects exit for all three termination stage values.

Arguments:

    ProcessObject - Referenced target EPROCESS.
    TimeoutMs - Maximum wait time in milliseconds; zero performs a poll.

Return Value:

    STATUS_SUCCESS when the process is signaled/exited; STATUS_PROCESS_IS_TERMINATING
    when it is still active after the timeout.

--*/
{
    LARGE_INTEGER timeoutInterval;
    NTSTATUS waitStatus = STATUS_SUCCESS;

    if (processObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_PROCESS_IS_TERMINATING;
    }

    if (timeoutMs == 0UL) {
        timeoutInterval.QuadPart = 0;
    }
    else {
        timeoutInterval.QuadPart = -((LONGLONG)timeoutMs * 10 * 1000);
    }

    waitStatus = KeWaitForSingleObject(
        processObject,
        Executive,
        KernelMode,
        FALSE,
        &timeoutInterval);
    if (waitStatus == STATUS_SUCCESS) {
        return STATUS_SUCCESS;
    }
    if (waitStatus == STATUS_TIMEOUT) {
        return STATUS_PROCESS_IS_TERMINATING;
    }
    return waitStatus;
}

static BOOLEAN
kswordArkDriverIsProcessTerminatedByObject(
    _In_ PEPROCESS processObject
    )
/*++

Routine Description:

    Poll the target process object signal state.

Arguments:

    ProcessObject - Referenced target EPROCESS.

Return Value:

    TRUE when the process is already signaled; FALSE when still active or when
    the poll cannot be performed safely.

--*/
{
    return NT_SUCCESS(kswordArkDriverWaitProcessExitByObject(processObject, 0UL)) ? TRUE : FALSE;
}

static NTSTATUS
kswordArkDriverReadProcessProtectionForTerminate(
    _In_ PEPROCESS processObject,
    _Out_ UCHAR* protectionOut
    )
/*++

Routine Description:

    Read EPROCESS.Protection before termination so PP/PPL targets can be
    downgraded by object. Note: Read failure does not block the termination
    chain; the caller will proceed with the strongest termination strategy.

Arguments:

    ProcessObject - Referenced target EPROCESS.
    ProtectionOut - Receives the raw protection byte.

Return Value:

    STATUS_SUCCESS or DynData/read status.

--*/
{
    KswDynState dynState;
    LONG runtimeProtectionOffset = -1;
    NTSTATUS status = STATUS_SUCCESS;

    if (processObject == NULL || protectionOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *protectionOut = 0U;

    /*
     * Prefer the Protection offset derived from the current kernel's PsIsProtectedProcess*.
     * Returns immediately if the runtime offset is readable; otherwise, attempts the DynData profile.
     */
    runtimeProtectionOffset = kswordArkDriverResolveProcessProtectionOffset();
    if (runtimeProtectionOffset > 0 && runtimeProtectionOffset <= 0x3000L) {
        __try {
            RtlCopyMemory(
                protectionOut,
                (PUCHAR)processObject + (ULONG)runtimeProtectionOffset,
                sizeof(*protectionOut));
            return STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }
    }

    RtlZeroMemory(&dynState, sizeof(dynState));
    kswordArkDynDataSnapshot(&dynState);
    if ((dynState.capabilityMask & KSW_CAP_PROCESS_PROTECTION_PATCH) !=
        KSW_CAP_PROCESS_PROTECTION_PATCH ||
        !kswordArkCrossViewOffsetPresent(dynState.kernel.epProtection)) {
        return NT_SUCCESS(status) ? STATUS_PROCEDURE_NOT_FOUND : status;
    }

    __try {
        RtlCopyMemory(protectionOut, (PUCHAR)processObject + dynState.kernel.epProtection, sizeof(*protectionOut));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    return status;
}

static NTSTATUS
kswordArkDriverClearProcessProtectionForTerminate(
    _In_opt_ WDFDEVICE device,
    _In_ const KswordArkTerminateProcessTarget* target
    )
/*++

Routine Description:

    Clear PP/PPL protection bytes before running the termination stages.
    Note: If the target has Protection, clear Protection/SignatureLevel/SectionSignatureLevel
    based on the resolved EPROCESS object. On failure, only log the event; do not abort the
    forced termination due to missing DynData.

Arguments:

    Device - Optional device used for diagnostic logging.
    Target - Resolved terminate target.

Return Value:

    STATUS_SUCCESS when no patch was needed or patch succeeded; otherwise the
    patch/read status for logging.

--*/
{
    UCHAR protection = 0U;
    UCHAR protectionAfter = 0U;
    NTSTATUS readStatus = STATUS_SUCCESS;
    NTSTATUS patchStatus = STATUS_SUCCESS;
    NTSTATUS verifyStatus = STATUS_SUCCESS;

    if (target == NULL || target->processObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    readStatus = kswordArkDriverReadProcessProtectionForTerminate(
        target->processObject,
        &protection);
    if (NT_SUCCESS(readStatus) && protection == 0U) {
        kswordArkDriverLogTerminateMessage(
            device,
            "Info",
            "R0 terminate protection precheck: requestPid=%lu, cid=%lu, unique=%lu, protection=0x00, patch skipped.",
            (unsigned long)target->requestedProcessId,
            (unsigned long)target->cidProcessId,
            (unsigned long)target->uniqueProcessId);
        return STATUS_SUCCESS;
    }

    patchStatus = kswordArkProcessPatchProtectionByDynDataObject(
        target->processObject,
        0U,
        0U,
        0U);
    verifyStatus = kswordArkDriverReadProcessProtectionForTerminate(
        target->processObject,
        &protectionAfter);
    kswordArkDriverLogTerminateMessage(
        device,
        (NT_SUCCESS(patchStatus) && NT_SUCCESS(verifyStatus) && protectionAfter == 0U) ? "Info" : "Warn",
        "R0 terminate protection clear: requestPid=%lu, cid=%lu, unique=%lu, readStatus=0x%08X, oldProtection=0x%02X, patchStatus=0x%08X, verifyStatus=0x%08X, newProtection=0x%02X.",
        (unsigned long)target->requestedProcessId,
        (unsigned long)target->cidProcessId,
        (unsigned long)target->uniqueProcessId,
        (unsigned int)readStatus,
        (unsigned int)protection,
        (unsigned int)patchStatus,
        (unsigned int)verifyStatus,
        (unsigned int)protectionAfter);

    return patchStatus;
}

static NTSTATUS
kswordArkDriverTerminateProcessThreadsByPointer(
    _In_opt_ WDFDEVICE device,
    _In_ const KswordArkTerminateProcessTarget* target,
    _In_ NTSTATUS exitStatus
    )
{
    KswordPsGetNextProcessThreadFn psGetNextProcessThread = NULL;
    KswordPspTerminateThreadByPointerFn pspTerminateThreadByPointer = NULL;
    KswordZwOrNtTerminateThreadFn zwOrNtTerminateThread = NULL;
    PEPROCESS processObject = NULL;
    ULONG processId = 0UL;
    PETHREAD threadCursor = NULL;
    ULONG threadVisitedCount = 0UL;
    ULONG threadTerminatedCount = 0UL;
    ULONG threadFailureCount = 0UL;
    BOOLEAN useCidThreadScan = FALSE;
    BOOLEAN hasTerminateRoutine = FALSE;
    NTSTATUS lastFailureStatus = STATUS_UNSUCCESSFUL;

    if (target == NULL || target->processObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    processObject = target->processObject;
    processId = target->requestedProcessId;

    psGetNextProcessThread = kswordArkDriverResolvePsGetNextProcessThread();
    pspTerminateThreadByPointer = kswordArkDriverResolvePspTerminateThreadByPointer();
    if (pspTerminateThreadByPointer == NULL) {
        zwOrNtTerminateThread = kswordArkDriverResolveZwOrNtTerminateThread();
    }
    hasTerminateRoutine =
        (pspTerminateThreadByPointer != NULL || zwOrNtTerminateThread != NULL) ? TRUE : FALSE;

    kswordArkDriverLogTerminateMessage(
        device,
        "Info",
        "R0 terminate fallback#2 resolver: pid=%lu, PsGetNextProcessThread=%p, PspTerminateThreadByPointer=%p, ZwOrNtTerminateThread=%p.",
        (unsigned long)processId,
        psGetNextProcessThread,
        pspTerminateThreadByPointer,
        zwOrNtTerminateThread);

    if (!hasTerminateRoutine) {
        kswordArkDriverLogTerminateMessage(
            device,
            "Warn",
            "R0 terminate fallback#2 unavailable: pid=%lu, reason=%s.",
            (unsigned long)processId,
            "thread terminate routine missing");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    useCidThreadScan = (psGetNextProcessThread == NULL) ? TRUE : FALSE;
    if (useCidThreadScan) {
        kswordArkDriverLogTerminateMessage(
            device,
            "Warn",
            "R0 terminate fallback#2 switching to CID thread scan: pid=%lu, maxTid=0x%08X.",
            (unsigned long)processId,
            (unsigned int)KSWORD_ARK_THREAD_SCAN_MAX_ID);
    }

    if (!useCidThreadScan) {
        threadCursor = psGetNextProcessThread(processObject, NULL);
        while (threadCursor != NULL) {
            PETHREAD nextThread = psGetNextProcessThread(processObject, threadCursor);
            NTSTATUS terminateStatus = STATUS_UNSUCCESSFUL;
            threadVisitedCount += 1UL;

            if (pspTerminateThreadByPointer != NULL) {
                terminateStatus = pspTerminateThreadByPointer(
                    threadCursor,
                    exitStatus,
                    FALSE,
                    NULL);
            }
            else {
                HANDLE threadHandle = NULL;
                terminateStatus = ObOpenObjectByPointer(
                    threadCursor,
                    OBJ_KERNEL_HANDLE,
                    NULL,
                    THREAD_TERMINATE,
                    *PsThreadType,
                    KernelMode,
                    &threadHandle);
                if (NT_SUCCESS(terminateStatus)) {
                    if (zwOrNtTerminateThread != NULL) {
                        terminateStatus = zwOrNtTerminateThread(threadHandle, exitStatus);
                    }
                    else {
                        terminateStatus = STATUS_PROCEDURE_NOT_FOUND;
                    }
                    ZwClose(threadHandle);
                }
            }

            if (NT_SUCCESS(terminateStatus) ||
                terminateStatus == STATUS_THREAD_IS_TERMINATING ||
                terminateStatus == STATUS_PROCESS_IS_TERMINATING) {
                threadTerminatedCount += 1UL;
            }
            else {
                threadFailureCount += 1UL;
                lastFailureStatus = terminateStatus;
            }

            ObDereferenceObject(threadCursor);
            threadCursor = nextThread;
        }
    }
    else {
        ULONG scanThreadId = 4UL;
        for (;;) {
            PETHREAD threadObject = NULL;
            NTSTATUS lookupThreadStatus = PsLookupThreadByThreadId(ULongToHandle(scanThreadId), &threadObject);
            if (NT_SUCCESS(lookupThreadStatus)) {
                if (PsGetThreadProcess(threadObject) == processObject) {
                    NTSTATUS terminateStatus = STATUS_UNSUCCESSFUL;
                    threadVisitedCount += 1UL;

                    if (pspTerminateThreadByPointer != NULL) {
                        terminateStatus = pspTerminateThreadByPointer(
                            threadObject,
                            exitStatus,
                            FALSE,
                            NULL);
                    }
                    else {
                        HANDLE threadHandle = NULL;
                        terminateStatus = ObOpenObjectByPointer(
                            threadObject,
                            OBJ_KERNEL_HANDLE,
                            NULL,
                            THREAD_TERMINATE,
                            *PsThreadType,
                            KernelMode,
                            &threadHandle);
                        if (NT_SUCCESS(terminateStatus)) {
                            if (zwOrNtTerminateThread != NULL) {
                                terminateStatus = zwOrNtTerminateThread(threadHandle, exitStatus);
                            }
                            else {
                                terminateStatus = STATUS_PROCEDURE_NOT_FOUND;
                            }
                            ZwClose(threadHandle);
                        }
                    }

                    if (NT_SUCCESS(terminateStatus) ||
                        terminateStatus == STATUS_THREAD_IS_TERMINATING ||
                        terminateStatus == STATUS_PROCESS_IS_TERMINATING) {
                        threadTerminatedCount += 1UL;
                    }
                    else {
                        threadFailureCount += 1UL;
                        lastFailureStatus = terminateStatus;
                    }
                }
                ObDereferenceObject(threadObject);
            }

            if ((KSWORD_ARK_THREAD_SCAN_MAX_ID - scanThreadId) < KSWORD_ARK_ENUM_PID_STEP) {
                break;
            }
            scanThreadId += KSWORD_ARK_ENUM_PID_STEP;
        }
    }

    kswordArkDriverLogTerminateMessage(
        device,
        "Info",
        "R0 terminate fallback#2 result: pid=%lu, visited=%lu, terminated=%lu, failed=%lu, lastFailure=0x%08X.",
        (unsigned long)processId,
        (unsigned long)threadVisitedCount,
        (unsigned long)threadTerminatedCount,
        (unsigned long)threadFailureCount,
        (unsigned int)lastFailureStatus);

    if (threadTerminatedCount > 0UL) {
        return STATUS_SUCCESS;
    }
    if (lastFailureStatus != STATUS_UNSUCCESSFUL) {
        return lastFailureStatus;
    }
    if (threadVisitedCount == 0UL) {
        return STATUS_NOT_FOUND;
    }
    return lastFailureStatus;
}

NTSTATUS
kswordArkDriverZeroProcessUserMemoryByPid(
    _In_opt_ WDFDEVICE device,
    _In_ ULONG processId
    );

NTSTATUS
kswordArkDriverZeroProcessUserMemoryByObject(
    _In_opt_ WDFDEVICE device,
    _In_ ULONG processId,
    _In_ PEPROCESS processObject
    );

NTSTATUS
kswordArkDriverTerminateProcessByPid(
    _In_opt_ WDFDEVICE device,
    _In_ ULONG processId,
    _In_ NTSTATUS exitStatus,
    _In_ ULONG64 expectedCreateTime100ns
    )
/*++

Routine Description:

    Resolve the target process by PID/CID evidence once, then run the full R0
    termination pipeline against that EPROCESS object. Note: R3/IOCTL passes PID and optional creation
    time; R0 reverse-looks up the real object via the CID table when the PID field is rewritten,
    verifies the object creation time, and all three termination schemes reuse the same object.

Arguments:

    processId - PID-like target identity supplied by user mode.
    exitStatus - Exit status to report.
    expectedCreateTime100ns - Optional creation time from the R0/R3 snapshot.

Return Value:

    NTSTATUS

--*/
{
    KswordArkTerminateProcessTarget target;
    HANDLE processHandle = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS waitStatus = STATUS_UNSUCCESSFUL;
    NTSTATUS threadTerminateStatus = STATUS_UNSUCCESSFUL;
    NTSTATUS memoryZeroStatus = STATUS_UNSUCCESSFUL;
    NTSTATUS aggregateFailureStatus = STATUS_UNSUCCESSFUL;
    NTSTATUS finalStatus = STATUS_UNSUCCESSFUL;
    ULONG64 observedCreateTime100ns = 0ULL;
    BOOLEAN processStillPresent = FALSE;

    RtlZeroMemory(&target, sizeof(target));

    if (processId == 0U || processId <= 4U) {
        kswordArkDriverLogTerminateMessage(
            device,
            "Warn",
            "R0 terminate rejected: pid=%lu.",
            (unsigned long)processId);
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkDriverResolveTerminateTarget(device, processId, &target);
    if (!NT_SUCCESS(status)) {
        kswordArkDriverLogTerminateMessage(
            device,
            "Warn",
            "R0 terminate target resolve failed: requestPid=%lu, status=0x%08X.",
            (unsigned long)processId,
            (unsigned int)status);
        return status;
    }

    // Note: Validation must occur on resolved objects with held references; do not rely on R3 OpenProcess, which may be compromised by Rootkits.
    observedCreateTime100ns = (ULONG64)PsGetProcessCreateTimeQuadPart(target.processObject);
    if (expectedCreateTime100ns != 0ULL &&
        observedCreateTime100ns != expectedCreateTime100ns) {
        // Note: STATUS_INVALID_CID is consistent with existing token privilege identity validation.
        kswordArkDriverLogTerminateMessage(
            device,
            "Warn",
            "R0 terminate identity rejected: requestPid=%lu, expectedCreate=%I64u, observedCreate=%I64u, process=%p.",
            (unsigned long)processId,
            expectedCreateTime100ns,
            observedCreateTime100ns,
            target.processObject);
        finalStatus = STATUS_INVALID_CID;
        goto Exit;
    }

    if (target.cidProcessId <= 4UL || target.processObject == PsInitialSystemProcess) {
        kswordArkDriverLogTerminateMessage(
            device,
            "Warn",
            "R0 terminate rejected after resolve: requestPid=%lu, cid=%lu, unique=%lu, process=%p.",
            (unsigned long)target.requestedProcessId,
            (unsigned long)target.cidProcessId,
            (unsigned long)target.uniqueProcessId,
            target.processObject);
        finalStatus = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    if (device != NULL && target.cidProcessId != target.requestedProcessId) {
        KswordArkSafetyContext resolvedSafetyContext;
        RtlZeroMemory(&resolvedSafetyContext, sizeof(resolvedSafetyContext));
        resolvedSafetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_PROCESS_TERMINATE;
        resolvedSafetyContext.targetProcessId = target.cidProcessId;
        resolvedSafetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        status = kswordArkSafetyEvaluate(device, &resolvedSafetyContext);
        if (!NT_SUCCESS(status)) {
            kswordArkDriverLogTerminateMessage(
                device,
                "Warn",
                "R0 terminate denied after CID resolve: requestPid=%lu, cid=%lu, status=0x%08X.",
                (unsigned long)target.requestedProcessId,
                (unsigned long)target.cidProcessId,
                (unsigned int)status);
            finalStatus = status;
            goto Exit;
        }
    }

    kswordArkDriverLogTerminateMessage(
        device,
        "Info",
        "R0 terminate pipeline begin: requestPid=%lu, cid=%lu, unique=%lu, source=%s, process=%p, exit=0x%08X.",
        (unsigned long)target.requestedProcessId,
        (unsigned long)target.cidProcessId,
        (unsigned long)target.uniqueProcessId,
        kswordArkDriverTerminateResolveSourceText(target.resolveSource),
        target.processObject,
        (unsigned int)exitStatus);

    if (kswordArkDriverIsProcessTerminatedByObject(target.processObject)) {
        kswordArkDriverLogTerminateMessage(
            device,
            "Info",
            "R0 terminate target already signaled before stage#1: requestPid=%lu, cid=%lu.",
            (unsigned long)target.requestedProcessId,
            (unsigned long)target.cidProcessId);
        finalStatus = STATUS_SUCCESS;
        goto Exit;
    }

    (void)kswordArkDriverClearProcessProtectionForTerminate(device, &target);

    status = kswordArkDriverOpenProcessHandleForTerminate(target.processObject, &processHandle);
    if (NT_SUCCESS(status)) {
        status = ZwTerminateProcess(processHandle, exitStatus);
        ZwClose(processHandle);
        processHandle = NULL;
    }
    else {
        kswordArkDriverLogTerminateMessage(
            device,
            "Warn",
            "R0 terminate stage#1 open-by-object failed: requestPid=%lu, cid=%lu, status=0x%08X.",
            (unsigned long)target.requestedProcessId,
            (unsigned long)target.cidProcessId,
            (unsigned int)status);
    }

    kswordArkDriverLogTerminateMessage(
        device,
        NT_SUCCESS(status) ? "Info" : "Warn",
        "R0 terminate stage#1 ZwTerminateProcess: requestPid=%lu, cid=%lu, status=0x%08X.",
        (unsigned long)target.requestedProcessId,
        (unsigned long)target.cidProcessId,
        (unsigned int)status);
    if (NT_SUCCESS(status)) {
        finalStatus = STATUS_SUCCESS;
        goto Exit;
    }
    kswordArkDriverMergeTerminateFailure(status, &aggregateFailureStatus);

    if (status == STATUS_PROCESS_IS_TERMINATING) {
        waitStatus = kswordArkDriverWaitProcessExitByObject(
            target.processObject,
            KSWORD_ARK_TERMINATE_WAIT_MAX_MS);
        kswordArkDriverLogTerminateMessage(
            device,
            NT_SUCCESS(waitStatus) ? "Info" : "Warn",
            "R0 terminate stage#1 wait: requestPid=%lu, cid=%lu, status=0x%08X.",
            (unsigned long)target.requestedProcessId,
            (unsigned long)target.cidProcessId,
            (unsigned int)waitStatus);
        if (NT_SUCCESS(waitStatus)) {
            finalStatus = STATUS_SUCCESS;
            goto Exit;
        }
        kswordArkDriverMergeTerminateFailure(waitStatus, &aggregateFailureStatus);
    }

    processStillPresent = !kswordArkDriverIsProcessTerminatedByObject(target.processObject);
    if (!processStillPresent) {
        kswordArkDriverLogTerminateMessage(
            device,
            "Info",
            "R0 terminate process already gone after stage#1: requestPid=%lu, cid=%lu.",
            (unsigned long)target.requestedProcessId,
            (unsigned long)target.cidProcessId);
        finalStatus = STATUS_SUCCESS;
        goto Exit;
    }

    // Fallback method #2:
    // dynamic-resolve PspTerminateThreadByPointer and terminate every thread.
    threadTerminateStatus = kswordArkDriverTerminateProcessThreadsByPointer(
        device,
        &target,
        exitStatus);
    kswordArkDriverLogTerminateMessage(
        device,
        NT_SUCCESS(threadTerminateStatus) ? "Info" : "Warn",
        "R0 terminate stage#2 thread-sweep: requestPid=%lu, cid=%lu, status=0x%08X.",
        (unsigned long)target.requestedProcessId,
        (unsigned long)target.cidProcessId,
        (unsigned int)threadTerminateStatus);
    kswordArkDriverMergeTerminateFailure(threadTerminateStatus, &aggregateFailureStatus);

    if (NT_SUCCESS(threadTerminateStatus)) {
        waitStatus = kswordArkDriverWaitProcessExitByObject(
            target.processObject,
            KSWORD_ARK_TERMINATE_WAIT_FALLBACK_MS);
        kswordArkDriverLogTerminateMessage(
            device,
            NT_SUCCESS(waitStatus) ? "Info" : "Warn",
            "R0 terminate stage#2 wait: requestPid=%lu, cid=%lu, status=0x%08X.",
            (unsigned long)target.requestedProcessId,
            (unsigned long)target.cidProcessId,
            (unsigned int)waitStatus);
        if (NT_SUCCESS(waitStatus)) {
            finalStatus = STATUS_SUCCESS;
            goto Exit;
        }
        kswordArkDriverMergeTerminateFailure(waitStatus, &aggregateFailureStatus);
    }

    processStillPresent = !kswordArkDriverIsProcessTerminatedByObject(target.processObject);
    if (!processStillPresent) {
        kswordArkDriverLogTerminateMessage(
            device,
            "Info",
            "R0 terminate process gone after stage#2: requestPid=%lu, cid=%lu.",
            (unsigned long)target.requestedProcessId,
            (unsigned long)target.cidProcessId);
        finalStatus = STATUS_SUCCESS;
        goto Exit;
    }

    // Fallback method #3:
    // zero writable user memory regions to force process unusable.
    memoryZeroStatus = kswordArkDriverZeroProcessUserMemoryByObject(
        device,
        target.requestedProcessId,
        target.processObject);
    kswordArkDriverLogTerminateMessage(
        device,
        NT_SUCCESS(memoryZeroStatus) ? "Info" : "Warn",
        "R0 terminate stage#3 memory-zero: requestPid=%lu, cid=%lu, status=0x%08X.",
        (unsigned long)target.requestedProcessId,
        (unsigned long)target.cidProcessId,
        (unsigned int)memoryZeroStatus);
    kswordArkDriverMergeTerminateFailure(memoryZeroStatus, &aggregateFailureStatus);

    if (NT_SUCCESS(memoryZeroStatus)) {
        waitStatus = kswordArkDriverWaitProcessExitByObject(
            target.processObject,
            KSWORD_ARK_TERMINATE_WAIT_FALLBACK_MS);
        kswordArkDriverLogTerminateMessage(
            device,
            NT_SUCCESS(waitStatus) ? "Info" : "Warn",
            "R0 terminate stage#3 wait: requestPid=%lu, cid=%lu, status=0x%08X.",
            (unsigned long)target.requestedProcessId,
            (unsigned long)target.cidProcessId,
            (unsigned int)waitStatus);
        if (NT_SUCCESS(waitStatus) ||
            kswordArkDriverIsProcessTerminatedByObject(target.processObject)) {
            finalStatus = STATUS_SUCCESS;
            goto Exit;
        }
        kswordArkDriverMergeTerminateFailure(waitStatus, &aggregateFailureStatus);
    }

    processStillPresent = !kswordArkDriverIsProcessTerminatedByObject(target.processObject);
    if (!processStillPresent) {
        kswordArkDriverLogTerminateMessage(
            device,
            "Info",
            "R0 terminate process gone after stage#3: requestPid=%lu, cid=%lu.",
            (unsigned long)target.requestedProcessId,
            (unsigned long)target.cidProcessId);
        finalStatus = STATUS_SUCCESS;
        goto Exit;
    }

    if (aggregateFailureStatus == STATUS_UNSUCCESSFUL) {
        aggregateFailureStatus = status;
    }
    kswordArkDriverLogTerminateMessage(
        device,
        "Error",
        "R0 terminate pipeline failed: requestPid=%lu, cid=%lu, unique=%lu, source=%s, final=0x%08X, stage1=0x%08X, stage2=0x%08X, stage3=0x%08X, wait=0x%08X.",
        (unsigned long)target.requestedProcessId,
        (unsigned long)target.cidProcessId,
        (unsigned long)target.uniqueProcessId,
        kswordArkDriverTerminateResolveSourceText(target.resolveSource),
        (unsigned int)aggregateFailureStatus,
        (unsigned int)status,
        (unsigned int)threadTerminateStatus,
        (unsigned int)memoryZeroStatus,
        (unsigned int)waitStatus);
    finalStatus = aggregateFailureStatus;

Exit:
    if (processHandle != NULL) {
        ZwClose(processHandle);
        processHandle = NULL;
    }
    kswordArkDriverReleaseTerminateTarget(&target);
    return finalStatus;
}

NTSTATUS
kswordArkDriverTerminateReferencedThreadPsp(
    _In_ PETHREAD threadObject,
    _In_ NTSTATUS exitStatus
    )
{
    KswordPspTerminateThreadByPointerFn pspTerminateThreadByPointer = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (threadObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    pspTerminateThreadByPointer = kswordArkDriverResolvePspTerminateThreadByPointer();
    if (pspTerminateThreadByPointer == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    status = pspTerminateThreadByPointer(threadObject, exitStatus, FALSE, NULL);
    if (status == STATUS_THREAD_IS_TERMINATING || status == STATUS_PROCESS_IS_TERMINATING) {
        status = STATUS_SUCCESS;
    }
    return status;
}

NTSTATUS
kswordArkDriverTerminateReferencedThreadZwOrNt(
    _In_ PETHREAD threadObject,
    _In_ NTSTATUS exitStatus
    )
{
    KswordZwOrNtTerminateThreadFn zwOrNtTerminateThread = NULL;
    HANDLE threadHandle = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (threadObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    zwOrNtTerminateThread = kswordArkDriverResolveZwOrNtTerminateThread();
    if (zwOrNtTerminateThread == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    status = ObOpenObjectByPointer(
        threadObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        THREAD_TERMINATE,
        *PsThreadType,
        KernelMode,
        &threadHandle);
    if (NT_SUCCESS(status)) {
        status = zwOrNtTerminateThread(threadHandle, exitStatus);
    }
    if (threadHandle != NULL) {
        ZwClose(threadHandle);
    }
    if (status == STATUS_THREAD_IS_TERMINATING || status == STATUS_PROCESS_IS_TERMINATING) {
        status = STATUS_SUCCESS;
    }
    return status;
}

NTSTATUS
kswordArkDriverTerminateReferencedThread(
    _In_ PETHREAD threadObject,
    _In_ NTSTATUS exitStatus
    )
{
    NTSTATUS status = kswordArkDriverTerminateReferencedThreadPsp(threadObject, exitStatus);
    if (status == STATUS_PROCEDURE_NOT_FOUND) {
        status = kswordArkDriverTerminateReferencedThreadZwOrNt(threadObject, exitStatus);
    }
    return status;
}

NTSTATUS
kswordArkDriverTerminateThreadById(
    _In_opt_ WDFDEVICE device,
    _In_ ULONG processId,
    _In_ ULONG threadId,
    _In_ NTSTATUS exitStatus
    )
/*++

Routine Description:

    Resolve a process through the existing CID-first termination resolver,
    reference one ETHREAD by TID, verify ownership, and terminate that one
    thread. This entry never invokes process-wide thread enumeration.

Arguments:

    device - Optional driver device used for diagnostics.
    processId - PID-like identity supplied by the shared IOCTL request.
    threadId - Requested thread identity supplied by the shared IOCTL request.
    exitStatus - Exit status forwarded to the selected thread termination call.

Return Value:

    STATUS_SUCCESS when the selected thread is terminated or already terminating.
    Otherwise returns target-resolution, ownership, or backend failure status.

--*/
{
    KswordArkTerminateProcessTarget target;
    KswordPspTerminateThreadByPointerFn pspTerminateThreadByPointer = NULL;
    KswordZwOrNtTerminateThreadFn zwOrNtTerminateThread = NULL;
    PETHREAD threadObject = NULL;
    HANDLE threadHandle = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    // Target object is parsed only by R0; zero it first so all exit paths can safely release it.
    RtlZeroMemory(&target, sizeof(target));

    // Reject requests for Idle, System, reserved low PIDs, or null TIDs.
    if (processId == 0UL || processId <= 4UL || threadId == 0UL) {
        kswordArkDriverLogTerminateMessage(
            device,
            "Warn",
            "R0 terminate-thread rejected: pid=%lu, tid=%lu.",
            (unsigned long)processId,
            (unsigned long)threadId);
        return STATUS_INVALID_PARAMETER;
    }

    // Use the full process termination with CID-priority resolution to ensure compatibility with targets whose PIDs have been tampered with.
    status = kswordArkDriverResolveTerminateTarget(device, processId, &target);
    if (!NT_SUCCESS(status)) {
        kswordArkDriverLogTerminateMessage(
            device,
            "Warn",
            "R0 terminate-thread target resolve failed: requestPid=%lu, tid=%lu, status=0x%08X.",
            (unsigned long)processId,
            (unsigned long)threadId,
            (unsigned int)status);
        return status;
    }

    // The resolved real object must still exclude the System process.
    if (target.cidProcessId <= 4UL || target.processObject == PsInitialSystemProcess) {
        kswordArkDriverLogTerminateMessage(
            device,
            "Warn",
            "R0 terminate-thread rejected after resolve: requestPid=%lu, tid=%lu, cid=%lu, unique=%lu, process=%p.",
            (unsigned long)target.requestedProcessId,
            (unsigned long)threadId,
            (unsigned long)target.cidProcessId,
            (unsigned long)target.uniqueProcessId,
            target.processObject);
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    // Reference the ETHREAD by TID, then verify it still belongs to the resolved EPROCESS for the requested PID.
    status = PsLookupThreadByThreadId(ULongToHandle(threadId), &threadObject);
    if (!NT_SUCCESS(status)) {
        kswordArkDriverLogTerminateMessage(
            device,
            "Warn",
            "R0 terminate-thread lookup failed: requestPid=%lu, tid=%lu, status=0x%08X.",
            (unsigned long)target.requestedProcessId,
            (unsigned long)threadId,
            (unsigned int)status);
        goto Exit;
    }
    if (PsGetThreadProcess(threadObject) != target.processObject) {
        kswordArkDriverLogTerminateMessage(
            device,
            "Warn",
            "R0 terminate-thread ownership mismatch: requestPid=%lu, tid=%lu.",
            (unsigned long)target.requestedProcessId,
            (unsigned long)threadId);
        status = STATUS_NOT_FOUND;
        goto Exit;
    }

    // Prefer using the existing private pointer termination routine to maintain fallback compatibility for process termination.
    pspTerminateThreadByPointer = kswordArkDriverResolvePspTerminateThreadByPointer();
    if (pspTerminateThreadByPointer != NULL) {
        status = pspTerminateThreadByPointer(threadObject, exitStatus, FALSE, NULL);
    }
    else {
        // When the private routine is unavailable, call the exported Zw/NtTerminateThread via a kernel handle.
        zwOrNtTerminateThread = kswordArkDriverResolveZwOrNtTerminateThread();
        if (zwOrNtTerminateThread == NULL) {
            status = STATUS_PROCEDURE_NOT_FOUND;
        }
        else {
            status = ObOpenObjectByPointer(
                threadObject,
                OBJ_KERNEL_HANDLE,
                NULL,
                THREAD_TERMINATE,
                *PsThreadType,
                KernelMode,
                &threadHandle);
            if (NT_SUCCESS(status)) {
                status = zwOrNtTerminateThread(threadHandle, exitStatus);
            }
        }
    }

    // Entering the terminating state is equivalent to the target thread no longer being executable; return success to R3.
    if (status == STATUS_THREAD_IS_TERMINATING || status == STATUS_PROCESS_IS_TERMINATING) {
        status = STATUS_SUCCESS;
    }
    kswordArkDriverLogTerminateMessage(
        device,
        NT_SUCCESS(status) ? "Info" : "Warn",
        "R0 terminate-thread result: requestPid=%lu, tid=%lu, cid=%lu, status=0x%08X.",
        (unsigned long)target.requestedProcessId,
        (unsigned long)threadId,
        (unsigned long)target.cidProcessId,
        (unsigned int)status);

Exit:
    // Kernel thread handles successfully opened via Zw/Nt fallback must be closed on all exit paths.
    if (threadHandle != NULL) {
        ZwClose(threadHandle);
        threadHandle = NULL;
    }
    // The ETHREAD reference held after a successful TID lookup is released here.
    if (threadObject != NULL) {
        ObDereferenceObject(threadObject);
        threadObject = NULL;
    }
    // Release the EPROCESS reference obtained during CID/ActiveProcessLinks resolution.
    kswordArkDriverReleaseTerminateTarget(&target);
    return status;
}
