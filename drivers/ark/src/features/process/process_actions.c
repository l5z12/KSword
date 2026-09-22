/*++

Module Name:

    process_actions.c

Abstract:

    This file contains kernel process control operations.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntifs.h>
#include "ark/ark_driver.h"
#include "../../platform/process_resolver.h"
#include "process_crossview.h"
#include "process_extended.h"
#include <ntstrsafe.h>
#include <stdarg.h>

NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE processId,
    _Outptr_ PEPROCESS* process
    );

NTSYSAPI
HANDLE
NTAPI
PsGetProcessInheritedFromUniqueProcessId(
    _In_ PEPROCESS process
    );

NTSYSAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS process
    );

#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME (0x0800)
#endif

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION (0x0400)
#endif

#ifndef SE_GROUP_INTEGRITY
#define SE_GROUP_INTEGRITY 0x00000020L
#endif

#ifndef STATUS_INVALID_SID
#define STATUS_INVALID_SID ((NTSTATUS)0xC0000078L)
#endif

#ifndef SE_SIGNING_LEVEL_UNCHECKED
#define SE_SIGNING_LEVEL_UNCHECKED 0x00
#endif

#ifndef SE_SIGNING_LEVEL_AUTHENTICODE
#define SE_SIGNING_LEVEL_AUTHENTICODE 0x04
#endif

#ifndef SE_SIGNING_LEVEL_STORE
#define SE_SIGNING_LEVEL_STORE 0x06
#endif

#ifndef SE_SIGNING_LEVEL_ANTIMALWARE
#define SE_SIGNING_LEVEL_ANTIMALWARE 0x07
#endif

#ifndef SE_SIGNING_LEVEL_MICROSOFT
#define SE_SIGNING_LEVEL_MICROSOFT 0x08
#endif

#ifndef SE_SIGNING_LEVEL_DYNAMIC_CODEGEN
#define SE_SIGNING_LEVEL_DYNAMIC_CODEGEN 0x0B
#endif

#ifndef SE_SIGNING_LEVEL_WINDOWS
#define SE_SIGNING_LEVEL_WINDOWS 0x0C
#endif

#ifndef SE_SIGNING_LEVEL_WINDOWS_TCB
#define SE_SIGNING_LEVEL_WINDOWS_TCB 0x0E
#endif

#define KSWORD_PS_PROTECTED_SIGNER_NONE ((UCHAR)0x00)
#define KSWORD_PS_PROTECTED_SIGNER_AUTHENTICODE ((UCHAR)0x01)
#define KSWORD_PS_PROTECTED_SIGNER_CODEGEN ((UCHAR)0x02)
#define KSWORD_PS_PROTECTED_SIGNER_ANTIMALWARE ((UCHAR)0x03)
#define KSWORD_PS_PROTECTED_SIGNER_LSA ((UCHAR)0x04)
#define KSWORD_PS_PROTECTED_SIGNER_WINDOWS ((UCHAR)0x05)
#define KSWORD_PS_PROTECTED_SIGNER_WINTCB ((UCHAR)0x06)
#define KSWORD_PS_PROTECTED_SIGNER_WINSYSTEM ((UCHAR)0x07)
#define KSWORD_PS_PROTECTED_SIGNER_APP ((UCHAR)0x08)

#define KSWORD_ARK_ENUM_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_PROCESS_RESPONSE) - sizeof(KSWORD_ARK_PROCESS_ENTRY))
#define KSWORD_ARK_ENUM_PID_STEP 4UL
#define KSWORD_ARK_ENUM_SCAN_MAX_PID 0x00400000UL
#define KSWORD_ARK_ENUM_SCAN_MIN_PID KSWORD_ARK_ENUM_PID_STEP
#define KSWORD_ARK_ENUM_CID_WALK_MAX_NODES 0x00100000UL
#define KSWORD_ARK_PROCESS_HIDE_MAX_PIDS 256UL
#define KSWORD_ARK_PROCESS_OFFSET_SCAN_LIMIT 0x2000UL
#define KSWORD_ARK_PROCESS_HIDDEN_PID_TAG 0xE0000000UL
#define KSWORD_ARK_PROCESS_HIDDEN_PID_MASK 0x0FFFFFFCUL
#if defined(_WIN64)
#define KSWORD_ARK_EX_FAST_REF_MASK ((ULONG_PTR)0x0FULL)
#else
#define KSWORD_ARK_EX_FAST_REF_MASK ((ULONG_PTR)0x07UL)
#endif
#define KSWORD_ARK_TOKEN_INTEGRITY_MAX_GROUPS 1024UL
#define KSWORD_ARK_PROCESS_INTEGRITY_DIAG_CHARS 512UL

#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#endif

#ifndef STATUS_INVALID_DEVICE_STATE
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xC0000184L)
#endif

#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif

typedef struct KswordArkProcessIntegrityAttemptDiag
{
    ULONG processId;
    ULONG integrityRid;
    NTSTATUS apiStatus;
    NTSTATUS fallbackStatus;
    NTSTATUS finalStatus;
    ULONG64 capabilityMask;
    ULONG epToken;
    ULONG tokUserAndGroupCount;
    ULONG tokUserAndGroups;
    ULONG tokIntegrityLevelIndex;
    ULONG tokMandatoryPolicy;
    ULONG epTokenSource;
    ULONG tokUserAndGroupCountSource;
    ULONG tokUserAndGroupsSource;
    ULONG tokIntegrityLevelIndexSource;
    ULONG tokMandatoryPolicySource;
} KswordArkProcessIntegrityAttemptDiag, *PkswordArkProcessIntegrityAttemptDiag;

static KswordArkProcessIntegrityAttemptDiag gKswordProcessIntegrityDiag;

typedef struct KswordArkProcessIntegrityTokenInformation
{
    TOKEN_MANDATORY_LABEL mandatoryLabel;
    UCHAR sidBuffer[SECURITY_MAX_SID_SIZE];
} KswordArkProcessIntegrityTokenInformation;

extern POBJECT_TYPE* PsProcessType;

typedef PEPROCESS(NTAPI* KswordPsGetNextProcessFn)(
    _In_opt_ PEPROCESS process
    );

typedef struct KswordArkProcessHideRecord
{
    ULONG pid;
    ULONG uniqueProcessIdOffset;
    ULONG activeProcessLinksOffset;
    PEPROCESS processObject;
    HANDLE originalUniqueProcessId;
    HANDLE hiddenUniqueProcessId;
    LIST_ENTRY* activeProcessLinks;
    LIST_ENTRY* previousLink;
    LIST_ENTRY* nextLink;
    BOOLEAN uniqueProcessIdPatched;
    BOOLEAN activeListUnlinked;
} KswordArkProcessHideRecord;

typedef struct KswordArkProcessHideState
{
    EX_PUSH_LOCK lock;
    BOOLEAN initialized;
    ULONG count;
    KswordArkProcessHideRecord records[KSWORD_ARK_PROCESS_HIDE_MAX_PIDS];
} KswordArkProcessHideState;

typedef struct KswordArkEnumProcessCidContext
{
    KSWORD_ARK_ENUM_PROCESS_RESPONSE* response;
    size_t entryCapacity;
    const KswDynState* dynState;
    const UCHAR* activePidBitmap;
    size_t activePidBitmapBytes;
    ULONG scanStartPid;
    ULONG scanEndPid;
    BOOLEAN activeWalkAvailable;
} KswordArkEnumProcessCidContext;

static KswordArkProcessHideState gKswordArkProcessHideState;

static VOID
kswordArkDriverEnsureProcessHideStateInitialized(
    VOID
    )
/*++

Routine Description:

    initialize the process hiding state table within the driver. Note: This table records the unlinking status
    of ActiveProcessLinks performed by Ksword, including the target EPROCESS reference and original
    predecessor/successor nodes, to restore the linked list during subsequent unhide or full clear operations.

Arguments:

    None.

Return Value:

    None. This function has no return value.

--*/
{
    if (gKswordArkProcessHideState.initialized) {
        return;
    }

    RtlZeroMemory(&gKswordArkProcessHideState, sizeof(gKswordArkProcessHideState));
    ExInitializePushLock(&gKswordArkProcessHideState.lock);
    gKswordArkProcessHideState.initialized = TRUE;
}

static BOOLEAN
kswordArkDriverIsProcessHiddenByUi(
    _In_ ULONG processId
    )
/*++

Routine Description:

    Check if the PID is recorded in the Ksword R0 recoverable hidden table. Note: True hiding is achieved by
    unlinking from ActiveProcessLinks; this helper is only used to supplement
    KSWORD_ARK_PROCESS_FLAG_HIDDEN_BY_KSWORD_UI during enumeration, facilitating R3 identification and filtering.

Arguments:

    ProcessId - target PID.

Return Value:

    TRUE indicates this PID is currently marked as hidden; FALSE indicates it is not hidden.

--*/
{
    ULONG index = 0UL;
    BOOLEAN hidden = FALSE;

    kswordArkDriverEnsureProcessHideStateInitialized();
    kswordArkAcquirePushLockShared(&gKswordArkProcessHideState.lock);
    for (index = 0UL; index < gKswordArkProcessHideState.count; ++index) {
        if (gKswordArkProcessHideState.records[index].pid == processId) {
            hidden = TRUE;
            break;
        }
    }
    kswordArkReleasePushLockShared(&gKswordArkProcessHideState.lock);
    return hidden;
}

static KswordPsGetNextProcessFn
kswordArkDriverResolvePsGetNextProcess(
    VOID
    )
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsGetNextProcess");
    return (KswordPsGetNextProcessFn)MmGetSystemRoutineAddress(&routineName);
}

static ULONG
kswordArkDriverAlignPidToStep(
    _In_ ULONG pidValue
    )
{
    return pidValue - (pidValue % KSWORD_ARK_ENUM_PID_STEP);
}

static BOOLEAN
kswordArkDriverPidInScanRange(
    _In_ ULONG pidValue,
    _In_ ULONG scanStartPid,
    _In_ ULONG scanEndPid
    )
{
    if (pidValue < scanStartPid || pidValue > scanEndPid) {
        return FALSE;
    }
    return ((pidValue % KSWORD_ARK_ENUM_PID_STEP) == 0U) ? TRUE : FALSE;
}

static VOID
kswordArkDriverBitmapSetPid(
    _Inout_updates_bytes_(bitmapBytes) PUCHAR bitmap,
    _In_ size_t bitmapBytes,
    _In_ ULONG pidValue
    )
{
    size_t bitIndex = 0;
    size_t byteIndex = 0;
    UCHAR bitMask = 0;

    if (bitmap == NULL || bitmapBytes == 0U) {
        return;
    }

    bitIndex = (size_t)(pidValue / KSWORD_ARK_ENUM_PID_STEP);
    byteIndex = (bitIndex >> 3);
    if (byteIndex >= bitmapBytes) {
        return;
    }

    bitMask = (UCHAR)(1U << (bitIndex & 0x07U));
    bitmap[byteIndex] = (UCHAR)(bitmap[byteIndex] | bitMask);
}

static BOOLEAN
kswordArkDriverBitmapHasPid(
    _In_reads_bytes_(bitmapBytes) const UCHAR* bitmap,
    _In_ size_t bitmapBytes,
    _In_ ULONG pidValue
    )
{
    size_t bitIndex = 0;
    size_t byteIndex = 0;
    UCHAR bitMask = 0;

    if (bitmap == NULL || bitmapBytes == 0U) {
        return FALSE;
    }

    bitIndex = (size_t)(pidValue / KSWORD_ARK_ENUM_PID_STEP);
    byteIndex = (bitIndex >> 3);
    if (byteIndex >= bitmapBytes) {
        return FALSE;
    }

    bitMask = (UCHAR)(1U << (bitIndex & 0x07U));
    return ((bitmap[byteIndex] & bitMask) != 0U) ? TRUE : FALSE;
}

static BOOLEAN
kswordArkDriverProcessDynOffsetPresent(
    _In_ ULONG offset
    )
/*++

Routine Description:

    Check if the EPROCESS offset provided by DynData is safe to read.

Arguments:

    Offset - Candidate offset from unified DynData state.

Return Value:

    Returns TRUE if the offset is valid; returns FALSE if the offset is missing or is an old sentinel value.

--*/
{
    return (offset != KSW_DYN_OFFSET_UNAVAILABLE && offset != 0x0000FFFFUL) ? TRUE : FALSE;
}

static BOOLEAN
kswordArkDriverProcessListPointerAligned(
    _In_ const VOID* pointer
    )
/*++

Routine Description:

    Validate basic LIST_ENTRY pointer alignment before touching neighbor links.
    Note: This function performs only a low-cost format check to avoid obvious errors in DynData offsets or
    corrupted linked list pointers that could cause subsequent reads/writes to land on misaligned addresses.

Arguments:

    Pointer - kernel pointer to check.

Return Value:

    TRUE indicates the pointer is non-null and satisfies pointer-width alignment; FALSE indicates it is unsafe for linked list read/write operations.

--*/
{
    return (pointer != NULL &&
        (((ULONG_PTR)pointer & (sizeof(PVOID) - 1U)) == 0U)) ? TRUE : FALSE;
}

static NTSTATUS
kswordArkDriverReadProcessHandleField(
    _In_ PEPROCESS processObject,
    _In_ ULONG offset,
    _Out_ HANDLE* valueOut
    )
/*++

Routine Description:

    Safely read one HANDLE-sized EPROCESS field. Note: Used to read _EPROCESS.UniqueProcessId,
    avoiding direct dereference of potentially incorrect DynData offsets.

Arguments:

    ProcessObject - Target EPROCESS.
    Offset - Field offset inside EPROCESS.
    ValueOut - Receives the HANDLE-sized value.

Return Value:

    STATUS_SUCCESS or validation/exception status.

--*/
{
    HANDLE handleValue = NULL;

    if (processObject == NULL || valueOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *valueOut = NULL;

    if (!kswordArkDriverProcessDynOffsetPresent(offset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    __try {
        RtlCopyMemory(&handleValue, (PUCHAR)processObject + offset, sizeof(handleValue));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    *valueOut = handleValue;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkDriverWriteProcessHandleField(
    _In_ PEPROCESS processObject,
    _In_ ULONG offset,
    _In_ HANDLE value
    )
/*++

Routine Description:

    Safely write one HANDLE-sized EPROCESS field. Note: Used for modifying
    and restoring the _EPROCESS.UniqueProcessId managed by Ksword.

Arguments:

    ProcessObject - Target EPROCESS.
    Offset - Field offset inside EPROCESS.
    Value - HANDLE-sized value to write.

Return Value:

    STATUS_SUCCESS or validation/exception status.

--*/
{
    if (processObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkDriverProcessDynOffsetPresent(offset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    __try {
        RtlCopyMemory((PUCHAR)processObject + offset, &value, sizeof(value));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkDriverValidateActiveProcessLinksForUnlink(
    _In_ LIST_ENTRY* link,
    _Outptr_ LIST_ENTRY** previousOut,
    _Outptr_ LIST_ENTRY** nextOut
    )
/*++

Routine Description:

    Validate the target EPROCESS.ActiveProcessLinks node before DKOM unlink.
    Note: Before hiding, verify the target node is still in the doubly linked list and that its predecessor and successor
    nodes correctly point back to it; otherwise, reject the unlink operation to avoid writing on a corrupted list.

Arguments:

    Note: Link: Address of the ActiveProcessLinks field of the target process.
    PreviousOut - returns Link->Blink.
    NextOut - Returns Link->Flink.

Return Value:

    STATUS_SUCCESS indicates the node can be unlinked; failure indicates parameter, alignment, or neighbor consistency check failure.

--*/
{
    LIST_ENTRY* next = NULL;
    LIST_ENTRY* previous = NULL;

    if (link == NULL || previousOut == NULL || nextOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *previousOut = NULL;
    *nextOut = NULL;

    if (!kswordArkDriverProcessListPointerAligned(link)) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    __try {
        next = link->Flink;
        previous = link->Blink;
        if (!kswordArkDriverProcessListPointerAligned(next) ||
            !kswordArkDriverProcessListPointerAligned(previous) ||
            next == link ||
            previous == link ||
            next->Blink != link ||
            previous->Flink != link) {
            return STATUS_DATA_ERROR;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    *previousOut = previous;
    *nextOut = next;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkDriverTryProcessListOffsets(
    _In_ PEPROCESS processObject,
    _In_ ULONG processId,
    _In_ ULONG uniqueProcessIdOffset,
    _In_ ULONG activeProcessLinksOffset
    )
/*++

Routine Description:

    Validate one candidate pair of _EPROCESS.UniqueProcessId and
    _EPROCESS.ActiveProcessLinks offsets.

Arguments:

    ProcessObject - Target EPROCESS.
    ProcessId - Original target PID.
    UniqueProcessIdOffset - Candidate UniqueProcessId offset.
    ActiveProcessLinksOffset - Candidate ActiveProcessLinks offset.

Return Value:

    STATUS_SUCCESS when the pair matches the target process and points to a
    consistent active-process list node.

--*/
{
    HANDLE uniqueProcessId = NULL;
    LIST_ENTRY* previous = NULL;
    LIST_ENTRY* next = NULL;
    LIST_ENTRY* link = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (processObject == NULL || processId == 0UL || processId <= 4UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkDriverProcessDynOffsetPresent(uniqueProcessIdOffset) ||
        !kswordArkDriverProcessDynOffsetPresent(activeProcessLinksOffset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    status = kswordArkDriverReadProcessHandleField(
        processObject,
        uniqueProcessIdOffset,
        &uniqueProcessId);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (HandleToULong(uniqueProcessId) != processId) {
        return STATUS_NOT_FOUND;
    }

    link = (LIST_ENTRY*)((PUCHAR)processObject + activeProcessLinksOffset);
    return kswordArkDriverValidateActiveProcessLinksForUnlink(link, &previous, &next);
}

static NTSTATUS
kswordArkDriverResolveProcessListOffsets(
    _In_ PEPROCESS processObject,
    _In_ ULONG processId,
    _In_opt_ const KswDynState* dynState,
    _Out_ ULONG* uniqueProcessIdOffsetOut,
    _Out_ ULONG* activeProcessLinksOffsetOut
    )
/*++

Routine Description:

    Resolve _EPROCESS.UniqueProcessId and ActiveProcessLinks offsets for the
    Target process. Note: Prefer using DynData/PDB profiles; if missing, perform a conservative runtime scan
    based on the adjacent layout of these two fields in EPROCESS to avoid returning STATUS_PROCEDURE_NOT_FOUND
    immediately when right-clicking to hide before the Kernel DynData page is flushed.

Arguments:

    ProcessObject - Target EPROCESS.
    ProcessId - Original target PID.
    DynState - Optional current DynData snapshot.
    UniqueProcessIdOffsetOut - Receives UniqueProcessId offset.
    ActiveProcessLinksOffsetOut - Receives ActiveProcessLinks offset.

Return Value:

    STATUS_SUCCESS or the best observed failure status.

--*/
{
    ULONG uniqueOffset = KSW_DYN_OFFSET_UNAVAILABLE;
    ULONG activeOffset = KSW_DYN_OFFSET_UNAVAILABLE;
    ULONG scanOffset = 0UL;
    NTSTATUS status = STATUS_PROCEDURE_NOT_FOUND;
    NTSTATUS lastStatus = STATUS_PROCEDURE_NOT_FOUND;

    if (processObject == NULL ||
        uniqueProcessIdOffsetOut == NULL ||
        activeProcessLinksOffsetOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *uniqueProcessIdOffsetOut = KSW_DYN_OFFSET_UNAVAILABLE;
    *activeProcessLinksOffsetOut = KSW_DYN_OFFSET_UNAVAILABLE;

    if (dynState != NULL && dynState->initialized) {
        uniqueOffset = dynState->kernel.epUniqueProcessId;
        activeOffset = dynState->kernel.epActiveProcessLinks;
    }

    if (kswordArkDriverProcessDynOffsetPresent(activeOffset) &&
        !kswordArkDriverProcessDynOffsetPresent(uniqueOffset) &&
        activeOffset >= sizeof(HANDLE)) {
        uniqueOffset = activeOffset - (ULONG)sizeof(HANDLE);
    }
    if (kswordArkDriverProcessDynOffsetPresent(uniqueOffset) &&
        !kswordArkDriverProcessDynOffsetPresent(activeOffset) &&
        uniqueOffset <= (MAXULONG - (ULONG)sizeof(HANDLE))) {
        activeOffset = uniqueOffset + (ULONG)sizeof(HANDLE);
    }

    if (kswordArkDriverProcessDynOffsetPresent(uniqueOffset) &&
        kswordArkDriverProcessDynOffsetPresent(activeOffset)) {
        status = kswordArkDriverTryProcessListOffsets(
            processObject,
            processId,
            uniqueOffset,
            activeOffset);
        if (NT_SUCCESS(status)) {
            *uniqueProcessIdOffsetOut = uniqueOffset;
            *activeProcessLinksOffsetOut = activeOffset;
            return STATUS_SUCCESS;
        }
        lastStatus = status;
    }

    for (scanOffset = 0UL;
         scanOffset + (ULONG)sizeof(HANDLE) + (ULONG)sizeof(LIST_ENTRY) <= KSWORD_ARK_PROCESS_OFFSET_SCAN_LIMIT;
         scanOffset += (ULONG)sizeof(PVOID)) {
        HANDLE candidatePid = NULL;

        status = kswordArkDriverReadProcessHandleField(processObject, scanOffset, &candidatePid);
        if (!NT_SUCCESS(status)) {
            if (status != STATUS_PROCEDURE_NOT_FOUND) {
                lastStatus = status;
            }
            continue;
        }
        if (HandleToULong(candidatePid) != processId) {
            continue;
        }

        uniqueOffset = scanOffset;
        activeOffset = scanOffset + (ULONG)sizeof(HANDLE);
        status = kswordArkDriverTryProcessListOffsets(
            processObject,
            processId,
            uniqueOffset,
            activeOffset);
        if (NT_SUCCESS(status)) {
            *uniqueProcessIdOffsetOut = uniqueOffset;
            *activeProcessLinksOffsetOut = activeOffset;
            return STATUS_SUCCESS;
        }
        lastStatus = status;
    }

    return (lastStatus == STATUS_NOT_FOUND) ? STATUS_PROCEDURE_NOT_FOUND : lastStatus;
}

static HANDLE
kswordArkDriverBuildHiddenUniqueProcessId(
    _In_ ULONG processId
    )
/*++

Routine Description:

    Build a deterministic fake PID for the UniqueProcessId field. Note: Set the high bits as a tag while
    preserving the lower PID bits to avoid conflicts with normal low-range PIDs and facilitate debugging.

Arguments:

    ProcessId - Original PID.

Return Value:

    HANDLE-sized fake PID value.

--*/
{
    ULONG hiddenPid = KSWORD_ARK_PROCESS_HIDDEN_PID_TAG |
        (processId & KSWORD_ARK_PROCESS_HIDDEN_PID_MASK);

    if (hiddenPid == processId || hiddenPid <= 4UL) {
        hiddenPid = KSWORD_ARK_PROCESS_HIDDEN_PID_TAG;
    }
    return ULongToHandle(hiddenPid);
}

static NTSTATUS
kswordArkDriverPatchUniqueProcessIdForHide(
    _In_ PEPROCESS processObject,
    _In_ ULONG processId,
    _In_ ULONG uniqueProcessIdOffset,
    _Out_ HANDLE* originalUniqueProcessIdOut,
    _Out_ HANDLE* hiddenUniqueProcessIdOut
    )
/*++

Routine Description:

    Patch _EPROCESS.UniqueProcessId for Ksword-managed hide.

Arguments:

    ProcessObject - Target EPROCESS.
    ProcessId - Original PID.
    UniqueProcessIdOffset - Offset resolved from DynData or runtime scan.
    OriginalUniqueProcessIdOut - Receives original HANDLE value.
    HiddenUniqueProcessIdOut - Receives written fake HANDLE value.

Return Value:

    STATUS_SUCCESS when the PID field was modified.

--*/
{
    HANDLE originalUniqueProcessId = NULL;
    HANDLE hiddenUniqueProcessId = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (originalUniqueProcessIdOut == NULL || hiddenUniqueProcessIdOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *originalUniqueProcessIdOut = NULL;
    *hiddenUniqueProcessIdOut = NULL;

    status = kswordArkDriverReadProcessHandleField(
        processObject,
        uniqueProcessIdOffset,
        &originalUniqueProcessId);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (HandleToULong(originalUniqueProcessId) != processId) {
        return STATUS_DATA_ERROR;
    }

    hiddenUniqueProcessId = kswordArkDriverBuildHiddenUniqueProcessId(processId);
    status = kswordArkDriverWriteProcessHandleField(
        processObject,
        uniqueProcessIdOffset,
        hiddenUniqueProcessId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *originalUniqueProcessIdOut = originalUniqueProcessId;
    *hiddenUniqueProcessIdOut = hiddenUniqueProcessId;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkDriverUnlinkActiveProcessLinks(
    _In_ PEPROCESS processObject,
    _In_ ULONG activeProcessLinksOffset,
    _Outptr_ LIST_ENTRY** linkOut,
    _Outptr_ LIST_ENTRY** previousOut,
    _Outptr_ LIST_ENTRY** nextOut
    )
/*++

Routine Description:

    Remove one process from the kernel ActiveProcessLinks list. Note: This function only detaches
    from ActiveProcessLinks; it does not remove entries from PspCidTable nor close handle tables.
    Consequently, the process is invisible to standard NtQuerySystemInformation views, but Ksword
    can still retrieve the EPROCESS via PsLookupProcessByProcessId/CID scanning.

Arguments:

    ProcessObject: Referenced target EPROCESS.
    ActiveProcessLinksOffset: Offset of EPROCESS.ActiveProcessLinks provided by DynData.
    LinkOut - Returns the address of the target LIST_ENTRY.
    PreviousOut - Returns the predecessor node before unlinking.
    NextOut: Returns the successor node before and after unlinking.

Return Value:

    STATUS_SUCCESS indicates the unlink operation is complete; failure indicates missing offset, list inconsistency, or invalid access.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    LIST_ENTRY* link = NULL;
    LIST_ENTRY* previous = NULL;
    LIST_ENTRY* next = NULL;

    if (processObject == NULL || linkOut == NULL || previousOut == NULL || nextOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *linkOut = NULL;
    *previousOut = NULL;
    *nextOut = NULL;

    if (!kswordArkDriverProcessDynOffsetPresent(activeProcessLinksOffset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    link = (LIST_ENTRY*)((PUCHAR)processObject + activeProcessLinksOffset);
    status = kswordArkDriverValidateActiveProcessLinksForUnlink(link, &previous, &next);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    __try {
        previous->Flink = next;
        next->Blink = previous;
        link->Flink = link;
        link->Blink = link;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    *linkOut = link;
    *previousOut = previous;
    *nextOut = next;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkDriverRestoreUniqueProcessIdRecord(
    _Inout_ KswordArkProcessHideRecord* record
    )
/*++

Routine Description:

    Restore _EPROCESS.UniqueProcessId for one Ksword hide record.

Arguments:

    Record - Hide record with original/fake PID values.

Return Value:

    STATUS_SUCCESS when restored or no PID patch is pending.

--*/
{
    HANDLE currentUniqueProcessId = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (record == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!record->uniqueProcessIdPatched) {
        return STATUS_SUCCESS;
    }
    if (record->processObject == NULL ||
        !kswordArkDriverProcessDynOffsetPresent(record->uniqueProcessIdOffset)) {
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkDriverReadProcessHandleField(
        record->processObject,
        record->uniqueProcessIdOffset,
        &currentUniqueProcessId);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (currentUniqueProcessId == record->originalUniqueProcessId) {
        record->uniqueProcessIdPatched = FALSE;
        return STATUS_SUCCESS;
    }
    if (currentUniqueProcessId != record->hiddenUniqueProcessId) {
        return STATUS_DATA_ERROR;
    }

    status = kswordArkDriverWriteProcessHandleField(
        record->processObject,
        record->uniqueProcessIdOffset,
        record->originalUniqueProcessId);
    if (NT_SUCCESS(status)) {
        record->uniqueProcessIdPatched = FALSE;
    }
    return status;
}

static NTSTATUS
kswordArkDriverRestoreActiveProcessLinksRecord(
    _Inout_ KswordArkProcessHideRecord* record
    )
/*++

Routine Description:

    Restore one Ksword-hidden process back into ActiveProcessLinks. Note:
    On restore, the target node must maintain a self-loop. If the predecessor and successor nodes saved during hiding remain
    adjacent, reinsert at the original position; if normal insertions during the list operation cause the original neighbors
    to become non-adjacent, fall back to inserting after PsInitialSystemProcess to avoid breaking the currently active chain.

Arguments:

    Record - Hidden record containing the target EPROCESS, target list node, and saved previous/next nodes.

Return Value:

    STATUS_SUCCESS indicates recovery is complete or the record was already unlinked; failure indicates the list state is unsuitable for recovery.

--*/
{
    LIST_ENTRY* link = NULL;
    LIST_ENTRY* previous = NULL;
    LIST_ENTRY* next = NULL;
    LIST_ENTRY* insertAfter = NULL;
    LIST_ENTRY* insertBefore = NULL;
    LIST_ENTRY* systemHead = NULL;

    if (record == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!record->activeListUnlinked) {
        return STATUS_SUCCESS;
    }

    link = record->activeProcessLinks;
    previous = record->previousLink;
    next = record->nextLink;

    if (!kswordArkDriverProcessListPointerAligned(link) ||
        !kswordArkDriverProcessListPointerAligned(previous) ||
        !kswordArkDriverProcessListPointerAligned(next) ||
        !kswordArkDriverProcessDynOffsetPresent(record->activeProcessLinksOffset)) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    __try {
        if (link->Flink != link || link->Blink != link) {
            return STATUS_DATA_ERROR;
        }

        /*
         * Prefer exact original placement when the saved neighbors are still
         * adjacent.  If they are not, insert immediately after the System
         * process list head.  This fallback preserves all current nodes instead
         * of overwriting previous->Flink/next->Blink across a changed chain.
         */
        if (previous->Flink == next && next->Blink == previous) {
            insertAfter = previous;
            insertBefore = next;
        }
        else {
            if (PsInitialSystemProcess == NULL) {
                return STATUS_PROCEDURE_NOT_FOUND;
            }
            systemHead = (LIST_ENTRY*)((PUCHAR)PsInitialSystemProcess + record->activeProcessLinksOffset);
            if (!kswordArkDriverProcessListPointerAligned(systemHead) ||
                !kswordArkDriverProcessListPointerAligned(systemHead->Flink) ||
                systemHead->Flink->Blink != systemHead) {
                return STATUS_DATA_ERROR;
            }
            insertAfter = systemHead;
            insertBefore = systemHead->Flink;
        }

        link->Blink = insertAfter;
        link->Flink = insertBefore;
        insertAfter->Flink = link;
        insertBefore->Blink = link;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    record->activeListUnlinked = FALSE;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkDriverReadProcessPointerField(
    _In_ PEPROCESS processObject,
    _In_ ULONG offset,
    _Out_ ULONG64* valueOut
    )
/*++

Routine Description:

    Read a pointer field via EPROCESS offset, protected against exception addresses using SEH.

Arguments:

    ProcessObject: Target EPROCESS object.
    Offset - Offset of the target field within EPROCESS.
    ValueOut: Returns the read pointer value, uniformly extended to ULONG64.

Return Value:

    Return STATUS_SUCCESS on success; return the corresponding status for parameter errors, missing offsets, or read exceptions.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID pointerValue = NULL;

    if (processObject == NULL || valueOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *valueOut = 0ULL;
    if (!kswordArkDriverProcessDynOffsetPresent(offset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    __try {
        RtlCopyMemory(&pointerValue, (PUCHAR)processObject + offset, sizeof(pointerValue));
        *valueOut = (ULONG64)(ULONG_PTR)pointerValue;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
}

static BOOLEAN
kswordArkDriverShouldSkipTerminatingProcess(
    _In_ PEPROCESS processObject,
    _In_ const KswDynState* dynState
    )
/*++

Routine Description:

    Check if the candidate EPROCESS has exited or is exiting.
    Prefer the exported routine PsGetProcessExitStatus, which directly reads EPROCESS.ExitStatus without
    relying on any DynData offsets; the fallback path reverts to the SKT64 EPROCESS.ObjectTable criteria.

Arguments:

    ProcessObject - candidate EPROCESS.
    DynState - The unified DynData state captured at the start of this enumeration; may be NULL.

Return Value:

    Returns TRUE if ExitStatus is no longer STATUS_PENDING, or if ObjectTable is
    readable and NULL, indicating the process is in a terminating/exited state.
    Return FALSE when neither criterion yields a conclusion, to avoid hiding legitimate processes due to missing diagnostic data.

--*/
{
    ULONG64 objectTableAddress = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (processObject == NULL) {
        return FALSE;
    }

    //
    // EPROCESS.ExitStatus is set to STATUS_PENDING during process creation and written with the actual exit code upon termination.
    // PsGetProcessExitStatus is an exported routine, so this check remains valid even when DynData is completely missing.
    // System Informer's offset table matches ntoskrnl's TimeDateStamp precisely; new kernels are often not in the table,
    // making EpObjectTable unavailable. Relying solely on the ObjectTable check below would degrade to 'never a zombie'.
    //
    if (PsGetProcessExitStatus(processObject) != STATUS_PENDING) {
        return TRUE;
    }

    if (dynState == NULL || !dynState->initialized ||
        !kswordArkDriverProcessDynOffsetPresent(dynState->kernel.epObjectTable)) {
        return FALSE;
    }

    status = kswordArkDriverReadProcessPointerField(
        processObject,
        dynState->kernel.epObjectTable,
        &objectTableAddress);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    return (objectTableAddress == 0ULL) ? TRUE : FALSE;
}

static VOID
kswordArkDriverCopyImageName(
    _Out_writes_all_(16) CHAR destinationImageName[16],
    _In_opt_z_ const CHAR* sourceImageName
    )
{
    ULONG copyIndex = 0;

    if (destinationImageName == NULL) {
        return;
    }

    RtlZeroMemory(destinationImageName, 16);
    if (sourceImageName == NULL) {
        return;
    }

    for (copyIndex = 0; copyIndex < 15U; ++copyIndex) {
        destinationImageName[copyIndex] = sourceImageName[copyIndex];
        if (sourceImageName[copyIndex] == '\0') {
            break;
        }
    }
    destinationImageName[15] = '\0';
}

static VOID
kswordArkDriverAppendProcessEntry(
    _Inout_ KSWORD_ARK_ENUM_PROCESS_RESPONSE* response,
    _In_ size_t entryCapacity,
    _In_ ULONG processId,
    _In_ ULONG parentProcessId,
    _In_ ULONG processFlags,
    _In_opt_z_ const CHAR* imageName,
    _In_opt_ PEPROCESS processObject
    )
{
    KSWORD_ARK_PROCESS_ENTRY* entry = NULL;

    if (response == NULL) {
        return;
    }

    if (response->totalCount != MAXULONG) {
        response->totalCount += 1UL;
    }

    if ((size_t)response->returnedCount >= entryCapacity) {
        return;
    }

    entry = &response->entries[response->returnedCount];
    RtlZeroMemory(entry, sizeof(*entry));
    entry->processId = processId;
    entry->parentProcessId = parentProcessId;
    entry->flags = processFlags;
    kswordArkDriverCopyImageName(entry->imageName, imageName);
    if (processObject != NULL) {
        kswordArkProcessPopulateExtendedEntry(entry, processObject);
    }
    else {
        /*
         * CID-only placeholder:
         * - Inputs: a decoded PspCidTable row whose object type matched Process
         *   but could not be safely referenced for detail sampling.
         * - Processing: keep the CID value visible and mark the detail state as
         *   read-failed instead of dropping the row.
         * - Return behavior: no return value; the partially populated row still
         *   lets R3 offer object-based R0 actions by CID.
         */
        entry->r0Status = KSWORD_ARK_PROCESS_R0_STATUS_READ_FAILED;
    }
    response->returnedCount += 1UL;
}

static VOID
kswordArkDriverEnumProcessCidCallback(
    _In_ const KswCrossviewCidEntry* entry,
    _Inout_opt_ PVOID context
    )
/*++

Routine Description:

    Merge one direct PspCidTable process candidate into the normal process
    Enumeration response. Note: Processes matching the CID table must be visible; even if an object cannot be
    referenced or is already terminating, it is only downgraded to a gray diagnostic line and never dropped.

Arguments:

    Entry - CID walker payload.
    Context - KswordArkEnumProcessCidContext.

Return Value:

    None. The response buffer is updated in place.

--*/
{
    KswordArkEnumProcessCidContext* enumContext =
        (KswordArkEnumProcessCidContext*)context;
    ULONG processFlags =
        KSWORD_ARK_PROCESS_FLAG_KERNEL_ENUMERATED |
        KSWORD_ARK_PROCESS_FLAG_CID_TABLE_ENUMERATED;
    ULONG parentProcessId = 0UL;
    const CHAR* imageName = "CIDOnly";

    if (enumContext == NULL || entry == NULL) {
        return;
    }
    if (!kswordArkDriverPidInScanRange(
            entry->cidValue,
            enumContext->scanStartPid,
            enumContext->scanEndPid)) {
        return;
    }
    if (enumContext->activePidBitmap != NULL &&
        enumContext->activePidBitmapBytes != 0U &&
        kswordArkDriverBitmapHasPid(
            enumContext->activePidBitmap,
            enumContext->activePidBitmapBytes,
            entry->cidValue)) {
        return;
    }

    if (enumContext->activeWalkAvailable) {
        processFlags |= KSWORD_ARK_PROCESS_FLAG_HIDDEN_FROM_ACTIVE_LIST;
    }
    if (kswordArkDriverIsProcessHiddenByUi(entry->cidValue)) {
        processFlags |= KSWORD_ARK_PROCESS_FLAG_HIDDEN_BY_KSWORD_UI;
    }

    if (entry->referenced && entry->object != NULL) {
        PEPROCESS processObject = (PEPROCESS)entry->object;
        if (kswordArkDriverShouldSkipTerminatingProcess(processObject, enumContext->dynState)) {
            //
            // EPROCESS objects removed from ActiveProcessLinks but still referenced by parent process handles after exit
            // remain in PspCidTable. These remnants are mostly not hidden processes, but the driver still reports them:
            // The criterion 'ExitStatus != STATUS_PENDING' alone cannot distinguish between orphaned processes and newly unlinked live
            // processes; discarding them directly would miss genuine hidden processes. Instead, mark them with TERMINATING_OR_EXITED,
            // let R3 flag them as 'potential false positives' and gray them out, leaving the final decision to the user.
            //
            processFlags |= KSWORD_ARK_PROCESS_FLAG_TERMINATING_OR_EXITED;
        }
        parentProcessId = HandleToULong(PsGetProcessInheritedFromUniqueProcessId(processObject));
        imageName = PsGetProcessImageFileName(processObject);
        kswordArkDriverAppendProcessEntry(
            enumContext->response,
            enumContext->entryCapacity,
            entry->cidValue,
            parentProcessId,
            processFlags,
            imageName,
            processObject);
        return;
    }

    processFlags |= KSWORD_ARK_PROCESS_FLAG_CID_TABLE_REFERENCE_FAILED;
    kswordArkDriverAppendProcessEntry(
        enumContext->response,
        enumContext->entryCapacity,
        entry->cidValue,
        parentProcessId,
        processFlags,
        imageName,
        NULL);
}

static NTSTATUS
kswordArkDriverEnumerateProcessesByCidTable(
    _Inout_ KSWORD_ARK_ENUM_PROCESS_RESPONSE* response,
    _In_ size_t entryCapacity,
    _In_ const KswDynState* dynState,
    _In_reads_bytes_opt_(activePidBitmapBytes) const UCHAR* activePidBitmap,
    _In_ size_t activePidBitmapBytes,
    _In_ ULONG scanStartPid,
    _In_ ULONG scanEndPid,
    _In_ BOOLEAN activeWalkAvailable
    )
/*++

Routine Description:

    enumerate process rows directly from PspCidTable. Note: This replaces the old
    'step-by-step by PID + PsLookupProcessByProcessId' scan to avoid hiding CID table
    evidence rows when PsLookup is hooked or candidate objects are in special states.

Arguments:

    Response - Mutable enum-process response.
    EntryCapacity - Maximum number of entries that fit in Response.
    DynState - DynData snapshot captured by the caller.
    ActivePidBitmap - Optional bitmap of PIDs already seen by PsGetNextProcess.
    ActivePidBitmapBytes - Byte length of ActivePidBitmap.
    ScanStartPid - Lower inclusive CID range.
    ScanEndPid - Upper inclusive CID range.
    ActiveWalkAvailable - TRUE when ActivePidBitmap represents an active walk.

Return Value:

    STATUS_SUCCESS when the CID table walk completed or was bounded; otherwise
    resolver/walker status for diagnostics. Rows already appended remain valid.

--*/
{
    KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS fieldOffsets;
    KswordArkEnumProcessCidContext enumContext;
    PVOID pspCidTableAddress = NULL;
    ULONG64 missingCapabilityMask = 0ULL;
    ULONG visitedEntries = 0UL;
    BOOLEAN usedDynDataGlobal = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (response == NULL || dynState == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (PsProcessType == NULL || *PsProcessType == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    RtlZeroMemory(&fieldOffsets, sizeof(fieldOffsets));
    RtlZeroMemory(&enumContext, sizeof(enumContext));
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

    enumContext.response = response;
    enumContext.entryCapacity = entryCapacity;
    enumContext.dynState = dynState;
    enumContext.activePidBitmap = activePidBitmap;
    enumContext.activePidBitmapBytes = activePidBitmapBytes;
    enumContext.scanStartPid = scanStartPid;
    enumContext.scanEndPid = scanEndPid;
    enumContext.activeWalkAvailable = activeWalkAvailable;

    status = kswordArkCrossViewWalkCidTable(
        dynState,
        pspCidTableAddress,
        *PsProcessType,
        KSWORD_ARK_ENUM_CID_WALK_MAX_NODES,
        kswordArkDriverEnumProcessCidCallback,
        &enumContext,
        &visitedEntries);
    UNREFERENCED_PARAMETER(visitedEntries);
    if (status == STATUS_BUFFER_OVERFLOW) {
        return STATUS_SUCCESS;
    }
    return status;
}

static NTSTATUS
kswordArkDriverResolveSignatureLevelsFromSigner(
    _In_ UCHAR signerType,
    _Out_ UCHAR* signatureLevel,
    _Out_ UCHAR* sectionSignatureLevel
    )
{
    if (signatureLevel == NULL || sectionSignatureLevel == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    switch (signerType) {
    case KSWORD_PS_PROTECTED_SIGNER_NONE:
        *signatureLevel = SE_SIGNING_LEVEL_UNCHECKED;
        *sectionSignatureLevel = SE_SIGNING_LEVEL_UNCHECKED;
        return STATUS_SUCCESS;
    case KSWORD_PS_PROTECTED_SIGNER_AUTHENTICODE:
        *signatureLevel = SE_SIGNING_LEVEL_AUTHENTICODE;
        *sectionSignatureLevel = SE_SIGNING_LEVEL_AUTHENTICODE;
        return STATUS_SUCCESS;
    case KSWORD_PS_PROTECTED_SIGNER_CODEGEN:
        *signatureLevel = SE_SIGNING_LEVEL_DYNAMIC_CODEGEN;
        *sectionSignatureLevel = SE_SIGNING_LEVEL_STORE;
        return STATUS_SUCCESS;
    case KSWORD_PS_PROTECTED_SIGNER_ANTIMALWARE:
        *signatureLevel = SE_SIGNING_LEVEL_ANTIMALWARE;
        *sectionSignatureLevel = SE_SIGNING_LEVEL_ANTIMALWARE;
        return STATUS_SUCCESS;
    case KSWORD_PS_PROTECTED_SIGNER_LSA:
        *signatureLevel = SE_SIGNING_LEVEL_WINDOWS;
        *sectionSignatureLevel = SE_SIGNING_LEVEL_MICROSOFT;
        return STATUS_SUCCESS;
    case KSWORD_PS_PROTECTED_SIGNER_WINDOWS:
        *signatureLevel = SE_SIGNING_LEVEL_WINDOWS;
        *sectionSignatureLevel = SE_SIGNING_LEVEL_WINDOWS;
        return STATUS_SUCCESS;
    case KSWORD_PS_PROTECTED_SIGNER_WINTCB:
        *signatureLevel = SE_SIGNING_LEVEL_WINDOWS_TCB;
        *sectionSignatureLevel = SE_SIGNING_LEVEL_WINDOWS;
        return STATUS_SUCCESS;
    case KSWORD_PS_PROTECTED_SIGNER_WINSYSTEM:
        // WinSystem is the highest signer used by System (PID 4). It has no user-mode image, so the signature level
        // in the kernel is not referenceable. Here, we follow the WinTcb combination, keeping the section as WINDOWS
        // rather than WINDOWS_TCB—the latter would prevent privileged processes from loading almost any DLL.
        *signatureLevel = SE_SIGNING_LEVEL_WINDOWS_TCB;
        *sectionSignatureLevel = SE_SIGNING_LEVEL_WINDOWS;
        return STATUS_SUCCESS;
    case KSWORD_PS_PROTECTED_SIGNER_APP:
        *signatureLevel = SE_SIGNING_LEVEL_STORE;
        *sectionSignatureLevel = SE_SIGNING_LEVEL_STORE;
        return STATUS_SUCCESS;
    default:
        return STATUS_INVALID_PARAMETER;
    }
}

// PPLcontrol-style fallback: calculate target bytes here, then let Phase-2
// DynData-owned process_extended.c perform the actual EPROCESS patch.
static NTSTATUS
kswordArkDriverPatchProcessProtectionStateByPid(
    _In_ ULONG processId,
    _In_ UCHAR protectionLevel
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    UCHAR signerType = (UCHAR)((protectionLevel & 0xF0U) >> 4U);
    UCHAR signatureLevel = SE_SIGNING_LEVEL_UNCHECKED;
    UCHAR sectionSignatureLevel = SE_SIGNING_LEVEL_UNCHECKED;

    if (protectionLevel == 0U) {
        signerType = KSWORD_PS_PROTECTED_SIGNER_NONE;
    }

    status = kswordArkDriverResolveSignatureLevelsFromSigner(
        signerType,
        &signatureLevel,
        &sectionSignatureLevel);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return kswordArkProcessPatchProtectionByDynData(
        processId,
        protectionLevel,
        signatureLevel,
        sectionSignatureLevel);
}

NTSTATUS
kswordArkDriverSetProcessVisibility(
    _In_ ULONG processId,
    _In_ ULONG action,
    _In_ ULONG flags,
    _Out_ ULONG* statusOut,
    _Out_ ULONG* hiddenCountOut
    )
/*++

Routine Description:

    Note: HIDE modifies _EPROCESS.UniqueProcessId only, removes ActiveProcessLinks
    only, or performs both for legacy compatibility based on Flags; all modes
    retain PspCidTable. UNHIDE/CLEAR_ALL only restores PID and linked list records
    saved by this driver, rejecting any kernel addresses passed from R3.

Arguments:

    ProcessId: Target PID; the ClearAll action ignores this value.
    Action - HIDE/UNHIDE/CLEAR_ALL。
    Flags: HIDE mode selection; 0 indicates compatibility with the legacy dual-operation mode.
    StatusOut - Returns a readable status enumeration.
    HiddenCountOut - Returns the current count of hidden PIDs.

Return Value:

    STATUS_SUCCESS indicates the action completed; failure indicates an anomaly in parameters, lookup, DynData, or linked list state.

--*/
{
    ULONG index = 0UL;
    ULONG foundIndex = MAXULONG;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS restoreStatus = STATUS_SUCCESS;
    PEPROCESS processObject = NULL;
    KswDynState dynState;
    ULONG uniqueProcessIdOffset = KSW_DYN_OFFSET_UNAVAILABLE;
    ULONG activeProcessLinksOffset = KSW_DYN_OFFSET_UNAVAILABLE;
    ULONG visibilityFlags = 0UL;
    BOOLEAN shouldPatchUniquePid = FALSE;
    BOOLEAN shouldUnlinkActiveList = FALSE;

    if (statusOut == NULL || hiddenCountOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *statusOut = KSWORD_ARK_PROCESS_VISIBILITY_STATUS_UNKNOWN;
    *hiddenCountOut = 0UL;
    RtlZeroMemory(&dynState, sizeof(dynState));
    kswordArkDriverEnsureProcessHideStateInitialized();

    if (action == KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE) {
        visibilityFlags = flags;
        if (visibilityFlags == 0UL) {
            visibilityFlags = KSWORD_ARK_PROCESS_VISIBILITY_FLAG_LEGACY_BOTH;
        }
        visibilityFlags &= KSWORD_ARK_PROCESS_VISIBILITY_FLAG_LEGACY_BOTH;
        if (visibilityFlags == 0UL) {
            return STATUS_INVALID_PARAMETER;
        }

        /*
         * The booleans are computed once before acquiring the state lock so the
         * actual mutation path has a single source of truth.  Return behavior:
         * UNHIDE/CLEAR_ALL ignore Flags and restore whatever a prior record says
         * was actually changed.
         */
        shouldPatchUniquePid =
            ((visibilityFlags & KSWORD_ARK_PROCESS_VISIBILITY_FLAG_PATCH_UNIQUE_PID) != 0UL)
            ? TRUE
            : FALSE;
        shouldUnlinkActiveList =
            ((visibilityFlags & KSWORD_ARK_PROCESS_VISIBILITY_FLAG_UNLINK_ACTIVE_LIST) != 0UL)
            ? TRUE
            : FALSE;
    }

    if (action == KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE &&
        (processId == 0UL || processId <= 4UL)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (action == KSWORD_ARK_PROCESS_VISIBILITY_ACTION_UNHIDE &&
        (processId == 0UL || processId <= 4UL)) {
        *statusOut = KSWORD_ARK_PROCESS_VISIBILITY_STATUS_VISIBLE;
        kswordArkAcquirePushLockShared(&gKswordArkProcessHideState.lock);
        *hiddenCountOut = gKswordArkProcessHideState.count;
        kswordArkReleasePushLockShared(&gKswordArkProcessHideState.lock);
        return STATUS_SUCCESS;
    }
    if (action == KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE) {
        BOOLEAN alreadyHidden = FALSE;
        kswordArkAcquirePushLockShared(&gKswordArkProcessHideState.lock);
        for (index = 0UL; index < gKswordArkProcessHideState.count; ++index) {
            if (gKswordArkProcessHideState.records[index].pid == processId) {
                alreadyHidden = TRUE;
                break;
            }
        }
        *hiddenCountOut = gKswordArkProcessHideState.count;
        kswordArkReleasePushLockShared(&gKswordArkProcessHideState.lock);
        if (alreadyHidden) {
            *statusOut = KSWORD_ARK_PROCESS_VISIBILITY_STATUS_HIDDEN;
            return STATUS_SUCCESS;
        }

        kswordArkDynDataSnapshot(&dynState);
        status = PsLookupProcessByProcessId(ULongToHandle(processId), &processObject);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = kswordArkDriverResolveProcessListOffsets(
            processObject,
            processId,
            &dynState,
            &uniqueProcessIdOffset,
            &activeProcessLinksOffset);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(processObject);
            processObject = NULL;
            return status;
        }
    }

    kswordArkAcquirePushLockExclusive(&gKswordArkProcessHideState.lock);
    __try {
        for (index = 0UL; index < gKswordArkProcessHideState.count; ++index) {
            if (gKswordArkProcessHideState.records[index].pid == processId) {
                foundIndex = index;
                break;
            }
        }

        if (action == KSWORD_ARK_PROCESS_VISIBILITY_ACTION_CLEAR_ALL) {
            index = 0UL;
            while (index < gKswordArkProcessHideState.count) {
                KswordArkProcessHideRecord* record =
                    &gKswordArkProcessHideState.records[index];
                restoreStatus = kswordArkDriverRestoreUniqueProcessIdRecord(record);
                if (NT_SUCCESS(restoreStatus)) {
                    restoreStatus = kswordArkDriverRestoreActiveProcessLinksRecord(record);
                }
                if (!NT_SUCCESS(restoreStatus)) {
                    if (NT_SUCCESS(status)) {
                        status = restoreStatus;
                    }
                    ++index;
                    continue;
                }

                if (record->processObject != NULL) {
                    ObDereferenceObject(record->processObject);
                    record->processObject = NULL;
                }
                for (foundIndex = index + 1UL;
                     foundIndex < gKswordArkProcessHideState.count;
                     ++foundIndex) {
                    gKswordArkProcessHideState.records[foundIndex - 1UL] =
                        gKswordArkProcessHideState.records[foundIndex];
                }
                gKswordArkProcessHideState.count -= 1UL;
                RtlZeroMemory(
                    &gKswordArkProcessHideState.records[gKswordArkProcessHideState.count],
                    sizeof(gKswordArkProcessHideState.records[gKswordArkProcessHideState.count]));
            }
            *statusOut = (gKswordArkProcessHideState.count == 0UL)
                ? KSWORD_ARK_PROCESS_VISIBILITY_STATUS_CLEARED
                : KSWORD_ARK_PROCESS_VISIBILITY_STATUS_HIDDEN;
        }
        else if (action == KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE) {
            if (foundIndex != MAXULONG) {
                *statusOut = KSWORD_ARK_PROCESS_VISIBILITY_STATUS_HIDDEN;
            }
            else if (gKswordArkProcessHideState.count >= KSWORD_ARK_PROCESS_HIDE_MAX_PIDS) {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
            else {
                KswordArkProcessHideRecord* record =
                    &gKswordArkProcessHideState.records[gKswordArkProcessHideState.count];
                LIST_ENTRY* link = NULL;
                LIST_ENTRY* previous = NULL;
                LIST_ENTRY* next = NULL;
                HANDLE originalUniqueProcessId = NULL;
                HANDLE hiddenUniqueProcessId = NULL;

                if (shouldPatchUniquePid) {
                    status = kswordArkDriverPatchUniqueProcessIdForHide(
                        processObject,
                        processId,
                        uniqueProcessIdOffset,
                        &originalUniqueProcessId,
                        &hiddenUniqueProcessId);
                    if (!NT_SUCCESS(status)) {
                        *statusOut = KSWORD_ARK_PROCESS_VISIBILITY_STATUS_UNKNOWN;
                    }
                }
                if (NT_SUCCESS(status) && shouldUnlinkActiveList) {
                    status = kswordArkDriverUnlinkActiveProcessLinks(
                        processObject,
                        activeProcessLinksOffset,
                        &link,
                        &previous,
                        &next);
                    if (!NT_SUCCESS(status) && shouldPatchUniquePid) {
                        KswordArkProcessHideRecord rollbackRecord;
                        NTSTATUS rollbackStatus = STATUS_SUCCESS;
                        RtlZeroMemory(&rollbackRecord, sizeof(rollbackRecord));
                        rollbackRecord.processObject = processObject;
                        rollbackRecord.pid = processId;
                        rollbackRecord.uniqueProcessIdOffset = uniqueProcessIdOffset;
                        rollbackRecord.originalUniqueProcessId = originalUniqueProcessId;
                        rollbackRecord.hiddenUniqueProcessId = hiddenUniqueProcessId;
                        rollbackRecord.uniqueProcessIdPatched = TRUE;
                        rollbackStatus = kswordArkDriverRestoreUniqueProcessIdRecord(&rollbackRecord);
                        if (!NT_SUCCESS(rollbackStatus)) {
                            RtlZeroMemory(record, sizeof(*record));
                            record->pid = processId;
                            record->uniqueProcessIdOffset = uniqueProcessIdOffset;
                            record->activeProcessLinksOffset = activeProcessLinksOffset;
                            record->processObject = processObject;
                            record->originalUniqueProcessId = originalUniqueProcessId;
                            record->hiddenUniqueProcessId = hiddenUniqueProcessId;
                            record->uniqueProcessIdPatched = TRUE;
                            record->activeListUnlinked = FALSE;
                            processObject = NULL;
                            gKswordArkProcessHideState.count += 1UL;
                            *statusOut = KSWORD_ARK_PROCESS_VISIBILITY_STATUS_HIDDEN;
                            status = rollbackStatus;
                        }
                    }
                }
                if (NT_SUCCESS(status)) {
                    RtlZeroMemory(record, sizeof(*record));
                    record->pid = processId;
                    record->uniqueProcessIdOffset = uniqueProcessIdOffset;
                    record->activeProcessLinksOffset = activeProcessLinksOffset;
                    record->processObject = processObject;
                    record->originalUniqueProcessId = originalUniqueProcessId;
                    record->hiddenUniqueProcessId = hiddenUniqueProcessId;
                    record->activeProcessLinks = link;
                    record->previousLink = previous;
                    record->nextLink = next;
                    record->uniqueProcessIdPatched = shouldPatchUniquePid;
                    record->activeListUnlinked = shouldUnlinkActiveList;
                    processObject = NULL;
                    gKswordArkProcessHideState.count += 1UL;
                    *statusOut = KSWORD_ARK_PROCESS_VISIBILITY_STATUS_HIDDEN;
                }
            }
        }
        else if (action == KSWORD_ARK_PROCESS_VISIBILITY_ACTION_UNHIDE) {
            if (foundIndex != MAXULONG) {
                KswordArkProcessHideRecord* record =
                    &gKswordArkProcessHideState.records[foundIndex];
                status = kswordArkDriverRestoreUniqueProcessIdRecord(record);
                if (NT_SUCCESS(status)) {
                    status = kswordArkDriverRestoreActiveProcessLinksRecord(record);
                }
                if (!NT_SUCCESS(status)) {
                    *statusOut = KSWORD_ARK_PROCESS_VISIBILITY_STATUS_HIDDEN;
                    *hiddenCountOut = gKswordArkProcessHideState.count;
                    __leave;
                }

                if (record->processObject != NULL) {
                    ObDereferenceObject(record->processObject);
                    record->processObject = NULL;
                }
                for (index = foundIndex + 1UL; index < gKswordArkProcessHideState.count; ++index) {
                    gKswordArkProcessHideState.records[index - 1UL] =
                        gKswordArkProcessHideState.records[index];
                }
                if (gKswordArkProcessHideState.count > 0UL) {
                    gKswordArkProcessHideState.count -= 1UL;
                    RtlZeroMemory(
                        &gKswordArkProcessHideState.records[gKswordArkProcessHideState.count],
                        sizeof(gKswordArkProcessHideState.records[gKswordArkProcessHideState.count]));
                }
            }
            *statusOut = KSWORD_ARK_PROCESS_VISIBILITY_STATUS_VISIBLE;
        }
        else {
            status = STATUS_INVALID_PARAMETER;
        }

        *hiddenCountOut = gKswordArkProcessHideState.count;
    }
    __finally {
        kswordArkReleasePushLockExclusive(&gKswordArkProcessHideState.lock);
    }

    if (processObject != NULL) {
        ObDereferenceObject(processObject);
        processObject = NULL;
    }

    return status;
}

NTSTATUS
kswordArkDriverSuspendProcessByPid(
    _In_ ULONG processId
    )
/*++

Routine Description:

    Suspend target process by PID (PsSuspendProcess preferred, Zw/Nt fallback).

Arguments:

    processId - Target process ID.

Return Value:

    NTSTATUS

--*/
{
    OBJECT_ATTRIBUTES objectAttributes;
    CLIENT_ID clientId;
    HANDLE processHandle = NULL;
    PEPROCESS processObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    KswordPsSuspendProcessFn psSuspendProcess = NULL;
    KswordZwOrNtSuspendProcessFn zwOrNtSuspendProcess = NULL;

    if (processId == 0U || processId <= 4U) {
        return STATUS_INVALID_PARAMETER;
    }

    // Prefer PsSuspendProcess with PEPROCESS input for wider compatibility.
    psSuspendProcess = kswordArkDriverResolvePsSuspendProcess();
    if (psSuspendProcess != NULL) {
        status = PsLookupProcessByProcessId(ULongToHandle(processId), &processObject);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = psSuspendProcess(processObject);
        ObDereferenceObject(processObject);
        return status;
    }

    // Fallback to Zw/NtSuspendProcess with process-handle input.
    zwOrNtSuspendProcess = kswordArkDriverResolveZwOrNtSuspendProcess();
    if (zwOrNtSuspendProcess == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = ULongToHandle(processId);
    clientId.UniqueThread = NULL;
    status = ZwOpenProcess(
        &processHandle,
        PROCESS_SUSPEND_RESUME,
        &objectAttributes,
        &clientId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = zwOrNtSuspendProcess(processHandle);
    ZwClose(processHandle);
    return status;
}

NTSTATUS
kswordArkDriverResumeProcessByPid(
    _In_ ULONG processId
    )
/*++

Routine Description:

    Resume target process by PID (PsResumeProcess preferred, Zw/Nt fallback).
    Note: This is symmetric line-by-line with kswordArkDriverSuspendProcessByPid, including the PID lower
    bound, resolution order, and access rights requested during fallback. Asymmetry between the two can cause
    a process to be suspended but not resumed, a state that is invisible from return values on either side.

Arguments:

    processId - Target process ID.

Return Value:

    NTSTATUS

--*/
{
    OBJECT_ATTRIBUTES objectAttributes;
    CLIENT_ID clientId;
    HANDLE processHandle = NULL;
    PEPROCESS processObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    KswordPsResumeProcessFn psResumeProcess = NULL;
    KswordZwOrNtResumeProcessFn zwOrNtResumeProcess = NULL;

    if (processId == 0U || processId <= 4U) {
        return STATUS_INVALID_PARAMETER;
    }

    // Prefer PsResumeProcess with PEPROCESS input for wider compatibility.
    psResumeProcess = kswordArkDriverResolvePsResumeProcess();
    if (psResumeProcess != NULL) {
        status = PsLookupProcessByProcessId(ULongToHandle(processId), &processObject);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = psResumeProcess(processObject);
        ObDereferenceObject(processObject);
        return status;
    }

    // Fallback to Zw/NtResumeProcess with process-handle input.
    zwOrNtResumeProcess = kswordArkDriverResolveZwOrNtResumeProcess();
    if (zwOrNtResumeProcess == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = ULongToHandle(processId);
    clientId.UniqueThread = NULL;
    status = ZwOpenProcess(
        &processHandle,
        PROCESS_SUSPEND_RESUME,
        &objectAttributes,
        &clientId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = zwOrNtResumeProcess(processHandle);
    ZwClose(processHandle);
    return status;
}

NTSTATUS
kswordArkDriverApplyProcessProtectionToObject(
    _In_ PEPROCESS processObject,
    _In_ UCHAR protectionLevel
    )
/*++

Routine Description:

    Apply a PS_PROTECTION byte to an already referenced process object.
    Note: The PP guardian only has PEPROCESS in both process creation callbacks and inspections,
    lacking a trusted PID (which may be modified via DKOM or reused). Thus, an entry point bypassing
    PsLookupProcessByProcessId is required. Since the signature level table resides in this file,
    parsing is implemented here; actual writing reuses the process_extended.c module owned by DynData.

Arguments:

    processObject - Referenced target EPROCESS.
    protectionLevel: Target PS_PROTECTION raw byte; 0 indicates clearing protection.

Return Value:

    NTSTATUS from signer resolution or the EPROCESS patch.

--*/
{
    const UCHAR kProtectionType = (UCHAR)(protectionLevel & 0x07U);
    UCHAR signerType = (UCHAR)((protectionLevel & 0xF0U) >> 4U);
    UCHAR signatureLevel = SE_SIGNING_LEVEL_UNCHECKED;
    UCHAR sectionSignatureLevel = SE_SIGNING_LEVEL_UNCHECKED;
    NTSTATUS status = STATUS_SUCCESS;

    if (processObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (protectionLevel == 0U) {
        signerType = KSWORD_PS_PROTECTED_SIGNER_NONE;
    }
    else if ((kProtectionType != KSWORD_PS_PROTECTED_TYPE_LIGHT &&
              kProtectionType != KSWORD_PS_PROTECTED_TYPE_FULL) ||
             signerType == KSWORD_PS_PROTECTED_SIGNER_NONE ||
             signerType > KSWORD_PS_PROTECTED_SIGNER_APP) {
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkDriverResolveSignatureLevelsFromSigner(
        signerType,
        &signatureLevel,
        &sectionSignatureLevel);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return kswordArkProcessPatchProtectionByDynDataObject(
        processObject,
        protectionLevel,
        signatureLevel,
        sectionSignatureLevel);
}

NTSTATUS
kswordArkDriverSetProcessPplLevelByPid(
    _In_ ULONG processId,
    _In_ UCHAR protectionLevel
    )
/*++

Routine Description:

    Set target process protection state by PID using PPLcontrol-style direct
    EPROCESS patching (Protection + SignatureLevel + SectionSignatureLevel).

    Note: The IOCTL name retains the historical SET_PPL_LEVEL, but this entry point accepts two protection types simultaneously:
    Type==1 denotes PPL (PsProtectedTypeProtectedLight), and Type==2 denotes full PP
    (PsProtectedTypeProtected). They differ only by the type bit in the Protection byte. Signature levels
    are still resolved via the signer lookup table—the kernel determines "who can open whom" solely based on
    the Protection byte, while the signature level dictates which images the process can subsequently load.

Arguments:

    processId - Target process ID.
    protectionLevel - Target PS_PROTECTION raw byte:
        Type bits 0-2, Audit bit 3, Signer bits 4-7.

Return Value:

    NTSTATUS

--*/
{
    const UCHAR kProtectionType = (UCHAR)(protectionLevel & 0x07U);
    const UCHAR kSignerType = (UCHAR)((protectionLevel & 0xF0U) >> 4U);

    if (processId == 0U || processId <= 4U) {
        return STATUS_INVALID_PARAMETER;
    }

    // 0x00: Disable protection and clear signature level.
    if (protectionLevel == 0U) {
        return kswordArkDriverPatchProcessProtectionStateByPid(processId, 0U);
    }

    // Only accept PPL and PP types; signer must fall within the mapped range 1..8.
    // Audit bit (bit 3) is independent of signature level; write it as-is following legacy behavior, do not block here.
    if ((kProtectionType != KSWORD_PS_PROTECTED_TYPE_LIGHT &&
         kProtectionType != KSWORD_PS_PROTECTED_TYPE_FULL) ||
        kSignerType == KSWORD_PS_PROTECTED_SIGNER_NONE ||
        kSignerType > KSWORD_PS_PROTECTED_SIGNER_APP) {
        return STATUS_INVALID_PARAMETER;
    }

    return kswordArkDriverPatchProcessProtectionStateByPid(processId, protectionLevel);
}

static NTSTATUS
kswordArkDriverBuildMandatoryIntegritySid(
    _In_ ULONG integrityRid,
    _Out_writes_bytes_(SECURITY_MAX_SID_SIZE) PSID sidBuffer
    )
/*++

Routine Description:

    Build an S-1-16-* mandatory integrity SID in caller-provided storage.

Arguments:

    IntegrityRid - Mandatory label RID.
    SidBuffer - SECURITY_MAX_SID_SIZE writable storage.

Return Value:

    STATUS_SUCCESS or an RTL SID construction failure.

--*/
{
    SID_IDENTIFIER_AUTHORITY mandatoryLabelAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    NTSTATUS status = STATUS_SUCCESS;
    PULONG subAuthority = NULL;

    if (sidBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(sidBuffer, SECURITY_MAX_SID_SIZE);
    status = RtlInitializeSid(sidBuffer, &mandatoryLabelAuthority, 1);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    subAuthority = RtlSubAuthoritySid(sidBuffer, 0);
    if (subAuthority == NULL) {
        return STATUS_INVALID_SID;
    }

    *subAuthority = integrityRid;
    return RtlValidSid(sidBuffer) ? STATUS_SUCCESS : STATUS_INVALID_SID;
}

static BOOLEAN
kswordArkDriverDynOffsetPresent(
    _In_ ULONG offset
    )
/*++

Routine Description:

    Test whether one DynData offset is usable by a private-field consumer.

Arguments:

    Offset - Normalized KSW_DYN offset value.

Return Value:

    TRUE when the offset is neither unavailable nor the legacy 0xffff sentinel;
    otherwise FALSE.

--*/
{
    return (offset != KSW_DYN_OFFSET_UNAVAILABLE && offset != 0x0000FFFFUL) ? TRUE : FALSE;
}

static BOOLEAN
kswordArkDriverTokenIntegritySourceTrusted(
    _In_ ULONG source
    )
/*++

Routine Description:

    Accept either an exact PDB profile or the live-validated runtime resolver.

Arguments:

    Source - DynData provenance value for one private token field.

Return Value:

    TRUE only for an identity-bound PDB fact or validated runtime pattern.

--*/
{
    return (source == KSW_DYN_FIELD_SOURCE_PDB_PROFILE ||
            source == KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN)
        ? TRUE
        : FALSE;
}

static BOOLEAN
kswordArkDriverTokenIntegrityDynDataReady(
    _In_ const KswDynState* state
    )
/*++

Routine Description:

    Validate the exact DynData dependencies required to patch a process token
    mandatory-label SID. Note: Speculative sources are not accepted here. _EPROCESS.Token
    and _TOKEN.UserAndGroupCount/UserAndGroups/IntegrityLevelIndex must originate from
    the current ntoskrnl PDB profile or be cross-validated via a real Token query runtime
    pattern, and the capability must already be calculated as available by DynData.

Arguments:

    State - Immutable DynData snapshot captured by the caller.

Return Value:

    TRUE when the private token integrity path may run; otherwise FALSE.

--*/
{
    if (state == NULL) {
        return FALSE;
    }
    if ((state->capabilityMask & KSW_CAP_TOKEN_INTEGRITY_FIELDS) == 0ULL) {
        return FALSE;
    }
    if (!kswordArkDriverDynOffsetPresent(state->kernel.epToken) ||
        !kswordArkDriverDynOffsetPresent(state->kernel.tokUserAndGroupCount) ||
        !kswordArkDriverDynOffsetPresent(state->kernel.tokUserAndGroups) ||
        !kswordArkDriverDynOffsetPresent(state->kernel.tokIntegrityLevelIndex)) {
        return FALSE;
    }

    return kswordArkDriverTokenIntegritySourceTrusted(state->kernelSources.epToken) &&
        kswordArkDriverTokenIntegritySourceTrusted(state->kernelSources.tokUserAndGroupCount) &&
        kswordArkDriverTokenIntegritySourceTrusted(state->kernelSources.tokUserAndGroups) &&
        kswordArkDriverTokenIntegritySourceTrusted(state->kernelSources.tokIntegrityLevelIndex);
}

static BOOLEAN
kswordArkDriverSidHasMandatoryAuthority(
    _In_ PSID sid
    )
/*++

Routine Description:

    Check whether a SID uses SECURITY_MANDATORY_LABEL_AUTHORITY. This confirms
    the token entry being overwritten is the integrity label rather than a user,
    group, capability, or restricted SID.

Arguments:

    Sid - Candidate SID pointer from the token's SID_AND_ATTRIBUTES array.

Return Value:

    TRUE when the SID authority is S-1-16; otherwise FALSE.

--*/
{
    SID_IDENTIFIER_AUTHORITY mandatoryLabelAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    SID* sidBody = NULL;

    if (sid == NULL) {
        return FALSE;
    }

    if (!RtlValidSid(sid)) {
        return FALSE;
    }

    sidBody = (SID*)sid;
    return RtlCompareMemory(
        sidBody->IdentifierAuthority.Value,
        mandatoryLabelAuthority.Value,
        sizeof(mandatoryLabelAuthority.Value)) == sizeof(mandatoryLabelAuthority.Value) ? TRUE : FALSE;
}

static NTSTATUS
kswordArkDriverCopyMandatorySidInPlace(
    _Inout_ PSID existingSid,
    _In_ PSID newSid
    )
/*++

Routine Description:

    Replace an existing token integrity SID by copying a caller-built
    S-16-* SID into the existing SID storage. Note: This function never replaces the Token's SID
    pointer with a stack or temporary buffer; it only overwrites SID bytes in-place when the existing
    SID is valid, is a mandatory label authority, and the target buffer length is sufficient.

Arguments:

    ExistingSid - SID pointer currently stored in the target token's integrity
        SID_AND_ATTRIBUTES entry.
    NewSid - Caller-built mandatory integrity SID.

Return Value:

    STATUS_SUCCESS when the copy completed; validation or exception status on
    failure.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG existingSidLength = 0UL;
    ULONG newSidLength = 0UL;
    PUCHAR existingSubAuthorityCount = NULL;

    if (existingSid == NULL || newSid == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        if (!RtlValidSid(existingSid) || !RtlValidSid(newSid)) {
            status = STATUS_INVALID_SID;
            __leave;
        }
        if (!kswordArkDriverSidHasMandatoryAuthority(existingSid) ||
            !kswordArkDriverSidHasMandatoryAuthority(newSid)) {
            status = STATUS_INVALID_SID;
            __leave;
        }

        existingSubAuthorityCount = RtlSubAuthorityCountSid(existingSid);
        if (existingSubAuthorityCount == NULL || *existingSubAuthorityCount == 0U) {
            status = STATUS_INVALID_SID;
            __leave;
        }

        existingSidLength = RtlLengthSid(existingSid);
        newSidLength = RtlLengthSid(newSid);
        if (existingSidLength < newSidLength) {
            status = STATUS_BUFFER_TOO_SMALL;
            __leave;
        }

        RtlCopyMemory(existingSid, newSid, newSidLength);
        status = RtlValidSid(existingSid) ? STATUS_SUCCESS : STATUS_INVALID_SID;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
}

static NTSTATUS
kswordArkDriverSetProcessIntegrityByPrivateTokenOffsets(
    _In_ ULONG processId,
    _In_ PSID mandatorySid
    )
/*++

Routine Description:

    Patch a process primary token's integrity SID through current-kernel
    validated DynData offsets. Processing steps:
    1. Snapshot DynData and require PDB-sourced or live-validated
       _EPROCESS.Token plus _TOKEN integrity fields.
    2. Reference the target process with PsLookupProcessByProcessId.
    3. Decode the EX_FAST_REF stored at EPROCESS.Token to obtain the token
       object pointer.
    4. Read UserAndGroupCount, UserAndGroups, and IntegrityLevelIndex from the
       token, bounds-check the index, then copy the new S-1-16-* SID into the
       existing SID storage.

Arguments:

    ProcessId - Target process ID.
    MandatorySid - Caller-built S-1-16-* SID that remains valid for this call.

Return Value:

    STATUS_SUCCESS when the private fallback applied; validation, DynData, or
    guarded-memory access status on failure.

--*/
{
    KswDynState dynState;
    PEPROCESS processObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR tokenFastRef = 0U;
    PVOID tokenObject = NULL;
    PACCESS_TOKEN referencedPrimaryToken = NULL;
    ULONG userAndGroupCount = 0UL;
    ULONG integrityLevelIndex = 0UL;
    SID_AND_ATTRIBUTES* userAndGroups = NULL;
    SID_AND_ATTRIBUTES* integrityEntry = NULL;
    PSID existingSid = NULL;
    ULONG existingAttributes = 0UL;

    if (processId == 0U || mandatorySid == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!RtlValidSid(mandatorySid) || !kswordArkDriverSidHasMandatoryAuthority(mandatorySid)) {
        return STATUS_INVALID_SID;
    }

    RtlZeroMemory(&dynState, sizeof(dynState));
    kswordArkDynDataSnapshot(&dynState);
    gKswordProcessIntegrityDiag.capabilityMask = dynState.capabilityMask;
    gKswordProcessIntegrityDiag.epToken = dynState.kernel.epToken;
    gKswordProcessIntegrityDiag.tokUserAndGroupCount = dynState.kernel.tokUserAndGroupCount;
    gKswordProcessIntegrityDiag.tokUserAndGroups = dynState.kernel.tokUserAndGroups;
    gKswordProcessIntegrityDiag.tokIntegrityLevelIndex = dynState.kernel.tokIntegrityLevelIndex;
    gKswordProcessIntegrityDiag.tokMandatoryPolicy = dynState.kernel.tokMandatoryPolicy;
    gKswordProcessIntegrityDiag.epTokenSource = dynState.kernelSources.epToken;
    gKswordProcessIntegrityDiag.tokUserAndGroupCountSource = dynState.kernelSources.tokUserAndGroupCount;
    gKswordProcessIntegrityDiag.tokUserAndGroupsSource = dynState.kernelSources.tokUserAndGroups;
    gKswordProcessIntegrityDiag.tokIntegrityLevelIndexSource = dynState.kernelSources.tokIntegrityLevelIndex;
    gKswordProcessIntegrityDiag.tokMandatoryPolicySource = dynState.kernelSources.tokMandatoryPolicy;
    if (!kswordArkDriverTokenIntegrityDynDataReady(&dynState)) {
        return STATUS_NOT_SUPPORTED;
    }

    status = PsLookupProcessByProcessId(ULongToHandle(processId), &processObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    __try {
        tokenFastRef = *(volatile ULONG_PTR*)((UCHAR*)processObject + dynState.kernel.epToken);
        tokenObject = (PVOID)(tokenFastRef & ~KSWORD_ARK_EX_FAST_REF_MASK);
        if (tokenObject == NULL) {
            status = STATUS_NOT_FOUND;
            __leave;
        }

        userAndGroupCount = *(volatile ULONG*)((UCHAR*)tokenObject + dynState.kernel.tokUserAndGroupCount);
        integrityLevelIndex = *(volatile ULONG*)((UCHAR*)tokenObject + dynState.kernel.tokIntegrityLevelIndex);
        userAndGroups = *(SID_AND_ATTRIBUTES**)((UCHAR*)tokenObject + dynState.kernel.tokUserAndGroups);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(processObject);
        return status;
    }

    referencedPrimaryToken = PsReferencePrimaryToken(processObject);
    if (referencedPrimaryToken == NULL || tokenObject != referencedPrimaryToken) {
        if (referencedPrimaryToken != NULL) {
            PsDereferencePrimaryToken(referencedPrimaryToken);
        }
        ObDereferenceObject(processObject);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    PsDereferencePrimaryToken(referencedPrimaryToken);
    referencedPrimaryToken = NULL;

    if (userAndGroupCount == 0UL ||
        userAndGroupCount > KSWORD_ARK_TOKEN_INTEGRITY_MAX_GROUPS ||
        integrityLevelIndex >= userAndGroupCount ||
        userAndGroups == NULL) {
        ObDereferenceObject(processObject);
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        integrityEntry = &userAndGroups[integrityLevelIndex];
        existingSid = integrityEntry->Sid;
        existingAttributes = integrityEntry->Attributes;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(processObject);
        return status;
    }

    status = kswordArkDriverCopyMandatorySidInPlace(existingSid, mandatorySid);
    if (NT_SUCCESS(status)) {
        __try {
            integrityEntry->Attributes = existingAttributes | SE_GROUP_INTEGRITY;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }
    }

    ObDereferenceObject(processObject);
    return status;
}

static NTSTATUS
kswordArkDriverSelectProcessIntegrityStatus(
    _In_ NTSTATUS apiStatus,
    _In_ NTSTATUS fallbackStatus
    )
/*++

Routine Description:

    Select the final status after the documented token API path failed and the
    Note: A private DynData fallback was attempted. If the private path is unavailable, retain the
    original API error to avoid misreporting 'Access Denied' as 'Feature Not Supported'; if the private
    path executes and yields a validation/access error, return that error to facilitate offset diagnosis.

Arguments:

    ApiStatus - Failure status from the documented process/token API path.
    FallbackStatus - Status from the private token-offset fallback.

Return Value:

    STATUS_SUCCESS if the fallback succeeded; ApiStatus when fallback was not
    available; otherwise FallbackStatus.

--*/
{
    if (NT_SUCCESS(fallbackStatus)) {
        return fallbackStatus;
    }

    return (fallbackStatus == STATUS_NOT_SUPPORTED) ? apiStatus : fallbackStatus;
}

static VOID
kswordArkDriverRecordProcessIntegrityResult(
    _In_ ULONG processId,
    _In_ ULONG integrityRid,
    _In_ NTSTATUS apiStatus,
    _In_ NTSTATUS fallbackStatus,
    _In_ NTSTATUS finalStatus
    )
/*++

Routine Description:

    Store the final status tuple for the latest process-integrity request. This
    best-effort diagnostic is read by the IOCTL layer immediately after the
    action returns so R0 logs can show why private-token fallback did or did not
    run.

Arguments:

    ProcessId - Target PID.
    IntegrityRid - Requested S-1-16-* RID.
    ApiStatus - Documented token API path status.
    FallbackStatus - Private offset fallback status, or STATUS_NOT_SUPPORTED.
    FinalStatus - Status returned to the IOCTL response.

Return Value:

    None.

--*/
{
    gKswordProcessIntegrityDiag.processId = processId;
    gKswordProcessIntegrityDiag.integrityRid = integrityRid;
    gKswordProcessIntegrityDiag.apiStatus = apiStatus;
    gKswordProcessIntegrityDiag.fallbackStatus = fallbackStatus;
    gKswordProcessIntegrityDiag.finalStatus = finalStatus;
}

NTSTATUS
kswordArkDriverDescribeLastProcessIntegrityAttempt(
    _Out_writes_bytes_(bufferBytes) CHAR* buffer,
    _In_ SIZE_T bufferBytes
    )
/*++

Routine Description:

    Format the latest process-integrity attempt diagnostic into caller storage.

Arguments:

    Buffer - Writable ANSI output buffer.
    BufferBytes - Size of Buffer in bytes.

Return Value:

    STATUS_SUCCESS when text was written; STATUS_INVALID_PARAMETER or
    STATUS_BUFFER_TOO_SMALL when storage is invalid.

--*/
{
    const KswordArkProcessIntegrityAttemptDiag kDiag = gKswordProcessIntegrityDiag;

    if (buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (bufferBytes == 0U) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    buffer[0] = '\0';
    return RtlStringCbPrintfA(
        buffer,
        bufferBytes,
        "pid=%lu, rid=0x%08lX, api=0x%08X, fallback=0x%08X, final=0x%08X, caps=0x%I64X, "
        "off={epToken=0x%lX,uagCount=0x%lX,uag=0x%lX,ilIndex=0x%lX,mandatory=0x%lX}, "
        "src={epToken=%lu,uagCount=%lu,uag=%lu,ilIndex=%lu,mandatory=%lu}.",
        (unsigned long)kDiag.processId,
        (unsigned long)kDiag.integrityRid,
        (unsigned int)kDiag.apiStatus,
        (unsigned int)kDiag.fallbackStatus,
        (unsigned int)kDiag.finalStatus,
        kDiag.capabilityMask,
        (unsigned long)kDiag.epToken,
        (unsigned long)kDiag.tokUserAndGroupCount,
        (unsigned long)kDiag.tokUserAndGroups,
        (unsigned long)kDiag.tokIntegrityLevelIndex,
        (unsigned long)kDiag.tokMandatoryPolicy,
        (unsigned long)kDiag.epTokenSource,
        (unsigned long)kDiag.tokUserAndGroupCountSource,
        (unsigned long)kDiag.tokUserAndGroupsSource,
        (unsigned long)kDiag.tokIntegrityLevelIndexSource,
        (unsigned long)kDiag.tokMandatoryPolicySource);
}

NTSTATUS
kswordArkDriverSetProcessIntegrityByPid(
    _In_ ULONG processId,
    _In_ ULONG integrityRid
    )
/*++

Routine Description:

    Set a process primary-token mandatory integrity label. The preferred path
    calls documented kernel token APIs. If Windows rejects a syntactically valid
    mandatory label (for example System/ProtectedProcess raises), the routine
    falls back to PDB/DynData-validated private token offsets and overwrites the
    existing mandatory SID in place.

Arguments:

    ProcessId - Target process ID.
    IntegrityRid - S-1-16-* mandatory label RID.

Return Value:

    NTSTATUS from process open, token open, SID construction, or token update.

--*/
{
    OBJECT_ATTRIBUTES objectAttributes;
    CLIENT_ID clientId;
    HANDLE processHandle = NULL;
    HANDLE tokenHandle = NULL;
    KswordArkProcessIntegrityTokenInformation tokenInformation = { 0 };
    ULONG tokenInformationLength = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS apiStatus = STATUS_SUCCESS;
    NTSTATUS fallbackStatus = STATUS_SUCCESS;
    NTSTATUS finalStatus = STATUS_SUCCESS;

    RtlZeroMemory(&gKswordProcessIntegrityDiag, sizeof(gKswordProcessIntegrityDiag));
    gKswordProcessIntegrityDiag.processId = processId;
    gKswordProcessIntegrityDiag.integrityRid = integrityRid;
    gKswordProcessIntegrityDiag.apiStatus = STATUS_UNSUCCESSFUL;
    gKswordProcessIntegrityDiag.fallbackStatus = STATUS_NOT_SUPPORTED;
    gKswordProcessIntegrityDiag.finalStatus = STATUS_UNSUCCESSFUL;

    if (processId == 0U || processId <= 4U) {
        kswordArkDriverRecordProcessIntegrityResult(
            processId,
            integrityRid,
            STATUS_INVALID_PARAMETER,
            STATUS_NOT_SUPPORTED,
            STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkDriverBuildMandatoryIntegritySid(integrityRid, (PSID)tokenInformation.sidBuffer);
    if (!NT_SUCCESS(status)) {
        kswordArkDriverRecordProcessIntegrityResult(
            processId,
            integrityRid,
            status,
            STATUS_NOT_SUPPORTED,
            status);
        return status;
    }

    InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = ULongToHandle(processId);
    clientId.UniqueThread = NULL;
    status = ZwOpenProcess(
        &processHandle,
        PROCESS_QUERY_INFORMATION,
        &objectAttributes,
        &clientId);
    if (!NT_SUCCESS(status)) {
        fallbackStatus = kswordArkDriverSetProcessIntegrityByPrivateTokenOffsets(
            processId,
            (PSID)tokenInformation.sidBuffer);
        finalStatus = kswordArkDriverSelectProcessIntegrityStatus(status, fallbackStatus);
        kswordArkDriverRecordProcessIntegrityResult(
            processId,
            integrityRid,
            status,
            fallbackStatus,
            finalStatus);
        return finalStatus;
    }

    status = ZwOpenProcessTokenEx(
        processHandle,
        TOKEN_ADJUST_DEFAULT | TOKEN_QUERY,
        OBJ_KERNEL_HANDLE,
        &tokenHandle);
    if (!NT_SUCCESS(status)) {
        ZwClose(processHandle);
        fallbackStatus = kswordArkDriverSetProcessIntegrityByPrivateTokenOffsets(
            processId,
            (PSID)tokenInformation.sidBuffer);
        finalStatus = kswordArkDriverSelectProcessIntegrityStatus(status, fallbackStatus);
        kswordArkDriverRecordProcessIntegrityResult(
            processId,
            integrityRid,
            status,
            fallbackStatus,
            finalStatus);
        return finalStatus;
    }

    RtlZeroMemory(&tokenInformation.mandatoryLabel, sizeof(tokenInformation.mandatoryLabel));
    tokenInformation.mandatoryLabel.Label.Attributes = SE_GROUP_INTEGRITY;
    tokenInformation.mandatoryLabel.Label.Sid = (PSID)tokenInformation.sidBuffer;
    tokenInformationLength =
        (ULONG)(FIELD_OFFSET(KswordArkProcessIntegrityTokenInformation, sidBuffer) +
            RtlLengthSid((PSID)tokenInformation.sidBuffer));

    status = ZwSetInformationToken(
        tokenHandle,
        TokenIntegrityLevel,
        &tokenInformation,
        tokenInformationLength);
    apiStatus = status;

    ZwClose(tokenHandle);
    ZwClose(processHandle);

    if (NT_SUCCESS(apiStatus)) {
        kswordArkDriverRecordProcessIntegrityResult(
            processId,
            integrityRid,
            apiStatus,
            STATUS_NOT_SUPPORTED,
            apiStatus);
        return apiStatus;
    }

    fallbackStatus = kswordArkDriverSetProcessIntegrityByPrivateTokenOffsets(
        processId,
        (PSID)tokenInformation.sidBuffer);
    finalStatus = kswordArkDriverSelectProcessIntegrityStatus(apiStatus, fallbackStatus);
    kswordArkDriverRecordProcessIntegrityResult(
        processId,
        integrityRid,
        apiStatus,
        fallbackStatus,
        finalStatus);
    return finalStatus;
}

NTSTATUS
kswordArkDriverEnumerateProcesses(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_ENUM_PROCESS_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
{
    KSWORD_ARK_ENUM_PROCESS_RESPONSE* response = NULL;
    size_t entryCapacity = 0;
    size_t totalBytesWritten = 0;
    ULONG requestFlags = 0;
    ULONG scanStartPid = KSWORD_ARK_ENUM_SCAN_MIN_PID;
    ULONG scanEndPid = KSWORD_ARK_ENUM_SCAN_MAX_PID;
    BOOLEAN scanCidTable = FALSE;
    UCHAR* pidBitmap = NULL;
    size_t pidBitmapBytes = 0;
    ULONG scanPid = 0;
    NTSTATUS cidWalkStatus = STATUS_SUCCESS;
    KswordPsGetNextProcessFn psGetNextProcess = NULL;
    PEPROCESS processCursor = NULL;
    KswDynState dynState;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *bytesWrittenOut = 0;
    if (outputBufferLength < KSWORD_ARK_ENUM_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_ENUM_PROCESS_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_ENUM_PROCESS_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_PROCESS_ENTRY);
    entryCapacity =
        (outputBufferLength - KSWORD_ARK_ENUM_RESPONSE_HEADER_SIZE) / sizeof(KSWORD_ARK_PROCESS_ENTRY);

    RtlZeroMemory(&dynState, sizeof(dynState));
    kswordArkDynDataSnapshot(&dynState);

    if (request != NULL) {
        requestFlags = request->flags;
        if (request->startPid != 0U) {
            scanStartPid = request->startPid;
        }
        if (request->endPid != 0U) {
            scanEndPid = request->endPid;
        }
    }

    if (scanStartPid < KSWORD_ARK_ENUM_SCAN_MIN_PID) {
        scanStartPid = KSWORD_ARK_ENUM_SCAN_MIN_PID;
    }
    if (scanEndPid < scanStartPid) {
        scanEndPid = scanStartPid;
    }
    if (scanEndPid > KSWORD_ARK_ENUM_SCAN_MAX_PID) {
        scanEndPid = KSWORD_ARK_ENUM_SCAN_MAX_PID;
    }

    scanStartPid = kswordArkDriverAlignPidToStep(scanStartPid);
    if (scanStartPid < KSWORD_ARK_ENUM_SCAN_MIN_PID) {
        scanStartPid = KSWORD_ARK_ENUM_SCAN_MIN_PID;
    }
    scanEndPid = kswordArkDriverAlignPidToStep(scanEndPid);
    if (scanEndPid < scanStartPid) {
        scanEndPid = scanStartPid;
    }

    scanCidTable = ((requestFlags & KSWORD_ARK_ENUM_PROCESS_FLAG_SCAN_CID_TABLE) != 0U) ? TRUE : FALSE;
    psGetNextProcess = kswordArkDriverResolvePsGetNextProcess();
    if (psGetNextProcess == NULL) {
        // Fallback: force CID scan when PsGetNextProcess is unavailable.
        scanCidTable = TRUE;
    }

    if (scanCidTable) {
        const size_t kBitmapBitCount = (size_t)(scanEndPid / KSWORD_ARK_ENUM_PID_STEP) + 1U;
        pidBitmapBytes = (kBitmapBitCount + 7U) >> 3;
#pragma warning(push)
#pragma warning(disable:4996)
        pidBitmap = (UCHAR*)ExAllocatePoolWithTag(NonPagedPoolNx, pidBitmapBytes, 'pKsK');
#pragma warning(pop)
        if (pidBitmap == NULL) {
            scanCidTable = FALSE;
            pidBitmapBytes = 0U;
        }
        else {
            RtlZeroMemory(pidBitmap, pidBitmapBytes);
        }
    }

    if (psGetNextProcess != NULL) {
        processCursor = psGetNextProcess(NULL);
        while (processCursor != NULL) {
            const ULONG kProcessId = HandleToULong(PsGetProcessId(processCursor));
            const ULONG kParentProcessId =
                HandleToULong(PsGetProcessInheritedFromUniqueProcessId(processCursor));
            const CHAR* imageName = PsGetProcessImageFileName(processCursor);
            ULONG processFlags = KSWORD_ARK_PROCESS_FLAG_KERNEL_ENUMERATED;
            PEPROCESS nextProcess = NULL;
            const BOOLEAN kTerminatingProcess =
                kswordArkDriverShouldSkipTerminatingProcess(processCursor, &dynState);

            if (kTerminatingProcess) {
                processFlags |= KSWORD_ARK_PROCESS_FLAG_TERMINATING_OR_EXITED;
            }
            if (kswordArkDriverIsProcessHiddenByUi(kProcessId)) {
                processFlags |= KSWORD_ARK_PROCESS_FLAG_HIDDEN_BY_KSWORD_UI;
            }
            kswordArkDriverAppendProcessEntry(
                response,
                entryCapacity,
                kProcessId,
                kParentProcessId,
                processFlags,
                imageName,
                processCursor);

            if (scanCidTable && kswordArkDriverPidInScanRange(kProcessId, scanStartPid, scanEndPid)) {
                kswordArkDriverBitmapSetPid(pidBitmap, pidBitmapBytes, kProcessId);
            }

            nextProcess = psGetNextProcess(processCursor);
            ObDereferenceObject(processCursor);
            processCursor = nextProcess;
        }
    }

    if (scanCidTable) {
        cidWalkStatus = kswordArkDriverEnumerateProcessesByCidTable(
            response,
            entryCapacity,
            &dynState,
            pidBitmap,
            pidBitmapBytes,
            scanStartPid,
            scanEndPid,
            (psGetNextProcess != NULL && pidBitmap != NULL) ? TRUE : FALSE);
    }

    if (scanCidTable && !NT_SUCCESS(cidWalkStatus)) {
        scanPid = scanStartPid;
        for (;;) {
            PEPROCESS hiddenProcessObject = NULL;
            NTSTATUS lookupStatus = STATUS_UNSUCCESSFUL;
            BOOLEAN presentInActiveList = FALSE;

            if (psGetNextProcess != NULL && pidBitmap != NULL) {
                presentInActiveList = kswordArkDriverBitmapHasPid(pidBitmap, pidBitmapBytes, scanPid);
            }

            if (!presentInActiveList) {
                lookupStatus = PsLookupProcessByProcessId(ULongToHandle(scanPid), &hiddenProcessObject);
                if (NT_SUCCESS(lookupStatus)) {
                    const ULONG kParentProcessId =
                        HandleToULong(PsGetProcessInheritedFromUniqueProcessId(hiddenProcessObject));
                    const CHAR* imageName = PsGetProcessImageFileName(hiddenProcessObject);
                    ULONG processFlags = KSWORD_ARK_PROCESS_FLAG_KERNEL_ENUMERATED;
                    const BOOLEAN kTerminatingProcess =
                        kswordArkDriverShouldSkipTerminatingProcess(hiddenProcessObject, &dynState);

                    if (psGetNextProcess != NULL && pidBitmap != NULL) {
                        processFlags |= KSWORD_ARK_PROCESS_FLAG_HIDDEN_FROM_ACTIVE_LIST;
                    }
                    if (kTerminatingProcess) {
                        processFlags |= KSWORD_ARK_PROCESS_FLAG_TERMINATING_OR_EXITED;
                    }
                    if (kswordArkDriverIsProcessHiddenByUi(scanPid)) {
                        processFlags |= KSWORD_ARK_PROCESS_FLAG_HIDDEN_BY_KSWORD_UI;
                    }

                    //
                    // Analogous to CID scanning: this queries for PIDs not in the active list. Residuals that have exited but whose objects
                    // still exist are also reported, tagged only with TERMINATING_OR_EXITED for R3 to mark as "possible false positive".
                    //
                    kswordArkDriverAppendProcessEntry(
                        response,
                        entryCapacity,
                        scanPid,
                        kParentProcessId,
                        processFlags,
                        imageName,
                        hiddenProcessObject);
                    ObDereferenceObject(hiddenProcessObject);
                }
            }

            if ((scanEndPid - scanPid) < KSWORD_ARK_ENUM_PID_STEP) {
                break;
            }
            scanPid += KSWORD_ARK_ENUM_PID_STEP;
        }
    }

    if (pidBitmap != NULL) {
        ExFreePoolWithTag(pidBitmap, 'pKsK');
        pidBitmap = NULL;
    }

    totalBytesWritten =
        KSWORD_ARK_ENUM_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_PROCESS_ENTRY));
    *bytesWrittenOut = totalBytesWritten;
    return STATUS_SUCCESS;
}
