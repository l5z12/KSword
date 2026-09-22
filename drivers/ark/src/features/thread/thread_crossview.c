/*++

Module Name:

    thread_crossview.c

Abstract:

    Read-only thread cross-view evidence collection for orphan/list/CID
    diagnostics.

Environment:

    Kernel-mode Driver Framework

--*/

#include "thread_crossview.h"
#include "../kernel/hook_scan_support.h"
#include "../kernel/object_header_fallback.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSW_THREAD_CROSSVIEW_TAG 'vTsK'
#define KSW_THREAD_CROSSVIEW_VISIT_TAG 'tVsK'
#define KSW_THREAD_CROSSVIEW_HEADER_SIZE \
    (sizeof(KSWORD_ARK_THREAD_CROSSVIEW_RESPONSE) - sizeof(KSWORD_ARK_THREAD_CROSSVIEW_ROW))

#ifndef STATUS_OBJECT_TYPE_MISMATCH
#define STATUS_OBJECT_TYPE_MISMATCH ((NTSTATUS)0xC0000024L)
#endif

#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif

#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#endif

typedef PEPROCESS(NTAPI* KswThreadCrossviewPsGetNextProcessFn)(
    _In_opt_ PEPROCESS process
    );

typedef PETHREAD(NTAPI* KswThreadCrossviewPsGetNextProcessThreadFn)(
    _In_ PEPROCESS process,
    _In_opt_ PETHREAD thread
    );

typedef struct KswThreadCrossviewVisitedSet
{
    ULONG_PTR* items;
    ULONG count;
    ULONG capacity;
} KswThreadCrossviewVisitedSet, *PkswThreadCrossviewVisitedSet;

typedef struct KswThreadCrossviewContext
{
    KSWORD_ARK_THREAD_CROSSVIEW_ROW* rows;
    ULONG rowCount;
    ULONG rowCapacity;
    ULONG flags;
    ULONG processId;
    ULONG startTid;
    ULONG endTid;
    ULONG maxNodes;
    ULONG64 missingCapabilityMask;
    NTSTATUS lastStatus;
    NTSTATUS moduleStatus;
    BOOLEAN truncated;
    BOOLEAN capabilityMissing;
    BOOLEAN publicProcessWalkComplete;
    KswDynState dynState;
    KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS fieldOffsets;
    KswHookSystemModuleInformation* moduleInfo;
    ULONG moduleInfoBytes;
    KswThreadCrossviewVisitedSet processSeen;
} KswThreadCrossviewContext, *PkswThreadCrossviewContext;

NTSYSAPI
PEPROCESS
NTAPI
PsGetThreadProcess(
    _In_ PETHREAD thread
    );

NTSYSAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS process
    );

NTKERNELAPI
POBJECT_TYPE
NTAPI
ObGetObjectType(
    _In_ PVOID object
    );

extern POBJECT_TYPE* PsThreadType;

static NTSTATUS
KswordARKThreadCrossViewReadCidFields(
    _In_ const KswThreadCrossviewContext* context,
    _In_ const VOID* threadObject,
    _Out_ ULONG* processIdOut,
    _Out_ ULONG* threadIdOut
    );

static PVOID
kswordArkThreadCrossViewAllocate(
    _In_ SIZE_T bufferBytes,
    _In_ ULONG tag
    )
/*++

Routine Description:

    Allocate a transient nonpaged buffer for one thread cross-view query.

Arguments:

    BufferBytes - Requested byte count.
    Tag - Pool tag for diagnostics.

Return Value:

    Allocation pointer on success; NULL for invalid size or allocation failure.

--*/
{
    if (bufferBytes == 0U) {
        return NULL;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(NonPagedPoolNx, bufferBytes, tag);
#pragma warning(pop)
}

static VOID
kswordArkThreadCrossViewFree(
    _In_opt_ PVOID buffer,
    _In_ ULONG tag
    )
/*++

Routine Description:

    Free a transient thread cross-view allocation.

Arguments:

    Buffer - Optional allocation pointer.
    Tag - Pool tag used at allocation time.

Return Value:

    None.

--*/
{
    if (buffer != NULL) {
        ExFreePoolWithTag(buffer, tag);
    }
}

static VOID
kswordArkThreadCrossViewFormatDetail(
    _Out_writes_bytes_(destinationBytes) CHAR* destination,
    _In_ SIZE_T destinationBytes,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Format a bounded ANSI detail string for one thread evidence row.

Arguments:

    Destination - Output protocol detail field.
    DestinationBytes - Size of Destination in bytes.
    FormatText - printf-style ANSI format string.
    ... - Format arguments.

Return Value:

    None. The destination remains NUL-terminated when valid.

--*/
{
    va_list arguments;

    if (destination == NULL || destinationBytes == 0U) {
        return;
    }
    destination[0] = '\0';
    if (formatText == NULL) {
        return;
    }

    va_start(arguments, formatText);
    (VOID)RtlStringCbVPrintfA(destination, destinationBytes, formatText, arguments);
    va_end(arguments);
    destination[destinationBytes - 1U] = '\0';
}

static VOID
kswordArkThreadCrossViewCopyImageName(
    _Out_writes_all_(16) CHAR destination[16],
    _In_opt_ PEPROCESS processObject
    )
/*++

Routine Description:

    Copy the owning process image name into a fixed 16-byte thread row field.

Arguments:

    Destination - Output image-name field.
    ProcessObject - Optional owning process object.

Return Value:

    None. The destination is zero-filled when input is unavailable.

--*/
{
    const CHAR* source = NULL;
    ULONG index = 0UL;

    if (destination == NULL) {
        return;
    }
    RtlZeroMemory(destination, 16U);
    if (processObject == NULL) {
        return;
    }

    __try {
        source = PsGetProcessImageFileName(processObject);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        source = NULL;
    }
    if (source == NULL) {
        return;
    }

    for (index = 0UL; index < 15UL; ++index) {
        destination[index] = source[index];
        if (source[index] == '\0') {
            break;
        }
    }
    destination[15] = '\0';
}

static ULONG
kswordArkThreadCrossViewNormalizeMaxNodes(
    _In_ ULONG requestedMaxNodes
    )
/*++

Routine Description:

    normalize the request node budget to default and hard-cap values.

Arguments:

    RequestedMaxNodes - Raw caller value.

Return Value:

    Effective node budget for bounded traversals.

--*/
{
    if (requestedMaxNodes == 0UL) {
        return KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES;
    }
    if (requestedMaxNodes > KSWORD_ARK_CROSSVIEW_HARD_MAX_NODES) {
        return KSWORD_ARK_CROSSVIEW_HARD_MAX_NODES;
    }
    return requestedMaxNodes;
}

static KswThreadCrossviewPsGetNextProcessFn
kswordArkThreadCrossViewResolvePsGetNextProcess(
    VOID
    )
/*++

Routine Description:

    Resolve PsGetNextProcess dynamically for public process walking.

Arguments:

    None.

Return Value:

    Function pointer when available; otherwise NULL.

--*/
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsGetNextProcess");
    return (KswThreadCrossviewPsGetNextProcessFn)MmGetSystemRoutineAddress(&routineName);
}

static KswThreadCrossviewPsGetNextProcessThreadFn
kswordArkThreadCrossViewResolvePsGetNextProcessThread(
    VOID
    )
/*++

Routine Description:

    Resolve psGetNextProcessThread dynamically for public thread walking.

Arguments:

    None.

Return Value:

    Function pointer when available; otherwise NULL.

--*/
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsGetNextProcessThread");
    return (KswThreadCrossviewPsGetNextProcessThreadFn)MmGetSystemRoutineAddress(&routineName);
}

static NTSTATUS
kswordArkThreadCrossViewVisitedInitialize(
    _Out_ KswThreadCrossviewVisitedSet* visited,
    _In_ ULONG maxNodes
    )
/*++

Routine Description:

    Allocate a visited-address set for thread-list loop detection.

Arguments:

    Visited - Output visited set.
    MaxNodes - Maximum list entries that can be recorded.

Return Value:

    STATUS_SUCCESS or validation/allocation status.

--*/
{
    SIZE_T bytes = 0U;

    if (visited == NULL || maxNodes == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(visited, sizeof(*visited));
    bytes = (SIZE_T)maxNodes * sizeof(ULONG_PTR);
    if ((bytes / sizeof(ULONG_PTR)) != (SIZE_T)maxNodes) {
        return STATUS_INTEGER_OVERFLOW;
    }

    visited->items = (ULONG_PTR*)kswordArkThreadCrossViewAllocate(bytes, KSW_THREAD_CROSSVIEW_VISIT_TAG);
    if (visited->items == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(visited->items, bytes);
    visited->capacity = maxNodes;
    return STATUS_SUCCESS;
}

static VOID
kswordArkThreadCrossViewVisitedDestroy(
    _Inout_ KswThreadCrossviewVisitedSet* visited
    )
/*++

Routine Description:

    Free a visited-address set.

Arguments:

    Visited - Mutable set descriptor to clear.

Return Value:

    None.

--*/
{
    if (visited == NULL) {
        return;
    }

    kswordArkThreadCrossViewFree(visited->items, KSW_THREAD_CROSSVIEW_VISIT_TAG);
    RtlZeroMemory(visited, sizeof(*visited));
}

static BOOLEAN
kswordArkThreadCrossViewVisitedCheckAndAdd(
    _Inout_ KswThreadCrossviewVisitedSet* visited,
    _In_ ULONG_PTR address
    )
/*++

Routine Description:

    Check and record a thread-list entry address for loop detection.

Arguments:

    Visited - Mutable visited set.
    Address - Candidate LIST_ENTRY address.

Return Value:

    TRUE when Address was already seen or the set is full; FALSE when newly
    added.

--*/
{
    ULONG index = 0UL;

    if (visited == NULL || visited->items == NULL || address == 0U) {
        return TRUE;
    }

    for (index = 0UL; index < visited->count; ++index) {
        if (visited->items[index] == address) {
            return TRUE;
        }
    }

    if (visited->count >= visited->capacity) {
        return TRUE;
    }

    visited->items[visited->count] = address;
    visited->count += 1UL;
    return FALSE;
}

static VOID
kswordArkThreadCrossViewRecordProcessSeen(
    _Inout_ KswThreadCrossviewContext* context,
    _In_ ULONG processId
    )
/*++

Routine Description:

    Record one process ID observed by the public process walk for orphan checks.

Arguments:

    Context - Query context.
    ProcessId - PID observed by the public walk.

Return Value:

    None.

--*/
{
    if (context == NULL || processId == 0UL) {
        return;
    }

    (VOID)kswordArkThreadCrossViewVisitedCheckAndAdd(&context->processSeen, (ULONG_PTR)processId);
}

static BOOLEAN
kswordArkThreadCrossViewHasProcessSeen(
    _In_ const KswThreadCrossviewContext* context,
    _In_ ULONG processId
    )
/*++

Routine Description:

    Test whether a PID was seen during the public process walk.

Arguments:

    Context - Query context containing ProcessSeen.
    ProcessId - PID to test.

Return Value:

    TRUE when the PID was seen; otherwise FALSE.

--*/
{
    ULONG index = 0UL;

    if (context == NULL || context->processSeen.items == NULL || processId == 0UL) {
        return FALSE;
    }

    for (index = 0UL; index < context->processSeen.count; ++index) {
        if (context->processSeen.items[index] == (ULONG_PTR)processId) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
kswordArkThreadCrossViewTidInRequest(
    _In_ const KswThreadCrossviewContext* context,
    _In_ ULONG threadId
    )
/*++

Routine Description:

    Apply optional TID range filtering from the request.

Arguments:

    Context - Query context containing start/end TID.
    ThreadId - Candidate TID.

Return Value:

    TRUE when ThreadId should be included; otherwise FALSE.

--*/
{
    if (context == NULL) {
        return FALSE;
    }
    if (context->startTid != 0UL && threadId < context->startTid) {
        return FALSE;
    }
    if (context->endTid != 0UL && threadId > context->endTid) {
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
kswordArkThreadCrossViewProcessInRequest(
    _In_ const KswThreadCrossviewContext* context,
    _In_ ULONG processId
    )
/*++

Routine Description:

    Apply the optional owning PID filter from the request.

Arguments:

    Context - Query context containing the PID filter.
    ProcessId - Candidate owning PID.

Return Value:

    TRUE when ProcessId should be included; otherwise FALSE.

--*/
{
    if (context == NULL) {
        return FALSE;
    }
    return (context->processId == 0UL || context->processId == processId) ? TRUE : FALSE;
}

static KSWORD_ARK_THREAD_CROSSVIEW_ROW*
kswordArkThreadCrossViewFindRow(
    _Inout_ KswThreadCrossviewContext* context,
    _In_ ULONG64 objectAddress,
    _In_ ULONG threadId
    )
/*++

Routine Description:

    Locate an existing thread evidence row by ETHREAD address or TID fallback.

Arguments:

    Context - Mutable query context.
    ObjectAddress - Candidate ETHREAD address.
    ThreadId - Candidate TID.

Return Value:

    Existing row pointer when found; otherwise NULL.

--*/
{
    ULONG index = 0UL;

    if (context == NULL || context->rows == NULL) {
        return NULL;
    }

    for (index = 0UL; index < context->rowCount; ++index) {
        KSWORD_ARK_THREAD_CROSSVIEW_ROW* row = &context->rows[index];
        if (objectAddress != 0ULL && row->objectAddress == objectAddress) {
            return row;
        }
        if (objectAddress == 0ULL && threadId != 0UL && row->threadId == threadId) {
            return row;
        }
    }

    return NULL;
}

static KSWORD_ARK_THREAD_CROSSVIEW_ROW*
kswordArkThreadCrossViewGetOrCreateRow(
    _Inout_ KswThreadCrossviewContext* context,
    _In_ ULONG64 objectAddress,
    _In_ ULONG threadId
    )
/*++

Routine Description:

    Return an existing row or append a new internal row when capacity permits.

Arguments:

    Context - Mutable query context.
    ObjectAddress - Candidate ETHREAD address.
    ThreadId - Candidate TID.

Return Value:

    Mutable row pointer, or NULL when capacity is exhausted.

--*/
{
    KSWORD_ARK_THREAD_CROSSVIEW_ROW* row = NULL;

    row = kswordArkThreadCrossViewFindRow(context, objectAddress, threadId);
    if (row != NULL) {
        return row;
    }

    if (context == NULL || context->rows == NULL || context->rowCount >= context->rowCapacity) {
        if (context != NULL) {
            context->truncated = TRUE;
            context->lastStatus = STATUS_BUFFER_OVERFLOW;
        }
        return NULL;
    }

    row = &context->rows[context->rowCount];
    RtlZeroMemory(row, sizeof(*row));
    row->objectAddress = objectAddress;
    row->threadId = threadId;
    row->dynDataCapabilityMask = context->dynState.capabilityMask;
    row->fieldOffsets = context->fieldOffsets;
    row->lastStatus = STATUS_SUCCESS;
    row->publicWalkStatus = STATUS_NOT_FOUND;
    row->threadListStatus = STATUS_NOT_FOUND;
    row->cidTableStatus = STATUS_NOT_FOUND;
    row->startAddressStatus = STATUS_NOT_FOUND;
    row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_OK;
    context->rowCount += 1UL;
    return row;
}

static VOID
kswordArkThreadCrossViewApplyDetailStatus(
    _Inout_ KSWORD_ARK_THREAD_CROSSVIEW_ROW* row,
    _In_ NTSTATUS sourceStatus,
    _In_ BOOLEAN unsupportedField
    )
/*++

Routine Description:

    Update row-level partial, unsupported, and read-failure detail flags from one
    collector branch without inferring undocumented thread termination state.

Arguments:

    Row - Mutable thread evidence row.
    SourceStatus - NTSTATUS produced by the guarded source path.
    UnsupportedField - TRUE when the collector intentionally skipped private
        field access because DynData did not provide the PDB offset.

Return Value:

    None. The row is annotated in place.

--*/
{
    if (row == NULL) {
        return;
    }

    if (unsupportedField) {
        row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_UNSUPPORTED;
        row->denoiseFlags |= KSWORD_ARK_CROSSVIEW_DENOISE_UNSUPPORTED_PDB_FIELD;
        return;
    }

    if (!NT_SUCCESS(sourceStatus)) {
        row->denoiseFlags |= KSWORD_ARK_CROSSVIEW_DENOISE_PARTIAL_EVIDENCE;
        if (sourceStatus == STATUS_PROCEDURE_NOT_FOUND) {
            row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_UNSUPPORTED;
            row->denoiseFlags |= KSWORD_ARK_CROSSVIEW_DENOISE_UNSUPPORTED_PDB_FIELD;
        }
        else {
            row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_READ_FAILED;
            row->denoiseFlags |= KSWORD_ARK_CROSSVIEW_DENOISE_READ_FAILURE;
        }
    }
}

static VOID
kswordArkThreadCrossViewRecordSourceEvidence(
    _Inout_ KSWORD_ARK_THREAD_CROSSVIEW_ROW* row,
    _In_ ULONG sourceMask,
    _In_ ULONG sourceProcessId,
    _In_ ULONG sourceThreadId,
    _In_ NTSTATUS sourceStatus
    )
/*++

Routine Description:

    Store per-source PID/TID/status values for public walk, ThreadListHead, and
    PspCidTable evidence.

Arguments:

    Row - Mutable thread evidence row.
    SourceMask - Single KSWORD_ARK_CROSSVIEW_SOURCE_* bit being merged.
    SourceProcessId - Process ID observed by that source.
    SourceThreadId - Thread ID observed by that source.
    SourceStatus - Status from the source collector branch.

Return Value:

    None. The source-specific evidence columns are updated in place.

--*/
{
    if (row == NULL) {
        return;
    }

    if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) != 0UL) {
        row->publicProcessId = sourceProcessId;
        row->publicThreadId = sourceThreadId;
        row->publicWalkStatus = sourceStatus;
    }
    if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST) != 0UL) {
        row->threadListProcessId = sourceProcessId;
        row->threadListThreadId = sourceThreadId;
        row->threadListStatus = sourceStatus;
    }
    if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) != 0UL) {
        row->cidTableProcessId = sourceProcessId;
        row->cidTableThreadId = sourceThreadId;
        row->cidTableStatus = sourceStatus;
    }

    kswordArkThreadCrossViewApplyDetailStatus(row, sourceStatus, FALSE);
}

static VOID
kswordArkThreadCrossViewMergeThreadObject(
    _Inout_ KswThreadCrossviewContext* context,
    _In_ PETHREAD threadObject,
    _In_ ULONG sourceMask,
    _In_ NTSTATUS sourceStatus,
    _In_ ULONG evidenceProcessId,
    _In_ ULONG evidenceThreadId,
    _In_opt_z_ PCSTR detailText
    )
/*++

Routine Description:

    Merge one referenced ETHREAD into the thread evidence set.

Arguments:

    Context - Mutable query context.
    ThreadObject - Referenced thread object.
    SourceMask - KSWORD_ARK_CROSSVIEW_SOURCE_* bit for the evidence source.
    SourceStatus - Last read/reference status to record.
    EvidenceProcessId - PID observed by the source itself, or zero when absent.
    EvidenceThreadId - TID observed by the source itself, or zero when absent.
    DetailText - Optional detail text when the row has no detail yet.

Return Value:

    None.

--*/
{
    KSWORD_ARK_THREAD_CROSSVIEW_ROW* row = NULL;
    PEPROCESS processObject = NULL;
    ULONG processId = 0UL;
    ULONG threadId = 0UL;
    ULONG cidProcessId = 0UL;
    ULONG cidThreadId = 0UL;
    ULONG sourceProcessId = 0UL;
    ULONG sourceThreadId = 0UL;
    NTSTATUS cidStatus = STATUS_SUCCESS;

    if (context == NULL || threadObject == NULL) {
        return;
    }

    processObject = PsGetThreadProcess(threadObject);
    if (processObject == NULL) {
        return;
    }

    threadId = HandleToULong(PsGetThreadId(threadObject));
    processId = HandleToULong(PsGetProcessId(processObject));
    sourceProcessId = (evidenceProcessId != 0UL) ? evidenceProcessId : processId;
    sourceThreadId = (evidenceThreadId != 0UL) ? evidenceThreadId : threadId;
    if ((!kswordArkThreadCrossViewProcessInRequest(context, processId) &&
            !kswordArkThreadCrossViewProcessInRequest(context, sourceProcessId)) ||
        (!kswordArkThreadCrossViewTidInRequest(context, threadId) &&
            !kswordArkThreadCrossViewTidInRequest(context, sourceThreadId))) {
        return;
    }

    row = kswordArkThreadCrossViewGetOrCreateRow(context, (ULONG64)(ULONG_PTR)threadObject, threadId);
    if (row == NULL) {
        return;
    }

    row->sourceMask |= sourceMask;
    row->processId = processId;
    row->threadId = threadId;
    row->processObjectAddress = (ULONG64)(ULONG_PTR)processObject;
    row->lastStatus = sourceStatus;
    kswordArkThreadCrossViewCopyImageName(row->imageName, processObject);
    cidStatus = KswordARKThreadCrossViewReadCidFields(context, threadObject, &cidProcessId, &cidThreadId);
    if (NT_SUCCESS(cidStatus)) {
        if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST) != 0UL) {
            sourceProcessId = (evidenceProcessId != 0UL) ? evidenceProcessId : cidProcessId;
            sourceThreadId = (evidenceThreadId != 0UL) ? evidenceThreadId : cidThreadId;
        }
        if (cidProcessId != processId || cidThreadId != threadId) {
            row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_DATA_MISMATCH;
            row->denoiseFlags |= KSWORD_ARK_CROSSVIEW_DENOISE_PARTIAL_EVIDENCE;
            row->lastStatus = STATUS_DATA_ERROR;
        }
    }
    else if (cidStatus == STATUS_PROCEDURE_NOT_FOUND) {
        context->capabilityMissing = TRUE;
        context->missingCapabilityMask |= KSW_CAP_THREAD_LIST_FIELDS;
        context->lastStatus = cidStatus;
        row->lastStatus = cidStatus;
        kswordArkThreadCrossViewApplyDetailStatus(row, cidStatus, TRUE);
    }
    else {
        context->lastStatus = cidStatus;
        row->lastStatus = cidStatus;
        kswordArkThreadCrossViewApplyDetailStatus(row, cidStatus, FALSE);
    }
    if ((evidenceProcessId != 0UL && evidenceProcessId != processId) ||
        (evidenceThreadId != 0UL && evidenceThreadId != threadId)) {
        row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_DATA_MISMATCH;
        row->denoiseFlags |= KSWORD_ARK_CROSSVIEW_DENOISE_PARTIAL_EVIDENCE;
        row->lastStatus = STATUS_DATA_ERROR;
    }
    kswordArkThreadCrossViewRecordSourceEvidence(
        row,
        sourceMask,
        sourceProcessId,
        sourceThreadId,
        sourceStatus);
    if (detailText != NULL && row->detail[0] == '\0') {
        kswordArkThreadCrossViewFormatDetail(row->detail, sizeof(row->detail), "%s", detailText);
    }
}

static VOID
kswordArkThreadCrossViewMergeDanglingCandidate(
    _Inout_ KswThreadCrossviewContext* context,
    _In_ ULONG64 objectAddress,
    _In_ ULONG threadId,
    _In_ ULONG processId,
    _In_ ULONG sourceMask,
    _In_ NTSTATUS sourceStatus,
    _In_z_ PCSTR detailText
    )
/*++

Routine Description:

    Merge a thread candidate that matched a source but could not be safely
    referenced.

Arguments:

    Context - Mutable query context.
    ObjectAddress - Candidate ETHREAD address.
    ThreadId - Candidate TID.
    ProcessId - Candidate owning PID.
    SourceMask - Evidence source bit.
    SourceStatus - Reference/read failure status.
    DetailText - Human-readable reason for the dangling classification.

Return Value:

    None.

--*/
{
    KSWORD_ARK_THREAD_CROSSVIEW_ROW* row = NULL;

    if (context == NULL || objectAddress == 0ULL) {
        return;
    }
    if (!kswordArkThreadCrossViewProcessInRequest(context, processId) ||
        !kswordArkThreadCrossViewTidInRequest(context, threadId)) {
        return;
    }

    row = kswordArkThreadCrossViewGetOrCreateRow(context, objectAddress, threadId);
    if (row == NULL) {
        return;
    }

    row->sourceMask |= sourceMask;
    row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_DANGLING_OBJECT;
    row->denoiseFlags |=
        KSWORD_ARK_CROSSVIEW_DENOISE_PARTIAL_EVIDENCE |
        KSWORD_ARK_CROSSVIEW_DENOISE_REFERENCE_FAILURE |
        KSWORD_ARK_CROSSVIEW_DENOISE_POSSIBLE_TERMINATING;
    row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_PARTIAL;
    row->processId = processId;
    row->lastStatus = sourceStatus;
    kswordArkThreadCrossViewRecordSourceEvidence(
        row,
        sourceMask,
        processId,
        threadId,
        sourceStatus);
    if (row->detail[0] == '\0') {
        kswordArkThreadCrossViewFormatDetail(row->detail, sizeof(row->detail), "%s", detailText);
    }
}

static NTSTATUS
kswordArkThreadCrossViewTryReferenceTypedObject(
    _In_ PVOID candidateObject,
    _In_opt_ POBJECT_TYPE expectedObjectType,
    _Out_ BOOLEAN* typeMatchedOut,
    _Out_ BOOLEAN* referencedOut
    )
/*++

Routine Description:

    Validate a decoded thread object by type and attempt a balanced reference.

Arguments:

    CandidateObject - Decoded thread object body pointer.
    ExpectedObjectType - Required object type, such as PsThreadType.
    TypeMatchedOut - Receives whether ObGetObjectType matched ExpectedObjectType.
    ReferencedOut - Receives whether the reference was taken.

Return Value:

    STATUS_SUCCESS when a reference was taken; otherwise a validation or read
    status.

    STATUS_DELETE_PENDING means the candidate is a real object that is already
    being torn down rather than a read failure.

--*/
{
    POBJECT_TYPE objectType = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (typeMatchedOut == NULL || referencedOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *typeMatchedOut = FALSE;
    *referencedOut = FALSE;

    if (candidateObject == NULL || expectedObjectType == NULL ||
        !kswordArkCrossViewPointerAligned((ULONG_PTR)candidateObject)) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        objectType = ObGetObjectType(candidateObject);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (objectType != expectedObjectType) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    *typeMatchedOut = TRUE;

    //
    // Same hazard as the process cross-view: the candidate is a pointer decoded
    // out of a kernel structure we hold no reference into, and a thread that has
    // just exited keeps its links while its pointer count is already zero.  The
    // Ob reference exports bugcheck 0x18 on such an object and no __except can
    // catch that, so take the reference by hand.
    //
    status = kswordArkObjectHeaderReferenceObjectSafe(candidateObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Re-read the type now that deletion is blocked, so a body recycled between
    // the first read and the reference cannot be reported as a thread.
    //
    __try {
        objectType = ObGetObjectType(candidateObject);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        objectType = NULL;
    }
    if (objectType != expectedObjectType) {
        ObDereferenceObject(candidateObject);
        *typeMatchedOut = FALSE;
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    *referencedOut = TRUE;
    return status;
}

static ULONG
kswordArkThreadCrossViewFlagsForProcess(
    _In_ const KswThreadCrossviewContext* context,
    _In_ PEPROCESS processObject
    )
/*++

Routine Description:

    Derive thread cross-view flags from owner-process visibility.

Arguments:

    Context - Query context.
    ProcessObject - Owning process object.

Return Value:

    Thread flag bits for owner-process-hidden evidence.

--*/
{
    ULONG flags = KSWORD_ARK_THREAD_FLAG_KERNEL_ENUMERATED;
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(processObject);
    return flags;
}

static NTSTATUS
KswordARKThreadCrossViewReadCidFields(
    _In_ const KswThreadCrossviewContext* context,
    _In_ const VOID* threadObject,
    _Out_ ULONG* processIdOut,
    _Out_ ULONG* threadIdOut
    )
/*++

Routine Description:

    Read ETHREAD.Cid.UniqueProcess and UniqueThread through DynData offsets with
    guarded reads.

Arguments:

    Context - Query context containing EtCid offset.
    ThreadObject - ETHREAD candidate address.
    ProcessIdOut - Receives UniqueProcess as ULONG.
    ThreadIdOut - Receives UniqueThread as ULONG.

Return Value:

    STATUS_SUCCESS on success, or capability/read status.

--*/
{
    PVOID processIdValue = NULL;
    PVOID threadIdValue = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (context == NULL || threadObject == NULL || processIdOut == NULL || threadIdOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *processIdOut = 0UL;
    *threadIdOut = 0UL;
    if (!kswordArkCrossViewOffsetPresent(context->dynState.kernel.etCid)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    status = kswordArkCrossViewReadPointerAddress(
        (const UCHAR*)threadObject + context->dynState.kernel.etCid,
        &processIdValue);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = kswordArkCrossViewReadPointerAddress(
        (const UCHAR*)threadObject + context->dynState.kernel.etCid + sizeof(PVOID),
        &threadIdValue);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *processIdOut = HandleToULong(processIdValue);
    *threadIdOut = HandleToULong(threadIdValue);
    return STATUS_SUCCESS;
}

static VOID
kswordArkThreadCrossViewPopulateStartAddress(
    _Inout_ KswThreadCrossviewContext* context,
    _Inout_ KSWORD_ARK_THREAD_CROSSVIEW_ROW* row,
    _In_ PETHREAD threadObject
    )
/*++

Routine Description:

    Read ETHREAD start-address evidence and optionally classify kernel-range
    starts against the loaded module snapshot.

Arguments:

    Context - Query context containing DynData and optional module snapshot.
    Row - Mutable thread evidence row.
    ThreadObject - Referenced ETHREAD object.

Return Value:

    None. Read failures update Row->lastStatus and detail.

--*/
{
    PVOID startAddress = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (context == NULL || row == NULL || threadObject == NULL) {
        return;
    }

    status = kswordArkCrossViewReadPointerField(
        threadObject,
        context->dynState.kernel.etStartAddress,
        &startAddress);
    if (!NT_SUCCESS(status) && kswordArkCrossViewOffsetPresent(context->dynState.kernel.etWin32StartAddress)) {
        status = kswordArkCrossViewReadPointerField(
            threadObject,
            context->dynState.kernel.etWin32StartAddress,
            &startAddress);
    }

    if (!NT_SUCCESS(status)) {
        row->lastStatus = status;
        row->startAddressStatus = status;
        kswordArkThreadCrossViewApplyDetailStatus(
            row,
            status,
            (status == STATUS_PROCEDURE_NOT_FOUND) ? TRUE : FALSE);
        if (row->detail[0] == '\0') {
            kswordArkThreadCrossViewFormatDetail(
                row->detail,
                sizeof(row->detail),
                "Start address unavailable, status=0x%08lX.",
                (ULONG)status);
        }
        return;
    }

    row->startAddress = (ULONG64)(ULONG_PTR)startAddress;
    row->startAddressStatus = STATUS_SUCCESS;
    if ((context->flags & KSWORD_ARK_THREAD_CROSSVIEW_FLAG_VALIDATE_START) != 0UL &&
        startAddress != NULL &&
        (ULONG_PTR)startAddress >= (ULONG_PTR)MmSystemRangeStart) {
        const KswHookSystemModuleEntry* ownerModule =
            kswordArkHookFindModuleForAddress(context->moduleInfo, (ULONG_PTR)startAddress);
        if (context->moduleInfo != NULL && ownerModule == NULL) {
            row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_START_ADDRESS_OUTSIDE_MODULE;
            row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_DATA_MISMATCH;
            kswordArkThreadCrossViewFormatDetail(
                row->detail,
                sizeof(row->detail),
                "Kernel start address 0x%I64X is outside loaded module snapshot.",
                row->startAddress);
        }
    }
}

static VOID
kswordArkThreadCrossViewMergeThreadObjectWithStart(
    _Inout_ KswThreadCrossviewContext* context,
    _In_ PETHREAD threadObject,
    _In_ ULONG sourceMask,
    _In_ NTSTATUS sourceStatus,
    _In_ ULONG evidenceProcessId,
    _In_ ULONG evidenceThreadId,
    _In_opt_z_ PCSTR detailText
    )
/*++

Routine Description:

    Merge a referenced ETHREAD and enrich the row with start-address evidence.

Arguments:

    Context - Mutable query context.
    ThreadObject - Referenced thread object.
    SourceMask - Evidence source bit.
    SourceStatus - Source read/reference status.
    EvidenceProcessId - PID observed by the source itself, or zero when absent.
    EvidenceThreadId - TID observed by the source itself, or zero when absent.
    DetailText - Optional row detail text.

Return Value:

    None.

--*/
{
    KSWORD_ARK_THREAD_CROSSVIEW_ROW* row = NULL;
    ULONG threadId = 0UL;

    if (context == NULL || threadObject == NULL) {
        return;
    }

    threadId = HandleToULong(PsGetThreadId(threadObject));
    kswordArkThreadCrossViewMergeThreadObject(
        context,
        threadObject,
        sourceMask,
        sourceStatus,
        evidenceProcessId,
        evidenceThreadId,
        detailText);
    row = kswordArkThreadCrossViewFindRow(
        context,
        (ULONG64)(ULONG_PTR)threadObject,
        threadId);
    if (row != NULL) {
        kswordArkThreadCrossViewPopulateStartAddress(context, row, threadObject);
    }
}

static VOID
kswordArkThreadCrossViewCollectPublicWalk(
    _Inout_ KswThreadCrossviewContext* context
    )
/*++

Routine Description:

    Collect public thread evidence through PsGetNextProcess and
    psGetNextProcessThread. All process/thread references are released exactly
    once after use.

Arguments:

    Context - Mutable query context.

Return Value:

    None. Failures are recorded in Context.

--*/
{
    KswThreadCrossviewPsGetNextProcessFn psGetNextProcess = NULL;
    KswThreadCrossviewPsGetNextProcessThreadFn psGetNextProcessThread = NULL;
    PEPROCESS processCursor = NULL;
    ULONG visitedThreads = 0UL;

    if (context == NULL) {
        return;
    }

    psGetNextProcess = kswordArkThreadCrossViewResolvePsGetNextProcess();
    psGetNextProcessThread = kswordArkThreadCrossViewResolvePsGetNextProcessThread();
    if (psGetNextProcess == NULL || psGetNextProcessThread == NULL) {
        context->capabilityMissing = TRUE;
        context->lastStatus = STATUS_PROCEDURE_NOT_FOUND;
        return;
    }

    processCursor = psGetNextProcess(NULL);
    while (processCursor != NULL) {
        PEPROCESS nextProcess = psGetNextProcess(processCursor);
        PETHREAD threadCursor = NULL;
        const ULONG kProcessId = HandleToULong(PsGetProcessId(processCursor));

        kswordArkThreadCrossViewRecordProcessSeen(context, kProcessId);

        if (kswordArkThreadCrossViewProcessInRequest(context, kProcessId)) {
            threadCursor = psGetNextProcessThread(processCursor, NULL);
            while (threadCursor != NULL) {
                PETHREAD nextThread = psGetNextProcessThread(processCursor, threadCursor);
                if (visitedThreads >= context->maxNodes) {
                    context->truncated = TRUE;
                    context->lastStatus = STATUS_BUFFER_OVERFLOW;
                    ObDereferenceObject(threadCursor);
                    if (nextThread != NULL) {
                        ObDereferenceObject(nextThread);
                    }
                    break;
                }
                visitedThreads += 1UL;

                kswordArkThreadCrossViewMergeThreadObjectWithStart(
                    context,
                    threadCursor,
                    KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK,
                    STATUS_SUCCESS,
                    kProcessId,
                    HandleToULong(PsGetThreadId(threadCursor)),
                    "Observed through PsGetNextProcessThread.");
                ObDereferenceObject(threadCursor);
                threadCursor = nextThread;
            }
        }

        ObDereferenceObject(processCursor);
        processCursor = nextProcess;
        if (context->truncated) {
            break;
        }
    }

    if (!context->truncated) {
        context->publicProcessWalkComplete = TRUE;
    }
}

static VOID
kswordArkThreadCrossViewCollectOneThreadList(
    _Inout_ KswThreadCrossviewContext* context,
    _In_ PEPROCESS processObject,
    _Inout_ ULONG* walkedThreads
    )
/*++

Routine Description:

    Walk EPROCESS.ThreadListHead for one process using DynData offsets, bounded
    traversal, loop detection, pointer alignment checks, and balanced object
    references.

Arguments:

    Context - Mutable query context.
    ProcessObject - Referenced process object from the public process walk.
    WalkedThreads - Shared node counter across all process thread lists.

Return Value:

    None. Failures are recorded in Context and row details.

--*/
{
    LIST_ENTRY* head = NULL;
    LIST_ENTRY* current = NULL;
    KswThreadCrossviewVisitedSet visited;
    NTSTATUS status = STATUS_SUCCESS;

    if (context == NULL || processObject == NULL || walkedThreads == NULL) {
        return;
    }
    RtlZeroMemory(&visited, sizeof(visited));

    status = kswordArkThreadCrossViewVisitedInitialize(&visited, context->maxNodes);
    if (!NT_SUCCESS(status)) {
        context->lastStatus = status;
        return;
    }

    head = (LIST_ENTRY*)((PUCHAR)processObject + context->dynState.kernel.epThreadListHead);
    if (!kswordArkCrossViewPointerAligned((ULONG_PTR)head)) {
        context->lastStatus = STATUS_DATATYPE_MISALIGNMENT;
        kswordArkThreadCrossViewVisitedDestroy(&visited);
        return;
    }

    status = kswordArkCrossViewReadPointerAddress(&head->Flink, (PVOID*)&current);
    if (!NT_SUCCESS(status)) {
        context->lastStatus = status;
        kswordArkThreadCrossViewVisitedDestroy(&visited);
        return;
    }

    while (current != NULL && current != head) {
        LIST_ENTRY* next = NULL;
        LIST_ENTRY* blink = NULL;
        PVOID candidateThread = NULL;
        PVOID ownerProcessByField = NULL;
        ULONG cidProcessId = 0UL;
        ULONG cidThreadId = 0UL;
        BOOLEAN typeMatched = FALSE;
        BOOLEAN referenced = FALSE;
        BOOLEAN linkMismatch = FALSE;
        NTSTATUS readStatus = STATUS_SUCCESS;
        NTSTATUS referenceStatus = STATUS_SUCCESS;

        if (*walkedThreads >= context->maxNodes) {
            context->truncated = TRUE;
            context->lastStatus = STATUS_BUFFER_OVERFLOW;
            break;
        }
        *walkedThreads += 1UL;

        if (!kswordArkCrossViewPointerAligned((ULONG_PTR)current) ||
            kswordArkThreadCrossViewVisitedCheckAndAdd(&visited, (ULONG_PTR)current)) {
            context->lastStatus = STATUS_DATATYPE_MISALIGNMENT;
            break;
        }

        readStatus = kswordArkCrossViewReadPointerAddress(&current->Flink, (PVOID*)&next);
        if (!NT_SUCCESS(readStatus)) {
            context->lastStatus = readStatus;
            break;
        }
        readStatus = kswordArkCrossViewReadPointerAddress(&current->Blink, (PVOID*)&blink);
        if (!NT_SUCCESS(readStatus)) {
            context->lastStatus = readStatus;
            break;
        }
        if (next != NULL && next != head) {
            LIST_ENTRY* nextBlink = NULL;
            NTSTATUS nextBlinkStatus = STATUS_SUCCESS;
            if (!kswordArkCrossViewPointerAligned((ULONG_PTR)next)) {
                linkMismatch = TRUE;
                context->lastStatus = STATUS_DATATYPE_MISALIGNMENT;
            }
            else {
                nextBlinkStatus = kswordArkCrossViewReadPointerAddress(&next->Blink, (PVOID*)&nextBlink);
            }
            if (NT_SUCCESS(nextBlinkStatus) && nextBlink != current) {
                linkMismatch = TRUE;
            }
        }
        if (blink != NULL && blink != head) {
            LIST_ENTRY* blinkFlink = NULL;
            NTSTATUS blinkFlinkStatus = STATUS_SUCCESS;
            if (!kswordArkCrossViewPointerAligned((ULONG_PTR)blink)) {
                linkMismatch = TRUE;
                context->lastStatus = STATUS_DATATYPE_MISALIGNMENT;
            }
            else {
                blinkFlinkStatus = kswordArkCrossViewReadPointerAddress(&blink->Flink, (PVOID*)&blinkFlink);
            }
            if (NT_SUCCESS(blinkFlinkStatus) && blinkFlink != current) {
                linkMismatch = TRUE;
            }
        }

        candidateThread = (PVOID)((PUCHAR)current - context->dynState.kernel.etThreadListEntry);
        referenceStatus = kswordArkThreadCrossViewTryReferenceTypedObject(
            candidateThread,
            (PsThreadType != NULL) ? *PsThreadType : NULL,
            &typeMatched,
            &referenced);

        if (referenced) {
            PETHREAD threadObject = (PETHREAD)candidateThread;
            KSWORD_ARK_THREAD_CROSSVIEW_ROW* row = NULL;
            ULONG tid = HandleToULong(PsGetThreadId(threadObject));
            kswordArkThreadCrossViewMergeThreadObjectWithStart(
                context,
                threadObject,
                KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST,
                linkMismatch ? STATUS_DATA_ERROR : STATUS_SUCCESS,
                0UL,
                0UL,
                linkMismatch ? "ThreadListHead blink/flink mismatch observed." : "Observed through EPROCESS.ThreadListHead.");
            row = kswordArkThreadCrossViewFindRow(context, (ULONG64)(ULONG_PTR)threadObject, tid);
            if (row != NULL && PsGetThreadProcess(threadObject) != processObject) {
                row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_ORPHAN;
                row->lastStatus = STATUS_DATA_ERROR;
                kswordArkThreadCrossViewFormatDetail(
                    row->detail,
                    sizeof(row->detail),
                    "Thread list owner process does not match ETHREAD owner.");
            }
            ObDereferenceObject(threadObject);
        }
        else if (typeMatched) {
            (VOID)KswordARKThreadCrossViewReadCidFields(context, candidateThread, &cidProcessId, &cidThreadId);
            (VOID)kswordArkCrossViewReadPointerField(
                candidateThread,
                context->dynState.kernel.ktProcess,
                &ownerProcessByField);
            kswordArkThreadCrossViewMergeDanglingCandidate(
                context,
                (ULONG64)(ULONG_PTR)candidateThread,
                cidThreadId,
                cidProcessId,
                KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST,
                referenceStatus,
                "ThreadListHead candidate type matched but could not be referenced.");
            if (ownerProcessByField != NULL && ownerProcessByField != processObject) {
                KSWORD_ARK_THREAD_CROSSVIEW_ROW* row = kswordArkThreadCrossViewFindRow(
                    context,
                    (ULONG64)(ULONG_PTR)candidateThread,
                    cidThreadId);
                if (row != NULL) {
                    row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_ORPHAN;
                }
            }
        }

        current = next;
    }

    kswordArkThreadCrossViewVisitedDestroy(&visited);
}

static VOID
kswordArkThreadCrossViewCollectThreadLists(
    _Inout_ KswThreadCrossviewContext* context
    )
/*++

Routine Description:

    Collect EPROCESS.ThreadListHead evidence for all public processes, without
    accepting any R3-provided object address.

Arguments:

    Context - Mutable query context.

Return Value:

    None. Capability and traversal failures are recorded in Context.

--*/
{
    KswThreadCrossviewPsGetNextProcessFn psGetNextProcess = NULL;
    PEPROCESS processCursor = NULL;
    ULONG walkedThreads = 0UL;

    if (context == NULL) {
        return;
    }

    if ((context->dynState.capabilityMask & KSW_CAP_THREAD_LIST_FIELDS) != KSW_CAP_THREAD_LIST_FIELDS ||
        !kswordArkCrossViewOffsetPresent(context->dynState.kernel.epThreadListHead) ||
        !kswordArkCrossViewOffsetPresent(context->dynState.kernel.etThreadListEntry) ||
        !kswordArkCrossViewOffsetPresent(context->dynState.kernel.etCid) ||
        !kswordArkCrossViewOffsetPresent(context->dynState.kernel.ktProcess) ||
        PsThreadType == NULL ||
        *PsThreadType == NULL) {
        context->capabilityMissing = TRUE;
        context->missingCapabilityMask |= KSW_CAP_THREAD_LIST_FIELDS;
        context->lastStatus = STATUS_PROCEDURE_NOT_FOUND;
        return;
    }

    psGetNextProcess = kswordArkThreadCrossViewResolvePsGetNextProcess();
    if (psGetNextProcess == NULL) {
        context->capabilityMissing = TRUE;
        context->lastStatus = STATUS_PROCEDURE_NOT_FOUND;
        return;
    }

    processCursor = psGetNextProcess(NULL);
    while (processCursor != NULL) {
        PEPROCESS nextProcess = psGetNextProcess(processCursor);
        const ULONG kProcessId = HandleToULong(PsGetProcessId(processCursor));
        if (kswordArkThreadCrossViewProcessInRequest(context, kProcessId)) {
            kswordArkThreadCrossViewCollectOneThreadList(context, processCursor, &walkedThreads);
        }
        ObDereferenceObject(processCursor);
        processCursor = nextProcess;
        if (context->truncated) {
            break;
        }
    }
}

static VOID
kswordArkThreadCrossViewCidCallback(
    _In_ const KswCrossviewCidEntry* entry,
    _Inout_opt_ PVOID contextArg
    )
/*++

Routine Description:

    Merge one ETHREAD candidate reported by the read-only CID table walker.

Arguments:

    Entry - CID walker payload with a temporary reference when Referenced is TRUE.
    Context - KswThreadCrossviewContext owned by the query.

Return Value:

    None.

--*/
{
    KswThreadCrossviewContext* context = (KswThreadCrossviewContext*)contextArg;
    ULONG processId = 0UL;
    ULONG threadId = 0UL;

    if (context == NULL || entry == NULL) {
        return;
    }

    if (entry->referenced && entry->object != NULL) {
        (VOID)KswordARKThreadCrossViewReadCidFields(context, entry->object, &processId, &threadId);
        UNREFERENCED_PARAMETER(threadId);
        kswordArkThreadCrossViewMergeThreadObjectWithStart(
            context,
            (PETHREAD)entry->object,
            KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE,
            entry->referenceStatus,
            processId,
            entry->cidValue,
            "Observed through PspCidTable.");
    }
    else if (entry->typeMatched) {
        PVOID candidateObject = entry->object;

        if (candidateObject == NULL) {
            candidateObject = (PVOID)(ULONG_PTR)entry->objectAddress;
        }

        (VOID)KswordARKThreadCrossViewReadCidFields(context, candidateObject, &processId, &threadId);
        if (threadId == 0UL) {
            threadId = entry->cidValue;
        }
        kswordArkThreadCrossViewMergeDanglingCandidate(
            context,
            entry->objectAddress,
            threadId,
            processId,
            KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE,
            entry->referenceStatus,
            "PspCidTable thread candidate type matched but could not be referenced.");
    }
}

static VOID
kswordArkThreadCrossViewCollectCidTable(
    _Inout_ KswThreadCrossviewContext* context
    )
/*++

Routine Description:

    Collect thread evidence from PspCidTable using the shared read-only CID table
    walker.

Arguments:

    Context - Mutable query context.

Return Value:

    None. Resolver and walk failures are stored in Context.

--*/
{
    PVOID pspCidTableAddress = NULL;
    ULONG64 missingMask = 0ULL;
    BOOLEAN usedDynGlobal = FALSE;
    ULONG visitedEntries = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (context == NULL) {
        return;
    }

    /*
     * The shared CID walker already supplies bounded, read-only defaults for
     * HandleTable.TableCode and HandleTableEntry.LowValue.  Keep the same
     * fallback contract as the process cross-view path instead of disabling
     * thread CID evidence merely because an exact PDB profile is absent.
     * Object-type validation remains mandatory before a decoded entry is
     * referenced.
     */
    if (PsThreadType == NULL || *PsThreadType == NULL) {
        context->capabilityMissing = TRUE;
        context->missingCapabilityMask |= KSW_CAP_CID_TABLE_WALK;
        context->lastStatus = STATUS_PROCEDURE_NOT_FOUND;
        return;
    }

    status = kswordArkCrossViewResolvePspCidTableAddress(
        &context->dynState,
        &context->fieldOffsets,
        &pspCidTableAddress,
        &missingMask,
        &usedDynGlobal);
    UNREFERENCED_PARAMETER(usedDynGlobal);
    if (!NT_SUCCESS(status) || pspCidTableAddress == NULL) {
        context->capabilityMissing = TRUE;
        context->missingCapabilityMask |= (missingMask != 0ULL) ? missingMask : KSW_CAP_CID_TABLE_WALK;
        context->lastStatus = status;
        return;
    }

    status = kswordArkCrossViewWalkCidTable(
        &context->dynState,
        pspCidTableAddress,
        *PsThreadType,
        context->maxNodes,
        kswordArkThreadCrossViewCidCallback,
        context,
        &visitedEntries);
    UNREFERENCED_PARAMETER(visitedEntries);
    if (!NT_SUCCESS(status)) {
        if (status == STATUS_BUFFER_OVERFLOW) {
            context->truncated = TRUE;
        }
        else if (status == STATUS_PROCEDURE_NOT_FOUND) {
            context->capabilityMissing = TRUE;
            context->missingCapabilityMask |= KSW_CAP_CID_TABLE_WALK;
        }
        context->lastStatus = status;
    }
}

static VOID
kswordArkThreadCrossViewFinalizeRows(
    _Inout_ KswThreadCrossviewContext* context
    )
/*++

Routine Description:

    Compute thread anomaly flags and confidence after all selected source views
    have been merged.

Arguments:

    Context - Mutable query context containing internal rows.

Return Value:

    None.

--*/
{
    ULONG index = 0UL;

    if (context == NULL || context->rows == NULL) {
        return;
    }

    for (index = 0UL; index < context->rowCount; ++index) {
        KSWORD_ARK_THREAD_CROSSVIEW_ROW* row = &context->rows[index];
        const BOOLEAN kHasPublic = ((row->sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) != 0UL) ? TRUE : FALSE;
        const BOOLEAN kHasThreadList = ((row->sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST) != 0UL) ? TRUE : FALSE;
        const BOOLEAN kHasCid = ((row->sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) != 0UL) ? TRUE : FALSE;
        const BOOLEAN kExpectPublic =
            ((context->flags & KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_PUBLIC_WALK) != 0UL) ? TRUE : FALSE;
        const BOOLEAN kExpectThreadList =
            ((context->flags & KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_THREAD_LIST) != 0UL &&
                (context->missingCapabilityMask & KSW_CAP_THREAD_LIST_FIELDS) == 0ULL) ? TRUE : FALSE;
        const BOOLEAN kExpectCid =
            ((context->flags & KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_CID_TABLE) != 0UL &&
                (context->missingCapabilityMask & KSW_CAP_CID_TABLE_WALK) == 0ULL) ? TRUE : FALSE;

        row->dynDataCapabilityMask = context->dynState.capabilityMask;
        row->fieldOffsets = context->fieldOffsets;

        if (kExpectCid && kHasCid &&
            (!kExpectPublic || !kHasPublic) &&
            (!kExpectThreadList || !kHasThreadList)) {
            row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY;
        }
        if (kExpectThreadList && kHasThreadList &&
            (!kExpectPublic || !kHasPublic) &&
            (!kExpectCid || !kHasCid)) {
            row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY;
        }
        if (kExpectThreadList && (kHasPublic || kHasCid) && !kHasThreadList) {
            row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_NOT_IN_PROCESS_LIST;
        }
        if (kExpectCid && (kHasPublic || kHasThreadList) && !kHasCid) {
            row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_CID_TABLE;
        }
        if (row->processId == 0UL ||
            row->processObjectAddress == 0ULL ||
            (context->publicProcessWalkComplete &&
                !kswordArkThreadCrossViewHasProcessSeen(context, row->processId))) {
            row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_ORPHAN;
        }

        if ((row->anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_DANGLING_OBJECT) != 0UL) {
            row->confidence = 30UL;
        }
        else if ((row->anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_START_ADDRESS_OUTSIDE_MODULE) != 0UL) {
            row->confidence = 55UL;
        }
        else if (kHasPublic && kHasThreadList && kHasCid) {
            row->confidence = 98UL;
        }
        else if ((kHasPublic && kHasThreadList) || (kHasPublic && kHasCid) || (kHasThreadList && kHasCid)) {
            row->confidence = 80UL;
        }
        else {
            row->confidence = 60UL;
        }

        if (context->capabilityMissing || context->truncated) {
            row->denoiseFlags |= KSWORD_ARK_CROSSVIEW_DENOISE_PARTIAL_EVIDENCE;
            if (row->detailStatus == KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_OK) {
                row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_PARTIAL;
            }
        }

        if (row->detail[0] == '\0') {
            kswordArkThreadCrossViewFormatDetail(
                row->detail,
                sizeof(row->detail),
                "sources=0x%08lX anomalies=0x%08lX.",
                row->sourceMask,
                row->anomalyFlags);
        }
    }
}

static VOID
kswordArkThreadCrossViewCopyResponse(
    _Inout_ KSWORD_ARK_THREAD_CROSSVIEW_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _In_ const KswThreadCrossviewContext* context,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Copy internal thread rows into the caller response while preserving totalCount
    when output capacity is smaller than collected evidence.

Arguments:

    Response - Output response header and flexible row array.
    OutputBufferLength - Writable response byte count.
    Context - Finalized query context.
    BytesWrittenOut - Receives bytes written.

Return Value:

    None.

--*/
{
    size_t entryCapacity = 0U;
    ULONG copyCount = 0UL;

    if (response == NULL || context == NULL || bytesWrittenOut == NULL) {
        return;
    }

    entryCapacity = (outputBufferLength - KSW_THREAD_CROSSVIEW_HEADER_SIZE) / sizeof(KSWORD_ARK_THREAD_CROSSVIEW_ROW);
    copyCount = (context->rowCount < (ULONG)entryCapacity) ? context->rowCount : (ULONG)entryCapacity;

    response->version = KSWORD_ARK_CROSSVIEW_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_THREAD_CROSSVIEW_ROW);
    response->totalCount = context->rowCount;
    response->returnedCount = copyCount;
    response->dynDataCapabilityMask = context->dynState.capabilityMask;
    response->missingCapabilityMask = context->missingCapabilityMask;
    response->lastStatus = context->lastStatus;
    response->fieldOffsets = context->fieldOffsets;

    if (context->capabilityMissing && context->rowCount == 0UL) {
        response->status = KSWORD_ARK_CROSSVIEW_STATUS_CAPABILITY_MISSING;
    }
    else if (context->capabilityMissing || context->truncated || copyCount < context->rowCount) {
        response->status = KSWORD_ARK_CROSSVIEW_STATUS_PARTIAL;
    }
    else if (!NT_SUCCESS(context->lastStatus)) {
        response->status = KSWORD_ARK_CROSSVIEW_STATUS_READ_FAILED;
    }
    else {
        response->status = KSWORD_ARK_CROSSVIEW_STATUS_OK;
    }

    if (copyCount != 0UL) {
        RtlCopyMemory(response->entries, context->rows, (SIZE_T)copyCount * sizeof(KSWORD_ARK_THREAD_CROSSVIEW_ROW));
    }

    *bytesWrittenOut = KSW_THREAD_CROSSVIEW_HEADER_SIZE + ((size_t)copyCount * sizeof(KSWORD_ARK_THREAD_CROSSVIEW_ROW));
}

NTSTATUS
kswordArkDriverQueryThreadCrossView(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_THREAD_CROSSVIEW_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Query read-only thread cross-view evidence from psGetNextProcessThread,
    EPROCESS.ThreadListHead, and PspCidTable.

Arguments:

    OutputBuffer - METHOD_BUFFERED output packet.
    OutputBufferLength - Writable output byte count.
    Request - Optional thread cross-view request.
    BytesWrittenOut - Receives bytes written to OutputBuffer.

Return Value:

    STATUS_SUCCESS when the response header is written; validation/allocation
    status otherwise. Per-source failures are reported in the response fields.

--*/
{
    KswThreadCrossviewContext context;
    KSWORD_ARK_THREAD_CROSSVIEW_RESPONSE* response = NULL;
    SIZE_T rowBytes = 0U;
    ULONG requestFlags = KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_ALL;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSW_THREAD_CROSSVIEW_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(&context, sizeof(context));
    context.lastStatus = STATUS_SUCCESS;
    context.moduleStatus = STATUS_SUCCESS;
    context.maxNodes = KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES;
    if (request != NULL) {
        if (request->flags != 0UL) {
            requestFlags = request->flags;
        }
        context.processId = request->processId;
        context.startTid = request->startTid;
        context.endTid = request->endTid;
        context.maxNodes = kswordArkThreadCrossViewNormalizeMaxNodes(request->maxNodes);
    }
    context.flags = requestFlags;
    context.rowCapacity = context.maxNodes;

    rowBytes = (SIZE_T)context.rowCapacity * sizeof(KSWORD_ARK_THREAD_CROSSVIEW_ROW);
    if ((rowBytes / sizeof(KSWORD_ARK_THREAD_CROSSVIEW_ROW)) != (SIZE_T)context.rowCapacity) {
        return STATUS_INTEGER_OVERFLOW;
    }

    context.rows = (KSWORD_ARK_THREAD_CROSSVIEW_ROW*)kswordArkThreadCrossViewAllocate(rowBytes, KSW_THREAD_CROSSVIEW_TAG);
    if (context.rows == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(context.rows, rowBytes);
    RtlZeroMemory(&context.processSeen, sizeof(context.processSeen));
    context.processSeen.capacity = context.maxNodes;
    context.processSeen.items = (ULONG_PTR*)kswordArkThreadCrossViewAllocate(
        (SIZE_T)context.maxNodes * sizeof(ULONG_PTR),
        KSW_THREAD_CROSSVIEW_VISIT_TAG);
    if (context.processSeen.items == NULL) {
        kswordArkThreadCrossViewFree(context.rows, KSW_THREAD_CROSSVIEW_TAG);
        context.rows = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(context.processSeen.items, (SIZE_T)context.maxNodes * sizeof(ULONG_PTR));

    kswordArkDynDataSnapshot(&context.dynState);
    kswordArkCrossViewFillFieldOffsets(&context.dynState, &context.fieldOffsets);

    if ((requestFlags & KSWORD_ARK_THREAD_CROSSVIEW_FLAG_VALIDATE_START) != 0UL) {
        context.moduleStatus = kswordArkHookBuildModuleSnapshot(&context.moduleInfo, &context.moduleInfoBytes);
        if (!NT_SUCCESS(context.moduleStatus)) {
            context.lastStatus = context.moduleStatus;
        }
    }

    if ((requestFlags & KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_PUBLIC_WALK) != 0UL) {
        kswordArkThreadCrossViewCollectPublicWalk(&context);
    }
    if ((requestFlags & KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_THREAD_LIST) != 0UL) {
        kswordArkThreadCrossViewCollectThreadLists(&context);
    }
    if ((requestFlags & KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_CID_TABLE) != 0UL) {
        kswordArkThreadCrossViewCollectCidTable(&context);
    }

    kswordArkThreadCrossViewFinalizeRows(&context);

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_THREAD_CROSSVIEW_RESPONSE*)outputBuffer;
    kswordArkThreadCrossViewCopyResponse(response, outputBufferLength, &context, bytesWrittenOut);

    if (context.moduleInfo != NULL) {
        ExFreePoolWithTag(context.moduleInfo, KSW_HOOK_SCAN_TAG);
        context.moduleInfo = NULL;
    }
    kswordArkThreadCrossViewFree(context.processSeen.items, KSW_THREAD_CROSSVIEW_VISIT_TAG);
    context.processSeen.items = NULL;
    kswordArkThreadCrossViewFree(context.rows, KSW_THREAD_CROSSVIEW_TAG);
    context.rows = NULL;
    return status;
}

NTSTATUS
kswordArkThreadIoctlQueryCrossView(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle the unregistered thread cross-view IOCTL. The handler validates
    buffers only, accepts an optional fixed request, and invokes the read-only
    backend without write access or caller-supplied object addresses.

Arguments:

    Device - WDF device used only for signature parity with other handlers.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes; shorter input selects defaults.
    OutputBufferLength - Supplied output bytes; checked by WDF retrieval.
    BytesReturned - Receives backend response bytes.

Return Value:

    NTSTATUS from buffer retrieval or kswordArkDriverQueryThreadCrossView.

--*/
{
    KSWORD_ARK_THREAD_CROSSVIEW_REQUEST* queryRequest = NULL;
    KSWORD_ARK_THREAD_CROSSVIEW_REQUEST defaultRequest;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    RtlZeroMemory(&defaultRequest, sizeof(defaultRequest));
    defaultRequest.version = KSWORD_ARK_CROSSVIEW_PROTOCOL_VERSION;
    defaultRequest.flags = KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_ALL;
    defaultRequest.maxNodes = KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES;

    status = kswordArkRetrieveOptionalInputBuffer(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_THREAD_CROSSVIEW_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    queryRequest = hasInput ? (KSWORD_ARK_THREAD_CROSSVIEW_REQUEST*)inputBuffer : &defaultRequest;

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSW_THREAD_CROSSVIEW_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return kswordArkDriverQueryThreadCrossView(
        outputBuffer,
        actualOutputLength,
        queryRequest,
        bytesReturned);
}
