/*++

Module Name:

    thread_detail.c

Abstract:

    Read-only PDB/DynData-backed thread runtime detail query.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../process/process_crossview.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>

typedef struct KswordArkDetailClientIdLocal
{
    HANDLE uniqueProcess;
    HANDLE uniqueThread;
} KswordArkDetailClientIdLocal, *PkswordArkDetailClientIdLocal;

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

static BOOLEAN
kswordArkThreadDetailOffsetPresent(
    _In_ ULONG offset
    )
/*++

Routine Description:

    Check if an ETHREAD/KTHREAD offset is usable for detailed sampling.

Arguments:

    Offset - Field offset from DynData/PDB.

Return Value:

    TRUE indicates the offset is available; FALSE indicates it is missing or a sentinel.

--*/
{
    return (offset != KSW_DYN_OFFSET_UNAVAILABLE && offset != 0x0000FFFFUL) ? TRUE : FALSE;
}

static ULONG
kswordArkThreadDetailProtocolOffset(
    _In_ ULONG offset
    )
/*++

Routine Description:

    Convert the driver-internal offset sentinel to a shared protocol sentinel.

Arguments:

    Offset - Original DynData/PDB offset.

Return Value:

    Returns a valid offset or KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE.

--*/
{
    if (!kswordArkThreadDetailOffsetPresent(offset)) {
        return KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    }

    return offset;
}

static VOID
kswordArkThreadDetailFillOffsets(
    _In_ const KswDynState* dynState,
    _Out_ KSWORD_ARK_THREAD_DETAIL_OFFSETS* offsets
    )
/*++

Routine Description:

    Copy the DynData offsets for the current thread into the response packet.

Arguments:

    DynState - Current DynData snapshot.
    Offsets: offset substructure within the shared response.

Return Value:

    None.

--*/
{
    RtlZeroMemory(offsets, sizeof(*offsets));
    offsets->etCid = kswordArkThreadDetailProtocolOffset(dynState->kernel.etCid);
    offsets->etThreadListEntry = kswordArkThreadDetailProtocolOffset(dynState->kernel.etThreadListEntry);
    offsets->etStartAddress = kswordArkThreadDetailProtocolOffset(dynState->kernel.etStartAddress);
    offsets->etWin32StartAddress = kswordArkThreadDetailProtocolOffset(dynState->kernel.etWin32StartAddress);
    offsets->ktProcess = kswordArkThreadDetailProtocolOffset(dynState->kernel.ktProcess);
    offsets->ktInitialStack = kswordArkThreadDetailProtocolOffset(dynState->kernel.ktInitialStack);
    offsets->ktStackLimit = kswordArkThreadDetailProtocolOffset(dynState->kernel.ktStackLimit);
    offsets->ktStackBase = kswordArkThreadDetailProtocolOffset(dynState->kernel.ktStackBase);
    offsets->ktKernelStack = kswordArkThreadDetailProtocolOffset(dynState->kernel.ktKernelStack);
    offsets->ktReadOperationCount = kswordArkThreadDetailProtocolOffset(dynState->kernel.ktReadOperationCount);
    offsets->ktWriteOperationCount = kswordArkThreadDetailProtocolOffset(dynState->kernel.ktWriteOperationCount);
    offsets->ktOtherOperationCount = kswordArkThreadDetailProtocolOffset(dynState->kernel.ktOtherOperationCount);
    offsets->ktReadTransferCount = kswordArkThreadDetailProtocolOffset(dynState->kernel.ktReadTransferCount);
    offsets->ktWriteTransferCount = kswordArkThreadDetailProtocolOffset(dynState->kernel.ktWriteTransferCount);
    offsets->ktOtherTransferCount = kswordArkThreadDetailProtocolOffset(dynState->kernel.ktOtherTransferCount);
}

static BOOLEAN
kswordArkThreadDetailSourcePresent(
    _In_ ULONG source
    )
/*++

Routine Description:

    Check if the thread detail field source is displayable. Note: An 'unavailable' source only
    indicates the current profile did not provide the field and cannot be used as evidence for output.

Arguments:

    Source - KSW_DYN_FIELD_SOURCE_* source value.

Return Value:

    TRUE indicates a valid source; FALSE indicates a missing source.

--*/
{
    return (source != KSW_DYN_FIELD_SOURCE_UNAVAILABLE) ? TRUE : FALSE;
}

static BOOLEAN
kswordArkThreadDetailFillSources(
    _In_ const KswDynState* dynState,
    _Out_ KSWORD_ARK_THREAD_DETAIL_SOURCES* sources
    )
/*++

Routine Description:

    Copy ETHREAD/KTHREAD detail offsets to the shared response.

Arguments:

    DynState - Current DynData snapshot.
    Sources: Thread detail source sub-structure within the shared response.

Return Value:

    TRUE indicates at least one source is available for display; FALSE indicates all sources are missing.

--*/
{
    BOOLEAN anySourcePresent = FALSE;

    RtlZeroMemory(sources, sizeof(*sources));
    sources->etCid = dynState->kernelSources.etCid;
    sources->etThreadListEntry = dynState->kernelSources.etThreadListEntry;
    sources->etStartAddress = dynState->kernelSources.etStartAddress;
    sources->etWin32StartAddress = dynState->kernelSources.etWin32StartAddress;
    sources->ktProcess = dynState->kernelSources.ktProcess;
    sources->ktInitialStack = dynState->kernelSources.ktInitialStack;
    sources->ktStackLimit = dynState->kernelSources.ktStackLimit;
    sources->ktStackBase = dynState->kernelSources.ktStackBase;
    sources->ktKernelStack = dynState->kernelSources.ktKernelStack;
    sources->ktReadOperationCount = dynState->kernelSources.ktReadOperationCount;
    sources->ktWriteOperationCount = dynState->kernelSources.ktWriteOperationCount;
    sources->ktOtherOperationCount = dynState->kernelSources.ktOtherOperationCount;
    sources->ktReadTransferCount = dynState->kernelSources.ktReadTransferCount;
    sources->ktWriteTransferCount = dynState->kernelSources.ktWriteTransferCount;
    sources->ktOtherTransferCount = dynState->kernelSources.ktOtherTransferCount;

    anySourcePresent = kswordArkThreadDetailSourcePresent(sources->etCid) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkThreadDetailSourcePresent(sources->etThreadListEntry) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkThreadDetailSourcePresent(sources->etStartAddress) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkThreadDetailSourcePresent(sources->etWin32StartAddress) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkThreadDetailSourcePresent(sources->ktProcess) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkThreadDetailSourcePresent(sources->ktInitialStack) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkThreadDetailSourcePresent(sources->ktStackLimit) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkThreadDetailSourcePresent(sources->ktStackBase) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkThreadDetailSourcePresent(sources->ktKernelStack) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkThreadDetailSourcePresent(sources->ktReadOperationCount) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkThreadDetailSourcePresent(sources->ktWriteOperationCount) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkThreadDetailSourcePresent(sources->ktOtherOperationCount) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkThreadDetailSourcePresent(sources->ktReadTransferCount) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkThreadDetailSourcePresent(sources->ktWriteTransferCount) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkThreadDetailSourcePresent(sources->ktOtherTransferCount) ? TRUE : anySourcePresent;

    return anySourcePresent;
}

static ULONG64
kswordArkThreadDetailKernelGlobalAddress(
    _In_ const KswDynState* dynState,
    _In_ ULONG rva
    )
/*++

Routine Description:

    Convert the PDB profile's global RVA to VA based on the current ntoskrnl imageBase.

Arguments:

    DynState - Current DynData snapshot.
    Rva - Global symbol RVA.

Return Value:

    Current kernel address; returns 0 if missing.

--*/
{
    if (!dynState->ntosActive || dynState->ntoskrnl.imageBase == 0ULL) {
        return 0ULL;
    }
    if (!kswordArkThreadDetailOffsetPresent(rva)) {
        return 0ULL;
    }

    return dynState->ntoskrnl.imageBase + (ULONG64)rva;
}

static BOOLEAN
kswordArkThreadDetailFillKernelGlobals(
    _In_ const KswDynState* dynState,
    _Out_ KSWORD_ARK_RUNTIME_KERNEL_GLOBALS* globals
    )
/*++

Routine Description:

    Copy the ntoskrnl global RVA evidence package also displayed on the thread details page.

Arguments:

    DynState - Current DynData snapshot.
    Globals - global RVA/source/VA package within the shared response.

Return Value:

    TRUE indicates at least one global RVA is displayable; FALSE indicates all are missing.

--*/
{
    BOOLEAN anyGlobalPresent = FALSE;

    RtlZeroMemory(globals, sizeof(*globals));
    globals->pspCidTableRva = kswordArkThreadDetailProtocolOffset(dynState->kernelGlobals.pspCidTable);
    globals->psLoadedModuleListRva = kswordArkThreadDetailProtocolOffset(dynState->kernelGlobals.psLoadedModuleList);
    globals->mmUnloadedDriversRva = kswordArkThreadDetailProtocolOffset(dynState->kernelGlobals.mmUnloadedDrivers);
    globals->piDdbCacheTableRva = kswordArkThreadDetailProtocolOffset(dynState->kernelGlobals.piDdbCacheTable);
    globals->keServiceDescriptorTableShadowRva = kswordArkThreadDetailProtocolOffset(dynState->kernelGlobals.keServiceDescriptorTableShadow);
    globals->mmLastUnloadedDriverRva = kswordArkThreadDetailProtocolOffset(dynState->kernelGlobals.mmLastUnloadedDriver);
    globals->pspCidTableSource = dynState->kernelGlobalSources.pspCidTable;
    globals->psLoadedModuleListSource = dynState->kernelGlobalSources.psLoadedModuleList;
    globals->mmUnloadedDriversSource = dynState->kernelGlobalSources.mmUnloadedDrivers;
    globals->piDdbCacheTableSource = dynState->kernelGlobalSources.piDdbCacheTable;
    globals->keServiceDescriptorTableShadowSource = dynState->kernelGlobalSources.keServiceDescriptorTableShadow;
    globals->mmLastUnloadedDriverSource = dynState->kernelGlobalSources.mmLastUnloadedDriver;
    globals->pspCidTableAddress = kswordArkThreadDetailKernelGlobalAddress(dynState, dynState->kernelGlobals.pspCidTable);
    globals->psLoadedModuleListAddress = kswordArkThreadDetailKernelGlobalAddress(dynState, dynState->kernelGlobals.psLoadedModuleList);
    globals->mmUnloadedDriversAddress = kswordArkThreadDetailKernelGlobalAddress(dynState, dynState->kernelGlobals.mmUnloadedDrivers);
    globals->piDdbCacheTableAddress = kswordArkThreadDetailKernelGlobalAddress(dynState, dynState->kernelGlobals.piDdbCacheTable);
    globals->keServiceDescriptorTableShadowAddress = kswordArkThreadDetailKernelGlobalAddress(dynState, dynState->kernelGlobals.keServiceDescriptorTableShadow);
    globals->mmLastUnloadedDriverAddress = kswordArkThreadDetailKernelGlobalAddress(dynState, dynState->kernelGlobals.mmLastUnloadedDriver);

    anyGlobalPresent = kswordArkThreadDetailOffsetPresent(dynState->kernelGlobals.pspCidTable) ? TRUE : anyGlobalPresent;
    anyGlobalPresent = kswordArkThreadDetailOffsetPresent(dynState->kernelGlobals.psLoadedModuleList) ? TRUE : anyGlobalPresent;
    anyGlobalPresent = kswordArkThreadDetailOffsetPresent(dynState->kernelGlobals.mmUnloadedDrivers) ? TRUE : anyGlobalPresent;
    anyGlobalPresent = kswordArkThreadDetailOffsetPresent(dynState->kernelGlobals.piDdbCacheTable) ? TRUE : anyGlobalPresent;
    anyGlobalPresent = kswordArkThreadDetailOffsetPresent(dynState->kernelGlobals.keServiceDescriptorTableShadow) ? TRUE : anyGlobalPresent;
    anyGlobalPresent = kswordArkThreadDetailOffsetPresent(dynState->kernelGlobals.mmLastUnloadedDriver) ? TRUE : anyGlobalPresent;

    return anyGlobalPresent;
}

static NTSTATUS
kswordArkThreadDetailReadClientId(
    _In_ const VOID* threadObject,
    _In_ ULONG offset,
    _Out_ ULONG64* processIdOut,
    _Out_ ULONG64* threadIdOut
    )
/*++

Routine Description:

    Read ETHREAD.Cid for the UI to compare against PsGetThreadId/PsGetThreadProcessId.

Arguments:

    ThreadObject - ETHREAD object.
    Offset - ETHREAD.Cid offset.
    ProcessIdOut - outputs UniqueProcess.
    ThreadIdOut - Output UniqueThread.

Return Value:

    STATUS_SUCCESS or secure read failure status.

--*/
{
    KswordArkDetailClientIdLocal cid;
    NTSTATUS status;

    if (processIdOut == NULL || threadIdOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkThreadDetailOffsetPresent(offset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    RtlZeroMemory(&cid, sizeof(cid));
    status = kswordArkCrossViewReadMemory((const UCHAR*)threadObject + offset, &cid, sizeof(cid));
    if (NT_SUCCESS(status)) {
        *processIdOut = (ULONG64)(ULONG_PTR)cid.uniqueProcess;
        *threadIdOut = (ULONG64)(ULONG_PTR)cid.uniqueThread;
    }

    return status;
}

static NTSTATUS
kswordArkThreadDetailReadListEntry(
    _In_ const VOID* threadObject,
    _In_ ULONG offset,
    _Out_ ULONG64* flinkOut,
    _Out_ ULONG64* blinkOut
    )
/*++

Routine Description:

    Note: Reads the ETHREAD.ThreadListEntry list pointer.

Arguments:

    ThreadObject - ETHREAD object.
    Offset - Offset of ThreadListEntry.
    FlinkOut: output Flink address.
    BlinkOut - Output the Blink address.

Return Value:

    STATUS_SUCCESS or secure read failure status.

--*/
{
    LIST_ENTRY listEntry;
    NTSTATUS status;

    if (flinkOut == NULL || blinkOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkThreadDetailOffsetPresent(offset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    RtlZeroMemory(&listEntry, sizeof(listEntry));
    status = kswordArkCrossViewReadMemory((const UCHAR*)threadObject + offset, &listEntry, sizeof(listEntry));
    if (NT_SUCCESS(status)) {
        *flinkOut = (ULONG64)(ULONG_PTR)listEntry.Flink;
        *blinkOut = (ULONG64)(ULONG_PTR)listEntry.Blink;
    }

    return status;
}

static NTSTATUS
kswordArkThreadDetailReadUlong64Field(
    _In_ const VOID* threadObject,
    _In_ ULONG offset,
    _Out_ ULONG64* valueOut
    )
/*++

Routine Description:

    Reads a 64-bit counter or address field from ETHREAD/KTHREAD.

Arguments:

    ThreadObject - ETHREAD object.
    Offset - Field offset.
    ValueOut - Output field value.

Return Value:

    STATUS_SUCCESS or secure read failure status.

--*/
{
    if (valueOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkThreadDetailOffsetPresent(offset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    return kswordArkCrossViewReadUlong64Address((const UCHAR*)threadObject + offset, valueOut);
}

static VOID
kswordArkThreadDetailNoteFailure(
    _In_ NTSTATUS readStatus,
    _Inout_ ULONG* failureCount,
    _Inout_ NTSTATUS* lastStatus
    )
/*++

Routine Description:

    Record a field read failure, which will eventually fold into a PARTIAL/CAPABILITY_MISSING state.

Arguments:

    ReadStatus - Single-field read status.
    FailureCount - Failure count.
    LastStatus - Most recent failure status.

Return Value:

    None.

--*/
{
    if (!NT_SUCCESS(readStatus)) {
        ++(*failureCount);
        *lastStatus = readStatus;
    }
}

NTSTATUS
kswordArkDriverQueryThreadDetail(
    _Out_writes_bytes_(outputBufferLength) KSWORD_ARK_THREAD_DETAIL_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_THREAD_DETAIL_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Query read-only runtime details for a single thread. Note: R0 references ETHREAD solely by TID, then reads
    fields using applied PDB/DynData offsets; no suspension, termination, or list repairs are performed.

Arguments:

    Response - METHOD_BUFFERED output response.
    OutputBufferLength - Length of the output buffer.
    Request - fixed request.
    BytesWrittenOut - Returns the response size.

Return Value:

    STATUS_SUCCESS indicates the response packet is valid; missing field writes go to status/detail.

--*/
{
    KswDynState dynState;
    PETHREAD threadObject = NULL;
    PVOID processObject = NULL;
    ULONG requestFlags = KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_ALL;
    ULONG failureCount = 0UL;
    ULONG missingRequired = 0UL;
    ULONG stackFieldSuccessCount = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS lastStatus = STATUS_SUCCESS;

    if (response == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (outputBufferLength < sizeof(*response)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    *bytesWrittenOut = sizeof(*response);
    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_RUNTIME_DETAIL_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_DETAIL_STATUS_UNKNOWN;
    response->threadId = request->threadId;
    response->processId = request->processId;
    response->requestedFlags = request->flags;

    if (request->version != KSWORD_ARK_RUNTIME_DETAIL_PROTOCOL_VERSION) {
        response->status = KSWORD_ARK_DETAIL_STATUS_UNSUPPORTED;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        (VOID)RtlStringCchCopyW(response->detail, KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS, L"Thread detail request version mismatch.");
        return STATUS_SUCCESS;
    }

    if (request->threadId == 0UL) {
        response->status = KSWORD_ARK_DETAIL_STATUS_LOOKUP_FAILED;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        (VOID)RtlStringCchCopyW(response->detail, KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS, L"Thread detail requires a non-zero TID.");
        return STATUS_SUCCESS;
    }

    if (request->flags != 0UL) {
        requestFlags = request->flags;
    }

    kswordArkDynDataSnapshot(&dynState);
    response->dynDataCapabilityMask = dynState.capabilityMask;
    kswordArkThreadDetailFillOffsets(&dynState, &response->offsets);
    if (kswordArkThreadDetailFillSources(&dynState, &response->sources)) {
        response->fieldFlags |= KSWORD_ARK_THREAD_DETAIL_FIELD_OFFSET_SOURCES;
    }
    if (kswordArkThreadDetailFillKernelGlobals(&dynState, &response->kernelGlobals)) {
        response->fieldFlags |= KSWORD_ARK_THREAD_DETAIL_FIELD_KERNEL_GLOBALS;
    }

    status = PsLookupThreadByThreadId(ULongToHandle(request->threadId), &threadObject);
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_DETAIL_STATUS_LOOKUP_FAILED;
        response->lastStatus = status;
        (VOID)RtlStringCchPrintfW(response->detail, KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS, L"PsLookupThreadByThreadId failed for TID %lu: 0x%08X.", request->threadId, (unsigned int)status);
        return STATUS_SUCCESS;
    }

    response->threadObjectAddress = (ULONG64)(ULONG_PTR)threadObject;
    response->fieldFlags |= KSWORD_ARK_THREAD_DETAIL_FIELD_OBJECT_ADDRESS;
    response->threadId = HandleToULong(PsGetThreadId(threadObject));
    response->processId = HandleToULong(PsGetThreadProcessId(threadObject));
    response->fieldFlags |= KSWORD_ARK_THREAD_DETAIL_FIELD_PUBLIC_IDENTITY;

    if (request->processId != 0UL && request->processId != response->processId) {
        response->status = KSWORD_ARK_DETAIL_STATUS_LOOKUP_FAILED;
        response->lastStatus = STATUS_OBJECT_NAME_NOT_FOUND;
        (VOID)RtlStringCchPrintfW(response->detail, KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS, L"TID %lu belongs to PID %lu, not requested PID %lu.", response->threadId, response->processId, request->processId);
        ObDereferenceObject(threadObject);
        return STATUS_SUCCESS;
    }

    if ((requestFlags & KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_IDENTITY) != 0UL) {
        status = kswordArkThreadDetailReadClientId(threadObject, dynState.kernel.etCid, &response->cidUniqueProcess, &response->cidUniqueThread);
        if (NT_SUCCESS(status)) {
            response->fieldFlags |= KSWORD_ARK_THREAD_DETAIL_FIELD_ETHREAD_CID;
        }
        else {
            response->missingCapabilityMask |= KSW_CAP_THREAD_LIST_FIELDS;
            ++missingRequired;
        }
        kswordArkThreadDetailNoteFailure(status, &failureCount, &lastStatus);

        processObject = PsGetThreadProcess(threadObject);
        response->processObjectAddress = (ULONG64)(ULONG_PTR)processObject;
    }

    if ((requestFlags & KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_LISTS) != 0UL) {
        status = kswordArkThreadDetailReadListEntry(threadObject, dynState.kernel.etThreadListEntry, &response->threadListEntryFlink, &response->threadListEntryBlink);
        if (NT_SUCCESS(status)) {
            response->fieldFlags |= KSWORD_ARK_THREAD_DETAIL_FIELD_THREAD_LIST_ENTRY;
        }
        else {
            response->missingCapabilityMask |= KSW_CAP_THREAD_LIST_FIELDS;
            ++missingRequired;
        }
        kswordArkThreadDetailNoteFailure(status, &failureCount, &lastStatus);
    }

    if ((requestFlags & KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_START) != 0UL) {
        status = kswordArkThreadDetailReadUlong64Field(threadObject, dynState.kernel.etStartAddress, &response->startAddress);
        if (NT_SUCCESS(status)) {
            response->fieldFlags |= KSWORD_ARK_THREAD_DETAIL_FIELD_START_ADDRESS;
        }
        else {
            response->missingCapabilityMask |= KSW_CAP_THREAD_LIST_FIELDS;
        }
        kswordArkThreadDetailNoteFailure(status, &failureCount, &lastStatus);

        status = kswordArkThreadDetailReadUlong64Field(threadObject, dynState.kernel.etWin32StartAddress, &response->win32StartAddress);
        if (NT_SUCCESS(status)) {
            response->fieldFlags |= KSWORD_ARK_THREAD_DETAIL_FIELD_WIN32_START_ADDRESS;
        }
        kswordArkThreadDetailNoteFailure(status, &failureCount, &lastStatus);
    }

    if ((requestFlags & KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_STACK) != 0UL) {
        status = kswordArkThreadDetailReadUlong64Field(threadObject, dynState.kernel.ktProcess, &response->kthreadProcessObject);
        if (NT_SUCCESS(status)) {
            response->fieldFlags |= KSWORD_ARK_THREAD_DETAIL_FIELD_KTHREAD_PROCESS;
        }
        else {
            response->missingCapabilityMask |= KSW_CAP_THREAD_LIST_FIELDS;
        }
        kswordArkThreadDetailNoteFailure(status, &failureCount, &lastStatus);

        status = kswordArkThreadDetailReadUlong64Field(threadObject, dynState.kernel.ktInitialStack, &response->initialStack);
        if (NT_SUCCESS(status)) {
            ++stackFieldSuccessCount;
        }
        kswordArkThreadDetailNoteFailure(status, &failureCount, &lastStatus);
        status = kswordArkThreadDetailReadUlong64Field(threadObject, dynState.kernel.ktStackLimit, &response->stackLimit);
        if (NT_SUCCESS(status)) {
            ++stackFieldSuccessCount;
        }
        kswordArkThreadDetailNoteFailure(status, &failureCount, &lastStatus);
        status = kswordArkThreadDetailReadUlong64Field(threadObject, dynState.kernel.ktStackBase, &response->stackBase);
        if (NT_SUCCESS(status)) {
            ++stackFieldSuccessCount;
        }
        kswordArkThreadDetailNoteFailure(status, &failureCount, &lastStatus);
        status = kswordArkThreadDetailReadUlong64Field(threadObject, dynState.kernel.ktKernelStack, &response->kernelStack);
        if (NT_SUCCESS(status)) {
            ++stackFieldSuccessCount;
        }
        if (stackFieldSuccessCount >= 3UL) {
            response->fieldFlags |= KSWORD_ARK_THREAD_DETAIL_FIELD_STACK_LIMITS;
        }
        if (stackFieldSuccessCount != 4UL) {
            response->missingCapabilityMask |= KSW_CAP_THREAD_STACK_FIELDS;
        }
        kswordArkThreadDetailNoteFailure(status, &failureCount, &lastStatus);
    }

    if ((requestFlags & KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_IO) != 0UL) {
        status = kswordArkThreadDetailReadUlong64Field(threadObject, dynState.kernel.ktReadOperationCount, &response->readOperationCount);
        kswordArkThreadDetailNoteFailure(status, &failureCount, &lastStatus);
        status = kswordArkThreadDetailReadUlong64Field(threadObject, dynState.kernel.ktWriteOperationCount, &response->writeOperationCount);
        kswordArkThreadDetailNoteFailure(status, &failureCount, &lastStatus);
        status = kswordArkThreadDetailReadUlong64Field(threadObject, dynState.kernel.ktOtherOperationCount, &response->otherOperationCount);
        kswordArkThreadDetailNoteFailure(status, &failureCount, &lastStatus);
        status = kswordArkThreadDetailReadUlong64Field(threadObject, dynState.kernel.ktReadTransferCount, &response->readTransferCount);
        kswordArkThreadDetailNoteFailure(status, &failureCount, &lastStatus);
        status = kswordArkThreadDetailReadUlong64Field(threadObject, dynState.kernel.ktWriteTransferCount, &response->writeTransferCount);
        kswordArkThreadDetailNoteFailure(status, &failureCount, &lastStatus);
        status = kswordArkThreadDetailReadUlong64Field(threadObject, dynState.kernel.ktOtherTransferCount, &response->otherTransferCount);
        if (NT_SUCCESS(status)) {
            response->fieldFlags |= KSWORD_ARK_THREAD_DETAIL_FIELD_IO_COUNTERS;
        }
        else {
            response->missingCapabilityMask |= KSW_CAP_THREAD_IO_COUNTERS;
        }
        kswordArkThreadDetailNoteFailure(status, &failureCount, &lastStatus);
    }

    ObDereferenceObject(threadObject);

    if (missingRequired != 0UL) {
        response->status = KSWORD_ARK_DETAIL_STATUS_CAPABILITY_MISSING;
    }
    else if (failureCount != 0UL) {
        response->status = KSWORD_ARK_DETAIL_STATUS_PARTIAL;
    }
    else {
        response->status = KSWORD_ARK_DETAIL_STATUS_OK;
    }

    response->lastStatus = lastStatus;
    (VOID)RtlStringCchPrintfW(
        response->detail,
        KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS,
        L"Thread detail sampled by TID. fields=0x%08lX missingCaps=0x%I64X failures=%lu.",
        (unsigned long)response->fieldFlags,
        response->missingCapabilityMask,
        (unsigned long)failureCount);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkThreadIoctlQueryDetail(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL. Note: The handler performs only fixed buffer validation
    and stack-based request copying; actual read-only ETHREAD/KTHREAD sampling is completed in the backend.

Arguments:

    Device - WDF device object; currently only maintains handler signature compatibility.
    Request - Current IOCTL request.
    InputBufferLength - input length; must include KSWORD_ARK_THREAD_DETAIL_REQUEST.
    OutputBufferLength: Output length; must be sufficient to hold KSWORD_ARK_THREAD_DETAIL_RESPONSE.
    BytesReturned - Returns the number of response bytes.

Return Value:

    NTSTATUS from WDF buffer retrieval or thread detail backend.

--*/
{
    KSWORD_ARK_THREAD_DETAIL_REQUEST requestCopy;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_THREAD_DETAIL_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(&requestCopy, sizeof(requestCopy));
    RtlCopyMemory(&requestCopy, inputBuffer, sizeof(requestCopy));

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_THREAD_DETAIL_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return kswordArkDriverQueryThreadDetail(
        (KSWORD_ARK_THREAD_DETAIL_RESPONSE*)outputBuffer,
        actualOutputLength,
        &requestCopy,
        bytesReturned);
}


/*
 * KswThreadRuntimeFieldRequestSnapshot
 * Stack layout for a METHOD_BUFFERED snapshot request. Note: The shared protocol uses items[1] as a
 * variable-length placeholder; here, the remaining MAX_ITEMS-1 items are padded so the handler can
 * save the entire request in an aligned stack local without allocating pool memory for each query.
 */
typedef struct KswThreadRuntimeFieldRequestSnapshot
{
    KSWORD_ARK_THREAD_RUNTIME_FIELD_SAMPLE_REQUEST header;
    KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ITEM_REQUEST extraItems[
        KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_ITEMS - 1U];
} KswThreadRuntimeFieldRequestSnapshot;

static size_t
kswordArkThreadRuntimeFieldRequestHeaderSize(VOID)
/*++

Routine Description:

    Calculate the length of the variable-length request header for thread runtime field samples.
    Note: items[1] is a protocol placeholder; the actual input length must exclude this item.

Arguments:

    None.

Return Value:

    Request header byte count excluding the placeholder for the first item.

--*/
{
    return sizeof(KSWORD_ARK_THREAD_RUNTIME_FIELD_SAMPLE_REQUEST) -
        sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ITEM_REQUEST);
}

static size_t
kswordArkThreadRuntimeFieldSampleResponseHeaderSize(VOID)
/*++

Routine Description:

    Calculate the length of the variable-length response header for the runtime field sample.

Arguments:

    None.

Return Value:

    Response header byte count excluding the space occupied by the first row.

--*/
{
    return sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_RESPONSE) -
        sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW);
}

static BOOLEAN
kswordArkThreadRuntimeFieldSampleInputValid(
    _In_ size_t headerSize,
    _In_ ULONG itemCount,
    _In_ size_t inputBufferLength
    )
/*++

Routine Description:

    Verify that the variable-length request length for thread runtime field samples covers all declared items.

Arguments:

    HeaderSize: Request header length excluding items[1].
    ItemCount: Number of sample items declared in R3.
    InputBufferLength - Actual input length provided by WDF.

Return Value:

    TRUE indicates the input length is valid; FALSE indicates insufficient length or count overflow.

--*/
{
    const size_t kItemSize = sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ITEM_REQUEST);
    size_t requiredLength = headerSize;

    if (inputBufferLength < headerSize) {
        return FALSE;
    }
    if (itemCount > ((((size_t)-1) - headerSize) / kItemSize)) {
        return FALSE;
    }

    requiredLength = headerSize + ((size_t)itemCount * kItemSize);
    return (inputBufferLength >= requiredLength) ? TRUE : FALSE;
}

static ULONG
kswordArkThreadRuntimeFieldSampleReturnedCount(
    _In_ ULONG itemCount,
    _In_ size_t outputBufferLength
    )
/*++

Routine Description:

    Calculate the thread sample returnedCount based on the output buffer capacity and the protocol's maximum item count.

Arguments:

    ItemCount - Number of requested items.
    OutputBufferLength - Length of the output buffer.

Return Value:

    Maximum number of rows that can be written.

--*/
{
    const size_t kHeaderSize = kswordArkThreadRuntimeFieldSampleResponseHeaderSize();
    const ULONG kCappedItemCount = itemCount > KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_ITEMS ?
        KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_ITEMS : itemCount;
    size_t outputRowCapacity = 0U;

    if (outputBufferLength <= kHeaderSize) {
        return 0UL;
    }

    outputRowCapacity = (outputBufferLength - kHeaderSize) /
        sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW);
    if (outputRowCapacity > (size_t)kCappedItemCount) {
        return kCappedItemCount;
    }

    return (ULONG)outputRowCapacity;
}

static VOID
kswordArkThreadRuntimeFieldSampleOne(
    _In_ const VOID* object,
    _In_ const KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ITEM_REQUEST* item,
    _Out_ KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW* row
    )
/*++

Routine Description:

    Use the PDB offset to read a small field from an ETHREAD/KTHREAD object referenced by R0, without modifying it.

Arguments:

    Object - ETHREAD address, must originate from PsLookupThreadByThreadId.
    Item: runtimeItemId/offset/size metadata converted from deep-offset JSON.
    Row - Output row recording field status and little-endian byte samples.

Return Value:

    None. Field-level errors are returned via Row->status/lastStatus.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(row, sizeof(*row));
    row->runtimeItemId = item->runtimeItemId;
    row->offset = item->offset;
    row->size = item->size;
    row->flags = item->flags;
    row->status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_UNKNOWN;
    row->lastStatus = STATUS_SUCCESS;

    if (item->size == 0UL || item->size > KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_VALUE_BYTES) {
        row->status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_SIZE_REJECTED;
        row->lastStatus = STATUS_INVALID_PARAMETER;
        return;
    }
    if (item->offset == KSW_DYN_OFFSET_UNAVAILABLE || item->offset == 0x0000FFFFUL) {
        row->status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_OFFSET_REJECTED;
        row->lastStatus = STATUS_PROCEDURE_NOT_FOUND;
        return;
    }
    if (item->offset > (KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_OFFSET - item->size)) {
        row->status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_OFFSET_REJECTED;
        row->lastStatus = STATUS_INVALID_PARAMETER;
        return;
    }

    status = kswordArkCrossViewReadMemory(
        (const UCHAR*)object + item->offset,
        row->sampleBytes,
        item->size);
    row->lastStatus = status;
    if (!NT_SUCCESS(status)) {
        row->status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_READ_FAILED;
        return;
    }

    row->status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_OK;
    row->bytesRead = item->size;
    if (item->size <= sizeof(row->valueU64)) {
        RtlCopyMemory(&row->valueU64, row->sampleBytes, item->size);
    }
}

NTSTATUS
kswordArkDriverQueryThreadRuntimeFields(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) KSWORD_ARK_RUNTIME_FIELD_SAMPLE_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _In_reads_bytes_(inputBufferLength) const KSWORD_ARK_THREAD_RUNTIME_FIELD_SAMPLE_REQUEST* request,
    _In_ size_t inputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Perform generic deep PDB runtime field sampling on ETHREAD/KTHREAD by TID.

Arguments:

    Response - variable-length METHOD_BUFFERED response buffer.
    OutputBufferLength - Length of the output buffer.
    Request - Variable-length request containing TID/PID and field sampling items.
    InputBufferLength: Actual length of the input buffer.
    BytesWrittenOut - Actual bytes written.

Return Value:

    STATUS_SUCCESS indicates the response header is valid; field-level results are in entries[].status.

--*/
{
    KswDynState dynState;
    PETHREAD threadObject = NULL;
    ULONG returnedCount = 0UL;
    ULONG rowIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    const size_t kRequestHeaderSize = kswordArkThreadRuntimeFieldRequestHeaderSize();
    const size_t kResponseHeaderSize = kswordArkThreadRuntimeFieldSampleResponseHeaderSize();

    if (response == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (outputBufferLength < kResponseHeaderSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    *bytesWrittenOut = kResponseHeaderSize;
    RtlZeroMemory(response, outputBufferLength);
    response->version = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW);
    response->status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_UNKNOWN;

    if (request->version != KSWORD_ARK_RUNTIME_FIELD_SAMPLE_PROTOCOL_VERSION ||
        !kswordArkThreadRuntimeFieldSampleInputValid(kRequestHeaderSize, request->itemCount, inputBufferLength)) {
        response->status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_INVALID_REQUEST;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    response->totalCount = request->itemCount;
    response->flags = request->flags;
    returnedCount = kswordArkThreadRuntimeFieldSampleReturnedCount(request->itemCount, outputBufferLength);
    response->returnedCount = returnedCount;
    *bytesWrittenOut = kResponseHeaderSize + ((size_t)returnedCount * sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW));
    if (returnedCount < request->itemCount || request->itemCount > KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_ITEMS) {
        response->status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_TRUNCATED;
    }

    kswordArkDynDataSnapshot(&dynState);
    response->dynDataCapabilityMask = dynState.capabilityMask;

    if (request->threadId == 0UL) {
        response->status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_LOOKUP_FAILED;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    status = PsLookupThreadByThreadId(ULongToHandle(request->threadId), &threadObject);
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_LOOKUP_FAILED;
        response->lastStatus = status;
        return STATUS_SUCCESS;
    }

    response->objectAddress = (ULONG64)(ULONG_PTR)threadObject;
    for (rowIndex = 0UL; rowIndex < returnedCount; ++rowIndex) {
        kswordArkThreadRuntimeFieldSampleOne(threadObject, &request->items[rowIndex], &response->entries[rowIndex]);
        if (!NT_SUCCESS(response->entries[rowIndex].lastStatus) && response->lastStatus == STATUS_SUCCESS) {
            response->lastStatus = response->entries[rowIndex].lastStatus;
        }
    }

    if (response->status == KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_UNKNOWN) {
        response->status = (response->lastStatus == STATUS_SUCCESS) ?
            KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_OK :
            KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_PARTIAL;
    }

    ObDereferenceObject(threadObject);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkThreadIoctlQueryRuntimeFields(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handling IOCTL_KSWORD_ARK_QUERY_THREAD_RUNTIME_FIELDS. Note: The handler only
    retrieves the WDF buffer; the actual read-only sampling is performed by the backend.

Arguments:

    Device - WDF device object; currently only maintains handler signature compatibility.
    Request - Current IOCTL request.
    InputBufferLength - WDF input length hint.
    OutputBufferLength - WDF output length hint.
    BytesReturned - Actual response bytes returned.

Return Value:

    NTSTATUS from WDF buffer retrieval or thread runtime sampler backend.

--*/
{
    // requestSnapshot covers the protocol limit (header + MAX_ITEMS samples); any valid request fits within this limit.
    KswThreadRuntimeFieldRequestSnapshot requestSnapshot;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    size_t snapshotLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        kswordArkThreadRuntimeFieldRequestHeaderSize(),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /*
     * For METHOD_BUFFERED, input and output share the same SystemBuffer. The backend first clears
     * the output with RtlZeroMemory, then reads itemCount and items[]. Without a snapshot, response
     * bytes are treated as sample items, corrupting the item count and offsets. Data exceeding
     * MAX_ITEMS is not copied; the backend's length check will then flag this as INVALID_REQUEST.
     */
    snapshotLength = min(actualInputLength, sizeof(requestSnapshot));
    RtlZeroMemory(&requestSnapshot, sizeof(requestSnapshot));
    RtlCopyMemory(&requestSnapshot, inputBuffer, snapshotLength);

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        kswordArkThreadRuntimeFieldSampleResponseHeaderSize(),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return kswordArkDriverQueryThreadRuntimeFields(
        (KSWORD_ARK_RUNTIME_FIELD_SAMPLE_RESPONSE*)outputBuffer,
        actualOutputLength,
        &requestSnapshot.header,
        snapshotLength,
        bytesReturned);
}
