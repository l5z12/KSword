/*++

Module Name:

    thread_query.c

Abstract:

    Phase-3 KTHREAD stack and I/O counter enumeration.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_thread.h"

#include "ark/ark_dyndata.h"
#include "thread_worker_state.h"
#include "work_queue_fallback.h"
#include "../../platform/runtime_signature_scan.h"

#define KSWORD_ARK_THREAD_ENUM_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_THREAD_RESPONSE) - sizeof(KSWORD_ARK_THREAD_ENTRY))

#define KSW_THREAD_STACK_FIELD_MASK \
    (KSWORD_ARK_THREAD_FIELD_INITIAL_STACK_PRESENT | \
     KSWORD_ARK_THREAD_FIELD_STACK_LIMIT_PRESENT | \
     KSWORD_ARK_THREAD_FIELD_STACK_BASE_PRESENT | \
     KSWORD_ARK_THREAD_FIELD_KERNEL_STACK_PRESENT)
#define KSW_THREAD_IO_FIELD_MASK \
    (KSWORD_ARK_THREAD_FIELD_READ_OPERATION_COUNT_PRESENT | \
     KSWORD_ARK_THREAD_FIELD_WRITE_OPERATION_COUNT_PRESENT | \
     KSWORD_ARK_THREAD_FIELD_OTHER_OPERATION_COUNT_PRESENT | \
     KSWORD_ARK_THREAD_FIELD_READ_TRANSFER_COUNT_PRESENT | \
     KSWORD_ARK_THREAD_FIELD_WRITE_TRANSFER_COUNT_PRESENT | \
     KSWORD_ARK_THREAD_FIELD_OTHER_TRANSFER_COUNT_PRESENT)
#define KSWORD_ARK_THREAD_ID_STEP 4UL
#define KSWORD_ARK_THREAD_SCAN_MIN_ID KSWORD_ARK_THREAD_ID_STEP
#define KSWORD_ARK_THREAD_SCAN_MAX_ID 0x00100000UL

typedef PEPROCESS(NTAPI* KswordPsGetNextProcessFn)(
    _In_opt_ PEPROCESS process
    );

typedef PETHREAD(NTAPI* KswordPsGetNextProcessThreadFn)(
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

static BOOLEAN
kswordArkThreadIsOffsetPresent(
    _In_ ULONG offset
    )
/*++

Routine Description:

    normalize DynData offset availability before reading a KTHREAD field.

Arguments:

    Offset - Candidate offset from the DynData state.

Return Value:

    TRUE when the offset can be used, otherwise FALSE.

--*/
{
    return (offset != KSW_DYN_OFFSET_UNAVAILABLE && offset != 0x0000FFFFUL) ? TRUE : FALSE;
}

static ULONG
kswordArkThreadNormalizeOffset(
    _In_ ULONG offset
    )
/*++

Routine Description:

    Convert internal DynData sentinel values into the shared protocol sentinel.

Arguments:

    Offset - Raw offset from KswDynState.

Return Value:

    Usable offset or KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE.

--*/
{
    if (!kswordArkThreadIsOffsetPresent(offset)) {
        return KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    }

    return offset;
}

static KswordPsGetNextProcessFn
kswordArkThreadResolvePsGetNextProcess(
    VOID
    )
/*++

Routine Description:

    Resolve PsGetNextProcess dynamically so the driver can enumerate active
    processes without depending on a fixed import surface.

Arguments:

    None.

Return Value:

    Function pointer when exported; otherwise NULL.

--*/
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsGetNextProcess");
    return (KswordPsGetNextProcessFn)MmGetSystemRoutineAddress(&routineName);
}

static KswordPsGetNextProcessThreadFn
kswordArkThreadResolvePsGetNextProcessThread(
    VOID
    )
/*++

Routine Description:

    Resolve psGetNextProcessThread dynamically for per-process thread walking.

Arguments:

    None.

Return Value:

    Function pointer when exported; otherwise NULL.

--*/
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsGetNextProcessThread");
    return (KswordPsGetNextProcessThreadFn)MmGetSystemRoutineAddress(&routineName);
}

static ULONG
kswordArkThreadAlignIdToStep(
    _In_ ULONG threadId
    )
/*++

Routine Description:

    Align a thread ID to the system CID stride used by the bounded scan view.

Arguments:

    ThreadId - Raw thread ID boundary.

Return Value:

    Thread ID rounded down to the nearest scan stride.

--*/
{
    return threadId - (threadId % KSWORD_ARK_THREAD_ID_STEP);
}

static VOID
kswordArkThreadBitmapSet(
    _Inout_updates_bytes_(bitmapBytes) UCHAR* bitmap,
    _In_ size_t bitmapBytes,
    _In_ ULONG threadId
    )
/*++

Routine Description:

    Mark one active-list TID in the compact scan bitmap.

Arguments:

    Bitmap - Mutable bitmap storage.
    BitmapBytes - Size of Bitmap in bytes.
    ThreadId - Thread ID to mark.

Return Value:

    None.

--*/
{
    const size_t kBitIndex = (size_t)(threadId / KSWORD_ARK_THREAD_ID_STEP);
    const size_t kByteIndex = kBitIndex >> 3;
    const UCHAR kBitMask = (UCHAR)(1U << (kBitIndex & 7U));

    if (bitmap == NULL || kByteIndex >= bitmapBytes) {
        return;
    }

    bitmap[kByteIndex] |= kBitMask;
}

static BOOLEAN
kswordArkThreadBitmapHas(
    _In_reads_bytes_(bitmapBytes) const UCHAR* bitmap,
    _In_ size_t bitmapBytes,
    _In_ ULONG threadId
    )
/*++

Routine Description:

    Test whether one TID was observed by the active process/thread walk.

Arguments:

    Bitmap - Immutable bitmap storage.
    BitmapBytes - Size of Bitmap in bytes.
    ThreadId - Thread ID to test.

Return Value:

    TRUE when the TID was marked by the active-list view.

--*/
{
    const size_t kBitIndex = (size_t)(threadId / KSWORD_ARK_THREAD_ID_STEP);
    const size_t kByteIndex = kBitIndex >> 3;
    const UCHAR kBitMask = (UCHAR)(1U << (kBitIndex & 7U));

    if (bitmap == NULL || kByteIndex >= bitmapBytes) {
        return FALSE;
    }

    return ((bitmap[kByteIndex] & kBitMask) != 0U) ? TRUE : FALSE;
}

static BOOLEAN
kswordArkThreadBitmapCanRepresent(
    _In_ size_t bitmapBytes,
    _In_ ULONG idValue
    )
/*++

Routine Description:

    Check whether a PID/TID can be safely represented by the bounded CID bitmap.

Arguments:

    BitmapBytes - Size of the active-view bitmap.
    IdValue - PID or TID to test.

Return Value:

    TRUE when IdValue maps into BitmapBytes; otherwise FALSE.

--*/
{
    const size_t kBitIndex = (size_t)(idValue / KSWORD_ARK_THREAD_ID_STEP);
    const size_t kByteIndex = kBitIndex >> 3;

    if ((idValue % KSWORD_ARK_THREAD_ID_STEP) != 0UL) {
        return FALSE;
    }

    return (kByteIndex < bitmapBytes) ? TRUE : FALSE;
}

static NTSTATUS
kswordArkThreadReadPointerField(
    _In_ PETHREAD threadObject,
    _In_ ULONG offset,
    _Out_ ULONG64* valueOut
    )
/*++

Routine Description:

    Safely read one pointer-sized field from KTHREAD/ETHREAD.

Arguments:

    ThreadObject - Target thread object.
    Offset - Field offset.
    ValueOut - Receives the pointer as ULONG64.

Return Value:

    STATUS_SUCCESS or the structured-exception code.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID pointerValue = NULL;

    if (threadObject == NULL || valueOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkThreadIsOffsetPresent(offset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    // Adding the offset to ETHREAD may exceed the object's end; touching unmapped addresses in kernel mode
    // triggers a bugcheck 0x50 rather than a catchable exception, so a safe read must be used instead of __try.
    if (!kswordArkRuntimeReadMemory(
            (const UCHAR*)threadObject + offset,
            &pointerValue,
            sizeof(pointerValue))) {
        return STATUS_PARTIAL_COPY;
    }
    *valueOut = (ULONG64)(ULONG_PTR)pointerValue;
    return status;
}

static NTSTATUS
kswordArkThreadReadUlong64Field(
    _In_ PETHREAD threadObject,
    _In_ ULONG offset,
    _Out_ ULONG64* valueOut
    )
/*++

Routine Description:

    Safely read one ULONG64 field from KTHREAD/ETHREAD.

Arguments:

    ThreadObject - Target thread object.
    Offset - Field offset.
    ValueOut - Receives the integer value.

Return Value:

    STATUS_SUCCESS or the structured-exception code.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    if (threadObject == NULL || valueOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkThreadIsOffsetPresent(offset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    // Same as above: DynData offset is not guaranteed to fall within the object; safe reading converts out-of-bounds access to failure instead of a BSOD.
    if (!kswordArkRuntimeReadMemory(
            (const UCHAR*)threadObject + offset,
            valueOut,
            sizeof(*valueOut))) {
        return STATUS_PARTIAL_COPY;
    }
    return status;
}

static VOID
kswordArkThreadPopulateStackFields(
    _Inout_ KSWORD_ARK_THREAD_ENTRY* entry,
    _In_ PETHREAD threadObject,
    _In_ const KswDynState* dynState
    )
/*++

Routine Description:

    Populate KTHREAD stack boundary fields when the capability is present.

Arguments:

    Entry - Mutable thread response row.
    ThreadObject - Target thread object.
    DynState - DynData snapshot.

Return Value:

    None.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    if (entry == NULL || threadObject == NULL || dynState == NULL) {
        return;
    }

    if (!kswordArkThreadIsOffsetPresent(dynState->kernel.ktInitialStack) &&
        !kswordArkThreadIsOffsetPresent(dynState->kernel.ktStackLimit) &&
        !kswordArkThreadIsOffsetPresent(dynState->kernel.ktStackBase) &&
        !kswordArkThreadIsOffsetPresent(dynState->kernel.ktKernelStack)) {
        return;
    }

    if (kswordArkThreadIsOffsetPresent(dynState->kernel.ktInitialStack)) {
        entry->stackFieldSource = dynState->kernelSources.ktInitialStack;
        status = kswordArkThreadReadPointerField(threadObject, dynState->kernel.ktInitialStack, &entry->initialStack);
        if (NT_SUCCESS(status)) {
            entry->fieldFlags |= KSWORD_ARK_THREAD_FIELD_INITIAL_STACK_PRESENT;
        }
        kswordArkThreadMarkFailure(entry, status);
    }
    if (kswordArkThreadIsOffsetPresent(dynState->kernel.ktStackLimit)) {
        if (entry->stackFieldSource == KSW_DYN_FIELD_SOURCE_UNAVAILABLE) {
            entry->stackFieldSource = dynState->kernelSources.ktStackLimit;
        }
        status = kswordArkThreadReadPointerField(threadObject, dynState->kernel.ktStackLimit, &entry->stackLimit);
        if (NT_SUCCESS(status)) {
            entry->fieldFlags |= KSWORD_ARK_THREAD_FIELD_STACK_LIMIT_PRESENT;
        }
        kswordArkThreadMarkFailure(entry, status);
    }
    if (kswordArkThreadIsOffsetPresent(dynState->kernel.ktStackBase)) {
        if (entry->stackFieldSource == KSW_DYN_FIELD_SOURCE_UNAVAILABLE) {
            entry->stackFieldSource = dynState->kernelSources.ktStackBase;
        }
        status = kswordArkThreadReadPointerField(threadObject, dynState->kernel.ktStackBase, &entry->stackBase);
        if (NT_SUCCESS(status)) {
            entry->fieldFlags |= KSWORD_ARK_THREAD_FIELD_STACK_BASE_PRESENT;
        }
        kswordArkThreadMarkFailure(entry, status);
    }
    if (kswordArkThreadIsOffsetPresent(dynState->kernel.ktKernelStack)) {
        if (entry->stackFieldSource == KSW_DYN_FIELD_SOURCE_UNAVAILABLE) {
            entry->stackFieldSource = dynState->kernelSources.ktKernelStack;
        }
        status = kswordArkThreadReadPointerField(threadObject, dynState->kernel.ktKernelStack, &entry->kernelStack);
        if (NT_SUCCESS(status)) {
            entry->fieldFlags |= KSWORD_ARK_THREAD_FIELD_KERNEL_STACK_PRESENT;
        }
        kswordArkThreadMarkFailure(entry, status);
    }
}

static VOID
kswordArkThreadPopulateIoFields(
    _Inout_ KSWORD_ARK_THREAD_ENTRY* entry,
    _In_ PETHREAD threadObject,
    _In_ const KswDynState* dynState
    )
/*++

Routine Description:

    Populate KTHREAD I/O counter fields when the capability is present.

Arguments:

    Entry - Mutable thread response row.
    ThreadObject - Target thread object.
    DynState - DynData snapshot.

Return Value:

    None.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    if (entry == NULL || threadObject == NULL || dynState == NULL) {
        return;
    }

    if (!kswordArkThreadIsOffsetPresent(dynState->kernel.ktReadOperationCount) &&
        !kswordArkThreadIsOffsetPresent(dynState->kernel.ktWriteOperationCount) &&
        !kswordArkThreadIsOffsetPresent(dynState->kernel.ktOtherOperationCount) &&
        !kswordArkThreadIsOffsetPresent(dynState->kernel.ktReadTransferCount) &&
        !kswordArkThreadIsOffsetPresent(dynState->kernel.ktWriteTransferCount) &&
        !kswordArkThreadIsOffsetPresent(dynState->kernel.ktOtherTransferCount)) {
        return;
    }

    entry->ioFieldSource = dynState->kernelSources.ktReadOperationCount;
    status = kswordArkThreadReadUlong64Field(threadObject, dynState->kernel.ktReadOperationCount, &entry->readOperationCount);
    if (NT_SUCCESS(status)) {
        entry->fieldFlags |= KSWORD_ARK_THREAD_FIELD_READ_OPERATION_COUNT_PRESENT;
    }
    kswordArkThreadMarkFailure(entry, status);

    status = kswordArkThreadReadUlong64Field(threadObject, dynState->kernel.ktWriteOperationCount, &entry->writeOperationCount);
    if (NT_SUCCESS(status)) {
        entry->fieldFlags |= KSWORD_ARK_THREAD_FIELD_WRITE_OPERATION_COUNT_PRESENT;
    }
    kswordArkThreadMarkFailure(entry, status);

    status = kswordArkThreadReadUlong64Field(threadObject, dynState->kernel.ktOtherOperationCount, &entry->otherOperationCount);
    if (NT_SUCCESS(status)) {
        entry->fieldFlags |= KSWORD_ARK_THREAD_FIELD_OTHER_OPERATION_COUNT_PRESENT;
    }
    kswordArkThreadMarkFailure(entry, status);

    status = kswordArkThreadReadUlong64Field(threadObject, dynState->kernel.ktReadTransferCount, &entry->readTransferCount);
    if (NT_SUCCESS(status)) {
        entry->fieldFlags |= KSWORD_ARK_THREAD_FIELD_READ_TRANSFER_COUNT_PRESENT;
    }
    kswordArkThreadMarkFailure(entry, status);

    status = kswordArkThreadReadUlong64Field(threadObject, dynState->kernel.ktWriteTransferCount, &entry->writeTransferCount);
    if (NT_SUCCESS(status)) {
        entry->fieldFlags |= KSWORD_ARK_THREAD_FIELD_WRITE_TRANSFER_COUNT_PRESENT;
    }
    kswordArkThreadMarkFailure(entry, status);

    status = kswordArkThreadReadUlong64Field(threadObject, dynState->kernel.ktOtherTransferCount, &entry->otherTransferCount);
    if (NT_SUCCESS(status)) {
        entry->fieldFlags |= KSWORD_ARK_THREAD_FIELD_OTHER_TRANSFER_COUNT_PRESENT;
    }
    kswordArkThreadMarkFailure(entry, status);
}

static VOID
kswordArkThreadPrepareEntryOffsets(
    _Inout_ KSWORD_ARK_THREAD_ENTRY* entry,
    _In_ const KswDynState* dynState
    )
/*++

Routine Description:

    Copy active KTHREAD offsets into the response row for UI diagnostics.

Arguments:

    Entry - Mutable thread response row.
    DynState - DynData snapshot.

Return Value:

    None.

--*/
{
    if (entry == NULL || dynState == NULL) {
        return;
    }

    entry->ktInitialStackOffset = kswordArkThreadNormalizeOffset(dynState->kernel.ktInitialStack);
    entry->ktStackLimitOffset = kswordArkThreadNormalizeOffset(dynState->kernel.ktStackLimit);
    entry->ktStackBaseOffset = kswordArkThreadNormalizeOffset(dynState->kernel.ktStackBase);
    entry->ktKernelStackOffset = kswordArkThreadNormalizeOffset(dynState->kernel.ktKernelStack);
    entry->ktReadOperationCountOffset = kswordArkThreadNormalizeOffset(dynState->kernel.ktReadOperationCount);
    entry->ktWriteOperationCountOffset = kswordArkThreadNormalizeOffset(dynState->kernel.ktWriteOperationCount);
    entry->ktOtherOperationCountOffset = kswordArkThreadNormalizeOffset(dynState->kernel.ktOtherOperationCount);
    entry->ktReadTransferCountOffset = kswordArkThreadNormalizeOffset(dynState->kernel.ktReadTransferCount);
    entry->ktWriteTransferCountOffset = kswordArkThreadNormalizeOffset(dynState->kernel.ktWriteTransferCount);
    entry->ktOtherTransferCountOffset = kswordArkThreadNormalizeOffset(dynState->kernel.ktOtherTransferCount);
    entry->dynDataCapabilityMask = dynState->capabilityMask;
}

static VOID
kswordArkThreadAppendEntry(
    _Inout_ KSWORD_ARK_ENUM_THREAD_RESPONSE* response,
    _In_ size_t entryCapacity,
    _In_ PETHREAD threadObject,
    _In_ ULONG processId,
    _In_ ULONG threadFlags,
    _In_ ULONG requestFlags,
    _In_ const KswDynState* dynState,
    _In_opt_ const KswDynV4BitFieldLayout* activeExWorkerField
    )
/*++

Routine Description:

    Append one thread row and populate optional KTHREAD fields.

Arguments:

    Response - Mutable response header and entry array.
    EntryCapacity - Number of entries that fit in the output buffer.
    ThreadObject - Referenced thread object owned by the caller.
    ProcessId - Owner process ID.
    ThreadFlags - KSWORD_ARK_THREAD_FLAG_* cross-view flags.
    RequestFlags - Request flags controlling optional field groups.
    DynState - DynData snapshot.
    ActiveExWorkerField - Optional v4 _ETHREAD.ActiveExWorker layout.

Return Value:

    None.

--*/
{
    KSWORD_ARK_THREAD_ENTRY* entry = NULL;
    BOOLEAN optionalFieldsPartial = FALSE;

    if (response == NULL || threadObject == NULL || dynState == NULL) {
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
    entry->threadId = HandleToULong(PsGetThreadId(threadObject));
    entry->processId = processId;
    entry->flags = threadFlags;
    entry->r0Status = KSWORD_ARK_THREAD_R0_STATUS_DYNDATA_MISSING;
    entry->stackFieldSource = KSW_DYN_FIELD_SOURCE_UNAVAILABLE;
    entry->ioFieldSource = KSW_DYN_FIELD_SOURCE_UNAVAILABLE;
    kswordArkThreadPrepareEntryOffsets(entry, dynState);

    if ((requestFlags & KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_STACK) != 0UL) {
        kswordArkThreadPopulateStackFields(entry, threadObject, dynState);
    }
    if ((requestFlags & KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_IO) != 0UL) {
        kswordArkThreadPopulateIoFields(entry, threadObject, dynState);
    }
    if ((requestFlags & KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_WORKER_STATE) != 0UL &&
        activeExWorkerField != NULL) {
        kswordArkThreadPopulateWorkerField(entry, threadObject, activeExWorkerField);
    }

    if ((requestFlags & KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_STACK) != 0UL &&
        (entry->fieldFlags & KSW_THREAD_STACK_FIELD_MASK) !=
            KSW_THREAD_STACK_FIELD_MASK) {
        optionalFieldsPartial = TRUE;
    }
    if ((requestFlags & KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_IO) != 0UL &&
        (entry->fieldFlags & KSW_THREAD_IO_FIELD_MASK) !=
            KSW_THREAD_IO_FIELD_MASK) {
        optionalFieldsPartial = TRUE;
    }

    if (entry->r0Status != KSWORD_ARK_THREAD_R0_STATUS_READ_FAILED) {
        if (entry->fieldFlags != 0UL) {
            entry->r0Status = optionalFieldsPartial ?
                KSWORD_ARK_THREAD_R0_STATUS_PARTIAL :
                KSWORD_ARK_THREAD_R0_STATUS_OK;
        }
        else if ((dynState->capabilityMask &
                (KSW_CAP_THREAD_STACK_FIELDS | KSW_CAP_THREAD_IO_COUNTERS)) != 0ULL) {
            entry->r0Status = KSWORD_ARK_THREAD_R0_STATUS_PARTIAL;
        }
    }

    response->returnedCount += 1UL;
}

static VOID
kswordArkThreadWalkProcessThreads(
    _Inout_ KSWORD_ARK_ENUM_THREAD_RESPONSE* response,
    _In_ size_t entryCapacity,
    _In_ PEPROCESS processObject,
    _In_ ULONG requestProcessId,
    _In_ ULONG requestFlags,
    _In_ const KswDynState* dynState,
    _In_opt_ const KswDynV4BitFieldLayout* activeExWorkerField,
    _In_ KswordPsGetNextProcessThreadFn PsGetNextProcessThread,
    _In_opt_ UCHAR* activeProcessBitmap,
    _In_ size_t activeProcessBitmapBytes,
    _In_opt_ UCHAR* activeThreadBitmap,
    _In_ size_t activeThreadBitmapBytes
    )
/*++

Routine Description:

    Walk every thread in one process via psGetNextProcessThread.

Arguments:

    Response - Mutable response packet.
    EntryCapacity - Output entry capacity.
    ProcessObject - Target process object.
    RequestProcessId - Optional PID filter.
    RequestFlags - Optional field group flags.
    DynState - DynData snapshot.
    ActiveExWorkerField - Optional v4 _ETHREAD.ActiveExWorker layout.
    psGetNextProcessThread - Resolved thread iterator.
    ActiveProcessBitmap - Optional active-list PID bitmap for cross-view scans.
    ActiveProcessBitmapBytes - PID bitmap size in bytes.
    ActiveThreadBitmap - Optional active-list TID bitmap for cross-view scans.
    ActiveThreadBitmapBytes - Bitmap size in bytes.

Return Value:

    None.

--*/
{
    PETHREAD threadCursor = NULL;
    ULONG processId = 0UL;

    if (response == NULL || processObject == NULL || dynState == NULL || PsGetNextProcessThread == NULL) {
        return;
    }

    processId = HandleToULong(PsGetProcessId(processObject));
    if (activeProcessBitmap != NULL) {
        kswordArkThreadBitmapSet(activeProcessBitmap, activeProcessBitmapBytes, processId);
    }

    if (requestProcessId != 0UL && processId != requestProcessId) {
        return;
    }

    threadCursor = PsGetNextProcessThread(processObject, NULL);
    while (threadCursor != NULL) {
        PETHREAD nextThread = PsGetNextProcessThread(processObject, threadCursor);
        if (activeThreadBitmap != NULL) {
            kswordArkThreadBitmapSet(
                activeThreadBitmap,
                activeThreadBitmapBytes,
                HandleToULong(PsGetThreadId(threadCursor)));
        }
        kswordArkThreadAppendEntry(
            response,
            entryCapacity,
            threadCursor,
            processId,
            KSWORD_ARK_THREAD_FLAG_KERNEL_ENUMERATED,
            requestFlags,
            dynState,
            activeExWorkerField);
        ObDereferenceObject(threadCursor);
        threadCursor = nextThread;
    }
}

static VOID
kswordArkThreadScanCidTable(
    _Inout_ KSWORD_ARK_ENUM_THREAD_RESPONSE* response,
    _In_ size_t entryCapacity,
    _In_ ULONG requestProcessId,
    _In_ ULONG requestFlags,
    _In_ const KswDynState* dynState,
    _In_opt_ const KswDynV4BitFieldLayout* activeExWorkerField,
    _In_reads_bytes_(activeProcessBitmapBytes) const UCHAR* activeProcessBitmap,
    _In_ size_t activeProcessBitmapBytes,
    _In_reads_bytes_(activeThreadBitmapBytes) const UCHAR* activeThreadBitmap,
    _In_ size_t activeThreadBitmapBytes
    )
/*++

Routine Description:

    Scan a bounded CID range and append only threads absent from the active
    process/thread walk. This is the optional cross-view path that can surface
    R0-only / CID-only threads.

Arguments:

    Response - Mutable response packet.
    EntryCapacity - Output entry capacity.
    RequestProcessId - Optional PID filter.
    RequestFlags - Optional field group flags.
    DynState - DynData snapshot.
    ActiveExWorkerField - Optional v4 _ETHREAD.ActiveExWorker layout.
    ActiveProcessBitmap - Bitmap of active PIDs.
    ActiveProcessBitmapBytes - Bitmap size in bytes.
    ActiveThreadBitmap - Bitmap of active TIDs.
    ActiveThreadBitmapBytes - Bitmap size in bytes.

Return Value:

    None.

--*/
{
    ULONG scanThreadId = KSWORD_ARK_THREAD_SCAN_MIN_ID;
    ULONG scanEndThreadId = KSWORD_ARK_THREAD_SCAN_MAX_ID;

    if (response == NULL || dynState == NULL) {
        return;
    }

    scanThreadId = kswordArkThreadAlignIdToStep(scanThreadId);
    if (scanThreadId < KSWORD_ARK_THREAD_SCAN_MIN_ID) {
        scanThreadId = KSWORD_ARK_THREAD_SCAN_MIN_ID;
    }
    scanEndThreadId = kswordArkThreadAlignIdToStep(scanEndThreadId);
    if (scanEndThreadId < scanThreadId) {
        scanEndThreadId = scanThreadId;
    }

    for (;;) {
        PETHREAD threadObject = NULL;
        NTSTATUS lookupStatus = PsLookupThreadByThreadId(ULongToHandle(scanThreadId), &threadObject);
        if (NT_SUCCESS(lookupStatus)) {
            const ULONG kOwnerProcessId = HandleToULong(PsGetThreadProcessId(threadObject));
            ULONG threadFlags = KSWORD_ARK_THREAD_FLAG_KERNEL_ENUMERATED;
            /*
             * When the public psGetNextProcessThread walk is unavailable, this
             * routine is also used as a fallback without active-list bitmaps.
             * In that mode a found CID entry is evidence, not an active-list
             * anomaly, so the hidden-thread flag must only be set when an
             * active thread bitmap actually exists.
             */
            const BOOLEAN kHasActiveThreadView =
                (activeThreadBitmap != NULL && activeThreadBitmapBytes != 0U) ? TRUE : FALSE;
            const BOOLEAN kActiveThreadSeen = kHasActiveThreadView
                ? kswordArkThreadBitmapHas(activeThreadBitmap, activeThreadBitmapBytes, scanThreadId)
                : FALSE;
            const BOOLEAN kOwnerProcessRepresented =
                kswordArkThreadBitmapCanRepresent(activeProcessBitmapBytes, kOwnerProcessId);
            const BOOLEAN kActiveProcessSeen =
                kOwnerProcessRepresented
                ? kswordArkThreadBitmapHas(activeProcessBitmap, activeProcessBitmapBytes, kOwnerProcessId)
                : TRUE;

            if (!kActiveThreadSeen && kHasActiveThreadView) {
                threadFlags |= KSWORD_ARK_THREAD_FLAG_HIDDEN_FROM_ACTIVE_THREAD_LIST;
            }
            if (kOwnerProcessRepresented && !kActiveProcessSeen) {
                threadFlags |= KSWORD_ARK_THREAD_FLAG_OWNER_PROCESS_HIDDEN;
            }

            if (!kActiveThreadSeen && (requestProcessId == 0UL || kOwnerProcessId == requestProcessId)) {
                kswordArkThreadAppendEntry(
                    response,
                    entryCapacity,
                    threadObject,
                    kOwnerProcessId,
                    threadFlags,
                    requestFlags,
                    dynState,
                    activeExWorkerField);
            }
            ObDereferenceObject(threadObject);
        }

        if ((scanEndThreadId - scanThreadId) < KSWORD_ARK_THREAD_ID_STEP) {
            break;
        }
        scanThreadId += KSWORD_ARK_THREAD_ID_STEP;
    }
}

NTSTATUS
kswordArkDriverEnumerateThreads(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_ENUM_THREAD_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    enumerate active threads and enrich them with DynData-gated KTHREAD fields.

Arguments:

    OutputBuffer - METHOD_BUFFERED output packet.
    OutputBufferLength - Writable output byte count.
    Request - Optional enumeration request.
    BytesWrittenOut - Receives bytes written.

Return Value:

    STATUS_SUCCESS when enumeration completed; otherwise a validation status.

--*/
{
    KSWORD_ARK_ENUM_THREAD_RESPONSE* response = NULL;
    KswordPsGetNextProcessFn psGetNextProcess = NULL;
    KswordPsGetNextProcessThreadFn psGetNextProcessThread = NULL;
    KswDynState dynState;
    KswDynV4BitFieldLayout activeExWorkerField;
    size_t entryCapacity = 0U;
    size_t totalBytesWritten = 0U;
    ULONG requestFlags = KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_ALL;
    ULONG requestProcessId = 0UL;
    PEPROCESS processCursor = NULL;
    BOOLEAN scanCidTable = FALSE;
    UCHAR* activeProcessBitmap = NULL;
    UCHAR* activeThreadBitmap = NULL;
    size_t activeBitmapBytes = 0U;
    BOOLEAN activeExWorkerFieldAvailable = FALSE;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSWORD_ARK_THREAD_ENUM_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (request != NULL) {
        requestFlags = request->flags;
        requestProcessId = request->processId;
    }
    if ((requestFlags & KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_ALL) == 0UL) {
        requestFlags |= KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_ALL;
    }
    scanCidTable = ((requestFlags & KSWORD_ARK_ENUM_THREAD_FLAG_SCAN_CID_TABLE) != 0UL) ? TRUE : FALSE;

    RtlZeroMemory(&dynState, sizeof(dynState));
    kswordArkDynDataSnapshot(&dynState);
    RtlZeroMemory(&activeExWorkerField, sizeof(activeExWorkerField));
    activeExWorkerFieldAvailable = NT_SUCCESS(
        kswordArkDynDataV4SnapshotActiveExWorkerField(&activeExWorkerField))
        ? TRUE
        : FALSE;
    if (!activeExWorkerFieldAvailable &&
        (requestFlags & KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_WORKER_STATE) != 0UL) {
        activeExWorkerFieldAvailable = NT_SUCCESS(
            kswordArkWorkQueueResolveActiveExWorkerField(
                &activeExWorkerField))
            ? TRUE
            : FALSE;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_ENUM_THREAD_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_THREAD_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_THREAD_ENTRY);
    entryCapacity =
        (outputBufferLength - KSWORD_ARK_THREAD_ENUM_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_THREAD_ENTRY);

    psGetNextProcess = kswordArkThreadResolvePsGetNextProcess();
    psGetNextProcessThread = kswordArkThreadResolvePsGetNextProcessThread();
    if (psGetNextProcess == NULL || psGetNextProcessThread == NULL) {
        /*
         * Some supported systems do not expose psGetNextProcessThread through
         * MmGetSystemRoutineAddress.  The process detail page already has an R3
         * Toolhelp thread list, so the R0 extension should return a valid
         * response instead of failing the IOCTL and making the UI report a
         * protocol mismatch.  Only callers that explicitly ask for the bounded
         * CID/TID scan pay that heavier fallback cost; the process detail page
         * already performs per-TID detail IOCTLs from its R3 Toolhelp list.
         */
        if (scanCidTable) {
            kswordArkThreadScanCidTable(
                response,
                entryCapacity,
                requestProcessId,
                requestFlags,
                &dynState,
                activeExWorkerFieldAvailable ? &activeExWorkerField : NULL,
                NULL,
                0U,
                NULL,
                0U);
        }
        *bytesWrittenOut =
            KSWORD_ARK_THREAD_ENUM_RESPONSE_HEADER_SIZE +
            ((size_t)response->returnedCount * sizeof(KSWORD_ARK_THREAD_ENTRY));
        return STATUS_SUCCESS;
    }

    if (scanCidTable) {
        const size_t kBitmapBitCount = (size_t)(KSWORD_ARK_THREAD_SCAN_MAX_ID / KSWORD_ARK_THREAD_ID_STEP) + 1U;
        activeBitmapBytes = (kBitmapBitCount + 7U) >> 3;
#pragma warning(push)
#pragma warning(disable:4996)
        activeProcessBitmap = (UCHAR*)ExAllocatePoolWithTag(NonPagedPoolNx, activeBitmapBytes, 'tKsK');
        activeThreadBitmap = (UCHAR*)ExAllocatePoolWithTag(NonPagedPoolNx, activeBitmapBytes, 'tKsK');
#pragma warning(pop)
        if (activeProcessBitmap == NULL || activeThreadBitmap == NULL) {
            if (activeProcessBitmap != NULL) {
                ExFreePoolWithTag(activeProcessBitmap, 'tKsK');
                activeProcessBitmap = NULL;
            }
            if (activeThreadBitmap != NULL) {
                ExFreePoolWithTag(activeThreadBitmap, 'tKsK');
                activeThreadBitmap = NULL;
            }
            activeBitmapBytes = 0U;
            scanCidTable = FALSE;
        }
        else {
            RtlZeroMemory(activeProcessBitmap, activeBitmapBytes);
            RtlZeroMemory(activeThreadBitmap, activeBitmapBytes);
        }
    }

    processCursor = psGetNextProcess(NULL);
    while (processCursor != NULL) {
        PEPROCESS nextProcess = psGetNextProcess(processCursor);
        kswordArkThreadWalkProcessThreads(
            response,
            entryCapacity,
            processCursor,
            requestProcessId,
            requestFlags,
            &dynState,
            activeExWorkerFieldAvailable ? &activeExWorkerField : NULL,
            psGetNextProcessThread,
            activeProcessBitmap,
            activeBitmapBytes,
            activeThreadBitmap,
            activeBitmapBytes);
        ObDereferenceObject(processCursor);
        processCursor = nextProcess;
    }

    if (scanCidTable) {
        kswordArkThreadScanCidTable(
            response,
            entryCapacity,
            requestProcessId,
            requestFlags,
            &dynState,
            activeExWorkerFieldAvailable ? &activeExWorkerField : NULL,
            activeProcessBitmap,
            activeBitmapBytes,
            activeThreadBitmap,
            activeBitmapBytes);
    }

    if (activeProcessBitmap != NULL) {
        ExFreePoolWithTag(activeProcessBitmap, 'tKsK');
        activeProcessBitmap = NULL;
    }
    if (activeThreadBitmap != NULL) {
        ExFreePoolWithTag(activeThreadBitmap, 'tKsK');
        activeThreadBitmap = NULL;
    }

    totalBytesWritten =
        KSWORD_ARK_THREAD_ENUM_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_THREAD_ENTRY));
    *bytesWrittenOut = totalBytesWritten;
    return STATUS_SUCCESS;
}
