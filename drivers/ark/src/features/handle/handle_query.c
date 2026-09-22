/*++

Module Name:

    handle_query.c

Abstract:

    Phase-4 direct EPROCESS.ObjectTable handle enumeration.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_handle.h"

#include "ark/ark_dyndata.h"
#include "handle_support.h"
#include "../kernel/object_header_fallback.h"
#include "../../platform/pool_compat.h"

#define KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE) - sizeof(KSWORD_ARK_HANDLE_ENTRY))

#define KSWORD_ARK_OBJECT_GRANTED_ACCESS_MASK 0x01ffffffUL
#define KSWORD_ARK_HANDLE_SNAPSHOT_POOL_TAG    'sHsK'
#define KSWORD_ARK_HANDLE_SNAPSHOT_INFO_CLASS  64UL
#define KSWORD_ARK_HANDLE_SNAPSHOT_MAX_BYTES   (64UL * 1024UL * 1024UL)

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

typedef struct KswSystemHandleTableEntryInfoEx
{
    PVOID object;
    ULONG_PTR uniqueProcessId;
    ULONG_PTR handleValue;
    ULONG grantedAccess;
    USHORT creatorBackTraceIndex;
    USHORT objectTypeIndex;
    ULONG handleAttributes;
    ULONG reserved;
} KswSystemHandleTableEntryInfoEx, *PkswSystemHandleTableEntryInfoEx;

typedef struct KswSystemHandleInformationEx
{
    ULONG_PTR numberOfHandles;
    ULONG_PTR reserved;
    KswSystemHandleTableEntryInfoEx handles[1];
} KswSystemHandleInformationEx, *PkswSystemHandleInformationEx;

typedef struct _HANDLE_TABLE HandleTable, *PhandleTable;

typedef struct HandleTableEntry
{
    union KswHandleTableEntryLow
    {
        PVOID object;
        ULONG obAttributes;
        ULONG_PTR value;
    } low;
    union KswHandleTableEntryHigh
    {
        ACCESS_MASK grantedAccess;
        LONG nextFreeTableEntry;
    } high;
} HandleTableEntry, *PhandleTableEntry;

typedef
_Function_class_(EX_ENUM_HANDLE_CALLBACK)
_Must_inspect_result_
BOOLEAN
NTAPI
KswordExEnumHandleCallback(
    _In_ PhandleTable handleTable,
    _Inout_ PhandleTableEntry handleTableEntry,
    _In_ HANDLE handle,
    _In_opt_ PVOID context
    );

typedef KswordExEnumHandleCallback* PkswordExEnumHandleCallback;

NTKERNELAPI
BOOLEAN
NTAPI
ExEnumHandleTable(
    _In_ PhandleTable handleTable,
    _In_ PkswordExEnumHandleCallback enumHandleProcedure,
    _Inout_ PVOID context,
    _Out_opt_ PHANDLE handle
    );

typedef struct _EX_PUSH_LOCK_WAIT_BLOCK* PexPushLockWaitBlock;

NTKERNELAPI
VOID
FASTCALL
ExfUnblockPushLock(
    _Inout_ PEX_PUSH_LOCK pushLock,
    _Inout_opt_ PexPushLockWaitBlock waitBlock
    );

NTKERNELAPI
NTSTATUS
NTAPI
PsAcquireProcessExitSynchronization(
    _In_ PEPROCESS process
    );

NTKERNELAPI
VOID
NTAPI
PsReleaseProcessExitSynchronization(
    _In_ PEPROCESS process
    );

NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE processId,
    _Outptr_ PEPROCESS* process
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG systemInformationClass,
    _Out_writes_bytes_opt_(systemInformationLength) PVOID systemInformation,
    _In_ ULONG systemInformationLength,
    _Out_opt_ PULONG returnLength
    );

NTKERNELAPI
VOID
KeStackAttachProcess(
    _Inout_ PVOID process,
    _Out_ PVOID apcState
    );

NTKERNELAPI
VOID
KeUnstackDetachProcess(
    _In_ PVOID apcState
    );

NTKERNELAPI
POBJECT_TYPE
NTAPI
ObGetObjectType(
    _In_ PVOID object
    );

typedef struct KswordArkHandleEnumContext
{
    KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE* response;
    size_t entryCapacity;
    ULONG processId;
    ULONG requestFlags;
    KswDynState dynState;
    NTSTATUS lastStatus;
} KswordArkHandleEnumContext, *PkswordArkHandleEnumContext;

static BOOLEAN
kswordArkHandleHasRequiredDynData(
    _In_ const KswDynState* dynState
    )
/*++

Routine Description:

    Check every Phase-4 dependency, including HtHandleContentionEvent.
    capability currently marks HtHandleContentionEvent as optional; however, since ExEnumHandleTable requires
    unlocking the entry immediately after direct invocation, this feature treats it as a strong dependency.

Arguments:

    DynState - Snapshot captured at IOCTL time.

Return Value:

    TRUE when all required offsets/shifts are present.

--*/
{
    if (dynState == NULL) {
        return FALSE;
    }

    return
        kswordArkHandleIsOffsetPresent(dynState->kernel.epObjectTable) &&
        kswordArkHandleIsOffsetPresent(dynState->kernel.htHandleContentionEvent) &&
        kswordArkHandleIsOffsetPresent(dynState->kernel.obDecodeShift) &&
        kswordArkHandleIsOffsetPresent(dynState->kernel.obAttributesShift) &&
        kswordArkHandleIsOffsetPresent(dynState->kernel.otName) &&
        kswordArkHandleIsOffsetPresent(dynState->kernel.otIndex);
}

static VOID
kswordArkHandlePrepareEntryDynData(
    _Inout_ KSWORD_ARK_HANDLE_ENTRY* entry,
    _In_ const KswDynState* dynState
    )
/*++

Routine Description:

    Copy DynData diagnostics into one response entry. Note: These fields are for displaying 'which
    offsets/shifts were used in this decoding' only; R3 must not use them as object credentials.

Arguments:

    Entry - Mutable response row.
    DynState - Active DynData snapshot.

Return Value:

    None.

--*/
{
    if (entry == NULL || dynState == NULL) {
        return;
    }

    entry->dynDataCapabilityMask = dynState->capabilityMask;
    entry->epObjectTableOffset = kswordArkHandleNormalizeOffset(dynState->kernel.epObjectTable);
    entry->htHandleContentionEventOffset = kswordArkHandleNormalizeOffset(dynState->kernel.htHandleContentionEvent);
    entry->obDecodeShift = kswordArkHandleNormalizeOffset(dynState->kernel.obDecodeShift);
    entry->obAttributesShift = kswordArkHandleNormalizeOffset(dynState->kernel.obAttributesShift);
    entry->otNameOffset = kswordArkHandleNormalizeOffset(dynState->kernel.otName);
    entry->otIndexOffset = kswordArkHandleNormalizeOffset(dynState->kernel.otIndex);
}

static PVOID
kswordArkHandleDecodeObjectHeader(
    _In_ const KswDynState* dynState,
    _In_ PhandleTableEntry handleTableEntry
    )
/*++

Routine Description:

    Decode the encoded object header pointer stored in HandleTableEntry.
    Note: Logic directly aligns with System Informer's KphObpDecodeObject; LA57 differences are
    absorbed by the dynamic data in ObDecodeShift, so the system version is not guessed here.

Arguments:

    DynState - Active DynData snapshot containing ObDecodeShift.
    HandleTableEntry - Current handle table entry supplied by ExEnumHandleTable.

Return Value:

    Decoded OBJECT_HEADER pointer, or NULL when decoding is unavailable/failed.

--*/
{
#if defined(_M_X64) || defined(_M_ARM64)
    LONG_PTR objectValue = 0;

    if (dynState == NULL || handleTableEntry == NULL) {
        return NULL;
    }
    if (!kswordArkHandleIsOffsetPresent(dynState->kernel.obDecodeShift)) {
        return NULL;
    }

    __try {
        objectValue = (LONG_PTR)handleTableEntry->low.object;
        objectValue >>= dynState->kernel.obDecodeShift;
        objectValue <<= 4;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    return (PVOID)objectValue;
#else
    UNREFERENCED_PARAMETER(DynState);
    if (HandleTableEntry == NULL) {
        return NULL;
    }
    __try {
        return (PVOID)((ULONG_PTR)HandleTableEntry->Low.Object & ~0x7UL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
#endif
}

static ULONG
kswordArkHandleDecodeAttributes(
    _In_ const KswDynState* dynState,
    _In_ PhandleTableEntry handleTableEntry
    )
/*++

Routine Description:

    Decode HandleTableEntry attributes. Note: On x64/ARM64, the new format encodes attribute
    bits in the high bits of Value; ObAttributesShift is derived from DynData to avoid hardcoding.

Arguments:

    DynState - Active DynData snapshot containing ObAttributesShift.
    HandleTableEntry - Current handle table entry.

Return Value:

    Low attribute bits used by UI (PROTECT/INHERIT/AUDIT subset).

--*/
{
#if defined(_M_X64) || defined(_M_ARM64)
    if (dynState == NULL || handleTableEntry == NULL) {
        return 0UL;
    }
    if (!kswordArkHandleIsOffsetPresent(dynState->kernel.obAttributesShift)) {
        return 0UL;
    }

    return (ULONG)((handleTableEntry->low.value >> dynState->kernel.obAttributesShift) & 0x3UL);
#else
    UNREFERENCED_PARAMETER(DynState);
    if (HandleTableEntry == NULL) {
        return 0UL;
    }
    return (ULONG)(HandleTableEntry->Low.ObAttributes & 0x7UL);
#endif
}

static VOID
kswordArkHandleUnlockEntry(
    _In_ const KswDynState* dynState,
    _In_ PhandleTable handleTable,
    _Inout_ PhandleTableEntry handleTableEntry
    )
/*++

Routine Description:

    Release one entry lock held by ExEnumHandleTable. Note: This replicates the
    unlock model from System Informer: first set the unlocked bit, then wake waiters.

Arguments:

    DynState - Active DynData snapshot containing HtHandleContentionEvent.
    HandleTable - Owning handle table.
    HandleTableEntry - Entry to unlock.

Return Value:

    None.

--*/
{
    PEX_PUSH_LOCK handleContentionEvent = NULL;

    if (dynState == NULL || handleTable == NULL || handleTableEntry == NULL) {
        return;
    }
    if (!kswordArkHandleIsOffsetPresent(dynState->kernel.htHandleContentionEvent)) {
        return;
    }

    #if defined(_WIN64)
    InterlockedExchangeAdd64((volatile LONG64*)&handleTableEntry->low.value, 1);
#else
    InterlockedExchangeAdd((volatile LONG*)&HandleTableEntry->Low.Value, 1);
#endif
    handleContentionEvent = (PEX_PUSH_LOCK)((PUCHAR)handleTable + dynState->kernel.htHandleContentionEvent);
    if (*(PULONG_PTR)handleContentionEvent != 0UL) {
        ExfUnblockPushLock(handleContentionEvent, NULL);
    }
}

static VOID
kswordArkHandleFillEntryFromTable(
    _Inout_ KSWORD_ARK_HANDLE_ENTRY* entry,
    _In_ PhandleTableEntry handleTableEntry,
    _In_ HANDLE handle,
    _In_ PkswordArkHandleEnumContext context
    )
/*++

Routine Description:

    Decode one handle table row into the shared response entry. Note: On failure, the row is not
    discarded; DecodeStatus records a conservative state to facilitate UI-based diff analysis.

Arguments:

    Entry - Mutable response entry.
    HandleTableEntry - Raw kernel handle table entry.
    Handle - Numeric handle value supplied by ExEnumHandleTable.
    Context - Enumeration context with DynData snapshot and request flags.

Return Value:

    None.

--*/
{
    PVOID objectHeader = NULL;
    PVOID objectBody = NULL;
    POBJECT_TYPE objectType = NULL;

    if (entry == NULL || handleTableEntry == NULL || context == NULL) {
        return;
    }

    entry->processId = context->processId;
    entry->handleValue = HandleToULong(handle);
    entry->decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_OK;
    entry->grantedAccessDecodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_UNAVAILABLE;
    entry->grantedAccessReadStatus = STATUS_UNSUCCESSFUL;
    kswordArkHandlePrepareEntryDynData(entry, &context->dynState);

    __try {
        entry->grantedAccess = ((ULONG)handleTableEntry->high.grantedAccess) & KSWORD_ARK_OBJECT_GRANTED_ACCESS_MASK;
        entry->attributes = kswordArkHandleDecodeAttributes(&context->dynState, handleTableEntry);
        entry->grantedAccessDecodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_OK;
        entry->grantedAccessReadStatus = STATUS_SUCCESS;
        entry->fieldFlags |= KSWORD_ARK_HANDLE_FIELD_GRANTED_ACCESS_PRESENT;
        entry->fieldFlags |= KSWORD_ARK_HANDLE_FIELD_ATTRIBUTES_PRESENT;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        context->lastStatus = GetExceptionCode();
        entry->decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_PARTIAL;
        entry->grantedAccessDecodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_ACCESS_DECODE_FAILED;
        entry->grantedAccessReadStatus = context->lastStatus;
    }

    if ((context->requestFlags & KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_OBJECT) != 0UL) {
        objectHeader = kswordArkHandleDecodeObjectHeader(&context->dynState, handleTableEntry);
        if (objectHeader != NULL) {
            objectBody = kswordArkHandleGetObjectBodyFromHeader(objectHeader);
            entry->objectAddress = (ULONG64)(ULONG_PTR)objectBody;
            entry->fieldFlags |= KSWORD_ARK_HANDLE_FIELD_OBJECT_PRESENT;
        }
        else {
            entry->decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_OBJECT_DECODE_FAILED;
        }
    }

    if ((context->requestFlags & KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_TYPE_INDEX) != 0UL) {
        if (objectBody == NULL) {
            entry->decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_OBJECT_DECODE_FAILED;
            return;
        }

        __try {
            objectType = ObGetObjectType(objectBody);
            if (NT_SUCCESS(kswordArkHandleReadObjectTypeIndex(objectType, &context->dynState, &entry->objectTypeIndex))) {
                entry->fieldFlags |= KSWORD_ARK_HANDLE_FIELD_TYPE_INDEX_PRESENT;
            }
            else if (entry->decodeStatus == KSWORD_ARK_HANDLE_DECODE_STATUS_OK) {
                entry->decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_TYPE_DECODE_FAILED;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            context->lastStatus = GetExceptionCode();
            if (entry->decodeStatus == KSWORD_ARK_HANDLE_DECODE_STATUS_OK) {
                entry->decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_TYPE_DECODE_FAILED;
            }
        }
    }

    if (objectHeader != NULL || objectBody != NULL) {
        kswordArkHandleFillEntryObjectHeaderAudit(
            entry,
            objectHeader,
            objectBody,
            objectType,
            &context->dynState);
        if (entry->objectHeaderDecodeStatus != KSWORD_ARK_HANDLE_DECODE_STATUS_OK &&
            entry->decodeStatus == KSWORD_ARK_HANDLE_DECODE_STATUS_OK) {
            entry->decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_PARTIAL;
        }
    }

    if (entry->objectTypeIndexSource == KSWORD_ARK_OBJECT_TYPE_SOURCE_NONE) {
        entry->objectTypeIndexSource = kswordArkHandleMergeTypeIndexSource(
            ((entry->fieldFlags & KSWORD_ARK_HANDLE_FIELD_TYPE_INDEX_PRESENT) != 0UL) ? TRUE : FALSE,
            entry->objectTypeIndex,
            ((entry->fieldFlags & KSWORD_ARK_HANDLE_FIELD_HEADER_TYPE_INDEX_PRESENT) != 0UL) ? TRUE : FALSE,
            entry->objectHeaderTypeIndex);
    }

    if (entry->decodeStatus == KSWORD_ARK_HANDLE_DECODE_STATUS_OK &&
        (entry->fieldFlags & KSWORD_ARK_HANDLE_FIELD_TYPE_INDEX_PRESENT) == 0UL &&
        (context->requestFlags & KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_TYPE_INDEX) != 0UL) {
        entry->decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_PARTIAL;
    }
}

static BOOLEAN NTAPI
kswordArkHandleEnumCallback(
    _In_ PhandleTable handleTable,
    _Inout_ PhandleTableEntry handleTableEntry,
    _In_ HANDLE handle,
    _In_opt_ PVOID context
    )
/*++

Routine Description:

    ExEnumHandleTable callback. Note: Continue counting totalCount even if the output buffer is
    insufficient. Before each entry callback completes, the current HandleTableEntry must be unlocked.

Arguments:

    HandleTable - Owning handle table.
    HandleTableEntry - Current entry locked by ExEnumHandleTable.
    Handle - Numeric handle value.
    Context - KswordArkHandleEnumContext pointer.

Return Value:

    FALSE to continue enumeration.

--*/
{
    PkswordArkHandleEnumContext enumContext = (PkswordArkHandleEnumContext)context;
    KSWORD_ARK_HANDLE_ENTRY* entry = NULL;

    if (enumContext == NULL || enumContext->response == NULL) {
        return FALSE;
    }

    if (enumContext->response->totalCount != MAXULONG) {
        enumContext->response->totalCount += 1UL;
    }

    if ((size_t)enumContext->response->returnedCount < enumContext->entryCapacity) {
        entry = &enumContext->response->entries[enumContext->response->returnedCount];
        RtlZeroMemory(entry, sizeof(*entry));
        kswordArkHandleFillEntryFromTable(entry, handleTableEntry, handle, enumContext);
        enumContext->response->returnedCount += 1UL;
    }

    kswordArkHandleUnlockEntry(&enumContext->dynState, handleTable, handleTableEntry);
    return FALSE;
}

static NTSTATUS
kswordArkHandleReadProcessHandleTable(
    _In_ PEPROCESS processObject,
    _In_ const KswDynState* dynState,
    _Outptr_result_nullonfailure_ PhandleTable* handleTableOut
    )
/*++

Routine Description:

    Acquire process-exit synchronization and read EPROCESS.ObjectTable. Note:
    After successful return, the caller must call PsReleaseProcessExitSynchronization.

Arguments:

    ProcessObject - Referenced target EPROCESS.
    DynState - Active DynData snapshot containing EpObjectTable.
    HandleTableOut - Receives the raw handle table pointer.

Return Value:

    STATUS_SUCCESS with the process exit lock held, or failure status.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    PhandleTable handleTable = NULL;

    if (processObject == NULL || dynState == NULL || handleTableOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *handleTableOut = NULL;

    if (!kswordArkHandleIsOffsetPresent(dynState->kernel.epObjectTable)) {
        return STATUS_NOT_SUPPORTED;
    }

    status = PsAcquireProcessExitSynchronization(processObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    __try {
        RtlCopyMemory(&handleTable, (PUCHAR)processObject + dynState->kernel.epObjectTable, sizeof(handleTable));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (!NT_SUCCESS(status) || handleTable == NULL) {
        PsReleaseProcessExitSynchronization(processObject);
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    *handleTableOut = handleTable;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkHandleCaptureSystemSnapshot(
    _Outptr_result_bytebuffer_(*snapshotBytesOut) KswSystemHandleInformationEx** snapshotOut,
    _Out_ ULONG* snapshotBytesOut
    )
/*++

Routine Description:

    Capture the documented system-wide extended handle projection used as the
    no-profile fallback.  The buffer is size-bounded and re-queried at most
    three times so handle churn cannot cause an unbounded allocation loop.

--*/
{
    KswSystemHandleInformationEx* snapshot = NULL;
    ULONG requiredBytes = 0UL;
    ULONG allocationBytes = 0UL;
    ULONG attempt = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (snapshotOut == NULL || snapshotBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *snapshotOut = NULL;
    *snapshotBytesOut = 0UL;

    status = ZwQuerySystemInformation(
        KSWORD_ARK_HANDLE_SNAPSHOT_INFO_CLASS,
        NULL,
        0UL,
        &requiredBytes);
    if (status != STATUS_INFO_LENGTH_MISMATCH && !NT_SUCCESS(status)) {
        return status;
    }
    if (requiredBytes < sizeof(KswSystemHandleInformationEx)) {
        requiredBytes = 64UL * 1024UL;
    }

    for (attempt = 0UL; attempt < 3UL; ++attempt) {
        if (requiredBytes > KSWORD_ARK_HANDLE_SNAPSHOT_MAX_BYTES - (64UL * 1024UL)) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        allocationBytes = requiredBytes + (64UL * 1024UL);
        snapshot = (KswSystemHandleInformationEx*)kswordArkAllocateNonPagedPool(
            allocationBytes,
            KSWORD_ARK_HANDLE_SNAPSHOT_POOL_TAG);
        if (snapshot == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(snapshot, allocationBytes);
        status = ZwQuerySystemInformation(
            KSWORD_ARK_HANDLE_SNAPSHOT_INFO_CLASS,
            snapshot,
            allocationBytes,
            &requiredBytes);
        if (NT_SUCCESS(status)) {
            *snapshotOut = snapshot;
            *snapshotBytesOut = allocationBytes;
            return STATUS_SUCCESS;
        }
        ExFreePoolWithTag(snapshot, KSWORD_ARK_HANDLE_SNAPSHOT_POOL_TAG);
        snapshot = NULL;
        if (status != STATUS_INFO_LENGTH_MISMATCH ||
            requiredBytes > KSWORD_ARK_HANDLE_SNAPSHOT_MAX_BYTES) {
            return status;
        }
    }

    return STATUS_INFO_LENGTH_MISMATCH;
}

static VOID
kswordArkHandlePopulateSnapshotHeaderAudit(
    _Inout_ KSWORD_ARK_HANDLE_ENTRY* entry,
    _In_ PVOID object
    )
/*++

Routine Description:

    Add only the OBJECT_HEADER fields independently proved by the runtime
    signature resolver.  TypeIndex/InfoMask are intentionally left absent;
    they must never be inferred from the legacy compile-time header layout.

--*/
{
    KswObjectHeaderFallbackResult result;
    NTSTATUS status = STATUS_SUCCESS;

    if (entry == NULL || object == NULL) {
        return;
    }
    RtlZeroMemory(&result, sizeof(result));
    status = kswordArkObjectHeaderQueryFallback(object, &result);
    entry->objectHeaderReadStatus = status;
    if (!NT_SUCCESS(status) || (ULONG_PTR)object < result.bodyOffset) {
        entry->objectHeaderDecodeStatus =
            KSWORD_ARK_HANDLE_DECODE_STATUS_HEADER_DYNDATA_MISSING;
        return;
    }

    entry->objectHeaderAddress = (ULONG64)((ULONG_PTR)object - result.bodyOffset);
    entry->pointerCount = (LONG64)result.pointerCount;
    entry->objectHeaderDecodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_PARTIAL;
    entry->fieldFlags |=
        KSWORD_ARK_HANDLE_FIELD_OBJECT_HEADER_PRESENT |
        KSWORD_ARK_HANDLE_FIELD_OBJECT_HEADER_BODY_PRESENT |
        KSWORD_ARK_HANDLE_FIELD_POINTER_COUNT_PRESENT;
    if ((result.validFields &
            KSW_OBJECT_HEADER_FALLBACK_FIELD_HANDLE_COUNT) != 0UL) {
        entry->handleCount = (ULONG64)result.handleCount;
        entry->fieldFlags |= KSWORD_ARK_HANDLE_FIELD_HANDLE_COUNT_PRESENT;
    }
}

static NTSTATUS
kswordArkHandleEnumerateSystemSnapshot(
    _Inout_ KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_ENUM_PROCESS_HANDLES_REQUEST* request,
    _In_ const KswDynState* dynState,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    enumerate handles without EPROCESS/HandleTable private offsets.  The
    system snapshot supplies handle/access/type metadata; emitted rows are
    optionally re-referenced in the target process before runtime header
    counters are read.  This is the fail-safe fallback when the direct
    handle-table profile is absent.

--*/
{
    KswSystemHandleInformationEx* snapshot = NULL;
    PEPROCESS processObject = NULL;
    ULONG snapshotBytes = 0UL;
    ULONG_PTR snapshotCapacity = 0U;
    ULONG_PTR snapshotCount = 0U;
    ULONG_PTR index = 0U;
    ULONG requestFlags = 0UL;
    size_t entryCapacity = 0U;
    DECLSPEC_ALIGN(16) UCHAR attachState[128];
    BOOLEAN attached = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (response == NULL || request == NULL || dynState == NULL ||
        bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    requestFlags = (request->flags == 0UL) ?
        KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_ALL : request->flags;
    entryCapacity = (outputBufferLength - KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_HANDLE_ENTRY);

    status = PsLookupProcessByProcessId(
        ULongToHandle(request->processId),
        &processObject);
    if (!NT_SUCCESS(status)) {
        response->overallStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_PROCESS_LOOKUP_FAILED;
        response->lastStatus = status;
        *bytesWrittenOut = KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE;
        return status;
    }
    status = kswordArkHandleCaptureSystemSnapshot(&snapshot, &snapshotBytes);
    if (!NT_SUCCESS(status)) {
        response->overallStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_READ_FAILED;
        response->lastStatus = status;
        ObDereferenceObject(processObject);
        *bytesWrittenOut = KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE;
        return status;
    }

    snapshotCapacity = (snapshotBytes - FIELD_OFFSET(
        KswSystemHandleInformationEx,
        handles)) / sizeof(snapshot->handles[0]);
    snapshotCount = snapshot->numberOfHandles;
    if (snapshotCount > snapshotCapacity) {
        snapshotCount = snapshotCapacity;
        response->lastStatus = STATUS_DATA_ERROR;
    }

    RtlZeroMemory(attachState, sizeof(attachState));
    __try {
        KeStackAttachProcess((PVOID)processObject, attachState);
        attached = TRUE;
        for (index = 0U; index < snapshotCount; ++index) {
            const KswSystemHandleTableEntryInfoEx* source =
                &snapshot->handles[index];
            KSWORD_ARK_HANDLE_ENTRY* entry = NULL;
            PVOID referencedObject = NULL;
            OBJECT_HANDLE_INFORMATION handleInformation;
            NTSTATUS referenceStatus = STATUS_SUCCESS;

            if (source->uniqueProcessId != (ULONG_PTR)request->processId) {
                continue;
            }
            if (response->totalCount != MAXULONG) {
                response->totalCount += 1UL;
            }
            if ((size_t)response->returnedCount >= entryCapacity) {
                continue;
            }

            entry = &response->entries[response->returnedCount++];
            RtlZeroMemory(entry, sizeof(*entry));
            entry->processId = request->processId;
            entry->handleValue = (ULONG)source->handleValue;
            entry->grantedAccess = source->grantedAccess;
            entry->attributes = source->handleAttributes;
            entry->decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_OK;
            entry->grantedAccessDecodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_OK;
            entry->grantedAccessReadStatus = STATUS_SUCCESS;
            entry->objectHeaderDecodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_UNAVAILABLE;
            entry->objectHeaderReadStatus = STATUS_NOT_SUPPORTED;
            entry->fieldFlags |=
                KSWORD_ARK_HANDLE_FIELD_GRANTED_ACCESS_PRESENT |
                KSWORD_ARK_HANDLE_FIELD_ATTRIBUTES_PRESENT;
            kswordArkHandlePrepareEntryDynData(entry, dynState);

            if ((requestFlags & KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_OBJECT) != 0UL &&
                source->object != NULL) {
                entry->objectAddress = (ULONG64)(ULONG_PTR)source->object;
                entry->fieldFlags |= KSWORD_ARK_HANDLE_FIELD_OBJECT_PRESENT;
            }
            if ((requestFlags & KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_TYPE_INDEX) != 0UL &&
                source->objectTypeIndex != 0U) {
                entry->objectTypeIndex = source->objectTypeIndex;
                entry->objectTypeIndexSource =
                    KSWORD_ARK_OBJECT_TYPE_SOURCE_SYSTEM_SNAPSHOT;
                entry->fieldFlags |= KSWORD_ARK_HANDLE_FIELD_TYPE_INDEX_PRESENT;
            }

            RtlZeroMemory(&handleInformation, sizeof(handleInformation));
            referenceStatus = ObReferenceObjectByHandle(
                (HANDLE)source->handleValue,
                0,
                NULL,
                UserMode,
                &referencedObject,
                &handleInformation);
            if (NT_SUCCESS(referenceStatus) && referencedObject != NULL) {
                if ((requestFlags & KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_OBJECT) != 0UL) {
                    entry->objectAddress = (ULONG64)(ULONG_PTR)referencedObject;
                    entry->fieldFlags |= KSWORD_ARK_HANDLE_FIELD_OBJECT_PRESENT;
                }
                kswordArkHandlePopulateSnapshotHeaderAudit(entry, referencedObject);
                ObDereferenceObject(referencedObject);
            }
            else {
                entry->objectHeaderReadStatus = referenceStatus;
            }
        }
        KeUnstackDetachProcess(attachState);
        attached = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        if (attached) {
            KeUnstackDetachProcess(attachState);
            attached = FALSE;
        }
    }

    ExFreePoolWithTag(snapshot, KSWORD_ARK_HANDLE_SNAPSHOT_POOL_TAG);
    ObDereferenceObject(processObject);
    if (!NT_SUCCESS(status)) {
        response->overallStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_READ_FAILED;
        response->lastStatus = status;
    }
    else {
        response->overallStatus = (response->returnedCount < response->totalCount) ?
            KSWORD_ARK_HANDLE_DECODE_STATUS_BUFFER_TOO_SMALL :
            KSWORD_ARK_HANDLE_DECODE_STATUS_OK;
        if (NT_SUCCESS(response->lastStatus)) {
            response->lastStatus = STATUS_SUCCESS;
        }
    }
    *bytesWrittenOut = KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_HANDLE_ENTRY));
    return status;
}

static KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE*
kswordArkHandlePrepareEnumerationResponse(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ ULONG processId
    )
/*++

Routine Description:

    Reset the common response header before either the private-table path or a
    retry through the system handle snapshot fallback.

--*/
{
    KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE* response = NULL;

    if (outputBuffer == NULL ||
        outputBufferLength < KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE) {
        return NULL;
    }
    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_HANDLE_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_HANDLE_ENTRY);
    response->processId = processId;
    response->overallStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_UNAVAILABLE;
    response->lastStatus = STATUS_SUCCESS;
    return response;
}

NTSTATUS
kswordArkDriverEnumerateProcessHandles(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_ENUM_PROCESS_HANDLES_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    enumerate a target process HandleTable directly from kernel mode. Note:
    This function returns only display/diff-analysis fields; the object address is a diagnostic value, not credentials for subsequent IOCTLs.

Arguments:

    OutputBuffer - Caller output packet.
    OutputBufferLength - Output packet capacity.
    Request - Required request containing a non-zero PID.
    BytesWrittenOut - Receives actual bytes written.

Return Value:

    STATUS_SUCCESS when the response header is valid; private-field or lookup
    failures are reflected in response->overallStatus and may also be returned.

--*/
{
    KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE* response = NULL;
    KswordArkHandleEnumContext enumContext;
    PEPROCESS processObject = NULL;
    PhandleTable handleTable = NULL;
    size_t entryCapacity = 0U;
    size_t totalBytesWritten = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || bytesWrittenOut == NULL || request == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (request->processId == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    response = kswordArkHandlePrepareEnumerationResponse(
        outputBuffer,
        outputBufferLength,
        request->processId);
    if (response == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(&enumContext, sizeof(enumContext));
    enumContext.response = response;
    enumContext.processId = request->processId;
    enumContext.requestFlags = (request->flags == 0UL) ? KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_ALL : request->flags;
    enumContext.lastStatus = STATUS_SUCCESS;
    kswordArkDynDataSnapshot(&enumContext.dynState);

    if (!kswordArkHandleHasRequiredDynData(&enumContext.dynState)) {
        return kswordArkHandleEnumerateSystemSnapshot(
            response,
            outputBufferLength,
            request,
            &enumContext.dynState,
            bytesWrittenOut);
    }

    status = PsLookupProcessByProcessId(ULongToHandle(request->processId), &processObject);
    if (!NT_SUCCESS(status)) {
        response->overallStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_PROCESS_LOOKUP_FAILED;
        response->lastStatus = status;
        totalBytesWritten = KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE;
        *bytesWrittenOut = totalBytesWritten;
        return status;
    }

    status = kswordArkHandleReadProcessHandleTable(processObject, &enumContext.dynState, &handleTable);
    if (!NT_SUCCESS(status)) {
        response->overallStatus = (status == STATUS_NOT_FOUND) ?
            KSWORD_ARK_HANDLE_DECODE_STATUS_HANDLE_TABLE_MISSING :
            KSWORD_ARK_HANDLE_DECODE_STATUS_PROCESS_EXITING;
        response->lastStatus = status;
        ObDereferenceObject(processObject);
        response = kswordArkHandlePrepareEnumerationResponse(
            outputBuffer,
            outputBufferLength,
            request->processId);
        return kswordArkHandleEnumerateSystemSnapshot(
            response,
            outputBufferLength,
            request,
            &enumContext.dynState,
            bytesWrittenOut);
    }

    entryCapacity = (outputBufferLength - KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE) / sizeof(KSWORD_ARK_HANDLE_ENTRY);
    enumContext.entryCapacity = entryCapacity;

    __try {
        (VOID)ExEnumHandleTable(handleTable, kswordArkHandleEnumCallback, &enumContext, NULL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        enumContext.lastStatus = status;
    }

    PsReleaseProcessExitSynchronization(processObject);
    ObDereferenceObject(processObject);

    if (!NT_SUCCESS(status)) {
        response = kswordArkHandlePrepareEnumerationResponse(
            outputBuffer,
            outputBufferLength,
            request->processId);
        return kswordArkHandleEnumerateSystemSnapshot(
            response,
            outputBufferLength,
            request,
            &enumContext.dynState,
            bytesWrittenOut);
    }

    response->overallStatus = (response->returnedCount < response->totalCount) ?
        KSWORD_ARK_HANDLE_DECODE_STATUS_BUFFER_TOO_SMALL :
        KSWORD_ARK_HANDLE_DECODE_STATUS_OK;
    response->lastStatus = enumContext.lastStatus;
    totalBytesWritten = KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_HANDLE_ENTRY));
    *bytesWrittenOut = totalBytesWritten;

    return STATUS_SUCCESS;
}
