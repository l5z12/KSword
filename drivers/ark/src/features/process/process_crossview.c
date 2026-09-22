/*++

Module Name:

    process_crossview.c

Abstract:

    Read-only process cross-view evidence collection for DKOM diagnostics.

Environment:

    Kernel-mode Driver Framework

--*/

#include "process_crossview.h"
#include "../kernel/hook_scan_support.h"
#include "../kernel/object_header_fallback.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSW_PROCESS_CROSSVIEW_TAG 'vPsK'
#define KSW_CROSSVIEW_SHARED_TAG 'vCsK'
#define KSW_PROCESS_CROSSVIEW_HEADER_SIZE \
    (sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_RESPONSE) - sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_ROW))
#define KSW_CROSSVIEW_CID_TABLE_LEVEL_MASK 0x3ULL
#define KSW_CROSSVIEW_CID_LEVEL0_ENTRY_COUNT 256UL
#define KSW_CROSSVIEW_CID_POINTER_ENTRY_COUNT 512UL
#define KSW_CROSSVIEW_CID_ENTRY_BYTES 16ULL
#define KSW_CROSSVIEW_CID_HANDLE_VALUE_STRIDE 4ULL
#define KSW_CROSSVIEW_PSP_CID_SCAN_BYTES 0x180UL
#define KSW_CROSSVIEW_FALLBACK_HT_TABLE_CODE_OFFSET ((ULONG)sizeof(PVOID))
#define KSW_CROSSVIEW_FALLBACK_HTE_LOW_VALUE_OFFSET 0UL

#ifndef STATUS_OBJECT_TYPE_MISMATCH
#define STATUS_OBJECT_TYPE_MISMATCH ((NTSTATUS)0xC0000024L)
#endif

#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#endif

#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif

typedef PEPROCESS(NTAPI* KswCrossviewPsGetNextProcessFn)(
    _In_opt_ PEPROCESS process
    );

typedef struct KswCrossviewVisitedSet
{
    ULONG_PTR* items;
    ULONG count;
    ULONG capacity;
} KswCrossviewVisitedSet, *PkswCrossviewVisitedSet;

typedef struct KswProcessCrossviewContext
{
    KSWORD_ARK_PROCESS_CROSSVIEW_ROW* rows;
    ULONG rowCount;
    ULONG rowCapacity;
    ULONG flags;
    ULONG startPid;
    ULONG endPid;
    ULONG maxNodes;
    ULONG64 missingCapabilityMask;
    NTSTATUS lastStatus;
    BOOLEAN truncated;
    BOOLEAN capabilityMissing;
    KswDynState dynState;
    KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS fieldOffsets;
} KswProcessCrossviewContext, *PkswProcessCrossviewContext;

typedef struct KswCrossviewCidWalkContext
{
    const KswDynState* dynState;
    POBJECT_TYPE expectedObjectType;
    ULONG maxNodes;
    ULONG visitedEntries;
    ULONG reportedEntries;
    NTSTATUS lastStatus;
    KswCrossviewCidCallback callback;
    PVOID callbackContext;
} KswCrossviewCidWalkContext, *PkswCrossviewCidWalkContext;

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

NTKERNELAPI
POBJECT_TYPE
NTAPI
ObGetObjectType(
    _In_ PVOID object
    );

extern NTKERNELAPI PEPROCESS PsInitialSystemProcess;
extern POBJECT_TYPE* PsProcessType;

static PVOID
KswordARKCrossViewAllocate(
    _In_ SIZE_T bufferBytes,
    _In_ ULONG tag
    )
/*++

Routine Description:

    Allocate a transient nonpaged buffer for one cross-view query.

Arguments:

    BufferBytes - Requested byte count.
    Tag - Pool tag used for diagnostics.

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
kswordArkCrossViewFree(
    _In_opt_ PVOID buffer,
    _In_ ULONG tag
    )
/*++

Routine Description:

    Free a buffer allocated by the cross-view collector.

Arguments:

    Buffer - Optional allocation pointer.
    Tag - Pool tag used during allocation.

Return Value:

    None. NULL input is ignored.

--*/
{
    if (buffer != NULL) {
        ExFreePoolWithTag(buffer, tag);
    }
}

BOOLEAN
kswordArkCrossViewOffsetPresent(
    _In_ ULONG offset
    )
/*++

Routine Description:

    normalize DynData offset availability before private-field reads.

Arguments:

    Offset - Candidate offset from the DynData snapshot.

Return Value:

    TRUE when the offset is usable; otherwise FALSE.

--*/
{
    return (offset != KSW_DYN_OFFSET_UNAVAILABLE && offset != 0x0000FFFFUL) ? TRUE : FALSE;
}

static BOOLEAN
kswordArkCrossViewGlobalRvaPresent(
    _In_ ULONG rva
    )
/*++

Routine Description:

    Check availability for DynData global RVAs. Unlike structure fields, RVA
    zero is not accepted for kernel globals in this collector.

Arguments:

    Rva - Candidate ntoskrnl-relative global RVA.

Return Value:

    TRUE when Rva is nonzero and not an unavailable sentinel.

--*/
{
    return (rva != 0UL && rva != KSW_DYN_OFFSET_UNAVAILABLE && rva != 0x0000FFFFUL) ? TRUE : FALSE;
}

ULONG
kswordArkCrossViewNormalizeOffset(
    _In_ ULONG offset
    )
/*++

Routine Description:

    Convert internal DynData sentinels into the shared cross-view sentinel.

Arguments:

    Offset - Raw DynData offset.

Return Value:

    Offset when usable; KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE otherwise.

--*/
{
    return kswordArkCrossViewOffsetPresent(offset) ? offset : KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
}

BOOLEAN
kswordArkCrossViewPointerAligned(
    _In_ ULONG_PTR address
    )
/*++

Routine Description:

    Check pointer alignment before list, table, or object dereferences.

Arguments:

    Address - Candidate kernel pointer value.

Return Value:

    TRUE when Address is nonzero and pointer-size aligned; otherwise FALSE.

--*/
{
    if (address == 0U) {
        return FALSE;
    }
    return ((address & (sizeof(PVOID) - 1U)) == 0U) ? TRUE : FALSE;
}

static ULONG
kswordArkCrossViewEffectiveHtTableCodeOffset(
    _In_opt_ const KswDynState* dynState,
    _Out_opt_ BOOLEAN* usedFallbackOut
    )
/*++

Routine Description:

    Pick the HandleTable.TableCode offset used by the CID-table walker.
    Note: Do not fall back to PsLookupProcessByProcessId just because DynData
    lacks HtTableCode. On modern x64 Windows, TableCode resides at
    HandleTable + sizeof(PVOID); this serves as a read-only fallback offset.

Arguments:

    DynState - Optional DynData snapshot.
    UsedFallbackOut - Receives whether the built-in fallback offset was used.

Return Value:

    A bounded offset used only for reading the kernel-owned HandleTable.

--*/
{
    if (usedFallbackOut != NULL) {
        *usedFallbackOut = FALSE;
    }
    if (dynState != NULL && kswordArkCrossViewOffsetPresent(dynState->kernel.htTableCode)) {
        return dynState->kernel.htTableCode;
    }
    if (usedFallbackOut != NULL) {
        *usedFallbackOut = TRUE;
    }
    return KSW_CROSSVIEW_FALLBACK_HT_TABLE_CODE_OFFSET;
}

static ULONG
kswordArkCrossViewEffectiveHteLowValueOffset(
    _In_opt_ const KswDynState* dynState,
    _Out_opt_ BOOLEAN* usedFallbackOut
    )
/*++

Routine Description:

    Pick the HandleTableEntry.LowValue offset used by the CID-table walker.
    Note: LowValue is the entry's starting field; decode PspCidTable read-only even if
    DynData lacks this field to avoid calling PID/TID lookup functions that may be hooked.

Arguments:

    DynState - Optional DynData snapshot.
    UsedFallbackOut - Receives whether the built-in fallback offset was used.

Return Value:

    A bounded offset inside one HandleTableEntry.

--*/
{
    if (usedFallbackOut != NULL) {
        *usedFallbackOut = FALSE;
    }
    if (dynState != NULL && kswordArkCrossViewOffsetPresent(dynState->kernel.hteLowValue)) {
        return dynState->kernel.hteLowValue;
    }
    if (usedFallbackOut != NULL) {
        *usedFallbackOut = TRUE;
    }
    return KSW_CROSSVIEW_FALLBACK_HTE_LOW_VALUE_OFFSET;
}

VOID
kswordArkCrossViewFillFieldOffsets(
    _In_ const KswDynState* dynState,
    _Out_ KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS* offsets
    )
/*++

Routine Description:

    Copy relevant DynData offsets and the PspCidTable global into a protocol
    field-offset packet.

Arguments:

    DynState - Snapshot captured at query start.
    Offsets - Output protocol structure.

Return Value:

    None. Invalid inputs are ignored after zeroing the output when possible.

--*/
{
    if (offsets == NULL) {
        return;
    }

    RtlZeroMemory(offsets, sizeof(*offsets));
    offsets->epUniqueProcessId = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    offsets->epActiveProcessLinks = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    offsets->epThreadListHead = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    offsets->epImageFileName = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    offsets->etCid = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    offsets->etThreadListEntry = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    offsets->etStartAddress = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    offsets->etWin32StartAddress = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    offsets->ktProcess = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    offsets->htTableCode = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    offsets->hteLowValue = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    offsets->pspCidTableRva = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;

    if (dynState == NULL) {
        return;
    }

    offsets->epUniqueProcessId = kswordArkCrossViewNormalizeOffset(dynState->kernel.epUniqueProcessId);
    offsets->epActiveProcessLinks = kswordArkCrossViewNormalizeOffset(dynState->kernel.epActiveProcessLinks);
    offsets->epThreadListHead = kswordArkCrossViewNormalizeOffset(dynState->kernel.epThreadListHead);
    offsets->epImageFileName = kswordArkCrossViewNormalizeOffset(dynState->kernel.epImageFileName);
    offsets->etCid = kswordArkCrossViewNormalizeOffset(dynState->kernel.etCid);
    offsets->etThreadListEntry = kswordArkCrossViewNormalizeOffset(dynState->kernel.etThreadListEntry);
    offsets->etStartAddress = kswordArkCrossViewNormalizeOffset(dynState->kernel.etStartAddress);
    offsets->etWin32StartAddress = kswordArkCrossViewNormalizeOffset(dynState->kernel.etWin32StartAddress);
    offsets->ktProcess = kswordArkCrossViewNormalizeOffset(dynState->kernel.ktProcess);
    offsets->htTableCode = kswordArkCrossViewOffsetPresent(dynState->kernel.htTableCode)
        ? dynState->kernel.htTableCode
        : KSW_CROSSVIEW_FALLBACK_HT_TABLE_CODE_OFFSET;
    offsets->hteLowValue = kswordArkCrossViewOffsetPresent(dynState->kernel.hteLowValue)
        ? dynState->kernel.hteLowValue
        : KSW_CROSSVIEW_FALLBACK_HTE_LOW_VALUE_OFFSET;
    offsets->pspCidTableRva = kswordArkCrossViewGlobalRvaPresent(dynState->kernelGlobals.pspCidTable)
        ? dynState->kernelGlobals.pspCidTable
        : KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    offsets->epUniqueProcessIdSource = dynState->kernelSources.epUniqueProcessId;
    offsets->epActiveProcessLinksSource = dynState->kernelSources.epActiveProcessLinks;
    offsets->epThreadListHeadSource = dynState->kernelSources.epThreadListHead;
    offsets->epImageFileNameSource = dynState->kernelSources.epImageFileName;
    offsets->etCidSource = dynState->kernelSources.etCid;
    offsets->etThreadListEntrySource = dynState->kernelSources.etThreadListEntry;
    offsets->etStartAddressSource = dynState->kernelSources.etStartAddress;
    offsets->etWin32StartAddressSource = dynState->kernelSources.etWin32StartAddress;
    offsets->ktProcessSource = dynState->kernelSources.ktProcess;
    offsets->htTableCodeSource = kswordArkCrossViewOffsetPresent(dynState->kernel.htTableCode)
        ? dynState->kernelSources.htTableCode
        : KSWORD_ARK_CROSSVIEW_FIELD_SOURCE_RUNTIME_PATTERN;
    offsets->hteLowValueSource = kswordArkCrossViewOffsetPresent(dynState->kernel.hteLowValue)
        ? dynState->kernelSources.hteLowValue
        : KSWORD_ARK_CROSSVIEW_FIELD_SOURCE_RUNTIME_PATTERN;
    offsets->pspCidTableSource = dynState->kernelGlobalSources.pspCidTable;
}

NTSTATUS
kswordArkCrossViewReadMemory(
    _In_ const VOID* address,
    _Out_writes_bytes_(bytesToRead) VOID* buffer,
    _In_ SIZE_T bytesToRead
    )
/*++

Routine Description:

    Safely copy kernel memory for read-only evidence collection.

Arguments:

    Address - Kernel source address.
    Buffer - Caller-owned output buffer.
    BytesToRead - Exact number of bytes to copy.

Return Value:

    STATUS_SUCCESS on a complete copy, or a validation/exception/copy status.

--*/
{
    MM_COPY_ADDRESS copyAddress;
    SIZE_T copiedBytes = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (address == NULL || buffer == NULL || bytesToRead == 0U) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&copyAddress, sizeof(copyAddress));
    copyAddress.VirtualAddress = (PVOID)address;

    __try {
        status = MmCopyMemory(
            buffer,
            copyAddress,
            bytesToRead,
            MM_COPY_MEMORY_VIRTUAL,
            &copiedBytes);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (!NT_SUCCESS(status)) {
        return status;
    }
    return (copiedBytes == bytesToRead) ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}

NTSTATUS
kswordArkCrossViewReadPointerAddress(
    _In_ const VOID* address,
    _Out_ PVOID* pointerOut
    )
/*++

Routine Description:

    Read one pointer-sized value from a kernel address with SEH and MmCopyMemory
    protection.

Arguments:

    Address - Address of the pointer value.
    PointerOut - Receives the pointer value.

Return Value:

    STATUS_SUCCESS on success, otherwise the guarded read status.

--*/
{
    PVOID pointerValue = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (pointerOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *pointerOut = NULL;

    status = kswordArkCrossViewReadMemory(address, &pointerValue, sizeof(pointerValue));
    if (NT_SUCCESS(status)) {
        *pointerOut = pointerValue;
    }
    return status;
}

NTSTATUS
kswordArkCrossViewReadUlong64Address(
    _In_ const VOID* address,
    _Out_ ULONGLONG* valueOut
    )
/*++

Routine Description:

    Read one 64-bit value from a kernel address with SEH and MmCopyMemory
    protection.

Arguments:

    Address - Address of the value.
    ValueOut - Receives the copied 64-bit value.

Return Value:

    STATUS_SUCCESS on success, otherwise the guarded read status.

--*/
{
    ULONGLONG value = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (valueOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *valueOut = 0ULL;

    status = kswordArkCrossViewReadMemory(address, &value, sizeof(value));
    if (NT_SUCCESS(status)) {
        *valueOut = value;
    }
    return status;
}

NTSTATUS
kswordArkCrossViewReadPointerField(
    _In_ const VOID* object,
    _In_ ULONG offset,
    _Out_ PVOID* pointerOut
    )
/*++

Routine Description:

    Read one pointer field from a kernel object using a DynData offset.

Arguments:

    Object - Base object address.
    Offset - Private field offset.
    PointerOut - Receives the pointer field value.

Return Value:

    STATUS_SUCCESS on success, STATUS_PROCEDURE_NOT_FOUND for missing offsets,
    or the guarded read status.

--*/
{
    if (pointerOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *pointerOut = NULL;

    if (object == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkCrossViewOffsetPresent(offset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    return kswordArkCrossViewReadPointerAddress((const UCHAR*)object + offset, pointerOut);
}

static NTSTATUS
kswordArkCrossViewReadUlongField(
    _In_ const VOID* object,
    _In_ ULONG offset,
    _Out_ ULONG* valueOut
    )
/*++

Routine Description:

    Read one ULONG field from a private kernel object offset.

Arguments:

    Object - Base object address.
    Offset - Private field offset.
    ValueOut - Receives the ULONG value.

Return Value:

    STATUS_SUCCESS on success, STATUS_PROCEDURE_NOT_FOUND for missing offsets,
    or the guarded read status.

--*/
{
    ULONG value = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (object == NULL || valueOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *valueOut = 0UL;
    if (!kswordArkCrossViewOffsetPresent(offset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    status = kswordArkCrossViewReadMemory((const UCHAR*)object + offset, &value, sizeof(value));
    if (NT_SUCCESS(status)) {
        *valueOut = value;
    }
    return status;
}

static VOID
kswordArkCrossViewCopyImageName(
    _Out_writes_all_(16) CHAR destination[16],
    _In_opt_z_ const CHAR* source
    )
/*++

Routine Description:

    Copy a process image name into the fixed 16-byte protocol field.

Arguments:

    Destination - Output image-name buffer.
    Source - Optional NUL-terminated source string.

Return Value:

    None. The destination is always NUL-terminated when valid.

--*/
{
    ULONG index = 0UL;

    if (destination == NULL) {
        return;
    }
    RtlZeroMemory(destination, 16U);
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

static VOID
kswordArkCrossViewFormatDetail(
    _Out_writes_bytes_(destinationBytes) CHAR* destination,
    _In_ SIZE_T destinationBytes,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Format a bounded ANSI detail string for a cross-view evidence row.

Arguments:

    Destination - Output detail buffer.
    DestinationBytes - Size of Destination in bytes.
    FormatText - printf-style ANSI format string.
    ... - Format arguments.

Return Value:

    None. Formatting failure leaves an empty string.

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

static KswCrossviewPsGetNextProcessFn
kswordArkProcessCrossViewResolvePsGetNextProcess(
    VOID
    )
/*++

Routine Description:

    Resolve PsGetNextProcess dynamically so the driver does not extend its fixed
    import surface.

Arguments:

    None.

Return Value:

    Function pointer when exported by the running kernel; otherwise NULL.

--*/
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsGetNextProcess");
    return (KswCrossviewPsGetNextProcessFn)MmGetSystemRoutineAddress(&routineName);
}

static NTSTATUS
kswordArkCrossViewVisitedInitialize(
    _Out_ KswCrossviewVisitedSet* visited,
    _In_ ULONG maxNodes
    )
/*++

Routine Description:

    Allocate a per-walk visited-address set used for loop detection.

Arguments:

    Visited - Output set descriptor.
    MaxNodes - Maximum list nodes the caller will traverse.

Return Value:

    STATUS_SUCCESS when the set is ready; otherwise a validation/allocation
    status.

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

    visited->items = (ULONG_PTR*)KswordARKCrossViewAllocate(bytes, KSW_CROSSVIEW_SHARED_TAG);
    if (visited->items == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(visited->items, bytes);
    visited->capacity = maxNodes;
    return STATUS_SUCCESS;
}

static VOID
kswordArkCrossViewVisitedDestroy(
    _Inout_ KswCrossviewVisitedSet* visited
    )
/*++

Routine Description:

    Release a visited-address set allocated for loop detection.

Arguments:

    Visited - Set descriptor to release and clear.

Return Value:

    None.

--*/
{
    if (visited == NULL) {
        return;
    }

    kswordArkCrossViewFree(visited->items, KSW_CROSSVIEW_SHARED_TAG);
    RtlZeroMemory(visited, sizeof(*visited));
}

static BOOLEAN
kswordArkCrossViewVisitedCheckAndAdd(
    _Inout_ KswCrossviewVisitedSet* visited,
    _In_ ULONG_PTR address
    )
/*++

Routine Description:

    Test whether a list address was already seen, and record it when new.

Arguments:

    Visited - Mutable visited-address set.
    Address - List entry address being examined.

Return Value:

    TRUE when Address was already present or the set is full; FALSE when the
    address was newly added and traversal may continue.

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

static BOOLEAN
kswordArkProcessCrossViewPidInRequest(
    _In_ const KswProcessCrossviewContext* context,
    _In_ ULONG processId
    )
/*++

Routine Description:

    Apply the optional PID range filter from the request.

Arguments:

    Context - Query context containing range boundaries.
    ProcessId - Candidate PID.

Return Value:

    TRUE when the PID should be included; otherwise FALSE.

--*/
{
    if (context == NULL) {
        return FALSE;
    }
    if (context->startPid != 0UL && processId < context->startPid) {
        return FALSE;
    }
    if (context->endPid != 0UL && processId > context->endPid) {
        return FALSE;
    }
    return TRUE;
}

static KSWORD_ARK_PROCESS_CROSSVIEW_ROW*
kswordArkProcessCrossViewFindRow(
    _Inout_ KswProcessCrossviewContext* context,
    _In_ ULONG64 objectAddress,
    _In_ ULONG processId
    )
/*++

Routine Description:

    Locate an existing process evidence row by object address first and PID as a
    fallback for dangling CID rows.

Arguments:

    Context - Mutable query context.
    ObjectAddress - Candidate EPROCESS address.
    ProcessId - Candidate PID.

Return Value:

    Existing row pointer when found; otherwise NULL.

--*/
{
    ULONG index = 0UL;

    if (context == NULL || context->rows == NULL) {
        return NULL;
    }

    for (index = 0UL; index < context->rowCount; ++index) {
        KSWORD_ARK_PROCESS_CROSSVIEW_ROW* row = &context->rows[index];
        if (objectAddress != 0ULL && row->objectAddress == objectAddress) {
            return row;
        }
        if (objectAddress == 0ULL && processId != 0UL && row->processId == processId) {
            return row;
        }
    }

    return NULL;
}

static KSWORD_ARK_PROCESS_CROSSVIEW_ROW*
kswordArkProcessCrossViewGetOrCreateRow(
    _Inout_ KswProcessCrossviewContext* context,
    _In_ ULONG64 objectAddress,
    _In_ ULONG processId
    )
/*++

Routine Description:

    Return an existing process row or append a new internal row when capacity
    permits.

Arguments:

    Context - Mutable query context.
    ObjectAddress - Candidate EPROCESS address.
    ProcessId - Candidate PID.

Return Value:

    Mutable row pointer on success; NULL when the internal row limit is reached.

--*/
{
    KSWORD_ARK_PROCESS_CROSSVIEW_ROW* row = NULL;

    row = kswordArkProcessCrossViewFindRow(context, objectAddress, processId);
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
    row->processId = processId;
    row->dynDataCapabilityMask = context->dynState.capabilityMask;
    row->fieldOffsets = context->fieldOffsets;
    row->lastStatus = STATUS_SUCCESS;
    row->publicWalkStatus = STATUS_NOT_FOUND;
    row->activeListStatus = STATUS_NOT_FOUND;
    row->cidTableStatus = STATUS_NOT_FOUND;
    row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_OK;
    row->confidence = 0UL;
    context->rowCount += 1UL;
    return row;
}

static VOID
kswordArkProcessCrossViewApplyDetailStatus(
    _Inout_ KSWORD_ARK_PROCESS_CROSSVIEW_ROW* row,
    _In_ NTSTATUS sourceStatus,
    _In_ BOOLEAN unsupportedField
    )
/*++

Routine Description:

    Update row-level detail status and denoise flags from one guarded read,
    source walk, or object-reference result.

Arguments:

    Row - Mutable process evidence row.
    SourceStatus - NTSTATUS reported by the source path.
    UnsupportedField - TRUE when the status means a required PDB field was not
        available and the collector intentionally avoided guessing an offset.

Return Value:

    None. The row is annotated in place for R3 display.

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
kswordArkProcessCrossViewRecordSourceEvidence(
    _Inout_ KSWORD_ARK_PROCESS_CROSSVIEW_ROW* row,
    _In_ ULONG sourceMask,
    _In_ ULONG sourceProcessId,
    _In_ NTSTATUS sourceStatus
    )
/*++

Routine Description:

    Store per-source PID and status values without changing the source mask or
    performing any target mutation.

Arguments:

    Row - Mutable process evidence row.
    SourceMask - Single KSWORD_ARK_CROSSVIEW_SOURCE_* bit being merged.
    SourceProcessId - PID observed through that source.
    SourceStatus - Status returned by that source path.

Return Value:

    None. The protocol row receives source-specific evidence fields.

--*/
{
    if (row == NULL) {
        return;
    }

    if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) != 0UL) {
        row->publicProcessId = sourceProcessId;
        row->publicWalkStatus = sourceStatus;
    }
    if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST) != 0UL) {
        row->activeListProcessId = sourceProcessId;
        row->activeListStatus = sourceStatus;
    }
    if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) != 0UL) {
        row->cidTableProcessId = sourceProcessId;
        row->cidTableStatus = sourceStatus;
    }

    kswordArkProcessCrossViewApplyDetailStatus(row, sourceStatus, FALSE);
}

static NTSTATUS
kswordArkProcessCrossViewReadPrivatePid(
    _In_ const KswProcessCrossviewContext* context,
    _In_ PEPROCESS processObject,
    _Out_ ULONG* processIdOut
    )
/*++

Routine Description:

    Read EPROCESS.UniqueProcessId only when DynData exposes the PDB-backed
    offset, so PID mismatch detection remains capability-gated.

Arguments:

    Context - Query context containing the DynData snapshot.
    ProcessObject - Referenced EPROCESS object to inspect.
    ProcessIdOut - Receives the private UniqueProcessId value as ULONG.

Return Value:

    STATUS_SUCCESS when the field was read; STATUS_PROCEDURE_NOT_FOUND when the
    offset is unavailable; otherwise the guarded memory-read status.

--*/
{
    PVOID processIdPointer = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (context == NULL || processObject == NULL || processIdOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *processIdOut = 0UL;

    if (!kswordArkCrossViewOffsetPresent(context->dynState.kernel.epUniqueProcessId)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    status = kswordArkCrossViewReadPointerField(
        processObject,
        context->dynState.kernel.epUniqueProcessId,
        &processIdPointer);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *processIdOut = HandleToULong(processIdPointer);
    return STATUS_SUCCESS;
}

static VOID
kswordArkProcessCrossViewMergeProcessObject(
    _Inout_ KswProcessCrossviewContext* context,
    _In_ PEPROCESS processObject,
    _In_ ULONG sourceMask,
    _In_ NTSTATUS sourceStatus,
    _In_ ULONG evidenceProcessId,
    _In_opt_z_ PCSTR detailText
    )
/*++

Routine Description:

    Merge evidence from a referenced EPROCESS object into the process row set.

Arguments:

    Context - Mutable query context.
    ProcessObject - Referenced process object owned by the caller.
    SourceMask - KSWORD_ARK_CROSSVIEW_SOURCE_* bit for the evidence source.
    SourceStatus - Last read/reference status to record.
    EvidenceProcessId - PID observed by the source itself, or zero when the
        source has no independent PID key.
    DetailText - Optional detail text when the row has no detail yet.

Return Value:

    None. Reference ownership remains with the caller.

--*/
{
    ULONG processId = 0UL;
    ULONG privateProcessId = 0UL;
    ULONG sourceProcessId = 0UL;
    KSWORD_ARK_PROCESS_CROSSVIEW_ROW* row = NULL;
    NTSTATUS privatePidStatus = STATUS_SUCCESS;

    if (context == NULL || processObject == NULL) {
        return;
    }

    processId = HandleToULong(PsGetProcessId(processObject));
    sourceProcessId = (evidenceProcessId != 0UL) ? evidenceProcessId : processId;
    if (!kswordArkProcessCrossViewPidInRequest(context, processId) &&
        !kswordArkProcessCrossViewPidInRequest(context, sourceProcessId)) {
        return;
    }

    row = kswordArkProcessCrossViewGetOrCreateRow(
        context,
        (ULONG64)(ULONG_PTR)processObject,
        processId);
    if (row == NULL) {
        return;
    }

    row->sourceMask |= sourceMask;
    row->processId = processId;
    row->parentProcessId = HandleToULong(PsGetProcessInheritedFromUniqueProcessId(processObject));
    row->lastStatus = sourceStatus;
    kswordArkCrossViewCopyImageName(row->imageName, PsGetProcessImageFileName(processObject));
    privatePidStatus = kswordArkProcessCrossViewReadPrivatePid(context, processObject, &privateProcessId);
    if (NT_SUCCESS(privatePidStatus)) {
        if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST) != 0UL &&
            evidenceProcessId == 0UL) {
            sourceProcessId = privateProcessId;
        }
        if (privateProcessId != processId) {
            row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_PID_FIELD_MISMATCH;
            row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_DATA_MISMATCH;
            row->lastStatus = STATUS_DATA_ERROR;
        }
    }
    else if (privatePidStatus == STATUS_PROCEDURE_NOT_FOUND) {
        context->capabilityMissing = TRUE;
        context->missingCapabilityMask |= KSW_CAP_PROCESS_LIST_FIELDS;
        context->lastStatus = privatePidStatus;
        row->lastStatus = privatePidStatus;
        kswordArkProcessCrossViewApplyDetailStatus(row, privatePidStatus, TRUE);
    }
    else {
        context->lastStatus = privatePidStatus;
        row->lastStatus = privatePidStatus;
        kswordArkProcessCrossViewApplyDetailStatus(row, privatePidStatus, FALSE);
    }
    if (evidenceProcessId != 0UL && evidenceProcessId != processId) {
        row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_PID_FIELD_MISMATCH;
        row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_DATA_MISMATCH;
        row->lastStatus = STATUS_DATA_ERROR;
    }
    kswordArkProcessCrossViewRecordSourceEvidence(row, sourceMask, sourceProcessId, sourceStatus);
    if (detailText != NULL && row->detail[0] == '\0') {
        kswordArkCrossViewFormatDetail(row->detail, sizeof(row->detail), "%s", detailText);
    }
}

static VOID
kswordArkProcessCrossViewMergeDanglingCandidate(
    _Inout_ KswProcessCrossviewContext* context,
    _In_ ULONG64 objectAddress,
    _In_ ULONG processId,
    _In_ ULONG sourceMask,
    _In_ NTSTATUS sourceStatus,
    _In_z_ PCSTR detailText
    )
/*++

Routine Description:

    Merge a CID/list candidate whose object address could not be safely
    referenced, preserving it as read-only evidence.

Arguments:

    Context - Mutable query context.
    ObjectAddress - Candidate object body address.
    ProcessId - Candidate PID derived from the CID table or object field.
    SourceMask - Evidence source bit.
    SourceStatus - Reference/read failure status.
    DetailText - Human-readable reason for the dangling classification.

Return Value:

    None.

--*/
{
    KSWORD_ARK_PROCESS_CROSSVIEW_ROW* row = NULL;

    if (context == NULL || objectAddress == 0ULL) {
        return;
    }
    if (!kswordArkProcessCrossViewPidInRequest(context, processId)) {
        return;
    }

    row = kswordArkProcessCrossViewGetOrCreateRow(context, objectAddress, processId);
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
    row->lastStatus = sourceStatus;
    kswordArkProcessCrossViewRecordSourceEvidence(row, sourceMask, processId, sourceStatus);
    if (row->detail[0] == '\0') {
        kswordArkCrossViewFormatDetail(row->detail, sizeof(row->detail), "%s", detailText);
    }
}

static NTSTATUS
kswordArkCrossViewTryReferenceTypedObject(
    _In_ PVOID candidateObject,
    _In_ POBJECT_TYPE expectedObjectType,
    _Out_ BOOLEAN* typeMatchedOut,
    _Out_ BOOLEAN* referencedOut
    )
/*++

Routine Description:

    Validate a decoded kernel object by type and attempt to take a balanced
    reference without trusting caller-supplied addresses.

Arguments:

    CandidateObject - Decoded object body pointer from a kernel-owned source.
    ExpectedObjectType - Required object type, such as PsProcessType.
    TypeMatchedOut - Receives whether ObGetObjectType matched ExpectedObjectType.
    ReferencedOut - Receives whether the reference was taken.

Return Value:

    STATUS_SUCCESS when a reference was taken; object-type or reference status
    otherwise. Caller must dereference CandidateObject only when ReferencedOut is
    TRUE.

    STATUS_DELETE_PENDING means the candidate is a real object that is already
    being torn down - the caller should report it as a dangling observation
    rather than treat it as a read failure.

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
    // CandidateObject came out of ActiveProcessLinks or PspCidTable, so we hold
    // no reference on it and it may already be mid-deletion: a process that has
    // exited keeps its list membership until PspProcessDelete runs, which is
    // after its pointer count reaches zero.  ObReferenceObjectByPointer would
    // bugcheck 0x18 on exactly that object, and the __try around it would never
    // see anything, so take the reference by hand instead.
    //
    status = kswordArkObjectHeaderReferenceObjectSafe(candidateObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // The type was read before the reference existed.  Read it again now that
    // the object cannot be deleted, so a body recycled between the two steps
    // cannot be reported as a process.
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

static NTSTATUS
kswordArkCrossViewResolveRelativeAddress(
    _In_reads_bytes_(instructionLength) const UCHAR* instructionAddress,
    _In_ ULONG displacementOffset,
    _In_ ULONG instructionLength,
    _Out_ PVOID* addressOut
    )
/*++

Routine Description:

    Resolve one x64 RIP-relative instruction target in read-only fashion.

Arguments:

    InstructionAddress - Address of the instruction bytes.
    DisplacementOffset - Offset of the signed displacement.
    InstructionLength - Full instruction length.
    AddressOut - Receives the resolved kernel address.

Return Value:

    STATUS_SUCCESS on success; otherwise validation or read status.

--*/
{
    LONG relativeOffset = 0;
    ULONG_PTR resolvedAddress = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (instructionAddress == NULL || addressOut == NULL ||
        displacementOffset > instructionLength ||
        (instructionLength - displacementOffset) < sizeof(relativeOffset)) {
        return STATUS_INVALID_PARAMETER;
    }
    *addressOut = NULL;

    status = kswordArkCrossViewReadMemory(
        instructionAddress + displacementOffset,
        &relativeOffset,
        sizeof(relativeOffset));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    resolvedAddress =
        (ULONG_PTR)instructionAddress +
        (ULONG_PTR)instructionLength +
        (ULONG_PTR)relativeOffset;
    if (resolvedAddress == 0U) {
        return STATUS_NOT_FOUND;
    }

    *addressOut = (PVOID)resolvedAddress;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkCrossViewTryResolveMovRip(
    _In_reads_bytes_(KSW_CROSSVIEW_PSP_CID_SCAN_BYTES) const UCHAR* scanBase,
    _In_ ULONG offset,
    _In_ UCHAR modRmByte,
    _Out_ PVOID* pspCidTableAddressOut
    )
/*++

Routine Description:

    Match a RIP-relative mov r64, qword ptr [rip+disp32] instruction variant.

Arguments:

    ScanBase - Function bytes being scanned.
    Offset - Candidate instruction offset.
    ModRmByte - Expected ModR/M byte, for example 0x05 for RAX or 0x0D for RCX.
    PspCidTableAddressOut - Receives the resolved global-variable address.

Return Value:

    STATUS_SUCCESS when matched; STATUS_NOT_FOUND when the bytes do not match;
    otherwise guarded read status.

--*/
{
    UCHAR instructionBytes[3] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    if (scanBase == NULL || pspCidTableAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *pspCidTableAddressOut = NULL;

    if ((offset + 7UL) > KSW_CROSSVIEW_PSP_CID_SCAN_BYTES) {
        return STATUS_NOT_FOUND;
    }

    status = kswordArkCrossViewReadMemory(scanBase + offset, instructionBytes, sizeof(instructionBytes));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (instructionBytes[0] != 0x48U || instructionBytes[1] != 0x8BU || instructionBytes[2] != modRmByte) {
        return STATUS_NOT_FOUND;
    }

    return kswordArkCrossViewResolveRelativeAddress(
        scanBase + offset,
        3UL,
        7UL,
        pspCidTableAddressOut);
}

static NTSTATUS
kswordArkCrossViewTryResolveThroughCallTarget(
    _In_reads_bytes_(KSW_CROSSVIEW_PSP_CID_SCAN_BYTES) const UCHAR* scanBase,
    _In_ ULONG offset,
    _Out_ PVOID* pspCidTableAddressOut
    )
/*++

Routine Description:

    Follow a nearby call in PsLookupProcessByProcessId and scan the target for a
    PspCidTable RIP-relative load, matching the existing DKOM resolver pattern
    without performing any write.

Arguments:

    ScanBase - Function bytes being scanned.
    Offset - Candidate call offset.
    PspCidTableAddressOut - Receives the resolved global-variable address.

Return Value:

    STATUS_SUCCESS when resolved; STATUS_NOT_FOUND for non-matches; otherwise a
    guarded read status.

--*/
{
    UCHAR opcode = 0U;
    PVOID callTarget = NULL;
    const UCHAR* targetBytes = NULL;
    ULONG targetOffset = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (scanBase == NULL || pspCidTableAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *pspCidTableAddressOut = NULL;

    if ((offset + 5UL) > KSW_CROSSVIEW_PSP_CID_SCAN_BYTES) {
        return STATUS_NOT_FOUND;
    }

    status = kswordArkCrossViewReadMemory(scanBase + offset, &opcode, sizeof(opcode));
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (opcode != 0xE8U) {
        return STATUS_NOT_FOUND;
    }

    status = kswordArkCrossViewResolveRelativeAddress(scanBase + offset, 1UL, 5UL, &callTarget);
    if (!NT_SUCCESS(status) || callTarget == NULL) {
        return status;
    }

    targetBytes = (const UCHAR*)callTarget;
    for (targetOffset = 0UL; targetOffset < 0x40UL; ++targetOffset) {
        PVOID resolvedAddress = NULL;
        NTSTATUS movStatus = STATUS_SUCCESS;

        movStatus = kswordArkCrossViewTryResolveMovRip(targetBytes, targetOffset, 0x05U, &resolvedAddress);
        if (NT_SUCCESS(movStatus) && resolvedAddress != NULL) {
            *pspCidTableAddressOut = resolvedAddress;
            return STATUS_SUCCESS;
        }

        movStatus = kswordArkCrossViewTryResolveMovRip(targetBytes, targetOffset, 0x0DU, &resolvedAddress);
        if (NT_SUCCESS(movStatus) && resolvedAddress != NULL) {
            *pspCidTableAddressOut = resolvedAddress;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

static NTSTATUS
kswordArkCrossViewResolvePspCidTableByPattern(
    _Out_ PVOID* pspCidTableAddressOut
    )
/*++

Routine Description:

    Locate the PspCidTable global-variable address by scanning
    PsLookupProcessByProcessId, as a read-only fallback when DynData does not
    provide the global RVA.

Arguments:

    PspCidTableAddressOut - Receives the address of the PspCidTable global.

Return Value:

    STATUS_SUCCESS when found; STATUS_NOT_FOUND or last guarded-read status on
    failure.

--*/
{
    const UCHAR* lookupBytes = (const UCHAR*)PsLookupProcessByProcessId;
    ULONG offset = 0UL;
    NTSTATUS lastStatus = STATUS_NOT_FOUND;

    if (pspCidTableAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *pspCidTableAddressOut = NULL;

    if (lookupBytes == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    for (offset = 0UL; offset < KSW_CROSSVIEW_PSP_CID_SCAN_BYTES; ++offset) {
        PVOID resolvedAddress = NULL;
        NTSTATUS status = STATUS_SUCCESS;

        status = kswordArkCrossViewTryResolveMovRip(lookupBytes, offset, 0x05U, &resolvedAddress);
        if (NT_SUCCESS(status) && resolvedAddress != NULL) {
            *pspCidTableAddressOut = resolvedAddress;
            return STATUS_SUCCESS;
        }
        if (status != STATUS_NOT_FOUND) {
            lastStatus = status;
        }

        status = kswordArkCrossViewTryResolveMovRip(lookupBytes, offset, 0x0DU, &resolvedAddress);
        if (NT_SUCCESS(status) && resolvedAddress != NULL) {
            *pspCidTableAddressOut = resolvedAddress;
            return STATUS_SUCCESS;
        }
        if (status != STATUS_NOT_FOUND) {
            lastStatus = status;
        }

        status = kswordArkCrossViewTryResolveThroughCallTarget(lookupBytes, offset, &resolvedAddress);
        if (NT_SUCCESS(status) && resolvedAddress != NULL) {
            *pspCidTableAddressOut = resolvedAddress;
            return STATUS_SUCCESS;
        }
        if (status != STATUS_NOT_FOUND) {
            lastStatus = status;
        }
    }

    return lastStatus;
}

NTSTATUS
kswordArkCrossViewResolvePspCidTableAddress(
    _In_ const KswDynState* dynState,
    _Inout_ KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS* offsets,
    _Out_ PVOID* pspCidTableAddressOut,
    _Out_ ULONG64* missingCapabilityMaskOut,
    _Out_ BOOLEAN* usedDynDataGlobalOut
    )
/*++

Routine Description:

    Resolve the PspCidTable global-variable address, preferring the DynData
    kernel global RVA and falling back to the existing pattern-resolver strategy.

Arguments:

    DynState - Query-time DynData snapshot.
    Offsets - Protocol offsets packet updated with the resolved VA.
    PspCidTableAddressOut - Receives the address of the PspCidTable global.
    MissingCapabilityMaskOut - Receives missing capability bits for diagnostics.
    UsedDynDataGlobalOut - Receives TRUE when the DynData global was used.

Return Value:

    STATUS_SUCCESS on success; otherwise a capability or resolver status.

--*/
{
    PVOID pspCidTableAddress = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (pspCidTableAddressOut == NULL || missingCapabilityMaskOut == NULL || usedDynDataGlobalOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *pspCidTableAddressOut = NULL;
    *missingCapabilityMaskOut = 0ULL;
    *usedDynDataGlobalOut = FALSE;

    if (dynState != NULL &&
        dynState->initialized &&
        dynState->ntosActive &&
        dynState->ntoskrnl.imageBase != 0ULL &&
        dynState->ntoskrnl.sizeOfImage != 0UL &&
        kswordArkCrossViewGlobalRvaPresent(dynState->kernelGlobals.pspCidTable)) {
        const ULONG kRva = dynState->kernelGlobals.pspCidTable;
        if (kRva < dynState->ntoskrnl.sizeOfImage &&
            (sizeof(PVOID) <= (SIZE_T)(dynState->ntoskrnl.sizeOfImage - kRva))) {
            pspCidTableAddress = (PVOID)(ULONG_PTR)(dynState->ntoskrnl.imageBase + (ULONG64)kRva);
            *pspCidTableAddressOut = pspCidTableAddress;
            *usedDynDataGlobalOut = TRUE;
            if (offsets != NULL) {
                offsets->pspCidTableRva = kRva;
                offsets->pspCidTableAddress = (ULONG64)(ULONG_PTR)pspCidTableAddress;
                offsets->pspCidTableSource = dynState->kernelGlobalSources.pspCidTable;
            }
            return STATUS_SUCCESS;
        }
    }

    status = kswordArkCrossViewResolvePspCidTableByPattern(&pspCidTableAddress);
    if (NT_SUCCESS(status) && pspCidTableAddress != NULL) {
        *pspCidTableAddressOut = pspCidTableAddress;
        if (offsets != NULL) {
            offsets->pspCidTableAddress = (ULONG64)(ULONG_PTR)pspCidTableAddress;
            offsets->pspCidTableSource = KSWORD_ARK_CROSSVIEW_FIELD_SOURCE_RUNTIME_PATTERN;
        }
        return STATUS_SUCCESS;
    }

    *missingCapabilityMaskOut = KSW_CAP_KERNEL_GLOBALS | KSW_CAP_CID_TABLE_WALK;
    return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
}

static PVOID
kswordArkCrossViewDecodeCidEntryObject(
    _In_ ULONGLONG entryValue
    )
/*++

Routine Description:

    Decode a HandleTableEntry LowValue into an object body pointer using the
    same read-only decoding used by the DKOM diagnostics.

Arguments:

    EntryValue - Raw LowValue field from the CID table entry.

Return Value:

    Decoded object body pointer, or NULL when the entry is empty.

--*/
{
    ULONGLONG objectValue = 0ULL;

    if (entryValue == 0ULL) {
        return NULL;
    }

#if defined(_WIN64)
    objectValue = (ULONGLONG)(((LONGLONG)entryValue) >> 0x10);
    objectValue &= 0xFFFFFFFFFFFFFFF0ULL;
#else
    objectValue = EntryValue & ~(ULONGLONG)0x7U;
#endif

    return (PVOID)(ULONG_PTR)objectValue;
}

static NTSTATUS
kswordArkCrossViewReadCidTableRoot(
    _In_ const KswDynState* dynState,
    _In_ PVOID pspCidTableAddress,
    _Out_ ULONGLONG* tableRootOut,
    _Out_ ULONG* tableLevelOut
    )
/*++

Routine Description:

    Read PspCidTable -> HandleTable -> TableCode and split the encoded root and
    table level.

Arguments:

    DynState - DynData snapshot containing HandleTable.TableCode offset.
    PspCidTableAddress - Address of the PspCidTable global variable.
    TableRootOut - Receives the decoded table root address.
    TableLevelOut - Receives the table level bits.

Return Value:

    STATUS_SUCCESS on success; STATUS_PROCEDURE_NOT_FOUND when required offsets
    are missing; otherwise guarded read status.

--*/
{
    PVOID handleTable = NULL;
    ULONGLONG tableCode = 0ULL;
    ULONG tableCodeOffset = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (dynState == NULL || pspCidTableAddress == NULL || tableRootOut == NULL || tableLevelOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *tableRootOut = 0ULL;
    *tableLevelOut = 0UL;

    tableCodeOffset = kswordArkCrossViewEffectiveHtTableCodeOffset(dynState, NULL);

    status = kswordArkCrossViewReadPointerAddress(pspCidTableAddress, &handleTable);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (handleTable == NULL || !kswordArkCrossViewPointerAligned((ULONG_PTR)handleTable)) {
        return STATUS_NOT_FOUND;
    }

    status = kswordArkCrossViewReadUlong64Address((PUCHAR)handleTable + tableCodeOffset, &tableCode);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *tableLevelOut = (ULONG)(tableCode & KSW_CROSSVIEW_CID_TABLE_LEVEL_MASK);
    *tableRootOut = tableCode & ~KSW_CROSSVIEW_CID_TABLE_LEVEL_MASK;
    return (*tableRootOut != 0ULL && kswordArkCrossViewPointerAligned((ULONG_PTR)*tableRootOut))
        ? STATUS_SUCCESS
        : STATUS_NOT_FOUND;
}

static VOID
kswordArkCrossViewReportCidCandidate(
    _Inout_ KswCrossviewCidWalkContext* context,
    _In_ PVOID objectBody,
    _In_ ULONG cidValue,
    _In_ NTSTATUS entryReadStatus
    )
/*++

Routine Description:

    Validate, reference, report, and dereference one decoded CID-table object.

Arguments:

    Context - CID walker context containing the callback and expected type.
    ObjectBody - Decoded object body pointer.
    CidValue - CID value represented by the table slot.
    EntryReadStatus - Status from reading the table entry.

Return Value:

    None. References are released before this function returns.

--*/
{
    KswCrossviewCidEntry entry;
    BOOLEAN typeMatched = FALSE;
    BOOLEAN referenced = FALSE;
    NTSTATUS referenceStatus = STATUS_SUCCESS;

    if (context == NULL || context->callback == NULL || objectBody == NULL) {
        return;
    }
    if (!kswordArkCrossViewPointerAligned((ULONG_PTR)objectBody)) {
        return;
    }

    RtlZeroMemory(&entry, sizeof(entry));
    referenceStatus = kswordArkCrossViewTryReferenceTypedObject(
        objectBody,
        context->expectedObjectType,
        &typeMatched,
        &referenced);
    if (!typeMatched) {
        return;
    }

    entry.object = referenced ? objectBody : NULL;
    entry.objectAddress = (ULONG64)(ULONG_PTR)objectBody;
    entry.cidValue = cidValue;
    entry.referenced = referenced;
    entry.typeMatched = typeMatched;
    entry.referenceStatus = NT_SUCCESS(referenceStatus) ? entryReadStatus : referenceStatus;

    context->callback(&entry, context->callbackContext);
    context->reportedEntries += 1UL;

    if (referenced) {
        ObDereferenceObject(objectBody);
    }
}

static NTSTATUS
kswordArkCrossViewWalkCidLevel0Table(
    _Inout_ KswCrossviewCidWalkContext* context,
    _In_ ULONGLONG tableAddress,
    _In_ ULONGLONG handleIndexBase
    )
/*++

Routine Description:

    Walk one leaf table of HandleTableEntry records in read-only mode.

Arguments:

    Context - CID walker state.
    TableAddress - Address of the leaf table.
    HandleIndexBase - Base handle index represented by entry zero.

Return Value:

    STATUS_SUCCESS when the leaf was bounded-scanned; STATUS_BUFFER_OVERFLOW
    when MaxNodes was reached; otherwise the most recent guarded read status.

--*/
{
    ULONG entryIndex = 0UL;
    ULONG lowValueOffset = 0UL;
    NTSTATUS lastStatus = STATUS_SUCCESS;

    if (context == NULL || tableAddress == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkCrossViewPointerAligned((ULONG_PTR)tableAddress)) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }
    lowValueOffset = kswordArkCrossViewEffectiveHteLowValueOffset(context->dynState, NULL);

    for (entryIndex = 0UL; entryIndex < KSW_CROSSVIEW_CID_LEVEL0_ENTRY_COUNT; ++entryIndex) {
        ULONGLONG lowValue = 0ULL;
        PVOID objectBody = NULL;
        NTSTATUS status = STATUS_SUCCESS;
        const ULONGLONG kHandleIndex = handleIndexBase + (ULONGLONG)entryIndex;
        const ULONGLONG kCidValue64 = kHandleIndex * KSW_CROSSVIEW_CID_HANDLE_VALUE_STRIDE;
        PVOID lowValueAddress = (PVOID)(ULONG_PTR)(
            tableAddress +
            ((ULONGLONG)entryIndex * KSW_CROSSVIEW_CID_ENTRY_BYTES) +
            (ULONGLONG)lowValueOffset);

        if (context->visitedEntries >= context->maxNodes) {
            context->lastStatus = STATUS_BUFFER_OVERFLOW;
            return STATUS_BUFFER_OVERFLOW;
        }
        context->visitedEntries += 1UL;

        status = kswordArkCrossViewReadUlong64Address(lowValueAddress, &lowValue);
        if (!NT_SUCCESS(status)) {
            lastStatus = status;
            context->lastStatus = status;
            continue;
        }

        objectBody = kswordArkCrossViewDecodeCidEntryObject(lowValue);
        if (objectBody == NULL || kCidValue64 > MAXULONG) {
            continue;
        }

        kswordArkCrossViewReportCidCandidate(
            context,
            objectBody,
            (ULONG)kCidValue64,
            status);
    }

    return lastStatus;
}

static NTSTATUS
kswordArkCrossViewWalkCidLevel1Table(
    _Inout_ KswCrossviewCidWalkContext* context,
    _In_ ULONGLONG tableAddress,
    _In_ ULONGLONG handleIndexBase
    )
/*++

Routine Description:

    Walk a level-1 CID table by reading child leaf pointers and scanning each
    child leaf with the same MaxNodes budget.

Arguments:

    Context - CID walker state.
    TableAddress - Address of the pointer table.
    HandleIndexBase - Base handle index represented by pointer slot zero.

Return Value:

    STATUS_SUCCESS or the last non-not-found child status; STATUS_BUFFER_OVERFLOW
    when the MaxNodes bound is reached.

--*/
{
    ULONG pointerIndex = 0UL;
    NTSTATUS lastStatus = STATUS_SUCCESS;

    if (context == NULL || tableAddress == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkCrossViewPointerAligned((ULONG_PTR)tableAddress)) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    for (pointerIndex = 0UL; pointerIndex < KSW_CROSSVIEW_CID_POINTER_ENTRY_COUNT; ++pointerIndex) {
        PVOID childTable = NULL;
        NTSTATUS status = STATUS_SUCCESS;
        const ULONGLONG kChildBase =
            handleIndexBase +
            ((ULONGLONG)pointerIndex * (ULONGLONG)KSW_CROSSVIEW_CID_LEVEL0_ENTRY_COUNT);

        status = kswordArkCrossViewReadPointerAddress(
            (PVOID)(ULONG_PTR)(tableAddress + ((ULONGLONG)pointerIndex * sizeof(PVOID))),
            &childTable);
        if (!NT_SUCCESS(status)) {
            lastStatus = status;
            context->lastStatus = status;
            continue;
        }
        if (childTable == NULL) {
            continue;
        }

        status = kswordArkCrossViewWalkCidLevel0Table(context, (ULONGLONG)(ULONG_PTR)childTable, kChildBase);
        if (status == STATUS_BUFFER_OVERFLOW) {
            return status;
        }
        if (!NT_SUCCESS(status) && status != STATUS_NOT_FOUND) {
            lastStatus = status;
        }
    }

    return lastStatus;
}

static NTSTATUS
kswordArkCrossViewWalkCidLevel2Table(
    _Inout_ KswCrossviewCidWalkContext* context,
    _In_ ULONGLONG tableAddress
    )
/*++

Routine Description:

    Walk a level-2 CID table by reading middle-table pointers and delegating to
    the level-1 walker under the same MaxNodes bound.

Arguments:

    Context - CID walker state.
    TableAddress - Address of the top-level pointer table.

Return Value:

    STATUS_SUCCESS or the last child status; STATUS_BUFFER_OVERFLOW when the
    MaxNodes bound is reached.

--*/
{
    ULONG pointerIndex = 0UL;
    NTSTATUS lastStatus = STATUS_SUCCESS;

    if (context == NULL || tableAddress == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkCrossViewPointerAligned((ULONG_PTR)tableAddress)) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    for (pointerIndex = 0UL; pointerIndex < KSW_CROSSVIEW_CID_POINTER_ENTRY_COUNT; ++pointerIndex) {
        PVOID childTable = NULL;
        NTSTATUS status = STATUS_SUCCESS;
        const ULONGLONG kChildBase =
            (ULONGLONG)pointerIndex *
            (ULONGLONG)KSW_CROSSVIEW_CID_POINTER_ENTRY_COUNT *
            (ULONGLONG)KSW_CROSSVIEW_CID_LEVEL0_ENTRY_COUNT;

        status = kswordArkCrossViewReadPointerAddress(
            (PVOID)(ULONG_PTR)(tableAddress + ((ULONGLONG)pointerIndex * sizeof(PVOID))),
            &childTable);
        if (!NT_SUCCESS(status)) {
            lastStatus = status;
            context->lastStatus = status;
            continue;
        }
        if (childTable == NULL) {
            continue;
        }

        status = kswordArkCrossViewWalkCidLevel1Table(context, (ULONGLONG)(ULONG_PTR)childTable, kChildBase);
        if (status == STATUS_BUFFER_OVERFLOW) {
            return status;
        }
        if (!NT_SUCCESS(status) && status != STATUS_NOT_FOUND) {
            lastStatus = status;
        }
    }

    return lastStatus;
}

NTSTATUS
kswordArkCrossViewWalkCidTable(
    _In_ const KswDynState* dynState,
    _In_ PVOID pspCidTableAddress,
    _In_ POBJECT_TYPE expectedObjectType,
    _In_ ULONG maxNodes,
    _In_ KswCrossviewCidCallback callback,
    _Inout_opt_ PVOID context,
    _Out_opt_ ULONG* visitedEntriesOut
    )
/*++

Routine Description:

    Walk PspCidTable in read-only mode, validate decoded object types, and report
    referenced or dangling type-matched candidates to the caller callback.

Arguments:

    DynState - DynData snapshot containing handle-table decode offsets.
    PspCidTableAddress - Address of the PspCidTable global variable.
    ExpectedObjectType - Object type required for decoded candidates.
    MaxNodes - Maximum leaf entries to inspect.
    Callback - Caller callback for each type-matched candidate.
    Context - Caller-owned callback context.
    VisitedEntriesOut - Optional count of inspected leaf entries.

Return Value:

    STATUS_SUCCESS when the bounded walk completes; STATUS_BUFFER_OVERFLOW when
    MaxNodes is reached; or validation/read/capability status.

--*/
{
    KswCrossviewCidWalkContext walkContext;
    ULONGLONG tableRoot = 0ULL;
    ULONG tableLevel = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (visitedEntriesOut != NULL) {
        *visitedEntriesOut = 0UL;
    }
    if (dynState == NULL || pspCidTableAddress == NULL || expectedObjectType == NULL || callback == NULL || maxNodes == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    status = kswordArkCrossViewReadCidTableRoot(dynState, pspCidTableAddress, &tableRoot, &tableLevel);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(&walkContext, sizeof(walkContext));
    walkContext.dynState = dynState;
    walkContext.expectedObjectType = expectedObjectType;
    walkContext.maxNodes = maxNodes;
    walkContext.lastStatus = STATUS_SUCCESS;
    walkContext.callback = callback;
    walkContext.callbackContext = context;

    if (tableLevel == 0UL) {
        status = kswordArkCrossViewWalkCidLevel0Table(&walkContext, tableRoot, 0ULL);
    }
    else if (tableLevel == 1UL) {
        status = kswordArkCrossViewWalkCidLevel1Table(&walkContext, tableRoot, 0ULL);
    }
    else if (tableLevel == 2UL) {
        status = kswordArkCrossViewWalkCidLevel2Table(&walkContext, tableRoot);
    }
    else {
        status = STATUS_NOT_SUPPORTED;
    }

    if (visitedEntriesOut != NULL) {
        *visitedEntriesOut = walkContext.visitedEntries;
    }
    if (status == STATUS_SUCCESS && !NT_SUCCESS(walkContext.lastStatus)) {
        status = walkContext.lastStatus;
    }
    return status;
}

NTSTATUS
kswordArkCrossViewReferenceProcessByActiveList(
    _In_ const KswDynState* dynState,
    _In_ ULONG processId,
    _In_ ULONG maxNodes,
    _Outptr_ PEPROCESS* processOut,
    _Out_opt_ ULONG* uniqueProcessIdOut,
    _Out_opt_ ULONG* visitedEntriesOut
    )
/*++

Routine Description:

    Resolve one process object from ActiveProcessLinks and return a stable
    reference to the caller. Note: This is a hook-resistant parsing backend for terminating processes.
    It traverses only kernel lists and calls ObReferenceObjectByPointer, without
    invoking NtOpenProcess, ZwOpenProcess, or PsLookupProcessByProcessId.

Arguments:

    DynState - DynData snapshot with process list offsets.
    ProcessId - PID-like value requested by R3.
    MaxNodes - Maximum ActiveProcessLinks nodes to inspect.
    ProcessOut - Receives a referenced EPROCESS on success.
    UniqueProcessIdOut - Optionally receives the matched UniqueProcessId field.
    VisitedEntriesOut - Optionally receives the number of inspected nodes.

Return Value:

    STATUS_SUCCESS when a referenced EPROCESS was found; otherwise a validation,
    capability, read, or not-found status.

--*/
{
    LIST_ENTRY* head = NULL;
    LIST_ENTRY* current = NULL;
    KswCrossviewVisitedSet visited;
    ULONG walked = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS lastStatus = STATUS_NOT_FOUND;

    if (processOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *processOut = NULL;
    if (uniqueProcessIdOut != NULL) {
        *uniqueProcessIdOut = 0UL;
    }
    if (visitedEntriesOut != NULL) {
        *visitedEntriesOut = 0UL;
    }
    if (dynState == NULL || processId == 0UL || maxNodes == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkCrossViewOffsetPresent(dynState->kernel.epActiveProcessLinks) ||
        !kswordArkCrossViewOffsetPresent(dynState->kernel.epUniqueProcessId) ||
        PsInitialSystemProcess == NULL ||
        PsProcessType == NULL ||
        *PsProcessType == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    RtlZeroMemory(&visited, sizeof(visited));
    status = kswordArkCrossViewVisitedInitialize(&visited, maxNodes);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    head = (LIST_ENTRY*)((PUCHAR)PsInitialSystemProcess + dynState->kernel.epActiveProcessLinks);
    if (!kswordArkCrossViewPointerAligned((ULONG_PTR)head)) {
        kswordArkCrossViewVisitedDestroy(&visited);
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    status = kswordArkCrossViewReadPointerAddress(&head->Flink, (PVOID*)&current);
    if (!NT_SUCCESS(status)) {
        kswordArkCrossViewVisitedDestroy(&visited);
        return status;
    }

    while (current != NULL && current != head) {
        LIST_ENTRY* next = NULL;
        PVOID candidateObject = NULL;
        PVOID uniqueProcessIdPointer = NULL;
        ULONG uniqueProcessId = 0UL;
        BOOLEAN typeMatched = FALSE;
        BOOLEAN referenced = FALSE;
        NTSTATUS referenceStatus = STATUS_SUCCESS;

        if (walked >= maxNodes) {
            lastStatus = STATUS_BUFFER_OVERFLOW;
            break;
        }
        walked += 1UL;

        if (!kswordArkCrossViewPointerAligned((ULONG_PTR)current) ||
            kswordArkCrossViewVisitedCheckAndAdd(&visited, (ULONG_PTR)current)) {
            lastStatus = STATUS_DATATYPE_MISALIGNMENT;
            break;
        }

        status = kswordArkCrossViewReadPointerAddress(&current->Flink, (PVOID*)&next);
        if (!NT_SUCCESS(status)) {
            lastStatus = status;
            break;
        }

        candidateObject = (PVOID)((PUCHAR)current - dynState->kernel.epActiveProcessLinks);
        referenceStatus = kswordArkCrossViewTryReferenceTypedObject(
            candidateObject,
            *PsProcessType,
            &typeMatched,
            &referenced);
        if (!typeMatched) {
            lastStatus = referenceStatus;
            current = next;
            continue;
        }
        if (!referenced) {
            lastStatus = referenceStatus;
            current = next;
            continue;
        }

        status = kswordArkCrossViewReadPointerField(
            candidateObject,
            dynState->kernel.epUniqueProcessId,
            &uniqueProcessIdPointer);
        if (NT_SUCCESS(status)) {
            uniqueProcessId = HandleToULong(uniqueProcessIdPointer);
        }
        else {
            uniqueProcessId = HandleToULong(PsGetProcessId((PEPROCESS)candidateObject));
            lastStatus = status;
        }

        if (uniqueProcessId == processId ||
            HandleToULong(PsGetProcessId((PEPROCESS)candidateObject)) == processId) {
            *processOut = (PEPROCESS)candidateObject;
            if (uniqueProcessIdOut != NULL) {
                *uniqueProcessIdOut = uniqueProcessId;
            }
            if (visitedEntriesOut != NULL) {
                *visitedEntriesOut = walked;
            }
            kswordArkCrossViewVisitedDestroy(&visited);
            return STATUS_SUCCESS;
        }

        ObDereferenceObject(candidateObject);
        current = next;
    }

    if (visitedEntriesOut != NULL) {
        *visitedEntriesOut = walked;
    }
    kswordArkCrossViewVisitedDestroy(&visited);
    return lastStatus;
}

static VOID
kswordArkProcessCrossViewCollectPublicWalk(
    _Inout_ KswProcessCrossviewContext* context
    )
/*++

Routine Description:

    Collect the public PsGetNextProcess process view. Every returned process
    reference is dereferenced exactly once after row merging.

Arguments:

    Context - Mutable query context.

Return Value:

    None. Failures are recorded in Context->LastStatus and response status.

--*/
{
    KswCrossviewPsGetNextProcessFn psGetNextProcess = NULL;
    PEPROCESS processCursor = NULL;
    ULONG visited = 0UL;

    if (context == NULL) {
        return;
    }

    psGetNextProcess = kswordArkProcessCrossViewResolvePsGetNextProcess();
    if (psGetNextProcess == NULL) {
        context->lastStatus = STATUS_PROCEDURE_NOT_FOUND;
        context->capabilityMissing = TRUE;
        return;
    }

    processCursor = psGetNextProcess(NULL);
    while (processCursor != NULL) {
        PEPROCESS nextProcess = NULL;

        if (visited >= context->maxNodes) {
            context->truncated = TRUE;
            context->lastStatus = STATUS_BUFFER_OVERFLOW;
            ObDereferenceObject(processCursor);
            break;
        }
        visited += 1UL;

        nextProcess = psGetNextProcess(processCursor);
        kswordArkProcessCrossViewMergeProcessObject(
            context,
            processCursor,
            KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK,
            STATUS_SUCCESS,
            HandleToULong(PsGetProcessId(processCursor)),
            "Observed through PsGetNextProcess.");
        ObDereferenceObject(processCursor);
        processCursor = nextProcess;
    }
}

static VOID
kswordArkProcessCrossViewCollectActiveList(
    _Inout_ KswProcessCrossviewContext* context
    )
/*++

Routine Description:

    Walk EPROCESS.ActiveProcessLinks from PsInitialSystemProcess using DynData
    offsets. Traversal uses a node budget, pointer alignment checks, loop
    detection, guarded reads, and object references before trusting rows.

Arguments:

    Context - Mutable query context.

Return Value:

    None. Capability/read failures are recorded in Context.

--*/
{
    LIST_ENTRY* head = NULL;
    LIST_ENTRY* current = NULL;
    KswCrossviewVisitedSet visited;
    ULONG walked = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (context == NULL) {
        return;
    }
    RtlZeroMemory(&visited, sizeof(visited));

    if ((context->dynState.capabilityMask & KSW_CAP_PROCESS_LIST_FIELDS) != KSW_CAP_PROCESS_LIST_FIELDS ||
        !kswordArkCrossViewOffsetPresent(context->dynState.kernel.epActiveProcessLinks) ||
        !kswordArkCrossViewOffsetPresent(context->dynState.kernel.epUniqueProcessId) ||
        PsProcessType == NULL ||
        *PsProcessType == NULL) {
        context->capabilityMissing = TRUE;
        context->missingCapabilityMask |= KSW_CAP_PROCESS_LIST_FIELDS;
        context->lastStatus = STATUS_PROCEDURE_NOT_FOUND;
        return;
    }
    if (PsInitialSystemProcess == NULL) {
        context->lastStatus = STATUS_PROCEDURE_NOT_FOUND;
        return;
    }

    status = kswordArkCrossViewVisitedInitialize(&visited, context->maxNodes);
    if (!NT_SUCCESS(status)) {
        context->lastStatus = status;
        return;
    }

    head = (LIST_ENTRY*)((PUCHAR)PsInitialSystemProcess + context->dynState.kernel.epActiveProcessLinks);
    if (!kswordArkCrossViewPointerAligned((ULONG_PTR)head)) {
        context->lastStatus = STATUS_DATATYPE_MISALIGNMENT;
        kswordArkCrossViewVisitedDestroy(&visited);
        return;
    }

    if (walked < context->maxNodes) {
        BOOLEAN typeMatched = FALSE;
        BOOLEAN referenced = FALSE;
        NTSTATUS referenceStatus = STATUS_SUCCESS;

        referenceStatus = kswordArkCrossViewTryReferenceTypedObject(
            PsInitialSystemProcess,
            (PsProcessType != NULL) ? *PsProcessType : NULL,
            &typeMatched,
            &referenced);
        if (referenced) {
            kswordArkProcessCrossViewMergeProcessObject(
                context,
                PsInitialSystemProcess,
                KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST,
                STATUS_SUCCESS,
                0UL,
                "Observed through ActiveProcessLinks head process.");
            ObDereferenceObject(PsInitialSystemProcess);
        }
        else if (typeMatched) {
            kswordArkProcessCrossViewMergeDanglingCandidate(
                context,
                (ULONG64)(ULONG_PTR)PsInitialSystemProcess,
                HandleToULong(PsGetProcessId(PsInitialSystemProcess)),
                KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST,
                referenceStatus,
                "ActiveProcessLinks head process type matched but could not be referenced.");
        }
        walked += 1UL;
    }
    else {
        context->truncated = TRUE;
        context->lastStatus = STATUS_BUFFER_OVERFLOW;
        kswordArkCrossViewVisitedDestroy(&visited);
        return;
    }

    status = kswordArkCrossViewReadPointerAddress(&head->Flink, (PVOID*)&current);
    if (!NT_SUCCESS(status)) {
        context->lastStatus = status;
        kswordArkCrossViewVisitedDestroy(&visited);
        return;
    }

    while (current != NULL && current != head) {
        LIST_ENTRY* next = NULL;
        LIST_ENTRY* blink = NULL;
        PEPROCESS processObject = NULL;
        PVOID candidateObject = NULL;
        PVOID processIdPointer = NULL;
        ULONG processId = 0UL;
        BOOLEAN typeMatched = FALSE;
        BOOLEAN referenced = FALSE;
        NTSTATUS referenceStatus = STATUS_SUCCESS;
        NTSTATUS readStatus = STATUS_SUCCESS;
        BOOLEAN linkMismatch = FALSE;

        if (walked >= context->maxNodes) {
            context->truncated = TRUE;
            context->lastStatus = STATUS_BUFFER_OVERFLOW;
            break;
        }
        walked += 1UL;

        if (!kswordArkCrossViewPointerAligned((ULONG_PTR)current) ||
            kswordArkCrossViewVisitedCheckAndAdd(&visited, (ULONG_PTR)current)) {
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

        candidateObject = (PVOID)((PUCHAR)current - context->dynState.kernel.epActiveProcessLinks);
        referenceStatus = kswordArkCrossViewTryReferenceTypedObject(
            candidateObject,
            (PsProcessType != NULL) ? *PsProcessType : NULL,
            &typeMatched,
            &referenced);

        if (referenced) {
            processObject = (PEPROCESS)candidateObject;
            kswordArkProcessCrossViewMergeProcessObject(
                context,
                processObject,
                KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST,
                linkMismatch ? STATUS_DATA_ERROR : STATUS_SUCCESS,
                0UL,
                linkMismatch ? "ActiveProcessLinks blink/flink mismatch observed." : "Observed through ActiveProcessLinks.");
            if (linkMismatch) {
                KSWORD_ARK_PROCESS_CROSSVIEW_ROW* row = kswordArkProcessCrossViewFindRow(
                    context,
                    (ULONG64)(ULONG_PTR)processObject,
                    HandleToULong(PsGetProcessId(processObject)));
                if (row != NULL) {
                    row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY;
                }
            }
            ObDereferenceObject(processObject);
        }
        else if (typeMatched) {
            (VOID)kswordArkCrossViewReadPointerField(
                candidateObject,
                context->dynState.kernel.epUniqueProcessId,
                &processIdPointer);
            processId = HandleToULong(processIdPointer);
            kswordArkProcessCrossViewMergeDanglingCandidate(
                context,
                (ULONG64)(ULONG_PTR)candidateObject,
                processId,
                KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST,
                referenceStatus,
                "ActiveProcessLinks candidate type matched but could not be referenced.");
        }

        current = next;
    }

    kswordArkCrossViewVisitedDestroy(&visited);
}

static VOID
kswordArkProcessCrossViewCidCallback(
    _In_ const KswCrossviewCidEntry* entry,
    _Inout_opt_ PVOID contextArg
    )
/*++

Routine Description:

    Merge one process object reported by the read-only CID table walker.

Arguments:

    Entry - CID walker payload, with a temporary reference when Referenced is
    TRUE.
    Context - KswProcessCrossviewContext owned by the query.

Return Value:

    None.

--*/
{
    KswProcessCrossviewContext* context = (KswProcessCrossviewContext*)contextArg;

    if (context == NULL || entry == NULL) {
        return;
    }

    if (entry->referenced && entry->object != NULL) {
        kswordArkProcessCrossViewMergeProcessObject(
            context,
            (PEPROCESS)entry->object,
            KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE,
            entry->referenceStatus,
            entry->cidValue,
            "Observed through PspCidTable.");
    }
    else if (entry->typeMatched) {
        kswordArkProcessCrossViewMergeDanglingCandidate(
            context,
            entry->objectAddress,
            entry->cidValue,
            KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE,
            entry->referenceStatus,
            "PspCidTable process candidate type matched but could not be referenced.");
    }
}

static VOID
kswordArkProcessCrossViewCollectCidTable(
    _Inout_ KswProcessCrossviewContext* context
    )
/*++

Routine Description:

    Collect process evidence from PspCidTable without deleting, clearing, or
    modifying any table entry.

Arguments:

    Context - Mutable query context.

Return Value:

    None. Resolver, capability, and read statuses are recorded in Context.

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
     * HtTableCode and HteLowValue have bounded read-only fallbacks in the
     * walker, so a missing PDB field must not disable the entire CID view.
     * Object-type validation remains mandatory before any decoded entry is
     * referenced.
     */
    if (PsProcessType == NULL || *PsProcessType == NULL) {
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
        *PsProcessType,
        context->maxNodes,
        kswordArkProcessCrossViewCidCallback,
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
kswordArkProcessCrossViewFinalizeRows(
    _Inout_ KswProcessCrossviewContext* context
    )
/*++

Routine Description:

    Compute process anomaly flags and confidence after all selected evidence
    sources have been merged.

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
        KSWORD_ARK_PROCESS_CROSSVIEW_ROW* row = &context->rows[index];
        const BOOLEAN kHasPublic = ((row->sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) != 0UL) ? TRUE : FALSE;
        const BOOLEAN kHasActive = ((row->sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST) != 0UL) ? TRUE : FALSE;
        const BOOLEAN kHasCid = ((row->sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) != 0UL) ? TRUE : FALSE;
        const BOOLEAN kExpectPublic =
            ((context->flags & KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_PUBLIC_WALK) != 0UL) ? TRUE : FALSE;
        const BOOLEAN kExpectActive =
            ((context->flags & KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ACTIVE_LIST) != 0UL &&
                (context->missingCapabilityMask & KSW_CAP_PROCESS_LIST_FIELDS) == 0ULL) ? TRUE : FALSE;
        const BOOLEAN kExpectCid =
            ((context->flags & KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_CID_TABLE) != 0UL &&
                (context->missingCapabilityMask & KSW_CAP_CID_TABLE_WALK) == 0ULL) ? TRUE : FALSE;

        row->dynDataCapabilityMask = context->dynState.capabilityMask;
        row->fieldOffsets = context->fieldOffsets;

        if (kExpectCid && kHasCid &&
            (!kExpectPublic || !kHasPublic) &&
            (!kExpectActive || !kHasActive)) {
            row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY;
        }
        if (kExpectActive && kHasActive &&
            (!kExpectPublic || !kHasPublic) &&
            (!kExpectCid || !kHasCid)) {
            row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY;
        }
        if (kExpectActive && (kHasPublic || kHasCid) && !kHasActive) {
            row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_ACTIVE_LIST;
        }
        if (kExpectCid && (kHasPublic || kHasActive) && !kHasCid) {
            row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_CID_TABLE;
        }

        if ((row->anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_DANGLING_OBJECT) != 0UL) {
            row->confidence = 30UL;
        }
        else if ((row->anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_PID_FIELD_MISMATCH) != 0UL) {
            row->confidence = 45UL;
        }
        else if (kHasPublic && kHasActive && kHasCid) {
            row->confidence = 98UL;
        }
        else if ((kHasPublic && kHasActive) || (kHasPublic && kHasCid) || (kHasActive && kHasCid)) {
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
            kswordArkCrossViewFormatDetail(
                row->detail,
                sizeof(row->detail),
                "sources=0x%08lX anomalies=0x%08lX.",
                row->sourceMask,
                row->anomalyFlags);
        }
    }
}

static VOID
kswordArkProcessCrossViewCopyResponse(
    _Inout_ KSWORD_ARK_PROCESS_CROSSVIEW_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _In_ const KswProcessCrossviewContext* context,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Copy internal process rows into the caller METHOD_BUFFERED response while
    preserving totalCount when the output buffer is smaller than the row set.

Arguments:

    Response - Output response buffer.
    OutputBufferLength - Writable response byte count.
    Context - Finalized query context.
    BytesWrittenOut - Receives exact response bytes written.

Return Value:

    None.

--*/
{
    size_t entryCapacity = 0U;
    ULONG copyCount = 0UL;

    if (response == NULL || context == NULL || bytesWrittenOut == NULL) {
        return;
    }

    entryCapacity = (outputBufferLength - KSW_PROCESS_CROSSVIEW_HEADER_SIZE) / sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_ROW);
    copyCount = (context->rowCount < (ULONG)entryCapacity) ? context->rowCount : (ULONG)entryCapacity;

    response->version = KSWORD_ARK_CROSSVIEW_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_ROW);
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
        RtlCopyMemory(response->entries, context->rows, (SIZE_T)copyCount * sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_ROW));
    }

    *bytesWrittenOut = KSW_PROCESS_CROSSVIEW_HEADER_SIZE + ((size_t)copyCount * sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_ROW));
}

static ULONG
kswordArkCrossViewNormalizeMaxNodes(
    _In_ ULONG requestedMaxNodes
    )
/*++

Routine Description:

    normalize caller-provided node budget to protocol defaults and hard limits.

Arguments:

    RequestedMaxNodes - Raw request value.

Return Value:

    Default or bounded node count.

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

NTSTATUS
kswordArkDriverQueryProcessCrossView(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_PROCESS_CROSSVIEW_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Query read-only process cross-view evidence from PsGetNextProcess,
    EPROCESS.ActiveProcessLinks, and PspCidTable.

Arguments:

    OutputBuffer - METHOD_BUFFERED output packet.
    OutputBufferLength - Writable output byte count.
    Request - Optional process cross-view request.
    BytesWrittenOut - Receives bytes written to OutputBuffer.

Return Value:

    STATUS_SUCCESS when the response header was written; validation/allocation
    status otherwise. Per-source failures are reported in the response fields.

--*/
{
    KswProcessCrossviewContext context;
    KSWORD_ARK_PROCESS_CROSSVIEW_RESPONSE* response = NULL;
    SIZE_T rowBytes = 0U;
    ULONG requestFlags = KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ALL;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSW_PROCESS_CROSSVIEW_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(&context, sizeof(context));
    context.lastStatus = STATUS_SUCCESS;
    context.maxNodes = KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES;
    if (request != NULL) {
        if (request->flags != 0UL) {
            requestFlags = request->flags;
        }
        context.startPid = request->startPid;
        context.endPid = request->endPid;
        context.maxNodes = kswordArkCrossViewNormalizeMaxNodes(request->maxNodes);
    }
    context.flags = requestFlags;
    context.rowCapacity = context.maxNodes;

    rowBytes = (SIZE_T)context.rowCapacity * sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_ROW);
    if ((rowBytes / sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_ROW)) != (SIZE_T)context.rowCapacity) {
        return STATUS_INTEGER_OVERFLOW;
    }

    context.rows = (KSWORD_ARK_PROCESS_CROSSVIEW_ROW*)KswordARKCrossViewAllocate(rowBytes, KSW_PROCESS_CROSSVIEW_TAG);
    if (context.rows == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(context.rows, rowBytes);

    kswordArkDynDataSnapshot(&context.dynState);
    kswordArkCrossViewFillFieldOffsets(&context.dynState, &context.fieldOffsets);

    if ((requestFlags & KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_PUBLIC_WALK) != 0UL) {
        kswordArkProcessCrossViewCollectPublicWalk(&context);
    }
    if ((requestFlags & KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ACTIVE_LIST) != 0UL) {
        kswordArkProcessCrossViewCollectActiveList(&context);
    }
    if ((requestFlags & KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_CID_TABLE) != 0UL) {
        kswordArkProcessCrossViewCollectCidTable(&context);
    }

    kswordArkProcessCrossViewFinalizeRows(&context);

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_PROCESS_CROSSVIEW_RESPONSE*)outputBuffer;
    kswordArkProcessCrossViewCopyResponse(response, outputBufferLength, &context, bytesWrittenOut);

    kswordArkCrossViewFree(context.rows, KSW_PROCESS_CROSSVIEW_TAG);
    context.rows = NULL;
    return status;
}

NTSTATUS
kswordArkProcessIoctlQueryCrossView(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle the unregistered process cross-view IOCTL. The handler accepts an
    optional fixed request, retrieves the output buffer, and invokes the read-only
    backend without requiring write access or trusting any R3 object address.

Arguments:

    Device - WDF device used only for signature parity with other handlers.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes; shorter input selects defaults.
    OutputBufferLength - Supplied output bytes; checked by WDF retrieval.
    BytesReturned - Receives backend response bytes.

Return Value:

    NTSTATUS from buffer retrieval or kswordArkDriverQueryProcessCrossView.

--*/
{
    KSWORD_ARK_PROCESS_CROSSVIEW_REQUEST* queryRequest = NULL;
    KSWORD_ARK_PROCESS_CROSSVIEW_REQUEST defaultRequest;
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
    defaultRequest.flags = KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ALL;
    defaultRequest.maxNodes = KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES;

    status = kswordArkRetrieveOptionalInputBuffer(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    queryRequest = hasInput ? (KSWORD_ARK_PROCESS_CROSSVIEW_REQUEST*)inputBuffer : &defaultRequest;

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSW_PROCESS_CROSSVIEW_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return kswordArkDriverQueryProcessCrossView(
        outputBuffer,
        actualOutputLength,
        queryRequest,
        bytesReturned);
}
