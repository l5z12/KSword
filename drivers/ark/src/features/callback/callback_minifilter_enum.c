/*++

Module Name:

    callback_minifilter_enum.c

Abstract:

    Enumerates Filter Manager filters and their registered Pre/Post operation
    callbacks without modifying Filter Manager state.

Environment:

    Kernel-mode Driver Framework / Filter Manager

--*/

#include <fltKernel.h>
#include "callback_internal.h"
#include "../dyndata/dyndata_v4_internal.h"

#define KSWORD_ARK_MINIFILTER_ENUM_TAG 'mCbK'
#define KSWORD_ARK_MINIFILTER_MAX_OPERATION_ROWS 64UL
#define KSWORD_ARK_MINIFILTER_FALLBACK_SCAN_START 0x80UL
#define KSWORD_ARK_MINIFILTER_FALLBACK_SCAN_END 0x500UL
#define KSWORD_ARK_MINIFILTER_MAX_PDB_STRUCT_OFFSET 0x1000UL
#define KSWORD_ARK_MINIFILTER_KNOWN_OPERATION_FLAGS 0x0000000FUL

typedef struct KswordArkMinifilterOperationLayout
{
    PFLT_OPERATION_REGISTRATION operations;
    ULONG operationsOffset;
    ULONG operationCount;
    BOOLEAN usedPdbProfile;
} KswordArkMinifilterOperationLayout;

static BOOLEAN
kswordArkMinifilterIsKnownMajorFunction(
    _In_ UCHAR majorFunction
    )
/*++

Routine Description:

    Validate one FLT_OPERATION_REGISTRATION MajorFunction value.

Return Value:

    TRUE for documented IRP or Filter Manager operation codes.

--*/
{
    if (majorFunction <= IRP_MJ_MAXIMUM_FUNCTION) {
        return TRUE;
    }

    switch (majorFunction) {
    case IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION:
    case IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION:
    case IRP_MJ_ACQUIRE_FOR_MOD_WRITE:
    case IRP_MJ_RELEASE_FOR_MOD_WRITE:
    case IRP_MJ_ACQUIRE_FOR_CC_FLUSH:
    case IRP_MJ_RELEASE_FOR_CC_FLUSH:
    case IRP_MJ_QUERY_OPEN:
    case IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE:
    case IRP_MJ_NETWORK_QUERY_OPEN:
    case IRP_MJ_MDL_READ:
    case IRP_MJ_MDL_READ_COMPLETE:
    case IRP_MJ_PREPARE_MDL_WRITE:
    case IRP_MJ_MDL_WRITE_COMPLETE:
    case IRP_MJ_VOLUME_MOUNT:
    case IRP_MJ_VOLUME_DISMOUNT:
        return TRUE;
    default:
        return FALSE;
    }
}

static PCWSTR
kswordArkMinifilterMajorFunctionName(
    _In_ UCHAR majorFunction
    )
/*++

Routine Description:

    Map a documented minifilter operation code to its symbolic name.

Return Value:

    Stable symbolic text; unknown values use IRP_MJ_UNKNOWN.

--*/
{
    switch (majorFunction) {
    case IRP_MJ_CREATE: return L"IRP_MJ_CREATE";
    case IRP_MJ_CREATE_NAMED_PIPE: return L"IRP_MJ_CREATE_NAMED_PIPE";
    case IRP_MJ_CLOSE: return L"IRP_MJ_CLOSE";
    case IRP_MJ_READ: return L"IRP_MJ_READ";
    case IRP_MJ_WRITE: return L"IRP_MJ_WRITE";
    case IRP_MJ_QUERY_INFORMATION: return L"IRP_MJ_QUERY_INFORMATION";
    case IRP_MJ_SET_INFORMATION: return L"IRP_MJ_SET_INFORMATION";
    case IRP_MJ_QUERY_EA: return L"IRP_MJ_QUERY_EA";
    case IRP_MJ_SET_EA: return L"IRP_MJ_SET_EA";
    case IRP_MJ_FLUSH_BUFFERS: return L"IRP_MJ_FLUSH_BUFFERS";
    case IRP_MJ_QUERY_VOLUME_INFORMATION: return L"IRP_MJ_QUERY_VOLUME_INFORMATION";
    case IRP_MJ_SET_VOLUME_INFORMATION: return L"IRP_MJ_SET_VOLUME_INFORMATION";
    case IRP_MJ_DIRECTORY_CONTROL: return L"IRP_MJ_DIRECTORY_CONTROL";
    case IRP_MJ_FILE_SYSTEM_CONTROL: return L"IRP_MJ_FILE_SYSTEM_CONTROL";
    case IRP_MJ_DEVICE_CONTROL: return L"IRP_MJ_DEVICE_CONTROL";
    case IRP_MJ_INTERNAL_DEVICE_CONTROL: return L"IRP_MJ_INTERNAL_DEVICE_CONTROL";
    case IRP_MJ_SHUTDOWN: return L"IRP_MJ_SHUTDOWN";
    case IRP_MJ_LOCK_CONTROL: return L"IRP_MJ_LOCK_CONTROL";
    case IRP_MJ_CLEANUP: return L"IRP_MJ_CLEANUP";
    case IRP_MJ_CREATE_MAILSLOT: return L"IRP_MJ_CREATE_MAILSLOT";
    case IRP_MJ_QUERY_SECURITY: return L"IRP_MJ_QUERY_SECURITY";
    case IRP_MJ_SET_SECURITY: return L"IRP_MJ_SET_SECURITY";
    case IRP_MJ_POWER: return L"IRP_MJ_POWER";
    case IRP_MJ_SYSTEM_CONTROL: return L"IRP_MJ_SYSTEM_CONTROL";
    case IRP_MJ_DEVICE_CHANGE: return L"IRP_MJ_DEVICE_CHANGE";
    case IRP_MJ_QUERY_QUOTA: return L"IRP_MJ_QUERY_QUOTA";
    case IRP_MJ_SET_QUOTA: return L"IRP_MJ_SET_QUOTA";
    case IRP_MJ_PNP: return L"IRP_MJ_PNP";
    case IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION: return L"IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION";
    case IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION: return L"IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION";
    case IRP_MJ_ACQUIRE_FOR_MOD_WRITE: return L"IRP_MJ_ACQUIRE_FOR_MOD_WRITE";
    case IRP_MJ_RELEASE_FOR_MOD_WRITE: return L"IRP_MJ_RELEASE_FOR_MOD_WRITE";
    case IRP_MJ_ACQUIRE_FOR_CC_FLUSH: return L"IRP_MJ_ACQUIRE_FOR_CC_FLUSH";
    case IRP_MJ_RELEASE_FOR_CC_FLUSH: return L"IRP_MJ_RELEASE_FOR_CC_FLUSH";
    case IRP_MJ_QUERY_OPEN: return L"IRP_MJ_QUERY_OPEN";
    case IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE: return L"IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE";
    case IRP_MJ_NETWORK_QUERY_OPEN: return L"IRP_MJ_NETWORK_QUERY_OPEN";
    case IRP_MJ_MDL_READ: return L"IRP_MJ_MDL_READ";
    case IRP_MJ_MDL_READ_COMPLETE: return L"IRP_MJ_MDL_READ_COMPLETE";
    case IRP_MJ_PREPARE_MDL_WRITE: return L"IRP_MJ_PREPARE_MDL_WRITE";
    case IRP_MJ_MDL_WRITE_COMPLETE: return L"IRP_MJ_MDL_WRITE_COMPLETE";
    case IRP_MJ_VOLUME_MOUNT: return L"IRP_MJ_VOLUME_MOUNT";
    case IRP_MJ_VOLUME_DISMOUNT: return L"IRP_MJ_VOLUME_DISMOUNT";
    default: return L"IRP_MJ_UNKNOWN";
    }
}

static BOOLEAN
kswordArkMinifilterValidateOperations(
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_ PFLT_OPERATION_REGISTRATION operations,
    _Out_ ULONG* operationCountOut
    )
/*++

Routine Description:

    Validate a candidate FLT_OPERATION_REGISTRATION array. Note: The candidate must contain
    IRP_MJ_OPERATION_END within 64 entries, all callbacks must belong to loaded modules, and
    reserved fields, flags, and MajorFunction must conform to the public structure contract.

Return Value:

    TRUE only for a complete and strongly validated callback array.

--*/
{
    ULONG index = 0UL;
    ULONG callbackCount = 0UL;
    ULONG64 seenMajorMask = 0ULL;

    if (moduleCache == NULL || operations == NULL || operationCountOut == NULL) {
        return FALSE;
    }
    *operationCountOut = 0UL;

    for (index = 0UL; index < KSWORD_ARK_MINIFILTER_MAX_OPERATION_ROWS; ++index) {
        FLT_OPERATION_REGISTRATION operation;
        ULONG64 operationAddress = (ULONG64)(ULONG_PTR)&operations[index];

        RtlZeroMemory(&operation, sizeof(operation));
        if (!kswordArkCallbackEnumReadMemory(
                (const VOID*)(ULONG_PTR)operationAddress,
                &operation,
                sizeof(operation))) {
            return FALSE;
        }

        if (operation.MajorFunction == IRP_MJ_OPERATION_END) {
            *operationCountOut = index;
            return index != 0UL && callbackCount != 0UL;
        }
        if (!kswordArkMinifilterIsKnownMajorFunction(operation.MajorFunction) ||
            (operation.Flags & ~KSWORD_ARK_MINIFILTER_KNOWN_OPERATION_FLAGS) != 0UL ||
            operation.Reserved1 != NULL ||
            (operation.PreOperation == NULL && operation.PostOperation == NULL)) {
            return FALSE;
        }

        if (operation.MajorFunction < 64U) {
            const ULONG64 kMajorBit = 1ULL << operation.MajorFunction;
            if ((seenMajorMask & kMajorBit) != 0ULL) {
                return FALSE;
            }
            seenMajorMask |= kMajorBit;
        }

        if (operation.PreOperation != NULL) {
            if (!kswordArkCallbackEnumIsKernelModuleAddress(
                    moduleCache,
                    (ULONG64)(ULONG_PTR)operation.PreOperation)) {
                return FALSE;
            }
            callbackCount += 1UL;
        }
        if (operation.PostOperation != NULL) {
            if (!kswordArkCallbackEnumIsKernelModuleAddress(
                    moduleCache,
                    (ULONG64)(ULONG_PTR)operation.PostOperation)) {
                return FALSE;
            }
            callbackCount += 1UL;
        }
    }

    return FALSE;
}

static BOOLEAN
kswordArkMinifilterReadOperationsPointer(
    _In_ PFLT_FILTER filterObject,
    _In_ ULONG operationsOffset,
    _Out_ PFLT_OPERATION_REGISTRATION* operationsOut
    )
/*++

Routine Description:

    Read the opaque _FLT_FILTER.Operations pointer at one bounded offset.

Return Value:

    TRUE when a non-NULL pointer is read without fault.

--*/
{
    PFLT_OPERATION_REGISTRATION operations = NULL;
    ULONG64 fieldAddress = 0ULL;

    if (filterObject == NULL || operationsOut == NULL ||
        operationsOffset > KSWORD_ARK_MINIFILTER_MAX_PDB_STRUCT_OFFSET) {
        return FALSE;
    }
    *operationsOut = NULL;
    fieldAddress = (ULONG64)(ULONG_PTR)filterObject + (ULONG64)operationsOffset;
    if (!kswordArkCallbackEnumReadMemory(
            (const VOID*)(ULONG_PTR)fieldAddress,
            &operations,
            sizeof(operations)) ||
        operations == NULL) {
        return FALSE;
    }

    *operationsOut = operations;
    return TRUE;
}

static BOOLEAN
kswordArkMinifilterLocateOperations(
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_ PFLT_FILTER filterObject,
    _Out_ KswordArkMinifilterOperationLayout* layoutOut
    )
/*++

Routine Description:

    Locate _FLT_FILTER.Operations by exact fltMgr PDB layout first, then by a
    bounded strongly validated fallback scan.

Return Value:

    TRUE when a complete operation array is found.

--*/
{
    KswDynV4FltmgrMinifilterLayout pdbLayout;
    ULONG candidateOffset = 0UL;

    if (moduleCache == NULL || filterObject == NULL || layoutOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(layoutOut, sizeof(*layoutOut));
    RtlZeroMemory(&pdbLayout, sizeof(pdbLayout));

    if (NT_SUCCESS(kswordArkDynDataV4SnapshotFltMgrMinifilterLayout(&pdbLayout))) {
        PFLT_OPERATION_REGISTRATION operations = NULL;
        ULONG operationCount = 0UL;
        if (kswordArkMinifilterReadOperationsPointer(
                filterObject,
                pdbLayout.fltFilterOperations,
                &operations) &&
            kswordArkMinifilterValidateOperations(moduleCache, operations, &operationCount)) {
            layoutOut->operations = operations;
            layoutOut->operationsOffset = pdbLayout.fltFilterOperations;
            layoutOut->operationCount = operationCount;
            layoutOut->usedPdbProfile = TRUE;
            return TRUE;
        }
    }

    for (candidateOffset = KSWORD_ARK_MINIFILTER_FALLBACK_SCAN_START;
         candidateOffset <= KSWORD_ARK_MINIFILTER_FALLBACK_SCAN_END;
         candidateOffset += sizeof(PVOID)) {
        PFLT_OPERATION_REGISTRATION operations = NULL;
        ULONG operationCount = 0UL;

        if (!kswordArkMinifilterReadOperationsPointer(filterObject, candidateOffset, &operations)) {
            continue;
        }
        if (!kswordArkMinifilterValidateOperations(moduleCache, operations, &operationCount)) {
            continue;
        }

        layoutOut->operations = operations;
        layoutOut->operationsOffset = candidateOffset;
        layoutOut->operationCount = operationCount;
        layoutOut->usedPdbProfile = FALSE;
        return TRUE;
    }

    return FALSE;
}

static NTSTATUS
kswordArkMinifilterQueryFilterInfo(
    _In_ PFLT_FILTER filterObject,
    _Outptr_result_maybenull_ FILTER_AGGREGATE_STANDARD_INFORMATION** filterInfoOut
    )
/*++

Routine Description:

    Query public aggregate information for one referenced Filter object.

Return Value:

    STATUS_SUCCESS with an allocated buffer, or the query/allocation status.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesReturned = 0UL;
    FILTER_AGGREGATE_STANDARD_INFORMATION* filterInfo = NULL;

    if (filterObject == NULL || filterInfoOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *filterInfoOut = NULL;

    status = FltGetFilterInformation(
        filterObject,
        FilterAggregateStandardInformation,
        NULL,
        0UL,
        &bytesReturned);
    if (status != STATUS_BUFFER_TOO_SMALL ||
        bytesReturned < sizeof(FILTER_AGGREGATE_STANDARD_INFORMATION)) {
        return status;
    }

    filterInfo = (FILTER_AGGREGATE_STANDARD_INFORMATION*)kswordArkAllocateNonPaged(
        bytesReturned,
        KSWORD_ARK_MINIFILTER_ENUM_TAG);
    if (filterInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(filterInfo, bytesReturned);

    status = FltGetFilterInformation(
        filterObject,
        FilterAggregateStandardInformation,
        filterInfo,
        bytesReturned,
        &bytesReturned);
    if (!NT_SUCCESS(status)) {
        ExFreePool(filterInfo);
        return status;
    }

    *filterInfoOut = filterInfo;
    return STATUS_SUCCESS;
}

static VOID
kswordArkMinifilterCopyPublicText(
    _In_ const FILTER_AGGREGATE_STANDARD_INFORMATION* filterInfo,
    _Out_writes_(nameChars) PWCHAR name,
    _In_ ULONG nameChars,
    _Out_writes_(altitudeChars) PWCHAR altitude,
    _In_ ULONG altitudeChars
    )
/*++

Routine Description:

    Copy the public filter name and altitude into bounded local buffers.

--*/
{
    UNICODE_STRING source;

    if (name == NULL || nameChars == 0UL || altitude == NULL || altitudeChars == 0UL) {
        return;
    }
    name[0] = L'\0';
    altitude[0] = L'\0';
    if (filterInfo == NULL || (filterInfo->Flags & FLTFL_ASI_IS_MINIFILTER) == 0UL) {
        return;
    }

    RtlZeroMemory(&source, sizeof(source));
    if (filterInfo->Type.MiniFilter.FilterNameBufferOffset != 0U &&
        filterInfo->Type.MiniFilter.FilterNameLength != 0U) {
        source.Buffer = (PWCHAR)((PUCHAR)filterInfo +
            filterInfo->Type.MiniFilter.FilterNameBufferOffset);
        source.Length = filterInfo->Type.MiniFilter.FilterNameLength;
        source.MaximumLength = source.Length;
        kswordArkCallbackEnumCopyUnicode(name, nameChars, &source);
    }

    RtlZeroMemory(&source, sizeof(source));
    if (filterInfo->Type.MiniFilter.FilterAltitudeBufferOffset != 0U &&
        filterInfo->Type.MiniFilter.FilterAltitudeLength != 0U) {
        source.Buffer = (PWCHAR)((PUCHAR)filterInfo +
            filterInfo->Type.MiniFilter.FilterAltitudeBufferOffset);
        source.Length = filterInfo->Type.MiniFilter.FilterAltitudeLength;
        source.MaximumLength = source.Length;
        kswordArkCallbackEnumCopyUnicode(altitude, altitudeChars, &source);
    }
}

static KSWORD_ARK_CALLBACK_ENUM_ENTRY*
kswordArkMinifilterAddParentRow(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _In_ PFLT_FILTER filterObject,
    _In_opt_ const FILTER_AGGREGATE_STANDARD_INFORMATION* filterInfo,
    _In_ NTSTATUS filterInfoStatus,
    _In_opt_ const KswordArkMinifilterOperationLayout* layout,
    _In_z_ PCWSTR filterName,
    _In_z_ PCWSTR altitude
    )
/*++

Routine Description:

    Add the tree parent row. Note: FilterObject writes only registration/identifier fields; callbackAddress
    remains 0 to prevent the UI from misreporting the object pointer as a Pre/Post function.

Return Value:

    The reserved response row, or NULL when the output is full.

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = kswordArkCallbackEnumReserveEntry(builder);

    if (entry == NULL) {
        return NULL;
    }

    entry->callbackClass = KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER;
    entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_FLTMGR_ENUMERATION;
    entry->status = NT_SUCCESS(filterInfoStatus)
        ? KSWORD_ARK_CALLBACK_ENUM_STATUS_OK
        : KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED;
    entry->registrationAddress = (ULONG64)(ULONG_PTR)filterObject;
    entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_HANDLE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTIFIER |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE;
    entry->trustFlags = KSWORD_ARK_CALLBACK_TRUST_PUBLIC_API |
        KSWORD_ARK_CALLBACK_TRUST_STORAGE_VALIDATED;
    entry->removeBehavior = KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API |
        KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION;
    entry->lastStatus = filterInfoStatus;
    kswordArkCallbackEnumCopyWide(entry->name, RTL_NUMBER_OF(entry->name), filterName);

    if (altitude[0] != L'\0') {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_ALTITUDE;
        kswordArkCallbackEnumCopyWide(entry->altitude, RTL_NUMBER_OF(entry->altitude), altitude);
    }
    if (layout != NULL && layout->operations != NULL) {
        entry->rawStorageValue = (ULONG64)(ULONG_PTR)layout->operations;
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_RAW_STORAGE_VALUE;
    }

    if (NT_SUCCESS(filterInfoStatus) && filterInfo != NULL &&
        (filterInfo->Flags & FLTFL_ASI_IS_MINIFILTER) != 0UL) {
        (VOID)RtlStringCbPrintfW(
            entry->detail,
            sizeof(entry->detail),
            L"Filter parent；FrameID=%lu，实例数=%lu，FilterObject=0x%p，"
            L"Operations=%p，布局来源=%ws，Operations偏移=0x%lX。",
            (unsigned long)filterInfo->Type.MiniFilter.FrameID,
            (unsigned long)filterInfo->Type.MiniFilter.NumberOfInstances,
            filterObject,
            (layout != NULL) ? layout->operations : NULL,
            (layout == NULL) ? L"unavailable" :
                (layout->usedPdbProfile ? L"fltMgr PDB profile" : L"validated fallback scan"),
            (layout != NULL) ? layout->operationsOffset : 0UL);
    }
    else {
        (VOID)RtlStringCbPrintfW(
            entry->detail,
            sizeof(entry->detail),
            L"FltGetFilterInformation 失败，FilterObject=0x%p，NTSTATUS=0x%08lX。",
            filterObject,
            (unsigned long)filterInfoStatus);
    }
    return entry;
}

static VOID
kswordArkMinifilterAddCallbackRow(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_ PFLT_FILTER filterObject,
    _In_ const KswordArkMinifilterOperationLayout* layout,
    _In_ const FLT_OPERATION_REGISTRATION* operation,
    _In_ ULONG operationIndex,
    _In_ BOOLEAN isPreOperation,
    _In_z_ PCWSTR filterName,
    _In_z_ PCWSTR altitude
    )
/*++

Routine Description:

    Add one real PreOperation or PostOperation callback row.

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;
    ULONG64 callbackAddress = 0ULL;
    PCWSTR stageName = isPreOperation ? L"PreOperation" : L"PostOperation";
    PCWSTR majorName = kswordArkMinifilterMajorFunctionName(operation->MajorFunction);

    callbackAddress = isPreOperation
        ? (ULONG64)(ULONG_PTR)operation->PreOperation
        : (ULONG64)(ULONG_PTR)operation->PostOperation;
    if (callbackAddress == 0ULL) {
        return;
    }

    entry = kswordArkCallbackEnumReserveEntry(builder);
    if (entry == NULL) {
        return;
    }

    entry->callbackClass = KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER;
    entry->source = layout->usedPdbProfile
        ? KSWORD_ARK_CALLBACK_ENUM_SOURCE_PDB_PROFILE
        : KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_PATTERN_SCAN;
    entry->status = KSWORD_ARK_CALLBACK_ENUM_STATUS_OK;
    entry->callbackAddress = callbackAddress;
    entry->contextAddress = (ULONG64)(ULONG_PTR)filterObject;
    entry->registrationAddress = (ULONG64)(ULONG_PTR)&layout->operations[operationIndex];
    entry->rawStorageValue = (ULONG64)(ULONG_PTR)layout->operations;
    entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_RAW_STORAGE_VALUE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME;
    entry->trustFlags = KSWORD_ARK_CALLBACK_TRUST_STORAGE_VALIDATED |
        (layout->usedPdbProfile
            ? (KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE | KSWORD_ARK_CALLBACK_TRUST_PROFILE_GATED)
            : KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN);
    entry->lastStatus = STATUS_SUCCESS;

    if (operation->MajorFunction < 32U) {
        entry->operationMask = 1UL << operation->MajorFunction;
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_OPERATION_MASK;
    }
    if (layout->usedPdbProfile) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_PROFILE_GATED |
            KSWORD_ARK_CALLBACK_ENUM_FIELD_TRUSTED;
    }
    if (altitude[0] != L'\0') {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_ALTITUDE;
        kswordArkCallbackEnumCopyWide(entry->altitude, RTL_NUMBER_OF(entry->altitude), altitude);
    }

    (VOID)RtlStringCbPrintfW(
        entry->name,
        sizeof(entry->name),
        L"%ws / %ws",
        majorName,
        stageName);
    (VOID)RtlStringCbPrintfW(
        entry->detail,
        sizeof(entry->detail),
        L"Filter=%ws；MajorFunction=%ws (0x%02X)；阶段=%ws；Flags=0x%08lX；"
        L"FilterObject=0x%p；Operations=%p；Operations偏移=0x%lX；布局来源=%ws。",
        filterName,
        majorName,
        (unsigned int)operation->MajorFunction,
        stageName,
        (unsigned long)operation->Flags,
        filterObject,
        layout->operations,
        layout->operationsOffset,
        layout->usedPdbProfile ? L"fltMgr PDB profile" : L"validated fallback scan");
    kswordArkCallbackEnumFinalizeModuleCached(moduleCache, entry);
}

static VOID
kswordArkMinifilterAddUnavailableChild(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _In_ PFLT_FILTER filterObject,
    _In_z_ PCWSTR altitude
    )
/*++

Routine Description:

    Add an explicit child row when neither the exact PDB layout nor the
    validated fallback can recover operation callbacks.

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = kswordArkCallbackEnumReserveEntry(builder);

    if (entry == NULL) {
        return;
    }
    entry->callbackClass = KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER;
    entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_UNSUPPORTED;
    entry->status = KSWORD_ARK_CALLBACK_ENUM_STATUS_UNSUPPORTED;
    entry->contextAddress = (ULONG64)(ULONG_PTR)filterObject;
    entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME;
    entry->lastStatus = STATUS_NOT_SUPPORTED;
    kswordArkCallbackEnumCopyWide(
        entry->name,
        RTL_NUMBER_OF(entry->name),
        L"Pre/Post callback layout unavailable");
    if (altitude[0] != L'\0') {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_ALTITUDE;
        kswordArkCallbackEnumCopyWide(entry->altitude, RTL_NUMBER_OF(entry->altitude), altitude);
    }
    kswordArkCallbackEnumCopyWide(
        entry->detail,
        RTL_NUMBER_OF(entry->detail),
        L"当前 fltMgr.sys 无可用 PDB 偏移，且有界扫描未发现通过完整结构与模块范围校验的 Operations 数组。");
}

static VOID
kswordArkMinifilterAddFilter(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_ PFLT_FILTER filterObject
    )
/*++

Routine Description:

    Add one public filter parent and all real Pre/Post callback children.

--*/
{
    FILTER_AGGREGATE_STANDARD_INFORMATION* filterInfo = NULL;
    KswordArkMinifilterOperationLayout layout;
    WCHAR filterName[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
    WCHAR altitude[KSWORD_ARK_CALLBACK_ENUM_ALTITUDE_CHARS];
    NTSTATUS filterInfoStatus = STATUS_SUCCESS;
    BOOLEAN layoutFound = FALSE;
    ULONG operationIndex = 0UL;

    RtlZeroMemory(&layout, sizeof(layout));
    RtlZeroMemory(filterName, sizeof(filterName));
    RtlZeroMemory(altitude, sizeof(altitude));

    filterInfoStatus = kswordArkMinifilterQueryFilterInfo(filterObject, &filterInfo);
    if (NT_SUCCESS(filterInfoStatus) && filterInfo != NULL) {
        kswordArkMinifilterCopyPublicText(
            filterInfo,
            filterName,
            RTL_NUMBER_OF(filterName),
            altitude,
            RTL_NUMBER_OF(altitude));
    }
    if (filterName[0] == L'\0') {
        kswordArkCallbackEnumCopyWide(
            filterName,
            RTL_NUMBER_OF(filterName),
            L"<unnamed minifilter>");
    }

    layoutFound = kswordArkMinifilterLocateOperations(moduleCache, filterObject, &layout);
    (VOID)kswordArkMinifilterAddParentRow(
        builder,
        filterObject,
        filterInfo,
        filterInfoStatus,
        layoutFound ? &layout : NULL,
        filterName,
        altitude);

    if (!layoutFound) {
        kswordArkMinifilterAddUnavailableChild(builder, filterObject, altitude);
    }
    else {
        for (operationIndex = 0UL; operationIndex < layout.operationCount; ++operationIndex) {
            FLT_OPERATION_REGISTRATION operation;

            RtlZeroMemory(&operation, sizeof(operation));
            if (!kswordArkCallbackEnumReadMemory(
                    &layout.operations[operationIndex],
                    &operation,
                    sizeof(operation))) {
                builder->lastStatus = STATUS_PARTIAL_COPY;
                break;
            }
            kswordArkMinifilterAddCallbackRow(
                builder,
                moduleCache,
                filterObject,
                &layout,
                &operation,
                operationIndex,
                TRUE,
                filterName,
                altitude);
            kswordArkMinifilterAddCallbackRow(
                builder,
                moduleCache,
                filterObject,
                &layout,
                &operation,
                operationIndex,
                FALSE,
                filterName,
                altitude);
        }
    }

    if (filterInfo != NULL) {
        ExFreePool(filterInfo);
    }
}

NTSTATUS
kswordArkMinifilterQueryFirstCallbackOwner(
    _In_ PFLT_FILTER filterObject,
    _Out_writes_(modulePathChars) PWCHAR modulePath,
    _In_ ULONG modulePathChars,
    _Out_opt_ ULONG64* moduleBaseOut,
    _Out_opt_ ULONG* moduleSizeOut
    )
/*++

Routine Description:

    Resolve the module that owns the first validated Pre/Post callback for one
    filter. This provides a compact owner hint to the inventory protocol while
    the full callback IOCTL returns every operation row.

Return Value:

    STATUS_SUCCESS when an owner module is resolved; otherwise the layout,
    validation, or module-resolution status.

--*/
{
    KswordArkCallbackModuleCache moduleCache;
    KswordArkMinifilterOperationLayout layout;
    ULONG operationIndex = 0UL;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    if (filterObject == NULL || modulePath == NULL || modulePathChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    modulePath[0] = L'\0';
    if (moduleBaseOut != NULL) {
        *moduleBaseOut = 0ULL;
    }
    if (moduleSizeOut != NULL) {
        *moduleSizeOut = 0UL;
    }
    RtlZeroMemory(&layout, sizeof(layout));
    kswordArkCallbackEnumInitModuleCache(&moduleCache);

    status = kswordArkCallbackEnumEnsureModuleCache(&moduleCache);
    if (!NT_SUCCESS(status) ||
        !kswordArkMinifilterLocateOperations(&moduleCache, filterObject, &layout)) {
        kswordArkCallbackEnumFreeModuleCache(&moduleCache);
        return NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status;
    }

    for (operationIndex = 0UL; operationIndex < layout.operationCount; ++operationIndex) {
        FLT_OPERATION_REGISTRATION operation;
        ULONG64 callbackAddress = 0ULL;

        RtlZeroMemory(&operation, sizeof(operation));
        if (!kswordArkCallbackEnumReadMemory(
                &layout.operations[operationIndex],
                &operation,
                sizeof(operation))) {
            status = STATUS_PARTIAL_COPY;
            break;
        }
        callbackAddress = operation.PreOperation != NULL
            ? (ULONG64)(ULONG_PTR)operation.PreOperation
            : (ULONG64)(ULONG_PTR)operation.PostOperation;
        if (callbackAddress == 0ULL) {
            continue;
        }

        status = kswordArkCallbackEnumResolveModuleByAddressCached(
            &moduleCache,
            callbackAddress,
            modulePath,
            modulePathChars,
            moduleBaseOut,
            moduleSizeOut);
        break;
    }

    kswordArkCallbackEnumFreeModuleCache(&moduleCache);
    return status;
}

VOID
kswordArkCallbackEnumAddMinifilters(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    )
/*++

Routine Description:

    enumerate all referenced Filter Manager filters, add stable parent rows, and
    recover each registered Pre/Post callback with module ownership.

--*/
{
    KswordArkCallbackModuleCache moduleCache;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG filterCount = 0UL;
    ULONG filterIndex = 0UL;
    PFLT_FILTER* filterList = NULL;
    SIZE_T allocationBytes = 0U;

    if (builder == NULL) {
        return;
    }
    kswordArkCallbackEnumInitModuleCache(&moduleCache);

    status = FltEnumerateFilters(NULL, 0UL, &filterCount);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_SUCCESS) {
        builder->lastStatus = status;
        kswordArkCallbackEnumAddUnsupportedRow(
            builder,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER,
            L"Minifilter enumeration failed",
            L"FltEnumerateFilters 长度探测失败，无法枚举 minifilter。");
        return;
    }
    if (filterCount == 0UL) {
        kswordArkCallbackEnumAddUnsupportedRow(
            builder,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER,
            L"Minifilter",
            L"FltEnumerateFilters 返回 0 个 minifilter。");
        return;
    }

    allocationBytes = (SIZE_T)filterCount * sizeof(PFLT_FILTER);
    filterList = (PFLT_FILTER*)kswordArkAllocateNonPaged(
        allocationBytes,
        KSWORD_ARK_MINIFILTER_ENUM_TAG);
    if (filterList == NULL) {
        builder->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        return;
    }
    RtlZeroMemory(filterList, allocationBytes);

    status = FltEnumerateFilters(filterList, filterCount, &filterCount);
    if (!NT_SUCCESS(status)) {
        builder->lastStatus = status;
        ExFreePool(filterList);
        kswordArkCallbackEnumAddUnsupportedRow(
            builder,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER,
            L"Minifilter enumeration failed",
            L"FltEnumerateFilters 返回错误，当前无法展示 minifilter 列表。");
        return;
    }

    (VOID)kswordArkCallbackEnumEnsureModuleCache(&moduleCache);
    for (filterIndex = 0UL; filterIndex < filterCount; ++filterIndex) {
        if (filterList[filterIndex] != NULL) {
            kswordArkMinifilterAddFilter(builder, &moduleCache, filterList[filterIndex]);
            FltObjectDereference(filterList[filterIndex]);
        }
    }

    kswordArkCallbackEnumFreeModuleCache(&moduleCache);
    ExFreePool(filterList);
}
