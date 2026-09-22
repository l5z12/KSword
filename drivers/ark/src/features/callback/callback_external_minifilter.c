/*++

Module Name:

    callback_external_minifilter.c

Abstract:

    Enumerates and safely unloads minifilters through Filter Manager APIs.

Environment:

    Kernel-mode minifilter support library

--*/

#include "callback_external_minifilter.h"

typedef struct KswordArkExternalMinifilterId
{
    ULONG64 filterObject;
    WCHAR name[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
} KswordArkExternalMinifilterId;

static NTSTATUS
kswordArkCallbackExternalMinifilterQueryName(
    _In_ PFLT_FILTER filterObject,
    _Out_writes_(nameChars) PWCHAR nameBuffer,
    _In_ ULONG nameChars,
    _Out_opt_ ULONG64* instanceInfoOut
    )
/*++

Routine Description:

    Query a minifilter's public name. Note: The function uses only
    FltGetFilterInformation(FilterAggregateStandardInformation)
    and does not read Filter Manager private structures.

Arguments:

    FilterObject: Input Filter Manager filter object.
    NameBuffer - Output filter name buffer.
    NameChars: Output buffer character count.
    InstanceInfoOut - Optional output for FrameID / compressed instance count.

Return Value:

    Return STATUS_SUCCESS on success; return the status from FltGetFilterInformation on query failure.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesReturned = 0UL;
    FILTER_AGGREGATE_STANDARD_INFORMATION* filterInfo = NULL;
    UNICODE_STRING nameString;

    if (nameBuffer == NULL || nameChars == 0UL || filterObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    nameBuffer[0] = L'\0';
    if (instanceInfoOut != NULL) {
        *instanceInfoOut = 0ULL;
    }
    RtlZeroMemory(&nameString, sizeof(nameString));

    status = FltGetFilterInformation(
        filterObject,
        FilterAggregateStandardInformation,
        NULL,
        0UL,
        &bytesReturned);
    if (status != STATUS_BUFFER_TOO_SMALL || bytesReturned < sizeof(FILTER_AGGREGATE_STANDARD_INFORMATION)) {
        return status;
    }

    filterInfo = (FILTER_AGGREGATE_STANDARD_INFORMATION*)kswordArkAllocateNonPaged(
        bytesReturned,
        KSWORD_ARK_CALLBACK_TAG_EXTERNAL);
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
    if (NT_SUCCESS(status) &&
        (filterInfo->Flags & FLTFL_ASI_IS_MINIFILTER) != 0UL &&
        filterInfo->Type.MiniFilter.FilterNameBufferOffset != 0U &&
        filterInfo->Type.MiniFilter.FilterNameLength != 0U) {
        nameString.Buffer = (PWCHAR)((PUCHAR)filterInfo + filterInfo->Type.MiniFilter.FilterNameBufferOffset);
        nameString.Length = filterInfo->Type.MiniFilter.FilterNameLength;
        nameString.MaximumLength = filterInfo->Type.MiniFilter.FilterNameLength;
        kswordArkCallbackEnumCopyUnicode(nameBuffer, nameChars, &nameString);
        if (instanceInfoOut != NULL) {
            *instanceInfoOut = ((ULONG64)filterInfo->Type.MiniFilter.FrameID << 32) |
                (ULONG64)filterInfo->Type.MiniFilter.NumberOfInstances;
        }
    }

    ExFreePool(filterInfo);
    return (nameBuffer[0] != L'\0') ? status : STATUS_NOT_FOUND;
}

VOID
kswordArkCallbackExternalMinifilterAddCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    )
/*++

Routine Description:

    Add documentation for external minifilter capabilities. Note: The main enumeration entry already lists
    minifilters item-by-item via FltEnumerateFilters; this function only adds a note that 'removal' uses
    FltUnloadFilter and requires re-validating the name against the object address obtained during enumeration.

Arguments:

    Builder: Input/output enumeration response builder.

Return Value:

    No return value.

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;

    if (builder == NULL) {
        return;
    }

    entry = kswordArkCallbackEnumReserveEntry(builder);
    if (entry == NULL) {
        return;
    }

    entry->callbackClass = KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER;
    entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_FLTMGR_ENUMERATION;
    entry->status = KSWORD_ARK_CALLBACK_ENUM_STATUS_OK;
    entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE;
    entry->trustFlags = KSWORD_ARK_CALLBACK_TRUST_PUBLIC_API;
    entry->removeBehavior = KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API |
        KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION;
    kswordArkCallbackEnumCopyWide(
        entry->name,
        RTL_NUMBER_OF(entry->name),
        L"Minifilter public unload capability");
    kswordArkCallbackEnumCopyWide(
        entry->detail,
        RTL_NUMBER_OF(entry->detail),
        L"Minifilter 已由 FltEnumerateFilters 枚举；安全移除只走 FltEnumerateFilters/FltUnloadFilter，目标驱动未提供卸载回调时返回不支持或对应错误。");
}

NTSTATUS
kswordArkCallbackExternalMinifilterRemove(
    _In_ const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST* requestPacket,
    _Inout_ KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE* responsePacket
    )
/*++

Routine Description:

    Unload the minifilter via the Filter Manager's public path. Note: The requested callbackAddress must match
    a PFLT_FILTER address obtained from a subsequent re-enumeration; after matching, call FltUnloadFilter
    using the filter name. Do not write to the linked list from the PFLT_FILTER private structure.

Arguments:

    RequestPacket: Input removal request; callbackAddress holds the enumerated PFLT_FILTER.
    ResponsePacket: Input/output response; serviceName returns the name used for FltUnloadFilter.

Return Value:

    Returns STATUS_SUCCESS on success; returns STATUS_INVALID_PARAMETER if unable to re-enumerate the matching target.
    Return the NTSTATUS of FltUnloadFilter immediately if the current IRQL or target unload conditions are not met.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG filterCount = 0UL;
    ULONG filterIndex = 0UL;
    PFLT_FILTER* filterList = NULL;
    SIZE_T allocationBytes = 0U;
    KswordArkExternalMinifilterId targetId;
    UNICODE_STRING filterName;
    BOOLEAN found = FALSE;

    if (requestPacket == NULL || responsePacket == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (requestPacket->callbackClass != KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_MINIFILTER ||
        requestPacket->callbackAddress == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_NOT_SUPPORTED;
    }

    RtlZeroMemory(&targetId, sizeof(targetId));
    RtlZeroMemory(&filterName, sizeof(filterName));

    status = FltEnumerateFilters(NULL, 0UL, &filterCount);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_SUCCESS) {
        return status;
    }
    if (filterCount == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    allocationBytes = (SIZE_T)filterCount * sizeof(PFLT_FILTER);
    filterList = (PFLT_FILTER*)kswordArkAllocateNonPaged(
        allocationBytes,
        KSWORD_ARK_CALLBACK_TAG_EXTERNAL);
    if (filterList == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(filterList, allocationBytes);

    status = FltEnumerateFilters(filterList, filterCount, &filterCount);
    if (!NT_SUCCESS(status)) {
        ExFreePool(filterList);
        return status;
    }

    for (filterIndex = 0UL; filterIndex < filterCount; ++filterIndex) {
        PFLT_FILTER currentFilter = filterList[filterIndex];
        WCHAR currentName[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];

        RtlZeroMemory(currentName, sizeof(currentName));
        if (currentFilter == NULL) {
            continue;
        }

        if ((ULONG64)(ULONG_PTR)currentFilter == requestPacket->callbackAddress) {
            status = kswordArkCallbackExternalMinifilterQueryName(
                currentFilter,
                currentName,
                RTL_NUMBER_OF(currentName),
                NULL);
            if (NT_SUCCESS(status)) {
                targetId.filterObject = (ULONG64)(ULONG_PTR)currentFilter;
                kswordArkCallbackEnumCopyWide(
                    targetId.name,
                    RTL_NUMBER_OF(targetId.name),
                    currentName);
                found = TRUE;
            }
        }
    }

    for (filterIndex = 0UL; filterIndex < filterCount; ++filterIndex) {
        if (filterList[filterIndex] != NULL) {
            FltObjectDereference(filterList[filterIndex]);
        }
    }
    ExFreePool(filterList);

    if (!found || targetId.name[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }

    kswordArkCallbackEnumCopyWide(
        responsePacket->serviceName,
        RTL_NUMBER_OF(responsePacket->serviceName),
        targetId.name);
    responsePacket->mappingFlags |=
        KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_ENUMERATED |
        KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PUBLIC_API;

    RtlInitUnicodeString(&filterName, targetId.name);
    status = FltUnloadFilter(&filterName);
    return status;
}
