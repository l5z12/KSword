/*++

Module Name:

    minifilter_inventory.c

Abstract:

    Read-only Filter Manager minifilter inventory and callback-owner hint IOCTL.

Environment:

    Kernel-mode Driver Framework / Filter Manager

--*/

#include <fltKernel.h>
#include "ark/ark_driver.h"
#include "driver/KswordArkFilterIoctl.h"
#include "callback_internal.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSWORD_ARK_MINIFILTER_INVENTORY_TAG 'iFsK'
#define KSWORD_ARK_MINIFILTER_INVENTORY_MAX_ROWS 4096UL
#define KSWORD_ARK_MINIFILTER_INVENTORY_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_RESPONSE) - sizeof(KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY))

static VOID
kswordArkMinifilterInventoryLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Format and enqueue one minifilter inventory log message. The log path is
    diagnostic only and never changes the IOCTL result.

Arguments:

    Device - WDF device that owns the shared log channel.
    levelText - Log severity text.
    FormatText - printf-style ANSI format string.
    ... - Format arguments.

Return Value:

    None. Formatting or enqueue failures are intentionally ignored.

--*/
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, formatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logMessage, sizeof(logMessage), formatText, arguments))) {
        (VOID)kswordArkDriverEnqueueLogFrame(device, levelText, logMessage);
    }
    va_end(arguments);
}

static PVOID
kswordArkMinifilterInventoryAllocate(
    _In_ SIZE_T bufferBytes
    )
/*++

Routine Description:

    Allocate transient nonpaged memory for Filter Manager enumeration buffers.

Arguments:

    BufferBytes - Number of bytes requested.

Return Value:

    Allocation pointer, or NULL when the allocation fails.

--*/
{
    if (bufferBytes == 0U) {
        return NULL;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(NonPagedPoolNx, bufferBytes, KSWORD_ARK_MINIFILTER_INVENTORY_TAG);
#pragma warning(pop)
}

static VOID
kswordArkMinifilterInventoryCopyUnicode(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_opt_ PCUNICODE_STRING source
    )
/*++

Routine Description:

    Copy a bounded UNICODE_STRING into a fixed response string.

Arguments:

    Destination - Fixed-size output string.
    DestinationChars - Character capacity of Destination.
    Source - Optional source UNICODE_STRING.

Return Value:

    None. Destination is always NUL-terminated when capacity is nonzero.

--*/
{
    ULONG copyChars = 0UL;

    if (destination == NULL || destinationChars == 0UL) {
        return;
    }

    destination[0] = L'\0';
    if (source == NULL || source->Buffer == NULL || source->Length == 0U) {
        return;
    }

    copyChars = (ULONG)(source->Length / sizeof(WCHAR));
    if (copyChars >= destinationChars) {
        copyChars = destinationChars - 1UL;
    }

    RtlCopyMemory(destination, source->Buffer, (SIZE_T)copyChars * sizeof(WCHAR));
    destination[copyChars] = L'\0';
}

static NTSTATUS
kswordArkMinifilterInventoryQueryFilterInfo(
    _In_ PFLT_FILTER filterObject,
    _Outptr_result_maybenull_ FILTER_AGGREGATE_STANDARD_INFORMATION** filterInfoOut
    )
/*++

Routine Description:

    Query FilterAggregateStandardInformation for one referenced filter.

Arguments:

    FilterObject - Referenced Filter Manager filter object.
    FilterInfoOut - Receives an allocated information buffer.

Return Value:

    STATUS_SUCCESS when FilterInfoOut receives a buffer; otherwise the
    Filter Manager or allocation failure status.

--*/
{
    FILTER_AGGREGATE_STANDARD_INFORMATION* filterInfo = NULL;
    ULONG bytesReturned = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (filterInfoOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *filterInfoOut = NULL;
    if (filterObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = FltGetFilterInformation(
        filterObject,
        FilterAggregateStandardInformation,
        NULL,
        0UL,
        &bytesReturned);
    if (status != STATUS_BUFFER_TOO_SMALL || bytesReturned < sizeof(FILTER_AGGREGATE_STANDARD_INFORMATION)) {
        return status;
    }

    filterInfo = (FILTER_AGGREGATE_STANDARD_INFORMATION*)kswordArkMinifilterInventoryAllocate(bytesReturned);
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
        ExFreePoolWithTag(filterInfo, KSWORD_ARK_MINIFILTER_INVENTORY_TAG);
        return status;
    }

    *filterInfoOut = filterInfo;
    return STATUS_SUCCESS;
}

static VOID
kswordArkMinifilterInventoryFillFilterText(
    _In_ const FILTER_AGGREGATE_STANDARD_INFORMATION* filterInfo,
    _Inout_ KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY* entry
    )
/*++

Routine Description:

    Copy filter name, altitude, frame ID, and instance count from public
    aggregate information into a response row.

Arguments:

    FilterInfo - Filter Manager aggregate information buffer.
    Entry - Response row being populated.

Return Value:

    None. Missing optional text leaves the corresponding string empty.

--*/
{
    UNICODE_STRING nameString;
    UNICODE_STRING altitudeString;

    if (filterInfo == NULL || entry == NULL) {
        return;
    }

    RtlZeroMemory(&nameString, sizeof(nameString));
    RtlZeroMemory(&altitudeString, sizeof(altitudeString));
    if ((filterInfo->Flags & FLTFL_ASI_IS_MINIFILTER) == 0UL) {
        return;
    }

    entry->instanceCount = filterInfo->Type.MiniFilter.NumberOfInstances;
    entry->frameId = filterInfo->Type.MiniFilter.FrameID;

    if (filterInfo->Type.MiniFilter.FilterNameBufferOffset != 0U &&
        filterInfo->Type.MiniFilter.FilterNameLength != 0U) {
        nameString.Buffer = (PWCHAR)((PUCHAR)filterInfo + filterInfo->Type.MiniFilter.FilterNameBufferOffset);
        nameString.Length = filterInfo->Type.MiniFilter.FilterNameLength;
        nameString.MaximumLength = filterInfo->Type.MiniFilter.FilterNameLength;
        kswordArkMinifilterInventoryCopyUnicode(
            entry->filterName,
            RTL_NUMBER_OF(entry->filterName),
            &nameString);
        entry->fieldFlags |= KSWORD_ARK_MINIFILTER_INVENTORY_ROW_FLAG_NAME_PRESENT;
    }

    if (filterInfo->Type.MiniFilter.FilterAltitudeBufferOffset != 0U &&
        filterInfo->Type.MiniFilter.FilterAltitudeLength != 0U) {
        altitudeString.Buffer = (PWCHAR)((PUCHAR)filterInfo + filterInfo->Type.MiniFilter.FilterAltitudeBufferOffset);
        altitudeString.Length = filterInfo->Type.MiniFilter.FilterAltitudeLength;
        altitudeString.MaximumLength = filterInfo->Type.MiniFilter.FilterAltitudeLength;
        kswordArkMinifilterInventoryCopyUnicode(
            entry->altitude,
            RTL_NUMBER_OF(entry->altitude),
            &altitudeString);
        entry->fieldFlags |= KSWORD_ARK_MINIFILTER_INVENTORY_ROW_FLAG_ALTITUDE_PRESENT;
    }
}

static NTSTATUS
kswordArkMinifilterInventoryCopyVolumeName(
    _In_ PFLT_VOLUME volumeObject,
    _Inout_ KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY* entry
    )
/*++

Routine Description:

    Query and copy the public Filter Manager volume name for a binding row.

Arguments:

    VolumeObject - Referenced Filter Manager volume object.
    Entry - Response row that receives volume name text.

Return Value:

    STATUS_SUCCESS when a name is copied; otherwise the Filter Manager or
    allocation status.

--*/
{
    UNICODE_STRING volumeName;
    ULONG bytesNeeded = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (volumeObject == NULL || entry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&volumeName, sizeof(volumeName));
    status = FltGetVolumeName(volumeObject, NULL, &bytesNeeded);
    if (status != STATUS_BUFFER_TOO_SMALL || bytesNeeded == 0UL) {
        return status;
    }
    if (bytesNeeded > 0xFFFEUL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    volumeName.Buffer = (PWCHAR)kswordArkMinifilterInventoryAllocate(bytesNeeded + sizeof(WCHAR));
    if (volumeName.Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    volumeName.Length = 0U;
    volumeName.MaximumLength = (USHORT)bytesNeeded;
    RtlZeroMemory(volumeName.Buffer, bytesNeeded + sizeof(WCHAR));

    status = FltGetVolumeName(volumeObject, &volumeName, &bytesNeeded);
    if (NT_SUCCESS(status)) {
        kswordArkMinifilterInventoryCopyUnicode(
            entry->volumeName,
            RTL_NUMBER_OF(entry->volumeName),
            &volumeName);
        entry->fieldFlags |= KSWORD_ARK_MINIFILTER_INVENTORY_ROW_FLAG_VOLUME_NAME_PRESENT;
    }

    ExFreePoolWithTag(volumeName.Buffer, KSWORD_ARK_MINIFILTER_INVENTORY_TAG);
    return status;
}

static VOID
kswordArkMinifilterInventoryAppendRow(
    _Inout_ KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_RESPONSE* response,
    _In_ ULONG entryCapacity,
    _In_ const KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY* entry
    )
/*++

Routine Description:

    Append one row to the variable inventory response while tracking truncation.

Arguments:

    Response - Response packet being built.
    EntryCapacity - Number of rows that fit in the caller output buffer.
    Entry - Source row.

Return Value:

    None. Response flags record truncation when capacity is exhausted.

--*/
{
    if (response == NULL || entry == NULL) {
        return;
    }

    if (response->totalCount != MAXULONG) {
        response->totalCount += 1UL;
    }

    if (response->returnedCount >= entryCapacity) {
        response->flags |= KSWORD_ARK_MINIFILTER_INVENTORY_RESPONSE_FLAG_TRUNCATED;
        response->queryStatus = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_BUFFER_TRUNCATED;
        return;
    }

    RtlCopyMemory(&response->entries[response->returnedCount], entry, sizeof(*entry));
    response->returnedCount += 1UL;
}

static VOID
kswordArkMinifilterInventorySeedRow(
    _In_ PFLT_FILTER filterObject,
    _In_opt_ const FILTER_AGGREGATE_STANDARD_INFORMATION* filterInfo,
    _Out_ KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY* entry
    )
/*++

Routine Description:

    initialize a row with filter identity and conservative callback-owner status.

Arguments:

    FilterObject - Referenced Filter Manager filter object.
    FilterInfo - Optional aggregate information buffer.
    Entry - Output row.

Return Value:

    None. Entry is zeroed and then populated.

--*/
{
    if (entry == NULL) {
        return;
    }

    RtlZeroMemory(entry, sizeof(*entry));
    entry->size = sizeof(*entry);
    entry->status = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_OK;
    entry->sourceFlags = KSWORD_ARK_CALLBACK_ENUM_SOURCE_FLTMGR_ENUMERATION;
    entry->filterObject = (ULONG64)(ULONG_PTR)filterObject;
    entry->callbackOwnerStatus = STATUS_NOT_SUPPORTED;
    entry->fieldFlags = KSWORD_ARK_MINIFILTER_INVENTORY_ROW_FLAG_FILTER_PRESENT |
        KSWORD_ARK_MINIFILTER_INVENTORY_ROW_FLAG_CALLBACK_OWNER_UNSUPPORTED;
    if (filterInfo != NULL) {
        kswordArkMinifilterInventoryFillFilterText(filterInfo, entry);
    }
}

static VOID
kswordArkMinifilterInventoryAddVolumeRows(
    _In_ PFLT_FILTER filterObject,
    _In_ const KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY* baseEntry,
    _Inout_ KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_RESPONSE* response,
    _In_ ULONG entryCapacity
    )
/*++

Routine Description:

    enumerate public volume bindings for one filter and append one row per
    bound volume. The routine only uses Filter Manager references and releases
    every object before returning.

Arguments:

    FilterObject - Referenced filter object.
    BaseEntry - Filter identity copied into each binding row.
    Response - Response packet being built.
    EntryCapacity - Number of rows available in Response.

Return Value:

    None. Partial failures set response flags and keep already-built rows.

--*/
{
    PFLT_VOLUME* volumeList = NULL;
    ULONG volumeCount = 0UL;
    ULONG volumeIndex = 0UL;
    SIZE_T allocationBytes = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    status = FltEnumerateVolumes(filterObject, NULL, 0UL, &volumeCount);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_SUCCESS) {
        response->lastStatus = status;
        response->flags |= KSWORD_ARK_MINIFILTER_INVENTORY_RESPONSE_FLAG_PARTIAL;
        return;
    }
    if (volumeCount == 0UL) {
        return;
    }

    allocationBytes = (SIZE_T)volumeCount * sizeof(PFLT_VOLUME);
    volumeList = (PFLT_VOLUME*)kswordArkMinifilterInventoryAllocate(allocationBytes);
    if (volumeList == NULL) {
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        response->flags |= KSWORD_ARK_MINIFILTER_INVENTORY_RESPONSE_FLAG_PARTIAL;
        return;
    }
    RtlZeroMemory(volumeList, allocationBytes);

    status = FltEnumerateVolumes(filterObject, volumeList, volumeCount, &volumeCount);
    if (!NT_SUCCESS(status)) {
        response->lastStatus = status;
        response->flags |= KSWORD_ARK_MINIFILTER_INVENTORY_RESPONSE_FLAG_PARTIAL;
        ExFreePoolWithTag(volumeList, KSWORD_ARK_MINIFILTER_INVENTORY_TAG);
        return;
    }

    for (volumeIndex = 0UL; volumeIndex < volumeCount; ++volumeIndex) {
        KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY row;
        PFLT_INSTANCE instanceProbe = NULL;
        ULONG bindingInstanceCount = 0UL;

        if (volumeList[volumeIndex] == NULL) {
            continue;
        }

        RtlCopyMemory(&row, baseEntry, sizeof(row));
        row.volumeObject = (ULONG64)(ULONG_PTR)volumeList[volumeIndex];
        row.fieldFlags |= KSWORD_ARK_MINIFILTER_INVENTORY_ROW_FLAG_VOLUME_PRESENT;
        (VOID)kswordArkMinifilterInventoryCopyVolumeName(volumeList[volumeIndex], &row);

        status = FltEnumerateInstances(volumeList[volumeIndex], filterObject, &instanceProbe, 1UL, &bindingInstanceCount);
        if (NT_SUCCESS(status) && instanceProbe != NULL) {
            FltObjectDereference(instanceProbe);
        }
        if (status == STATUS_BUFFER_TOO_SMALL || NT_SUCCESS(status)) {
            row.volumeBindingInstanceCount = bindingInstanceCount;
        }
        else {
            row.status = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_PARTIAL;
            response->lastStatus = status;
            response->flags |= KSWORD_ARK_MINIFILTER_INVENTORY_RESPONSE_FLAG_PARTIAL;
        }

        kswordArkMinifilterInventoryAppendRow(response, entryCapacity, &row);
    }

    for (volumeIndex = 0UL; volumeIndex < volumeCount; ++volumeIndex) {
        if (volumeList[volumeIndex] != NULL) {
            FltObjectDereference(volumeList[volumeIndex]);
        }
    }
    ExFreePoolWithTag(volumeList, KSWORD_ARK_MINIFILTER_INVENTORY_TAG);
}

static NTSTATUS
kswordArkMinifilterInventoryBuild(
    _In_ const KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_REQUEST* request,
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Build the read-only minifilter inventory response by using Filter Manager
    public enumeration APIs. When requested, the first validated Pre/Post
    callback supplies a module-owner hint without modifying fltMgr state.

Arguments:

    Request - Validated request packet.
    OutputBuffer - Caller output buffer.
    OutputBufferLength - Output buffer size.
    BytesWrittenOut - Receives the number of bytes populated.

Return Value:

    STATUS_SUCCESS when the response header is valid; hard failures represent
    only buffer or parameter errors.

--*/
{
    KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_RESPONSE* response = NULL;
    PFLT_FILTER* filterList = NULL;
    ULONG filterCount = 0UL;
    ULONG filterIndex = 0UL;
    ULONG maxRows = 0UL;
    ULONG entryCapacity = 0UL;
    SIZE_T allocationBytes = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (request == NULL || outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSWORD_ARK_MINIFILTER_INVENTORY_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_RESPONSE*)outputBuffer;
    response->size = KSWORD_ARK_MINIFILTER_INVENTORY_HEADER_SIZE;
    response->version = KSWORD_ARK_FILTER_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY);
    response->queryStatus = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_UNAVAILABLE;
    response->lastStatus = STATUS_SUCCESS;

    maxRows = request->maxRows;
    if (maxRows == 0UL || maxRows > KSWORD_ARK_MINIFILTER_INVENTORY_MAX_ROWS) {
        maxRows = KSWORD_ARK_MINIFILTER_INVENTORY_MAX_ROWS;
    }
    entryCapacity = (ULONG)((outputBufferLength - KSWORD_ARK_MINIFILTER_INVENTORY_HEADER_SIZE) / sizeof(KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY));
    if (entryCapacity > maxRows) {
        entryCapacity = maxRows;
    }

    status = FltEnumerateFilters(NULL, 0UL, &filterCount);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_SUCCESS) {
        response->queryStatus = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_QUERY_FAILED;
        response->lastStatus = status;
        *bytesWrittenOut = KSWORD_ARK_MINIFILTER_INVENTORY_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    if (filterCount == 0UL) {
        response->queryStatus = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_OK;
        *bytesWrittenOut = KSWORD_ARK_MINIFILTER_INVENTORY_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    allocationBytes = (SIZE_T)filterCount * sizeof(PFLT_FILTER);
    filterList = (PFLT_FILTER*)kswordArkMinifilterInventoryAllocate(allocationBytes);
    if (filterList == NULL) {
        response->queryStatus = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_QUERY_FAILED;
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        *bytesWrittenOut = KSWORD_ARK_MINIFILTER_INVENTORY_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    RtlZeroMemory(filterList, allocationBytes);

    status = FltEnumerateFilters(filterList, filterCount, &filterCount);
    if (!NT_SUCCESS(status)) {
        response->queryStatus = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_QUERY_FAILED;
        response->lastStatus = status;
        ExFreePoolWithTag(filterList, KSWORD_ARK_MINIFILTER_INVENTORY_TAG);
        *bytesWrittenOut = KSWORD_ARK_MINIFILTER_INVENTORY_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    for (filterIndex = 0UL; filterIndex < filterCount; ++filterIndex) {
        FILTER_AGGREGATE_STANDARD_INFORMATION* filterInfo = NULL;
        KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY row;

        if (filterList[filterIndex] == NULL) {
            continue;
        }

        status = kswordArkMinifilterInventoryQueryFilterInfo(filterList[filterIndex], &filterInfo);
        response->lastStatus = status;
        kswordArkMinifilterInventorySeedRow(filterList[filterIndex], filterInfo, &row);
        if ((request->flags & KSWORD_ARK_MINIFILTER_INVENTORY_FLAG_INCLUDE_CALLBACK_OWNER_HINT) != 0UL) {
            row.callbackOwnerStatus = kswordArkMinifilterQueryFirstCallbackOwner(
                filterList[filterIndex],
                row.callbackOwnerModule,
                RTL_NUMBER_OF(row.callbackOwnerModule),
                &row.callbackOwnerModuleBase,
                &row.callbackOwnerModuleSize);
            if (NT_SUCCESS(row.callbackOwnerStatus)) {
                row.fieldFlags &= ~KSWORD_ARK_MINIFILTER_INVENTORY_ROW_FLAG_CALLBACK_OWNER_UNSUPPORTED;
                row.fieldFlags |= KSWORD_ARK_MINIFILTER_INVENTORY_ROW_FLAG_CALLBACK_OWNER_PRESENT;
            }
        }
        if (!NT_SUCCESS(status)) {
            row.status = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_PARTIAL;
            response->flags |= KSWORD_ARK_MINIFILTER_INVENTORY_RESPONSE_FLAG_PARTIAL;
        }

        if ((request->flags & KSWORD_ARK_MINIFILTER_INVENTORY_FLAG_INCLUDE_VOLUMES) != 0UL) {
            kswordArkMinifilterInventoryAddVolumeRows(filterList[filterIndex], &row, response, entryCapacity);
        }
        else {
            kswordArkMinifilterInventoryAppendRow(response, entryCapacity, &row);
        }

        if (filterInfo != NULL) {
            ExFreePoolWithTag(filterInfo, KSWORD_ARK_MINIFILTER_INVENTORY_TAG);
        }
        FltObjectDereference(filterList[filterIndex]);
    }

    ExFreePoolWithTag(filterList, KSWORD_ARK_MINIFILTER_INVENTORY_TAG);
    if ((response->flags & KSWORD_ARK_MINIFILTER_INVENTORY_RESPONSE_FLAG_TRUNCATED) != 0UL) {
        response->queryStatus = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_BUFFER_TRUNCATED;
    }
    else if ((response->flags & KSWORD_ARK_MINIFILTER_INVENTORY_RESPONSE_FLAG_PARTIAL) != 0UL) {
        response->queryStatus = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_PARTIAL;
    }
    else {
        response->queryStatus = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_OK;
    }

    *bytesWrittenOut = KSWORD_ARK_MINIFILTER_INVENTORY_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY));
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkMinifilterIoctlQueryInventory(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_MINIFILTER_INVENTORY. The handler validates
    METHOD_BUFFERED buffers and delegates all collection to the feature builder.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Input length supplied by the dispatch layer.
    OutputBufferLength - Output length supplied by the dispatch layer.
    BytesReturned - Receives the completed byte count.

Return Value:

    NTSTATUS from buffer validation or the inventory builder.

--*/
{
    KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_REQUEST* queryRequest = NULL;
    KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_REQUEST defaultRequest;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    RtlZeroMemory(&defaultRequest, sizeof(defaultRequest));
    defaultRequest.size = sizeof(defaultRequest);
    defaultRequest.version = KSWORD_ARK_FILTER_PROTOCOL_VERSION;
    defaultRequest.flags = KSWORD_ARK_MINIFILTER_INVENTORY_FLAG_INCLUDE_ALL;
    defaultRequest.maxRows = 1024UL;

    status = kswordArkRetrieveOptionalInputBuffer(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        kswordArkMinifilterInventoryLog(device, "Error", "R0 minifilter inventory ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    UNREFERENCED_PARAMETER(actualInputLength);

    queryRequest = hasInput ? (KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_REQUEST*)inputBuffer : &defaultRequest;
    if (queryRequest->size != sizeof(KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_REQUEST) ||
        queryRequest->version != KSWORD_ARK_FILTER_PROTOCOL_VERSION ||
        (queryRequest->flags & ~KSWORD_ARK_MINIFILTER_INVENTORY_FLAG_INCLUDE_ALL) != 0UL) {
        kswordArkMinifilterInventoryLog(device, "Warn", "R0 minifilter inventory ioctl: request rejected, size=%lu, version=%lu, flags=0x%08X.",
            (unsigned long)queryRequest->size,
            (unsigned long)queryRequest->version,
            (unsigned int)queryRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_MINIFILTER_INVENTORY_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMinifilterInventoryLog(device, "Error", "R0 minifilter inventory ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkMinifilterInventoryBuild(queryRequest, outputBuffer, actualOutputLength, bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkMinifilterInventoryLog(device, "Error", "R0 minifilter inventory failed: status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_MINIFILTER_INVENTORY_HEADER_SIZE) {
        const KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_RESPONSE* response =
            (const KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_RESPONSE*)outputBuffer;
        kswordArkMinifilterInventoryLog(
            device,
            "Info",
            "R0 minifilter inventory success: status=%lu, total=%lu, returned=%lu.",
            (unsigned long)response->queryStatus,
            (unsigned long)response->totalCount,
            (unsigned long)response->returnedCount);
    }

    return STATUS_SUCCESS;
}
