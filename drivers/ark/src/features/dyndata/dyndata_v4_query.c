/*++

Module Name:

    dyndata_v4_query.c

Abstract:

    DynData v4 multi-module PDB profile query IOCTL handlers.

Environment:

    Kernel-mode Driver Framework

--*/

#include "dyndata_v4_internal.h"
#include "ark/ark_push_lock.h"
#include "ark/ark_log.h"
#include "../../dispatch/ioctl_validation.h"

#define KSW_DYN_V4_IOCTL_POOL_TAG '4DsK'

typedef PVOID
(NTAPI* KswDynV4ExAllocatePooL2Fn)(
    _In_ POOL_FLAGS flags,
    _In_ SIZE_T numberOfBytes,
    _In_ ULONG tag
    );

static PVOID
kswordArkDynDataV4AllocateRequestCopy(
    _In_ SIZE_T bufferBytes
    )
/*++

Routine Description:

    Allocate the nonpaged METHOD_BUFFERED input copy used by v4 apply. The copy
    keeps the request stable because buffered IOCTL input and output can point to
    the same WDF system buffer.

Arguments:

    BufferBytes - Number of request bytes to preserve.

Return Value:

    Nonpaged allocation on success; NULL on zero length or allocation failure.

--*/
{
    static volatile LONG allocatorResolved = 0;
    static KswDynV4ExAllocatePooL2Fn exAllocatePool2Fn = NULL;

    if (bufferBytes == 0U) {
        return NULL;
    }

    if (InterlockedCompareExchange(&allocatorResolved, 1L, 0L) == 0L) {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ExAllocatePool2");
        exAllocatePool2Fn = (KswDynV4ExAllocatePooL2Fn)MmGetSystemRoutineAddress(&routineName);
    }

    if (exAllocatePool2Fn != NULL) {
        return exAllocatePool2Fn(POOL_FLAG_NON_PAGED, bufferBytes, KSW_DYN_V4_IOCTL_POOL_TAG);
    }

#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(NonPagedPoolNx, bufferBytes, KSW_DYN_V4_IOCTL_POOL_TAG);
#pragma warning(pop)
}

NTSTATUS
kswordArkDynDataV4QueryModules(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Return cached v4 module profile status rows.

Arguments:

    OutputBuffer - METHOD_BUFFERED output buffer.
    OutputBufferLength - Writable byte count.
    BytesWrittenOut - Receives bytes written.

Return Value:

    STATUS_SUCCESS when the response header is written.

--*/
{
    KSW_QUERY_DYN_V4_MODULES_RESPONSE* response = NULL;
    ULONG totalCount = 0UL;
    ULONG returnedCount = 0UL;
    ULONG capacity = 0UL;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSW_QUERY_DYN_V4_MODULES_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSW_QUERY_DYN_V4_MODULES_RESPONSE*)outputBuffer;
    response->version = KSW_DYN_V4_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSW_DYN_V4_MODULE_STATUS_ENTRY);
    capacity = (ULONG)((outputBufferLength - KSW_QUERY_DYN_V4_MODULES_RESPONSE_HEADER_SIZE) / sizeof(KSW_DYN_V4_MODULE_STATUS_ENTRY));

    // Even if the profile is not yet applied, return the current module identity so R3 can precisely select multi-module entries like CI.
    returnedCount = kswordArkDynDataV4BuildModuleStatusSnapshot(
        response->entries,
        capacity,
        &totalCount);

    response->totalCount = totalCount;
    response->returnedCount = returnedCount;
    response->size = (ULONG)(KSW_QUERY_DYN_V4_MODULES_RESPONSE_HEADER_SIZE + ((size_t)returnedCount * sizeof(KSW_DYN_V4_MODULE_STATUS_ENTRY)));
    *bytesWrittenOut = response->size;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDynDataV4QueryCapabilityGroups(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Return cached v4 capability group coverage rows.

Arguments:

    OutputBuffer - METHOD_BUFFERED output buffer.
    OutputBufferLength - Writable byte count.
    BytesWrittenOut - Receives bytes written.

Return Value:

    STATUS_SUCCESS when the response header is written.

--*/
{
    KSW_QUERY_DYN_V4_CAPABILITY_GROUPS_RESPONSE* response = NULL;
    ULONG moduleIndex = 0UL;
    ULONG groupIndex = 0UL;
    ULONG totalCount = 0UL;
    ULONG returnedCount = 0UL;
    ULONG capacity = 0UL;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSW_QUERY_DYN_V4_CAPABILITY_GROUPS_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSW_QUERY_DYN_V4_CAPABILITY_GROUPS_RESPONSE*)outputBuffer;
    response->version = KSW_DYN_V4_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSW_DYN_V4_CAPABILITY_GROUP_STATUS_ENTRY);
    capacity = (ULONG)((outputBufferLength - KSW_QUERY_DYN_V4_CAPABILITY_GROUPS_RESPONSE_HEADER_SIZE) / sizeof(KSW_DYN_V4_CAPABILITY_GROUP_STATUS_ENTRY));

    kswordArkAcquirePushLockShared(&gKswordDynDataV4Lock);
    for (moduleIndex = 0UL; moduleIndex < KSW_DYN_V4_MAX_MODULES; ++moduleIndex) {
        if (!gKswordDynDataV4State.modules[moduleIndex].occupied) {
            continue;
        }
        for (groupIndex = 0UL; groupIndex < gKswordDynDataV4State.modules[moduleIndex].publicEntry.capabilityGroupCount; ++groupIndex) {
            totalCount += 1UL;
            if (returnedCount < capacity) {
                response->entries[returnedCount] = gKswordDynDataV4State.modules[moduleIndex].groups[groupIndex].publicEntry;
                returnedCount += 1UL;
            }
        }
    }
    kswordArkReleasePushLockShared(&gKswordDynDataV4Lock);

    response->totalCount = totalCount;
    response->returnedCount = returnedCount;
    response->size = (ULONG)(KSW_QUERY_DYN_V4_CAPABILITY_GROUPS_RESPONSE_HEADER_SIZE + ((size_t)returnedCount * sizeof(KSW_DYN_V4_CAPABILITY_GROUP_STATUS_ENTRY)));
    *bytesWrittenOut = response->size;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDynDataV4QueryMissingItems(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Return cached v4 required/optional missing item summary rows.

Arguments:

    OutputBuffer - METHOD_BUFFERED output buffer.
    OutputBufferLength - Writable byte count.
    BytesWrittenOut - Receives bytes written.

Return Value:

    STATUS_SUCCESS when the response header is written.

--*/
{
    KSW_QUERY_DYN_V4_MISSING_ITEMS_RESPONSE* response = NULL;
    ULONG index = 0UL;
    ULONG returnedCount = 0UL;
    ULONG capacity = 0UL;
    ULONG totalCount = 0UL;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSW_QUERY_DYN_V4_MISSING_ITEMS_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSW_QUERY_DYN_V4_MISSING_ITEMS_RESPONSE*)outputBuffer;
    response->version = KSW_DYN_V4_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSW_DYN_V4_MISSING_ITEM_ENTRY);
    capacity = (ULONG)((outputBufferLength - KSW_QUERY_DYN_V4_MISSING_ITEMS_RESPONSE_HEADER_SIZE) / sizeof(KSW_DYN_V4_MISSING_ITEM_ENTRY));

    kswordArkAcquirePushLockShared(&gKswordDynDataV4Lock);
    totalCount = gKswordDynDataV4State.missingCount;
    for (index = 0UL; index < totalCount && returnedCount < capacity; ++index) {
        response->entries[returnedCount] = gKswordDynDataV4State.missing[index];
        returnedCount += 1UL;
    }
    kswordArkReleasePushLockShared(&gKswordDynDataV4Lock);

    response->totalCount = totalCount;
    response->returnedCount = returnedCount;
    response->size = (ULONG)(KSW_QUERY_DYN_V4_MISSING_ITEMS_RESPONSE_HEADER_SIZE + ((size_t)returnedCount * sizeof(KSW_DYN_V4_MISSING_ITEM_ENTRY)));
    *bytesWrittenOut = response->size;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDynDataV4QueryItems(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Return cached v4 accepted item rows. This is a read-only audit query; it
    exposes the compact PDB facts that have already passed v4 identity and
    validation checks, without applying them to any feature path.

Arguments:

    OutputBuffer - METHOD_BUFFERED output buffer.
    OutputBufferLength - Writable byte count.
    BytesWrittenOut - Receives bytes written.

Return Value:

    STATUS_SUCCESS when the response header is written.

--*/
{
    KSW_QUERY_DYN_V4_ITEMS_RESPONSE* response = NULL;
    ULONG moduleIndex = 0UL;
    ULONG itemIndex = 0UL;
    ULONG itemCount = 0UL;
    ULONG totalCount = 0UL;
    ULONG returnedCount = 0UL;
    ULONG capacity = 0UL;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSW_QUERY_DYN_V4_ITEMS_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSW_QUERY_DYN_V4_ITEMS_RESPONSE*)outputBuffer;
    response->version = KSW_DYN_V4_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSW_DYN_V4_ITEM_STATUS_ENTRY);
    capacity = (ULONG)((outputBufferLength - KSW_QUERY_DYN_V4_ITEMS_RESPONSE_HEADER_SIZE) / sizeof(KSW_DYN_V4_ITEM_STATUS_ENTRY));

    kswordArkAcquirePushLockShared(&gKswordDynDataV4Lock);
    for (moduleIndex = 0UL; moduleIndex < KSW_DYN_V4_MAX_MODULES; ++moduleIndex) {
        const KswDynV4ModuleState* moduleState = &gKswordDynDataV4State.modules[moduleIndex];
        if (!moduleState->occupied) {
            continue;
        }

        itemCount = moduleState->storedItemCount;
        if (itemCount > KSW_DYN_V4_MAX_ITEMS_PER_MODULE) {
            itemCount = KSW_DYN_V4_MAX_ITEMS_PER_MODULE;
        }

        for (itemIndex = 0UL; itemIndex < itemCount; ++itemIndex) {
            totalCount += 1UL;
            if (returnedCount < capacity) {
                response->entries[returnedCount].moduleClassId = moduleState->publicEntry.module.image.classId;
                response->entries[returnedCount].itemIndex = itemIndex;
                response->entries[returnedCount].item = moduleState->items[itemIndex];
                returnedCount += 1UL;
            }
        }
    }
    kswordArkReleasePushLockShared(&gKswordDynDataV4Lock);

    response->totalCount = totalCount;
    response->returnedCount = returnedCount;
    response->size = (ULONG)(KSW_QUERY_DYN_V4_ITEMS_RESPONSE_HEADER_SIZE + ((size_t)returnedCount * sizeof(KSW_DYN_V4_ITEM_STATUS_ENTRY)));
    *bytesWrittenOut = response->size;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkDynDataV4RetrieveOutput(
    _In_ WDFREQUEST request,
    _In_ size_t headerBytes,
    _Outptr_result_bytebuffer_(*actualOutputLength) PVOID* outputBuffer,
    _Out_ size_t* actualOutputLength
    )
/*++

Routine Description:

    Retrieve a v4 variable or fixed output buffer through the shared helper.

Arguments:

    Request - WDF IOCTL request.
    HeaderBytes - Minimum response header size.
    OutputBuffer - Receives output buffer.
    ActualOutputLength - Receives actual writable length.

Return Value:

    NTSTATUS from common output-buffer validation.

--*/
{
    return kswordArkRetrieveRequiredOutputBuffer(request, headerBytes, outputBuffer, actualOutputLength);
}

NTSTATUS
kswordArkDynDataIoctlApplyProfileV4(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle the buffered v4 module profile apply IOCTL.

Arguments:

    Device - WDF device used only for diagnostic logging.
    Request - WDF IOCTL request.
    InputBufferLength - Dispatcher-supplied input length.
    OutputBufferLength - Dispatcher-supplied output length.
    BytesReturned - Receives response bytes.

Return Value:

    STATUS_SUCCESS when a handled response is produced; otherwise validation status.

--*/
{
    KSW_APPLY_DYN_PROFILE_V4_REQUEST* inputBuffer = NULL;
    KSW_APPLY_DYN_PROFILE_V4_REQUEST* inputCopy = NULL;
    KSW_APPLY_DYN_PROFILE_V4_RESPONSE* outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    size_t copyLength = 0U;
    const size_t kMaxProfileRequestBytes =
        KSW_APPLY_DYN_PROFILE_V4_REQUEST_HEADER_SIZE +
        ((size_t)KSW_DYN_V4_MAX_ITEMS_PER_MODULE * sizeof(KSW_DYN_V4_ITEM_PACKET));
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveRequiredInputBuffer(request, KSW_APPLY_DYN_PROFILE_V4_REQUEST_HEADER_SIZE, (PVOID*)&inputBuffer, &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    copyLength = actualInputLength;
    if (copyLength > kMaxProfileRequestBytes) {
        copyLength = kMaxProfileRequestBytes;
    }
    inputCopy = (KSW_APPLY_DYN_PROFILE_V4_REQUEST*)kswordArkDynDataV4AllocateRequestCopy(copyLength);
    if (inputCopy == NULL) {
        (VOID)kswordArkDriverEnqueueLogFrame(device, "Error", "DynData v4 profile apply input copy allocation failed.");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(inputCopy, inputBuffer, copyLength);

    status = kswordArkRetrieveRequiredOutputBuffer(request, sizeof(KSW_APPLY_DYN_PROFILE_V4_RESPONSE), (PVOID*)&outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(inputCopy, KSW_DYN_V4_IOCTL_POOL_TAG);
        return status;
    }

    status = kswordArkDynDataV4ApplyProfile(inputCopy, copyLength, outputBuffer, actualOutputLength, bytesReturned);
    ExFreePoolWithTag(inputCopy, KSW_DYN_V4_IOCTL_POOL_TAG);
    (VOID)kswordArkDriverEnqueueLogFrame(device, NT_SUCCESS(status) ? "Info" : "Warn", "DynData v4 profile apply completed.");
    return (*bytesReturned >= sizeof(KSW_APPLY_DYN_PROFILE_V4_RESPONSE)) ? STATUS_SUCCESS : status;
}

NTSTATUS
kswordArkDynDataIoctlQueryV4Modules(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle the v4 applied-module status query IOCTL.

Arguments:

    Device - WDF device reserved for parity with other handlers.
    Request - WDF IOCTL request.
    InputBufferLength - Unused query input length.
    OutputBufferLength - Dispatcher-supplied output length.
    BytesReturned - Receives response bytes.

Return Value:

    NTSTATUS from buffer retrieval or query construction.

--*/
{
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    status = kswordArkDynDataV4RetrieveOutput(request, KSW_QUERY_DYN_V4_MODULES_RESPONSE_HEADER_SIZE, &outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return kswordArkDynDataV4QueryModules(outputBuffer, actualOutputLength, bytesReturned);
}

NTSTATUS
kswordArkDynDataIoctlQueryV4CapabilityGroups(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle the v4 capability group coverage query IOCTL.

Arguments:

    Device - WDF device reserved for parity with other handlers.
    Request - WDF IOCTL request.
    InputBufferLength - Unused query input length.
    OutputBufferLength - Dispatcher-supplied output length.
    BytesReturned - Receives response bytes.

Return Value:

    NTSTATUS from buffer retrieval or query construction.

--*/
{
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    status = kswordArkDynDataV4RetrieveOutput(request, KSW_QUERY_DYN_V4_CAPABILITY_GROUPS_RESPONSE_HEADER_SIZE, &outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return kswordArkDynDataV4QueryCapabilityGroups(outputBuffer, actualOutputLength, bytesReturned);
}

NTSTATUS
kswordArkDynDataIoctlQueryV4MissingItems(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle the v4 missing required/optional summary query IOCTL.

Arguments:

    Device - WDF device reserved for parity with other handlers.
    Request - WDF IOCTL request.
    InputBufferLength - Unused query input length.
    OutputBufferLength - Dispatcher-supplied output length.
    BytesReturned - Receives response bytes.

Return Value:

    NTSTATUS from buffer retrieval or query construction.

--*/
{
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    status = kswordArkDynDataV4RetrieveOutput(request, KSW_QUERY_DYN_V4_MISSING_ITEMS_RESPONSE_HEADER_SIZE, &outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return kswordArkDynDataV4QueryMissingItems(outputBuffer, actualOutputLength, bytesReturned);
}

NTSTATUS
kswordArkDynDataIoctlQueryV4Items(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle the v4 accepted item inventory query IOCTL.

Arguments:

    Device - WDF device reserved for parity with other handlers.
    Request - WDF IOCTL request.
    InputBufferLength - Unused query input length.
    OutputBufferLength - Dispatcher-supplied output length.
    BytesReturned - Receives response bytes.

Return Value:

    NTSTATUS from buffer retrieval or query construction.

--*/
{
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    status = kswordArkDynDataV4RetrieveOutput(request, KSW_QUERY_DYN_V4_ITEMS_RESPONSE_HEADER_SIZE, &outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return kswordArkDynDataV4QueryItems(outputBuffer, actualOutputLength, bytesReturned);
}
