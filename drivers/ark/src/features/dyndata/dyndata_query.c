/*++

Module Name:

    dyndata_query.c

Abstract:

    DynData state snapshot query helpers and IOCTL handlers.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_dyndata.h"
#include "ark/ark_dyndata_fields.h"
#include "ark/ark_log.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSW_DYN_FIELDS_RESPONSE_HEADER_SIZE \
    (sizeof(KSW_QUERY_DYN_FIELDS_RESPONSE) - sizeof(KSW_DYN_FIELD_ENTRY))

#define KSW_DYN_PROFILE_IOCTL_POOL_TAG 'pDsK'

typedef PVOID
(NTAPI* KswDynExAllocatePooL2Fn)(
    _In_ POOL_FLAGS flags,
    _In_ SIZE_T numberOfBytes,
    _In_ ULONG tag
    );

static PVOID
kswordArkDynDataAllocateProfileCopy(
    _In_ SIZE_T bufferBytes
    )
/*++

Routine Description:

    Allocate the METHOD_BUFFERED input copy used by the PDB profile apply IOCTL.
    The helper prefers ExAllocatePool2 when the running kernel exports it, while
    preserving the existing old-kernel fallback style used by other feature
    modules in this driver.

Arguments:

    BufferBytes - Number of nonpaged bytes required for the copied request.

Return Value:

    A nonpaged allocation on success; NULL on invalid size or allocation failure.

--*/
{
    static volatile LONG allocatorResolved = 0;
    static KswDynExAllocatePooL2Fn exAllocatePool2Fn = NULL;

    if (bufferBytes == 0U) {
        return NULL;
    }

    if (InterlockedCompareExchange(&allocatorResolved, 1L, 0L) == 0L) {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ExAllocatePool2");
        exAllocatePool2Fn = (KswDynExAllocatePooL2Fn)MmGetSystemRoutineAddress(&routineName);
    }

    if (exAllocatePool2Fn != NULL) {
        return exAllocatePool2Fn(POOL_FLAG_NON_PAGED, bufferBytes, KSW_DYN_PROFILE_IOCTL_POOL_TAG);
    }

#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(NonPagedPoolNx, bufferBytes, KSW_DYN_PROFILE_IOCTL_POOL_TAG);
#pragma warning(pop)
}

static ULONG
kswordArkDynDataStatusFlagsFromState(
    _In_ const KswDynState* state
    )
/*++

Routine Description:

    Convert internal boolean DynData state into public KSW_DYN_STATUS_FLAG_* bits.

Arguments:

    State - State snapshot to convert.

Return Value:

    Public status flag bit mask.

--*/
{
    ULONG flags = 0UL;

    if (state == NULL) {
        return 0UL;
    }
    if (state->initialized) {
        flags |= KSW_DYN_STATUS_FLAG_INITIALIZED;
    }
    if (state->ntosActive) {
        flags |= KSW_DYN_STATUS_FLAG_NTOS_ACTIVE;
    }
    if (state->lxcoreActive) {
        flags |= KSW_DYN_STATUS_FLAG_LXCORE_ACTIVE;
    }
    if (state->extraActive) {
        flags |= KSW_DYN_STATUS_FLAG_EXTRA_ACTIVE;
    }
    if (state->pdbProfileActive) {
        flags |= KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE;
    }
    if (state->callbackProfileActive) {
        flags |= KSW_DYN_STATUS_FLAG_CALLBACK_PROFILE_ACTIVE;
    }

    return flags;
}

static VOID
kswordArkDynDataIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Format and enqueue one DynData IOCTL diagnostic message.

Arguments:

    Device - WDF device that owns the log channel.
    levelText - Log level string.
    FormatText - printf-style message template.
    ... - Template arguments.

Return Value:

    None. Formatting or queue failures are intentionally ignored.

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

ULONG
kswordArkDynDataBuildFieldEntries(
    _Out_writes_opt_(entryCapacity) KSW_DYN_FIELD_ENTRY* entries,
    _In_ ULONG entryCapacity
    )
/*++

Routine Description:

    Build public field entries from a global DynData state snapshot.

Arguments:

    Entries - Optional destination entry array.
    EntryCapacity - Number of entries that fit in Entries.

Return Value:

    Number of entries copied when Entries is present; otherwise total descriptor
    count so callers can size variable responses.

--*/
{
    KswDynState state;

    if (entries == NULL || entryCapacity == 0UL) {
        return kswordArkDynDataCountFieldDescriptors();
    }

    kswordArkDynDataSnapshot(&state);
    return kswordArkDynDataCopyFieldDescriptors(&state, entries, entryCapacity);
}

NTSTATUS
kswordArkDynDataQueryStatus(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Write the fixed DynData status response for R3 diagnostics.

Arguments:

    OutputBuffer - METHOD_BUFFERED output buffer.
    OutputBufferLength - Writable output byte count.
    BytesWrittenOut - Receives bytes written on success.

Return Value:

    STATUS_SUCCESS when the fixed response is written; otherwise validation
    status.

--*/
{
    KswDynState state;
    KSW_QUERY_DYN_STATUS_RESPONSE* response = NULL;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSW_QUERY_DYN_STATUS_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    kswordArkDynDataSnapshot(&state);
    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSW_QUERY_DYN_STATUS_RESPONSE*)outputBuffer;
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_DYNDATA_PROTOCOL_VERSION;
    response->statusFlags = kswordArkDynDataStatusFlagsFromState(&state);
    response->systemInformerDataVersion = state.systemInformerDataVersion;
    response->systemInformerDataLength = state.systemInformerDataLength;
    response->lastStatus = (LONG)state.lastStatus;
    response->matchedProfileClass = state.matchedProfileClass;
    response->matchedProfileOffset = state.matchedProfileOffset;
    response->matchedFieldsId = state.matchedFieldsId;
    response->fieldCount = kswordArkDynDataCountFieldDescriptors();
    response->capabilityMask = state.capabilityMask;
    response->ntoskrnl = state.ntoskrnl;
    response->lxcore = state.lxcore;
    RtlCopyMemory(
        response->unavailableReason,
        state.unavailableReason,
        sizeof(response->unavailableReason));
    response->unavailableReason[KSW_DYN_REASON_CHARS - 1U] = L'\0';

    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDynDataQueryFields(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Write a variable-length DynData field descriptor response. The response can
    be partially filled; totalCount tells R3 how many rows exist.

Arguments:

    OutputBuffer - METHOD_BUFFERED output buffer.
    OutputBufferLength - Writable output byte count.
    BytesWrittenOut - Receives bytes written.

Return Value:

    STATUS_SUCCESS when at least the response header is written; otherwise
    validation status.

--*/
{
    KSW_QUERY_DYN_FIELDS_RESPONSE* response = NULL;
    ULONG entryCapacity = 0UL;
    ULONG returnedCount = 0UL;
    ULONG totalCount = kswordArkDynDataCountFieldDescriptors();

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSW_DYN_FIELDS_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSW_QUERY_DYN_FIELDS_RESPONSE*)outputBuffer;
    response->size = (ULONG)KSW_DYN_FIELDS_RESPONSE_HEADER_SIZE;
    response->version = KSWORD_ARK_DYNDATA_PROTOCOL_VERSION;
    response->totalCount = totalCount;
    response->entrySize = sizeof(KSW_DYN_FIELD_ENTRY);

    entryCapacity = (ULONG)((outputBufferLength - KSW_DYN_FIELDS_RESPONSE_HEADER_SIZE) / sizeof(KSW_DYN_FIELD_ENTRY));
    if (entryCapacity > 0UL) {
        returnedCount = kswordArkDynDataBuildFieldEntries(response->entries, entryCapacity);
    }

    response->returnedCount = returnedCount;
    response->size = (ULONG)(KSW_DYN_FIELDS_RESPONSE_HEADER_SIZE + ((size_t)returnedCount * sizeof(KSW_DYN_FIELD_ENTRY)));
    *bytesWrittenOut = response->size;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDynDataQueryCapabilities(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Write the fixed DynData capability response for quick R3 feature gating.

Arguments:

    OutputBuffer - METHOD_BUFFERED output buffer.
    OutputBufferLength - Writable output byte count.
    BytesWrittenOut - Receives bytes written.

Return Value:

    STATUS_SUCCESS when the fixed response is written; otherwise validation
    status.

--*/
{
    KswDynState state;
    KSW_QUERY_CAPABILITIES_RESPONSE* response = NULL;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSW_QUERY_CAPABILITIES_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    kswordArkDynDataSnapshot(&state);
    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSW_QUERY_CAPABILITIES_RESPONSE*)outputBuffer;
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_DYNDATA_PROTOCOL_VERSION;
    response->statusFlags = kswordArkDynDataStatusFlagsFromState(&state);
    response->capabilityMask = state.capabilityMask;

    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDynDataIoctlQueryStatus(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_DYN_STATUS by returning the fixed status packet.

Arguments:

    Device - WDF device used for log emission.
    Request - Current IOCTL request.
    InputBufferLength - Unused because this query has no input packet.
    OutputBufferLength - Supplied output bytes; WDF retrieval validates minimum.
    BytesReturned - Receives response byte count.

Return Value:

    NTSTATUS from output retrieval or status response construction.

--*/
{
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSW_QUERY_DYN_STATUS_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkDynDataIoctlLog(device, "Error", "DynData status output buffer invalid: 0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDynDataQueryStatus(outputBuffer, actualOutputLength, bytesReturned);
    kswordArkDynDataIoctlLog(device, NT_SUCCESS(status) ? "Info" : "Error", "DynData status query completed: status=0x%08X, bytes=%Iu.", (unsigned int)status, *bytesReturned);
    return status;
}

NTSTATUS
kswordArkDynDataIoctlQueryFields(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_DYN_FIELDS by returning public field rows.

Arguments:

    Device - WDF device used for log emission.
    Request - Current IOCTL request.
    InputBufferLength - Unused because this query has no input packet.
    OutputBufferLength - Supplied output bytes; WDF retrieval validates minimum.
    BytesReturned - Receives response byte count.

Return Value:

    NTSTATUS from output retrieval or field response construction.

--*/
{
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSW_DYN_FIELDS_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkDynDataIoctlLog(device, "Error", "DynData fields output buffer invalid: 0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDynDataQueryFields(outputBuffer, actualOutputLength, bytesReturned);
    kswordArkDynDataIoctlLog(device, NT_SUCCESS(status) ? "Info" : "Error", "DynData fields query completed: status=0x%08X, bytes=%Iu.", (unsigned int)status, *bytesReturned);
    return status;
}

NTSTATUS
kswordArkDynDataIoctlQueryCapabilities(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_CAPABILITIES by returning quick feature flags.

Arguments:

    Device - WDF device used for log emission.
    Request - Current IOCTL request.
    InputBufferLength - Unused because this query has no input packet.
    OutputBufferLength - Supplied output bytes; WDF retrieval validates minimum.
    BytesReturned - Receives response byte count.

Return Value:

    NTSTATUS from output retrieval or capability response construction.

--*/
{
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSW_QUERY_CAPABILITIES_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkDynDataIoctlLog(device, "Error", "DynData capability output buffer invalid: 0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDynDataQueryCapabilities(outputBuffer, actualOutputLength, bytesReturned);
    kswordArkDynDataIoctlLog(device, NT_SUCCESS(status) ? "Info" : "Error", "DynData capability query completed: status=0x%08X, bytes=%Iu.", (unsigned int)status, *bytesReturned);
    return status;
}

NTSTATUS
kswordArkDynDataIoctlApplyProfile(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE. The handler performs only WDF
    buffer/access validation and leaves semantic validation to the DynData owner
    so the global state update remains centralized.

Arguments:

    Device - WDF device used for log emission.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes.
    OutputBufferLength - Supplied output bytes.
    BytesReturned - Receives fixed response byte count when a response is built.

Return Value:

    NTSTATUS from access validation, buffer retrieval, or profile application.

--*/
{
    KSW_APPLY_DYN_PROFILE_REQUEST* inputBuffer = NULL;
    KSW_APPLY_DYN_PROFILE_REQUEST* inputCopy = NULL;
    KSW_APPLY_DYN_PROFILE_RESPONSE* outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    size_t copyLength = 0U;
    const size_t kMaxProfileRequestBytes =
        KSW_APPLY_DYN_PROFILE_REQUEST_HEADER_SIZE +
        ((size_t)KSW_DYN_PROFILE_MAX_FIELDS * sizeof(KSW_DYN_PROFILE_FIELD_PACKET));
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        kswordArkDynDataIoctlLog(device, "Warn", "DynData apply profile denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        KSW_APPLY_DYN_PROFILE_REQUEST_HEADER_SIZE,
        (PVOID*)&inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkDynDataIoctlLog(device, "Error", "DynData apply profile input invalid: 0x%08X.", (unsigned int)status);
        return status;
    }

    copyLength = actualInputLength;
    if (copyLength > kMaxProfileRequestBytes) {
        copyLength = kMaxProfileRequestBytes;
    }
    inputCopy = (KSW_APPLY_DYN_PROFILE_REQUEST*)kswordArkDynDataAllocateProfileCopy(copyLength);
    if (inputCopy == NULL) {
        kswordArkDynDataIoctlLog(device, "Error", "DynData apply profile input copy allocation failed, bytes=%Iu.", copyLength);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(inputCopy, inputBuffer, copyLength);

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSW_APPLY_DYN_PROFILE_RESPONSE),
        (PVOID*)&outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(inputCopy, KSW_DYN_PROFILE_IOCTL_POOL_TAG);
        kswordArkDynDataIoctlLog(device, "Error", "DynData apply profile output invalid: 0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDynDataApplyProfile(
        inputCopy,
        copyLength,
        outputBuffer,
        actualOutputLength,
        bytesReturned);
    ExFreePoolWithTag(inputCopy, KSW_DYN_PROFILE_IOCTL_POOL_TAG);
    kswordArkDynDataIoctlLog(
        device,
        NT_SUCCESS(status) ? "Info" : "Warn",
        "DynData apply profile completed: status=0x%08X, applied=%lu, rejected=%lu, unknown=%lu, caps=0x%I64X.",
        (unsigned int)status,
        (unsigned long)outputBuffer->appliedFieldCount,
        (unsigned long)outputBuffer->rejectedFieldCount,
        (unsigned long)outputBuffer->unknownFieldCount,
        outputBuffer->capabilityMask);
    if (*bytesReturned >= sizeof(KSW_APPLY_DYN_PROFILE_RESPONSE)) {
        return STATUS_SUCCESS;
    }

    return status;
}

NTSTATUS
kswordArkDynDataIoctlApplyProfileEx(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_EX. The handler performs WDF
    access and buffer validation only; semantic validation and copy-on-success
    state updates remain centralized in the DynData loader.

Arguments:

    Device - WDF device used for log emission.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes.
    OutputBufferLength - Supplied output bytes.
    BytesReturned - Receives fixed EX response byte count when a response is
        built.

Return Value:

    NTSTATUS from access validation, buffer retrieval, or EX profile
    application.

--*/
{
    KSW_APPLY_DYN_PROFILE_EX_REQUEST* inputBuffer = NULL;
    KSW_APPLY_DYN_PROFILE_EX_REQUEST* inputCopy = NULL;
    KSW_APPLY_DYN_PROFILE_EX_RESPONSE* outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    size_t copyLength = 0U;
    const size_t kMaxProfileRequestBytes =
        KSW_APPLY_DYN_PROFILE_EX_REQUEST_HEADER_SIZE +
        ((size_t)KSW_DYN_PROFILE_EX_MAX_ITEMS * sizeof(KSW_DYN_PROFILE_EX_ITEM_PACKET));
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        kswordArkDynDataIoctlLog(device, "Warn", "DynData apply profile EX denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        KSW_APPLY_DYN_PROFILE_EX_REQUEST_HEADER_SIZE,
        (PVOID*)&inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkDynDataIoctlLog(device, "Error", "DynData apply profile EX input invalid: 0x%08X.", (unsigned int)status);
        return status;
    }

    copyLength = actualInputLength;
    if (copyLength > kMaxProfileRequestBytes) {
        copyLength = kMaxProfileRequestBytes;
    }
    inputCopy = (KSW_APPLY_DYN_PROFILE_EX_REQUEST*)kswordArkDynDataAllocateProfileCopy(copyLength);
    if (inputCopy == NULL) {
        kswordArkDynDataIoctlLog(device, "Error", "DynData apply profile EX input copy allocation failed, bytes=%Iu.", copyLength);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(inputCopy, inputBuffer, copyLength);

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSW_APPLY_DYN_PROFILE_EX_RESPONSE),
        (PVOID*)&outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(inputCopy, KSW_DYN_PROFILE_IOCTL_POOL_TAG);
        kswordArkDynDataIoctlLog(device, "Error", "DynData apply profile EX output invalid: 0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDynDataApplyProfileEx(
        inputCopy,
        copyLength,
        outputBuffer,
        actualOutputLength,
        bytesReturned);
    ExFreePoolWithTag(inputCopy, KSW_DYN_PROFILE_IOCTL_POOL_TAG);
    kswordArkDynDataIoctlLog(
        device,
        NT_SUCCESS(status) ? "Info" : "Warn",
        "DynData apply profile EX completed: status=0x%08X, applied=%lu, rejected=%lu, unknown=%lu, caps=0x%I64X.",
        (unsigned int)status,
        (unsigned long)outputBuffer->appliedItemCount,
        (unsigned long)outputBuffer->rejectedItemCount,
        (unsigned long)outputBuffer->unknownItemCount,
        outputBuffer->capabilityMask);
    if (*bytesReturned >= sizeof(KSW_APPLY_DYN_PROFILE_EX_RESPONSE)) {
        return STATUS_SUCCESS;
    }

    return status;
}
