/*++

Module Name:

    storage_ioctl.c

Abstract:

    IOCTL handlers for read-only storage, BitLocker/FVE, MountMgr, and
    file-system integrity audit queries.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSW_STORAGE_VOLUME_STACK_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_VOLUME_STACK_RESPONSE) - sizeof(KSWORD_ARK_VOLUME_STACK_ROW))

#define KSW_STORAGE_BITLOCKER_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_BITLOCKER_FVE_RESPONSE) - sizeof(KSWORD_ARK_BITLOCKER_FVE_ROW))

#define KSW_STORAGE_MOUNTMGR_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_RESPONSE) - sizeof(KSWORD_ARK_MOUNTMGR_MAPPING_ROW))

#define KSW_STORAGE_FILESYSTEM_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_RESPONSE) - sizeof(KSWORD_ARK_FILESYSTEM_INTEGRITY_ROW))

static VOID
kswordArkStorageIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Format and enqueue one storage audit handler log message.

Arguments:

    Device - WDF device that owns the log channel.
    levelText - Log level string.
    FormatText - printf-style ANSI message template.
    ... - Template arguments.

Return Value:

    None. Formatting or enqueue failures are intentionally ignored.

--*/
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, formatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logMessage, sizeof(logMessage), formatText, arguments))) {
        (void)kswordArkDriverEnqueueLogFrame(device, levelText, logMessage);
    }
    va_end(arguments);
}

static NTSTATUS
kswordArkStorageRetrieveBuffers(
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputHeaderBytes,
    _Outptr_result_maybenull_ KSWORD_ARK_STORAGE_AUDIT_REQUEST** queryRequest,
    _Outptr_ PVOID* outputBuffer,
    _Out_ size_t* actualOutputLength
    )
/*++

Routine Description:

    Retrieve the optional common storage request and the required variable-row
    output buffer for a storage audit IOCTL.

Arguments:

    Request - Current WDF IOCTL request.
    InputBufferLength - User-supplied input length.
    OutputHeaderBytes - Minimum output header bytes for the specific response.
    QueryRequest - Receives NULL for default options or the caller request.
    OutputBuffer - Receives the WDF output buffer.
    ActualOutputLength - Receives the WDF output buffer length.

Return Value:

    NTSTATUS from WDF buffer validation helpers.

--*/
{
    PVOID inputBuffer = NULL;
    size_t actualInputLength = 0U;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status;

    if (queryRequest == NULL || outputBuffer == NULL || actualOutputLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *queryRequest = NULL;
    *outputBuffer = NULL;
    *actualOutputLength = 0U;
    status = kswordArkRetrieveOptionalInputBuffer(request, inputBufferLength, sizeof(KSWORD_ARK_STORAGE_AUDIT_REQUEST), &inputBuffer, &actualInputLength, &hasInput);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    UNREFERENCED_PARAMETER(actualInputLength);
    if (hasInput) {
        *queryRequest = (KSWORD_ARK_STORAGE_AUDIT_REQUEST*)inputBuffer;
    }
    return kswordArkRetrieveRequiredOutputBuffer(request, outputHeaderBytes, outputBuffer, actualOutputLength);
}

NTSTATUS
kswordArkStorageIoctlQueryVolumeStackAudit(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_VOLUME_STACK_AUDIT by forwarding validated
    METHOD_BUFFERED buffers to the read-only storage backend.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes.
    OutputBufferLength - Supplied output bytes.
    BytesReturned - Receives the feature-written response byte count.

Return Value:

    NTSTATUS from buffer retrieval or the storage backend.

--*/
{
    KSWORD_ARK_STORAGE_AUDIT_REQUEST* queryRequest = NULL;
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(outputBufferLength);
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    status = kswordArkStorageRetrieveBuffers(request, inputBufferLength, KSW_STORAGE_VOLUME_STACK_RESPONSE_HEADER_SIZE, &queryRequest, &outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkStorageIoctlLog(device, "Error", "R0 storage volume-stack ioctl buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    status = kswordArkStorageQueryVolumeStackAudit(outputBuffer, actualOutputLength, queryRequest, bytesReturned);
    kswordArkStorageIoctlLog(device, NT_SUCCESS(status) ? "Info" : "Error", "R0 storage volume-stack audit completed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *bytesReturned);
    return status;
}

NTSTATUS
kswordArkStorageIoctlQueryBitLockerFveAudit(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_BITLOCKER_FVE_AUDIT by invoking the safe
    fvevol stack-position status backend.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes.
    OutputBufferLength - Supplied output bytes.
    BytesReturned - Receives the feature-written response byte count.

Return Value:

    NTSTATUS from buffer retrieval or the storage backend.

--*/
{
    KSWORD_ARK_STORAGE_AUDIT_REQUEST* queryRequest = NULL;
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(outputBufferLength);
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    status = kswordArkStorageRetrieveBuffers(request, inputBufferLength, KSW_STORAGE_BITLOCKER_RESPONSE_HEADER_SIZE, &queryRequest, &outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkStorageIoctlLog(device, "Error", "R0 storage bitlocker ioctl buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    status = kswordArkStorageQueryBitLockerFveAudit(outputBuffer, actualOutputLength, queryRequest, bytesReturned);
    kswordArkStorageIoctlLog(device, NT_SUCCESS(status) ? "Info" : "Error", "R0 storage bitlocker audit completed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *bytesReturned);
    return status;
}

NTSTATUS
kswordArkStorageIoctlQueryMountMgrMappingAudit(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_AUDIT by returning read-only
    DOS drive-letter to NT device symbolic-link mappings.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes.
    OutputBufferLength - Supplied output bytes.
    BytesReturned - Receives the feature-written response byte count.

Return Value:

    NTSTATUS from buffer retrieval or the storage backend.

--*/
{
    KSWORD_ARK_STORAGE_AUDIT_REQUEST* queryRequest = NULL;
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(outputBufferLength);
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    status = kswordArkStorageRetrieveBuffers(request, inputBufferLength, KSW_STORAGE_MOUNTMGR_RESPONSE_HEADER_SIZE, &queryRequest, &outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkStorageIoctlLog(device, "Error", "R0 storage mountmgr ioctl buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    status = kswordArkStorageQueryMountMgrMappingAudit(outputBuffer, actualOutputLength, queryRequest, bytesReturned);
    kswordArkStorageIoctlLog(device, NT_SUCCESS(status) ? "Info" : "Error", "R0 storage mountmgr audit completed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *bytesReturned);
    return status;
}

NTSTATUS
kswordArkStorageIoctlQueryFileSystemIntegrityAudit(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_AUDIT by invoking the
    read-only DriverObject dispatch/FastIo owner evidence backend.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes.
    OutputBufferLength - Supplied output bytes.
    BytesReturned - Receives the feature-written response byte count.

Return Value:

    NTSTATUS from buffer retrieval or the storage backend.

--*/
{
    KSWORD_ARK_STORAGE_AUDIT_REQUEST* queryRequest = NULL;
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(outputBufferLength);
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    status = kswordArkStorageRetrieveBuffers(request, inputBufferLength, KSW_STORAGE_FILESYSTEM_RESPONSE_HEADER_SIZE, &queryRequest, &outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkStorageIoctlLog(device, "Error", "R0 storage filesystem ioctl buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    status = kswordArkStorageQueryFileSystemIntegrityAudit(outputBuffer, actualOutputLength, queryRequest, bytesReturned);
    kswordArkStorageIoctlLog(device, NT_SUCCESS(status) ? "Info" : "Error", "R0 storage filesystem audit completed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *bytesReturned);
    return status;
}
