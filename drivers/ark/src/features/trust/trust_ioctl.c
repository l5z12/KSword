/*++

Module Name:

    trust_ioctl.c

Abstract:

    IOCTL handler for Phase-14 image trust diagnostics.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

static VOID
kswordArkTrustIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Output trust query log. Note: Log records only length, flags, and status
    code, not full file paths, to avoid leaking user privacy paths in logs.

Arguments:

    Device - The WDF device object.
    levelText - Log level.
    FormatText - printf-style format string.
    ... - Format arguments.

Return Value:

    None. This function has no return value.

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

NTSTATUS
kswordArkTrustIoctlQueryImageTrust(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handles IOCTL_KSWORD_ARK_QUERY_IMAGE_TRUST. Note: The handler performs only protocol
    length/flags/path validation; the actual CI/signing level query is delegated to trust_query.c.

Arguments:

    Device - The WDF device object.
    Request - Current IOCTL request.
    InputBufferLength - Input length.
    OutputBufferLength - Output length.
    BytesReturned - number of bytes written.

Return Value:

    NTSTATUS from validation or feature backend.

--*/
{
    KSWORD_ARK_QUERY_IMAGE_TRUST_REQUEST* queryRequest = NULL;
    KSWORD_ARK_QUERY_IMAGE_TRUST_REQUEST queryRequestSnapshot = { 0 };
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    const ULONG kAllowedFlags =
        KSWORD_ARK_TRUST_QUERY_FLAG_INCLUDE_GLOBAL_CI |
        KSWORD_ARK_TRUST_QUERY_FLAG_INCLUDE_FILE_SIGNING_LEVEL |
        KSWORD_ARK_TRUST_QUERY_FLAG_OPEN_REPARSE_POINT;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_IMAGE_TRUST_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkTrustIoctlLog(device, "Error", "R0 query-image-trust: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED can alias the input and output SystemBuffer. Keep the
     * validated request stable before output retrieval/backend zeroing.
     */
    RtlCopyMemory(
        &queryRequestSnapshot,
        inputBuffer,
        sizeof(queryRequestSnapshot));
    queryRequest = &queryRequestSnapshot;
    if ((queryRequest->flags & ~kAllowedFlags) != 0UL) {
        kswordArkTrustIoctlLog(device, "Warn", "R0 query-image-trust: flags rejected, flags=0x%08X.", (unsigned int)queryRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }
    if (queryRequest->pathLengthChars >= KSWORD_ARK_TRUST_PATH_MAX_CHARS) {
        kswordArkTrustIoctlLog(device, "Warn", "R0 query-image-trust: path length rejected, chars=%u.", (unsigned int)queryRequest->pathLengthChars);
        return STATUS_INVALID_PARAMETER;
    }
    if (queryRequest->pathLengthChars != 0U &&
        queryRequest->path[queryRequest->pathLengthChars] != L'\0') {
        kswordArkTrustIoctlLog(device, "Warn", "R0 query-image-trust: path not null-terminated, chars=%u.", (unsigned int)queryRequest->pathLengthChars);
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_IMAGE_TRUST_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkTrustIoctlLog(device, "Error", "R0 query-image-trust: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverQueryImageTrust(
        outputBuffer,
        actualOutputLength,
        queryRequest,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkTrustIoctlLog(device, "Error", "R0 query-image-trust failed: chars=%u, status=0x%08X.", (unsigned int)queryRequest->pathLengthChars, (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_QUERY_IMAGE_TRUST_RESPONSE)) {
        KSWORD_ARK_QUERY_IMAGE_TRUST_RESPONSE* response =
            (KSWORD_ARK_QUERY_IMAGE_TRUST_RESPONSE*)outputBuffer;
        kswordArkTrustIoctlLog(
            device,
            "Info",
            "R0 query-image-trust completed: status=%lu, source=%lu, fields=0x%08X.",
            (unsigned long)response->queryStatus,
            (unsigned long)response->trustSource,
            (unsigned int)response->fieldFlags);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkTrustIoctlQueryImageSignature(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle the bounded R0 PE certificate-table and cached signing-level query.
    The handler validates only protocol fields; all file reads and parsing live
    in trust_query.c.

--*/
{
    KSWORD_ARK_QUERY_IMAGE_SIGNATURE_REQUEST* queryRequest = NULL;
    KSWORD_ARK_QUERY_IMAGE_SIGNATURE_REQUEST queryRequestSnapshot = { 0 };
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    const ULONG kAllowedFlags =
        KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_INCLUDE_PE_CERTIFICATE_TABLE |
        KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_INCLUDE_CACHED_SIGNING_LEVEL |
        KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_MATCH_LOADED_MODULE |
        KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_OPEN_REPARSE_POINT;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_IMAGE_SIGNATURE_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkTrustIoctlLog(device, "Error", "R0 query-image-signature: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED input/output buffers can be the same SystemBuffer.
     * Preserve path/base/flags before the backend clears the output packet.
     */
    RtlCopyMemory(
        &queryRequestSnapshot,
        inputBuffer,
        sizeof(queryRequestSnapshot));
    queryRequest = &queryRequestSnapshot;
    if (queryRequest->reserved != 0U) {
        kswordArkTrustIoctlLog(device, "Warn", "R0 query-image-signature: reserved field is nonzero.");
        return STATUS_INVALID_PARAMETER;
    }
    if ((queryRequest->flags & ~kAllowedFlags) != 0UL) {
        kswordArkTrustIoctlLog(device, "Warn", "R0 query-image-signature: flags rejected, flags=0x%08X.", (unsigned int)queryRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }
    if (queryRequest->pathLengthChars == 0U ||
        queryRequest->pathLengthChars >= KSWORD_ARK_TRUST_PATH_MAX_CHARS ||
        queryRequest->path[queryRequest->pathLengthChars] != L'\0') {
        kswordArkTrustIoctlLog(device, "Warn", "R0 query-image-signature: path rejected, chars=%u.", (unsigned int)queryRequest->pathLengthChars);
        return STATUS_INVALID_PARAMETER;
    }
    if ((queryRequest->flags & KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_MATCH_LOADED_MODULE) != 0UL &&
        queryRequest->expectedModuleBase == 0ULL) {
        kswordArkTrustIoctlLog(device, "Warn", "R0 query-image-signature: loaded-module match requested without base.");
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_IMAGE_SIGNATURE_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkTrustIoctlLog(device, "Error", "R0 query-image-signature: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverQueryImageSignature(
        outputBuffer,
        actualOutputLength,
        queryRequest,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkTrustIoctlLog(device, "Error", "R0 query-image-signature failed: chars=%u, status=0x%08X.", (unsigned int)queryRequest->pathLengthChars, (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_QUERY_IMAGE_SIGNATURE_RESPONSE)) {
        KSWORD_ARK_QUERY_IMAGE_SIGNATURE_RESPONSE* response =
            (KSWORD_ARK_QUERY_IMAGE_SIGNATURE_RESPONSE*)outputBuffer;
        kswordArkTrustIoctlLog(
            device,
            "Info",
            "R0 query-image-signature completed: status=%lu, fields=0x%08X, structural=0x%08X, certs=%lu.",
            (unsigned long)response->queryStatus,
            (unsigned int)response->fieldFlags,
            (unsigned int)response->structuralFlags,
            (unsigned long)response->certificateCount);
    }

    return STATUS_SUCCESS;
}
