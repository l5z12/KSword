/*++

Module Name:

    section_ioctl.c

Abstract:

    IOCTL handler for process SectionObject / ControlArea inspection.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSWORD_ARK_SECTION_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_PROCESS_SECTION_RESPONSE) - sizeof(KSWORD_ARK_SECTION_MAPPING_ENTRY))

#define KSWORD_ARK_FILE_SECTION_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_RESPONSE) - sizeof(KSWORD_ARK_FILE_SECTION_MAPPING_ENTRY))

static VOID
kswordArkSectionIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Format Section IOCTL logs. Note: Logs are for diagnostics
    only and do not affect IOCTL completion status.

Arguments:

    Device - The WDF device object.
    levelText - Log level.
    FormatText: printf-style format string.
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
kswordArkSectionIoctlQueryProcessSection(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_PROCESS_SECTION. Note: The handler is responsible only for WDF buffer
    acquisition and logging; actual PID querying and ControlArea traversal are completed in the feature layer.

Arguments:

    Device - The WDF device object.
    Request - current WDF request.
    InputBufferLength - Input length.
    OutputBufferLength - Output length.
    BytesReturned - number of bytes returned.

Return Value:

    NTSTATUS indicates the result of buffer validation or query execution.

--*/
{
    KSWORD_ARK_QUERY_PROCESS_SECTION_REQUEST* queryRequest = NULL;
    // requestSnapshot: Saves the complete request before zeroing the shared SystemBuffer in the backend.
    KSWORD_ARK_QUERY_PROCESS_SECTION_REQUEST requestSnapshot;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0;
    size_t actualOutputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_PROCESS_SECTION_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkSectionIoctlLog(device, "Error", "R0 query-section ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED input and output share the same SystemBuffer; the backend clears the output before
     * reading processId/flags/maxMappings. Without a snapshot, incorrect processes will be enumerated.
     */
    queryRequest = (KSWORD_ARK_QUERY_PROCESS_SECTION_REQUEST*)inputBuffer;
    RtlCopyMemory(&requestSnapshot, queryRequest, sizeof(requestSnapshot));
    queryRequest = &requestSnapshot;

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_SECTION_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkSectionIoctlLog(device, "Error", "R0 query-section ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverQueryProcessSection(outputBuffer, actualOutputLength, queryRequest, bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkSectionIoctlLog(
            device,
            "Error",
            "R0 query-section failed: pid=%lu, status=0x%08X.",
            (unsigned long)queryRequest->processId,
            (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_SECTION_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_QUERY_PROCESS_SECTION_RESPONSE* response = (KSWORD_ARK_QUERY_PROCESS_SECTION_RESPONSE*)outputBuffer;
        kswordArkSectionIoctlLog(
            device,
            "Info",
            "R0 query-section success: pid=%lu, status=%lu, total=%lu, returned=%lu.",
            (unsigned long)response->processId,
            (unsigned long)response->queryStatus,
            (unsigned long)response->totalCount,
            (unsigned long)response->returnedCount);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkSectionIoctlQueryFileSectionMappings(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS. Note: The handler performs only request packet and
    path length validation; file object opening and ControlArea traversal are delegated to the feature layer.

Arguments:

    Device - The WDF device object.
    Request - current WDF request.
    InputBufferLength - Input length.
    OutputBufferLength - Output length.
    BytesReturned - number of bytes returned.

Return Value:

    NTSTATUS indicates the result of buffer validation or query execution.

--*/
{
    KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_REQUEST* queryRequest = NULL;
    // requestSnapshot: Saves the complete request before zeroing the shared SystemBuffer in the backend.
    KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_REQUEST requestSnapshot;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0;
    size_t actualOutputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkSectionIoctlLog(device, "Error", "R0 query-file-section ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * For METHOD_BUFFERED, input and output share the same SystemBuffer. The backend first clears the
     * output with RtlZeroMemory and writes the response header, then reads path/pathLengthChars to
     * construct a UNICODE_STRING for ZwCreateFile. Without taking a snapshot, the response header bytes
     * would be misinterpreted as the path character count, causing an immediate kernel out-of-bounds read.
     */
    queryRequest = (KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_REQUEST*)inputBuffer;
    RtlCopyMemory(&requestSnapshot, queryRequest, sizeof(requestSnapshot));
    queryRequest = &requestSnapshot;

    if (queryRequest->pathLengthChars == 0U ||
        queryRequest->pathLengthChars >= KSWORD_ARK_FILE_SECTION_PATH_MAX_CHARS ||
        queryRequest->path[queryRequest->pathLengthChars] != L'\0') {
        kswordArkSectionIoctlLog(device, "Warn", "R0 query-file-section ioctl: path rejected, chars=%u.", (unsigned int)queryRequest->pathLengthChars);
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_FILE_SECTION_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkSectionIoctlLog(device, "Error", "R0 query-file-section ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverQueryFileSectionMappings(outputBuffer, actualOutputLength, queryRequest, bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkSectionIoctlLog(
            device,
            "Error",
            "R0 query-file-section failed: chars=%u, status=0x%08X.",
            (unsigned int)queryRequest->pathLengthChars,
            (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_FILE_SECTION_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_RESPONSE* response = (KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_RESPONSE*)outputBuffer;
        kswordArkSectionIoctlLog(
            device,
            "Info",
            "R0 query-file-section success: chars=%u, status=%lu, total=%lu, returned=%lu.",
            (unsigned int)queryRequest->pathLengthChars,
            (unsigned long)response->queryStatus,
            (unsigned long)response->totalCount,
            (unsigned long)response->returnedCount);
    }

    return STATUS_SUCCESS;
}
