/*++

Module Name:

    redirect_ioctl.c

Abstract:

    IOCTL handlers for KswordARK file and registry redirection rules.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

static VOID
kswordArkRedirectIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Output redirection IOCTL logs. Note: Only record rule counts and status codes,
    not full paths, to prevent sensitive paths from entering the log channel.

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
kswordArkRedirectIoctlSetRules(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_REDIRECT_SET_RULES. Note: Rule modification requires
    write permissions; the backend performs full validation and snapshot replacement.

Arguments:

    Device - The WDF device object.
    Request - current WDF request.
    InputBufferLength - Input length.
    OutputBufferLength - Output length.
    BytesReturned - Returns the number of bytes written.

Return Value:

    NTSTATUS from validation or backend.

--*/
{
    KSWORD_ARK_REDIRECT_SET_RULES_REQUEST* setRequest = NULL;
    // requestSnapshot: Saves the complete request before zeroing the shared SystemBuffer in the backend.
    KSWORD_ARK_REDIRECT_SET_RULES_REQUEST requestSnapshot;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        kswordArkRedirectIoctlLog(device, "Warn", "R0 redirect set-rules denied, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_REDIRECT_SET_RULES_REQUEST),
        (PVOID*)&setRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkRedirectIoctlLog(device, "Error", "R0 redirect set-rules input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * For METHOD_BUFFERED, input and output share the same SystemBuffer; the backend first clears the output with
     * RtlZeroMemory, then iterates and copies rules[] based on ruleCount. Without a snapshot, response header
     * bytes would be incorrectly interpreted as rule counts and redirect paths, corrupting the runtime table.
     */
    RtlCopyMemory(&requestSnapshot, setRequest, sizeof(requestSnapshot));
    setRequest = &requestSnapshot;

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_REDIRECT_SET_RULES_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkRedirectIoctlLog(device, "Error", "R0 redirect set-rules output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRedirectSetRules(
        setRequest,
        outputBuffer,
        actualOutputLength,
        bytesReturned);
    if (NT_SUCCESS(status) && *bytesReturned >= sizeof(KSWORD_ARK_REDIRECT_SET_RULES_RESPONSE)) {
        KSWORD_ARK_REDIRECT_SET_RULES_RESPONSE* response =
            (KSWORD_ARK_REDIRECT_SET_RULES_RESPONSE*)outputBuffer;
        kswordArkRedirectIoctlLog(
            device,
            response->status == KSWORD_ARK_REDIRECT_STATUS_APPLIED ? "Info" : "Warn",
            "R0 redirect set-rules status=%lu file=%lu registry=%lu last=0x%08X.",
            (unsigned long)response->status,
            (unsigned long)response->fileRuleCount,
            (unsigned long)response->registryRuleCount,
            (unsigned int)response->lastStatus);
    }

    return status;
}

NTSTATUS
kswordArkRedirectIoctlQueryStatus(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_REDIRECT_QUERY_STATUS. Note: Return the current
    rule snapshot, hit count, and registry callback registration status.

Arguments:

    Device - The WDF device object.
    Request - current WDF request.
    InputBufferLength - Input length.
    OutputBufferLength - Output length.
    BytesReturned - Returns the number of bytes written.

Return Value:

    NTSTATUS from output retrieval or backend.

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
        sizeof(KSWORD_ARK_REDIRECT_STATUS_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkRedirectIoctlLog(device, "Error", "R0 redirect status output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRedirectQueryStatus(
        outputBuffer,
        actualOutputLength,
        bytesReturned);
    if (NT_SUCCESS(status) && *bytesReturned >= sizeof(KSWORD_ARK_REDIRECT_STATUS_RESPONSE)) {
        KSWORD_ARK_REDIRECT_STATUS_RESPONSE* response =
            (KSWORD_ARK_REDIRECT_STATUS_RESPONSE*)outputBuffer;
        kswordArkRedirectIoctlLog(
            device,
            "Info",
            "R0 redirect status flags=0x%08X file=%lu registry=%lu.",
            (unsigned int)response->runtimeFlags,
            (unsigned long)response->fileRuleCount,
            (unsigned long)response->registryRuleCount);
    }

    return status;
}
