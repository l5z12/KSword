/*++

Module Name:

    safety_ioctl.c

Abstract:

    IOCTL handlers for Phase-15 dangerous-operation policy.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

static VOID
kswordArkSafetyIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Output safety IOCTL log. Note: Policy changes are security-sensitive actions;
    record status code and generation uniformly to facilitate R3 log panel display.

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
kswordArkSafetyIoctlQueryPolicy(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_SAFETY_POLICY. Note: The input packet is optional;
    the output is always a fixed response structure to facilitate status page polling.

Arguments:

    Device - The WDF device object.
    Request - Current IOCTL request.
    InputBufferLength - Input length.
    OutputBufferLength - Output length.
    BytesReturned: Number of bytes written.

Return Value:

    NTSTATUS from buffer retrieval or policy query.

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
        sizeof(KSWORD_ARK_QUERY_SAFETY_POLICY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkSafetyIoctlLog(device, "Error", "R0 query-safety-policy: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkSafetyQueryPolicy(outputBuffer, actualOutputLength, bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkSafetyIoctlLog(device, "Error", "R0 query-safety-policy failed, status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_QUERY_SAFETY_POLICY_RESPONSE)) {
        KSWORD_ARK_QUERY_SAFETY_POLICY_RESPONSE* response =
            (KSWORD_ARK_QUERY_SAFETY_POLICY_RESPONSE*)outputBuffer;
        kswordArkSafetyIoctlLog(
            device,
            "Info",
            "R0 query-safety-policy success: flags=0x%08X, generation=%lu.",
            (unsigned int)response->policyFlags,
            (unsigned long)response->policyGeneration);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkSafetyIoctlSetPolicy(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handling IOCTL_KSWORD_ARK_SET_SAFETY_POLICY. Note: This IOCTL requires write
    access and is used for R3 advanced mode toggling and confirming policy switches.

Arguments:

    Device - The WDF device object.
    Request - Current IOCTL request.
    InputBufferLength - Input length.
    OutputBufferLength - Output length.
    BytesReturned: Number of bytes written.

Return Value:

    NTSTATUS from validation or policy update.

--*/
{
    KSWORD_ARK_SET_SAFETY_POLICY_REQUEST* setRequest = NULL;
    // requestSnapshot: Saves the complete request before zeroing the shared SystemBuffer in the backend.
    KSWORD_ARK_SET_SAFETY_POLICY_REQUEST requestSnapshot;
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
        kswordArkSafetyIoctlLog(device, "Warn", "R0 set-safety-policy denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_SET_SAFETY_POLICY_REQUEST),
        (PVOID*)&setRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkSafetyIoctlLog(device, "Error", "R0 set-safety-policy: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED input and output share the same SystemBuffer; the backend clears the output
     * with RtlZeroMemory before reading expectedGeneration and each policy switch. Skipping the
     * snapshot effectively rewrites global security policies using response header bytes.
     */
    RtlCopyMemory(&requestSnapshot, setRequest, sizeof(requestSnapshot));
    setRequest = &requestSnapshot;

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_SET_SAFETY_POLICY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkSafetyIoctlLog(device, "Error", "R0 set-safety-policy: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkSafetySetPolicy(
        setRequest,
        outputBuffer,
        actualOutputLength,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkSafetyIoctlLog(device, "Error", "R0 set-safety-policy failed, status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_SET_SAFETY_POLICY_RESPONSE)) {
        KSWORD_ARK_SET_SAFETY_POLICY_RESPONSE* response =
            (KSWORD_ARK_SET_SAFETY_POLICY_RESPONSE*)outputBuffer;
        kswordArkSafetyIoctlLog(
            device,
            NT_SUCCESS(response->status) ? "Info" : "Warn",
            "R0 set-safety-policy complete: old=0x%08X, new=0x%08X, status=0x%08X.",
            (unsigned int)response->oldPolicyFlags,
            (unsigned int)response->newPolicyFlags,
            (unsigned int)response->status);
    }

    return STATUS_SUCCESS;
}
