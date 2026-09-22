/*++

Module Name:

    capability_ioctl.c

Abstract:

    IOCTL handler for the unified driver capability query.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_capability.h"
#include "ark/ark_log.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

static VOID
kswordArkCapabilityIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Format and enqueue one capability-IOCTL diagnostic message.

Arguments:

    Device - WDF device that owns the log channel.
    levelText - Log level string.
    FormatText - printf-style message template.
    ... - Template arguments.

Return Value:

    None. Logging failures are ignored.

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
kswordArkCapabilityIoctlQueryDriverCapabilities(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_DRIVER_CAPABILITIES by returning the unified
    Phase 1 status and feature matrix.

Arguments:

    Device - WDF device used for log emission.
    Request - Current IOCTL request.
    InputBufferLength - Unused because this query has no input packet.
    OutputBufferLength - Supplied output bytes.
    BytesReturned - Receives response byte count.

Return Value:

    NTSTATUS from output retrieval or response construction.

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
        sizeof(KSWORD_ARK_QUERY_DRIVER_CAPABILITIES_RESPONSE) - sizeof(KSWORD_ARK_FEATURE_CAPABILITY_ENTRY),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkCapabilityIoctlLog(device, "Error", "Capability output buffer invalid: 0x%08X.", (unsigned int)status);
        kswordArkCapabilityRecordLastError(status, "capability_ioctl", "Capability query output buffer invalid.");
        return status;
    }

    status = kswordArkCapabilityQuery(outputBuffer, actualOutputLength, bytesReturned);
    kswordArkCapabilityIoctlLog(
        device,
        NT_SUCCESS(status) ? "Info" : "Error",
        "Capability query completed: status=0x%08X, bytes=%Iu.",
        (unsigned int)status,
        *bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkCapabilityRecordLastError(status, "capability_ioctl", "Capability query response construction failed.");
    }
    return status;
}
