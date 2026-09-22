/*++

Module Name:

    kernel_ioctl.c

Abstract:

    IOCTL handlers for KswordARK kernel inspection operations.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSWORD_ARK_ENUM_SSDT_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_SSDT_RESPONSE) - sizeof(KSWORD_ARK_SSDT_ENTRY))

#define KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE) - sizeof(KSWORD_ARK_DRIVER_DEVICE_ENTRY))

#define KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE) - sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE))

#define KSWORD_ARK_INLINE_HOOK_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_SCAN_INLINE_HOOKS_RESPONSE) - sizeof(KSWORD_ARK_INLINE_HOOK_ENTRY))

#define KSWORD_ARK_IAT_EAT_HOOK_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_IAT_EAT_HOOKS_RESPONSE) - sizeof(KSWORD_ARK_IAT_EAT_HOOK_ENTRY))

typedef VOID(NTAPI* KswordHalReturnToFirmwareFn)(
    _In_ LONG firmwareAction
    );

static VOID
kswordArkKernelIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Format and enqueue one kernel-handler log message.

Arguments:

    Device - WDF device that owns the log channel.
    levelText - Log level string.
    FormatText - printf-style ANSI message template.
    ... - Template arguments.

Return Value:

    None. Formatting or enqueue failures are ignored.

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

NTSTATUS
kswordArkKernelIoctlExperimentalReturnToFirmware(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    KSWORD_ARK_EXPERIMENTAL_RETURN_TO_FIRMWARE_REQUEST* firmwareRequest = NULL;
    KswordArkSafetyContext safetyContext;
    KswordHalReturnToFirmwareFn halReturnToFirmware = NULL;
    UNICODE_STRING routineName;
    size_t actualInputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(*firmwareRequest),
        (PVOID*)&firmwareRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (firmwareRequest->action !=
            KSWORD_ARK_FIRMWARE_RETURN_ACTION_HAL_REBOOT_ROUTINE ||
        (firmwareRequest->flags &
            KSWORD_ARK_FIRMWARE_RETURN_FLAG_UI_CONFIRMED) == 0UL ||
        firmwareRequest->confirmationToken !=
            KSWORD_ARK_FIRMWARE_RETURN_CONFIRMATION_TOKEN ||
        firmwareRequest->reserved != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&safetyContext, sizeof(safetyContext));
    safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_FIRMWARE_RETURN;
    safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
    safetyContext.targetText = L"HalReturnToFirmware(HalRebootRoutine)";
    safetyContext.targetTextChars =
        (USHORT)(RTL_NUMBER_OF(L"HalReturnToFirmware(HalRebootRoutine)") - 1U);
    status = kswordArkSafetyEvaluate(device, &safetyContext);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(
            device,
            "Warn",
            "Experimental HalReturnToFirmware denied by safety policy: status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    RtlInitUnicodeString(&routineName, L"HalReturnToFirmware");
    halReturnToFirmware =
        (KswordHalReturnToFirmwareFn)MmGetSystemRoutineAddress(&routineName);
    if (halReturnToFirmware == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    kswordArkKernelIoctlLog(
        device,
        "Warn",
        "Experimental raw API call starting: HalReturnToFirmware(HalRebootRoutine). This is a machine-wide unsupported action, not thread termination.");
    halReturnToFirmware(KSWORD_ARK_FIRMWARE_RETURN_ACTION_HAL_REBOOT_ROUTINE);

    // The success path typically does not return; if HAL rejects or the implementation returns, it cannot be reported as restarted.
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS
kswordArkKernelIoctlEnumSsdt(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_ENUM_SSDT. Optional input preserves the legacy
    default request, and the feature function owns SSDT enumeration details.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes; shorter input selects defaults.
    OutputBufferLength - Supplied output bytes; checked by WDF output retrieval.
    BytesReturned - Receives the feature-written response byte count.

Return Value:

    NTSTATUS from buffer retrieval or kswordArkDriverEnumerateSsdt.

--*/
{
    KSWORD_ARK_ENUM_SSDT_REQUEST* enumRequest = NULL;
    KSWORD_ARK_ENUM_SSDT_REQUEST defaultRequest = { 0 };
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0;
    size_t actualOutputLength = 0;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkRetrieveOptionalInputBuffer(request, inputBufferLength, sizeof(KSWORD_ARK_ENUM_SSDT_REQUEST), &inputBuffer, &actualInputLength, &hasInput);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 enum-ssdt ioctl: input buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (hasInput) {
        enumRequest = (KSWORD_ARK_ENUM_SSDT_REQUEST*)inputBuffer;
    }
    else {
        enumRequest = &defaultRequest;
        enumRequest->flags = KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED;
        enumRequest->reserved = 0UL;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(request, KSWORD_ARK_ENUM_SSDT_RESPONSE_HEADER_SIZE, &outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 enum-ssdt ioctl: output buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverEnumerateSsdt(outputBuffer, actualOutputLength, enumRequest, bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 enum-ssdt failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *bytesReturned);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_ENUM_SSDT_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_ENUM_SSDT_RESPONSE* responseHeader = (KSWORD_ARK_ENUM_SSDT_RESPONSE*)outputBuffer;
        kswordArkKernelIoctlLog(device, "Info", "R0 enum-ssdt success: total=%lu, returned=%lu, outBytes=%Iu.", (unsigned long)responseHeader->totalCount, (unsigned long)responseHeader->returnedCount, *bytesReturned);
    }
    else {
        kswordArkKernelIoctlLog(device, "Warn", "R0 enum-ssdt success: outBytes=%Iu (header partial).", *bytesReturned);
    }

    return status;
}

NTSTATUS
kswordArkKernelIoctlQueryDriverObject(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_DRIVER_OBJECT. The UI supplies only a driver
    object namespace name; kernel mode references the DriverObject itself and
    returns diagnostic-only addresses, dispatch table rows and device chains.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes.
    OutputBufferLength - Supplied output bytes.
    BytesReturned - Receives the feature-written response byte count.

Return Value:

    NTSTATUS from buffer retrieval or kswordArkDriverQueryDriverObject.

--*/
{
    KSWORD_ARK_QUERY_DRIVER_OBJECT_REQUEST* queryRequest = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0;
    size_t actualOutputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_DRIVER_OBJECT_REQUEST),
        (PVOID*)&queryRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(
            device,
            "Error",
            "R0 query-driver-object ioctl: input invalid, status=0x%08X, supplied=%Iu, required=%Iu.",
            (unsigned int)status,
            inputBufferLength,
            sizeof(KSWORD_ARK_QUERY_DRIVER_OBJECT_REQUEST));
        return status;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 query-driver-object ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverQueryDriverObject(
        outputBuffer,
        actualOutputLength,
        queryRequest,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 query-driver-object failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *bytesReturned);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE* responseHeader =
            (KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE*)outputBuffer;
        if (responseHeader->queryStatus != KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_NOT_FOUND) {
            kswordArkKernelIoctlLog(
                device,
                responseHeader->queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_OK ||
                    responseHeader->queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL
                    ? "Info"
                    : "Warn",
                "R0 query-driver-object success: status=%lu, devices=%lu/%lu, outBytes=%Iu.",
                (unsigned long)responseHeader->queryStatus,
                (unsigned long)responseHeader->returnedDeviceCount,
                (unsigned long)responseHeader->totalDeviceCount,
                *bytesReturned);
        }
    }

    return status;
}

NTSTATUS
kswordArkKernelIoctlEnumShadowSsdt(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_ENUM_SHADOW_SSDT. Note: the handler only buffers the
    request and fills defaults; SSSDT parsing policies are handled by ssdt_query.c.

Arguments:

    Device: WDF device object, used for logging.
    Request - Current IOCTL request.
    InputBufferLength - input length; uses include-unresolved by default.
    OutputBufferLength: Output length; re-confirmed by WDF.
    BytesReturned - Returns the number of bytes written.

Return Value:

    NTSTATUS from validation or feature backend.

--*/
{
    KSWORD_ARK_ENUM_SSDT_REQUEST* enumRequest = NULL;
    KSWORD_ARK_ENUM_SSDT_REQUEST defaultRequest = { 0 };
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

    status = kswordArkRetrieveOptionalInputBuffer(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_ENUM_SSDT_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 enum-shadow-ssdt ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (hasInput) {
        enumRequest = (KSWORD_ARK_ENUM_SSDT_REQUEST*)inputBuffer;
    }
    else {
        enumRequest = &defaultRequest;
        enumRequest->flags = KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_ENUM_SSDT_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 enum-shadow-ssdt ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverEnumerateShadowSsdt(
        outputBuffer,
        actualOutputLength,
        enumRequest,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 enum-shadow-ssdt failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *bytesReturned);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_ENUM_SSDT_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_ENUM_SSDT_RESPONSE* responseHeader =
            (KSWORD_ARK_ENUM_SSDT_RESPONSE*)outputBuffer;
        kswordArkKernelIoctlLog(
            device,
            "Info",
            "R0 enum-shadow-ssdt success: total=%lu, returned=%lu, outBytes=%Iu.",
            (unsigned long)responseHeader->totalCount,
            (unsigned long)responseHeader->returnedCount,
            *bytesReturned);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkKernelIoctlQueryDriverIntegrity(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY. The existing 0x849 IOCTL
    stays read-only and uses version/size fields so v1 rows remain a stable
    prefix while v2/v3 callers can consume typed DriverObject and descriptor
    evidence columns.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Input length; absent input uses safe defaults.
    OutputBufferLength - Output length; WDF validates the concrete buffer.
    BytesReturned - Receives the feature-written response byte count.

Return Value:

    NTSTATUS from validation or the read-only integrity backend.

--*/
{
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST* queryRequest = NULL;
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST defaultRequest = { 0 };
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

    status = kswordArkRetrieveOptionalInputBuffer(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 query-driver-integrity ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    queryRequest = hasInput ?
        (KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST*)inputBuffer :
        &defaultRequest;
    if (!hasInput) {
        defaultRequest.version = KSWORD_ARK_DRIVER_INTEGRITY_PROTOCOL_VERSION;
        defaultRequest.flags = KSWORD_ARK_DRIVER_INTEGRITY_FLAG_DEFAULT;
        defaultRequest.requestSize = sizeof(KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST);
        defaultRequest.maxRows = KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS;
        defaultRequest.maxIdtVectorsPerCpu = KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 query-driver-integrity ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverQueryDriverIntegrity(
        outputBuffer,
        actualOutputLength,
        queryRequest,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 query-driver-integrity backend failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *bytesReturned);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE* response =
            (KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE*)outputBuffer;
        kswordArkKernelIoctlLog(
            device,
            "Info",
            "R0 query-driver-integrity staged response: status=%lu, total=%lu, returned=%lu, cpus=%lu, flags=0x%08lX.",
            (unsigned long)response->queryStatus,
            (unsigned long)response->totalCount,
            (unsigned long)response->returnedCount,
            (unsigned long)response->cpuCount,
            (unsigned long)response->flags);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkKernelIoctlQueryCpuHardware(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_CPU_HARDWARE. This is a fixed-size, read-only
    CPUID snapshot used by HardwareDock to enrich the utilization page with
    architectural CPU details.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes; ignored because the query has no input.
    OutputBufferLength - Supplied output bytes; WDF validates the concrete buffer.
    BytesReturned - Receives sizeof(KSWORD_ARK_QUERY_CPU_HARDWARE_RESPONSE).

Return Value:

    NTSTATUS from buffer retrieval or kswordArkDriverQueryCpuHardware.

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
        sizeof(KSWORD_ARK_QUERY_CPU_HARDWARE_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 query-cpu-hardware ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverQueryCpuHardware(outputBuffer, actualOutputLength, bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 query-cpu-hardware backend failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *bytesReturned);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_QUERY_CPU_HARDWARE_RESPONSE)) {
        KSWORD_ARK_QUERY_CPU_HARDWARE_RESPONSE* response =
            (KSWORD_ARK_QUERY_CPU_HARDWARE_RESPONSE*)outputBuffer;
        kswordArkKernelIoctlLog(
            device,
            "Info",
            "R0 query-cpu-hardware success: vendor=%s, logical=%lu, active=%lu, family=%lu, model=%lu, features=0x%I64X.",
            response->vendor,
            (unsigned long)response->logicalProcessorCount,
            (unsigned long)response->activeProcessorCount,
            (unsigned long)response->family,
            (unsigned long)response->model,
            response->featureMask);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkKernelIoctlQueryPhysicalMemoryLayout(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT. The handler returns
    aggregate R0 physical memory geometry for HardwareDock statistics and does
    not expose per-page or byte content.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes; ignored because this query has no input.
    OutputBufferLength - Supplied output bytes; WDF validates the concrete buffer.
    BytesReturned - Receives sizeof(KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT_RESPONSE).

Return Value:

    NTSTATUS from buffer retrieval or kswordArkDriverQueryPhysicalMemoryLayout.

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
        sizeof(KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 query-physical-memory-layout ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverQueryPhysicalMemoryLayout(outputBuffer, actualOutputLength, bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 query-physical-memory-layout backend failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *bytesReturned);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT_RESPONSE)) {
        KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT_RESPONSE* response =
            (KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT_RESPONSE*)outputBuffer;
        kswordArkKernelIoctlLog(
            device,
            "Info",
            "R0 query-physical-memory-layout success: ranges=%lu, total=%I64u, highest=0x%I64X, largest=%I64u.",
            (unsigned long)response->rangeCount,
            response->totalPhysicalBytes,
            response->highestPhysicalAddress,
            response->largestRangeBytes);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkKernelIoctlEnumTimerDpc(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_ENUM_TIMER_DPC. The optional request carries only
    traversal budgets; the backend performs a bounded, read-only enumeration.

--*/
{
    KSWORD_ARK_ENUM_TIMER_DPC_REQUEST defaultRequest = { 0 };
    KSWORD_ARK_ENUM_TIMER_DPC_REQUEST requestCopy = { 0 };
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

    defaultRequest.version = KSWORD_ARK_TIMER_DPC_PROTOCOL_VERSION;
    defaultRequest.maxEntries = KSWORD_ARK_TIMER_DPC_DEFAULT_MAX_ENTRIES;
    defaultRequest.maxEntriesPerBucket = KSWORD_ARK_TIMER_DPC_DEFAULT_BUCKET_BUDGET;

    status = kswordArkRetrieveOptionalInputBuffer(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_ENUM_TIMER_DPC_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 enum-timer-dpc ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    requestCopy = hasInput ? *(KSWORD_ARK_ENUM_TIMER_DPC_REQUEST*)inputBuffer : defaultRequest;

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 enum-timer-dpc ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverEnumerateTimerDpc(
        outputBuffer,
        actualOutputLength,
        &requestCopy,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 enum-timer-dpc backend failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *bytesReturned);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE) {
        const KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE* response =
            (const KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE*)outputBuffer;
        kswordArkKernelIoctlLog(
            device,
            response->queryStatus == KSWORD_ARK_TIMER_DPC_QUERY_STATUS_OK ? "Info" : "Warn",
            "R0 enum-timer-dpc completed: status=%lu flags=0x%08lX cpus=%lu buckets=%lu/%lu total=%lu returned=%lu corrupt=%lu readfail=%lu duplicate=%lu.",
            (unsigned long)response->queryStatus,
            (unsigned long)response->statusFlags,
            (unsigned long)response->processorCount,
            (unsigned long)response->bucketsVisited,
            (unsigned long)response->bucketCount,
            (unsigned long)response->totalCount,
            (unsigned long)response->returnedCount,
            (unsigned long)response->corruptBucketCount,
            (unsigned long)response->readFailureCount,
            (unsigned long)response->duplicateCount);
    }
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkKernelIoctlScanInlineHooks(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_SCAN_INLINE_HOOKS. Note: Scanning is a read-only diagnostic; the handler
    supports optional requests. By default, only suspicious external jump locations are returned.

Arguments:

    Device: WDF device object, used for logging.
    Request - Current IOCTL request.
    InputBufferLength: input length; use default scan parameters if not specified.
    OutputBufferLength: Output length; re-confirmed by WDF.
    BytesReturned - Returns the number of bytes written.

Return Value:

    NTSTATUS from validation or feature backend.

--*/
{
    KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST* scanRequest = NULL;
    KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST defaultRequest = { 0 };
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

    status = kswordArkRetrieveOptionalInputBuffer(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 scan-inline-hooks ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    scanRequest = hasInput ?
        (KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST*)inputBuffer :
        &defaultRequest;

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_INLINE_HOOK_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 scan-inline-hooks ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverScanInlineHooks(
        outputBuffer,
        actualOutputLength,
        scanRequest,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 scan-inline-hooks failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *bytesReturned);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_INLINE_HOOK_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_SCAN_INLINE_HOOKS_RESPONSE* responseHeader =
            (KSWORD_ARK_SCAN_INLINE_HOOKS_RESPONSE*)outputBuffer;
        kswordArkKernelIoctlLog(
            device,
            "Info",
            "R0 scan-inline-hooks success: total=%lu, returned=%lu, modules=%lu, outBytes=%Iu.",
            (unsigned long)responseHeader->totalCount,
            (unsigned long)responseHeader->returnedCount,
            (unsigned long)responseHeader->moduleCount,
            *bytesReturned);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkKernelIoctlPatchInlineHook(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_PATCH_INLINE_HOOK. Note: Standard requests return
    FORCE_REQUIRED; mandatory requests must include write access and pass the safety policy.

Arguments:

    Device - WDF device object, used for logging and safety policy.
    Request - Current IOCTL request.
    InputBufferLength - Input length; must contain the fixed patch request.
    OutputBufferLength: Output length; must accommodate the fixed response.
    BytesReturned - Returns the number of bytes written.

Return Value:

    NTSTATUS from validation, safety policy or feature backend.

--*/
{
    KSWORD_ARK_PATCH_INLINE_HOOK_REQUEST* patchRequest = NULL;
    KSWORD_ARK_PATCH_INLINE_HOOK_REQUEST patchRequestCopy;
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
        kswordArkKernelIoctlLog(device, "Warn", "R0 patch-inline-hook denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_PATCH_INLINE_HOOK_REQUEST),
        (PVOID*)&patchRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 patch-inline-hook ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    // Note: PATCH_INLINE_HOOK uses METHOD_BUFFERED, and WDF's input/output may be the same
    // SystemBuffer; since the backend zeroes the output buffer, the request must be copied first.
    RtlZeroMemory(&patchRequestCopy, sizeof(patchRequestCopy));
    RtlCopyMemory(&patchRequestCopy, patchRequest, sizeof(patchRequestCopy));

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_PATCH_INLINE_HOOK_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 patch-inline-hook ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    if ((patchRequestCopy.flags & KSWORD_ARK_KERNEL_PATCH_FLAG_FORCE) != 0UL) {
        KswordArkSafetyContext safetyContext;

        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            kswordArkKernelIoctlLog(device, "Warn", "R0 patch-inline-hook denied by safety policy: target=0x%I64X, status=0x%08X.", patchRequestCopy.functionAddress, (unsigned int)status);
            return status;
        }
    }

    status = kswordArkDriverPatchInlineHook(
        outputBuffer,
        actualOutputLength,
        &patchRequestCopy,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 patch-inline-hook failed: target=0x%I64X, status=0x%08X.", patchRequestCopy.functionAddress, (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_PATCH_INLINE_HOOK_RESPONSE)) {
        KSWORD_ARK_PATCH_INLINE_HOOK_RESPONSE* response =
            (KSWORD_ARK_PATCH_INLINE_HOOK_RESPONSE*)outputBuffer;
        kswordArkKernelIoctlLog(
            device,
            response->status == KSWORD_ARK_KERNEL_HOOK_STATUS_PATCHED ? "Info" : "Warn",
            "R0 patch-inline-hook response: target=0x%I64X, status=%lu, bytes=%lu, last=0x%08X.",
            response->functionAddress,
            (unsigned long)response->status,
            (unsigned long)response->bytesPatched,
            (unsigned int)response->lastStatus);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkKernelIoctlEnumIatEatHooks(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handles IOCTL_KSWORD_ARK_ENUM_IAT_EAT_HOOKS. Note: Enumeration is read-only diagnostics,
    supporting module name filtering, import-only/export-only, and inclusion of clean items.

Arguments:

    Device: WDF device object, used for logging.
    Request - Current IOCTL request.
    InputBufferLength - input length; if omitted, scan IAT and EAT for suspicious items.
    OutputBufferLength: Output length; re-confirmed by WDF.
    BytesReturned - Returns the number of bytes written.

Return Value:

    NTSTATUS from validation or feature backend.

--*/
{
    KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST* scanRequest = NULL;
    KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST defaultRequest = { 0 };
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

    defaultRequest.flags =
        KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_IMPORTS |
        KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_EXPORTS;

    status = kswordArkRetrieveOptionalInputBuffer(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 enum-iat-eat ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    scanRequest = hasInput ?
        (KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST*)inputBuffer :
        &defaultRequest;

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_IAT_EAT_HOOK_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 enum-iat-eat ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverEnumerateIatEatHooks(
        outputBuffer,
        actualOutputLength,
        scanRequest,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 enum-iat-eat failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *bytesReturned);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_IAT_EAT_HOOK_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_ENUM_IAT_EAT_HOOKS_RESPONSE* responseHeader =
            (KSWORD_ARK_ENUM_IAT_EAT_HOOKS_RESPONSE*)outputBuffer;
        kswordArkKernelIoctlLog(
            device,
            "Info",
            "R0 enum-iat-eat success: total=%lu, returned=%lu, modules=%lu, outBytes=%Iu.",
            (unsigned long)responseHeader->totalCount,
            (unsigned long)responseHeader->returnedCount,
            (unsigned long)responseHeader->moduleCount,
            *bytesReturned);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkKernelIoctlForceUnloadDriver(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_FORCE_UNLOAD_DRIVER. Note: The handler is responsible only for write access,
    fixed buffer validation, and safety policy; the actual unloading logic resides in driver_unload.c.

Arguments:

    Device - WDF device object, used for logging and safety policy.
    Request - Current IOCTL request.
    InputBufferLength - Input length; must include the fixed request.
    OutputBufferLength: Output length; must accommodate the fixed response.
    BytesReturned - Returns the number of response bytes.

Return Value:

    NTSTATUS from validation, safety policy or feature backend.

--*/
{
    KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST* unloadRequest = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    KswDriverUnloadDiagnostics unloadDiagnostics;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    RtlZeroMemory(&unloadDiagnostics, sizeof(unloadDiagnostics));

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Warn", "R0 force-unload-driver denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        FIELD_OFFSET(KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST, targetModuleBase),
        (PVOID*)&unloadRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 force-unload-driver ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_FORCE_UNLOAD_DRIVER_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 force-unload-driver ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_DRIVER_UNLOAD;
        safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        safetyContext.targetText = unloadRequest->driverName;
        safetyContext.targetTextChars = KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            kswordArkKernelIoctlLog(device, "Warn", "R0 force-unload-driver denied by safety policy: status=0x%08X.", (unsigned int)status);
            return status;
        }
    }

    status = kswordArkDriverForceUnloadDriver(
        outputBuffer,
        actualOutputLength,
        unloadRequest,
        bytesReturned,
        &unloadDiagnostics);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelIoctlLog(device, "Error", "R0 force-unload-driver backend failed: status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_FORCE_UNLOAD_DRIVER_RESPONSE)) {
        KSWORD_ARK_FORCE_UNLOAD_DRIVER_RESPONSE* response =
            (KSWORD_ARK_FORCE_UNLOAD_DRIVER_RESPONSE*)outputBuffer;
        const char* logLevel =
            (response->status == KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNLOADED ||
                response->status == KSWORD_ARK_DRIVER_UNLOAD_STATUS_FORCED_CLEANUP ||
                response->status == KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNLOAD_ROUTINE_CALLED)
            ? "Info"
            : "Warn";

        kswordArkKernelIoctlLog(
            device,
            logLevel,
            "R0 force-unload-driver response: status=%lu, requested=0x%08X, effective=0x%08X, applied=0x%08X, deleted=%lu, detached=%lu, object=0x%I64X, unload=0x%I64X, last=0x%08X, wait=0x%08X, callbacks=%lu/%lu, cbfail=%lu, cblast=0x%08X, threads=%lu/%lu, thfail=%lu, thlast=0x%08X.",
            (unsigned long)response->status,
            (unsigned int)response->reserved,
            (unsigned int)response->flags,
            (unsigned int)response->cleanupFlagsApplied,
            (unsigned long)response->deletedDeviceCount,
            (unsigned long)response->detachedDeviceCount,
            response->driverObjectAddress,
            response->driverUnloadAddress,
            (unsigned int)response->lastStatus,
            (unsigned int)response->waitStatus,
            (unsigned long)response->callbacksRemoved,
            (unsigned long)response->callbackCandidates,
            (unsigned long)response->callbackFailures,
            (unsigned int)response->callbackLastStatus,
            (unsigned long)response->threadsTerminated,
            (unsigned long)response->threadCandidates,
            (unsigned long)response->threadFailures,
            (unsigned int)response->threadLastStatus);

        kswordArkKernelIoctlLog(
            device,
            logLevel,
            "R0 unload diag flags: stages=0x%08X req=0x%08X san=0x%08X fin=0x%08X ref=0x%08X pfBuild=0x%08X pf=0x%08X deny=0x%08X.",
            (unsigned int)unloadDiagnostics.stages,
            (unsigned int)unloadDiagnostics.requestedFlags,
            (unsigned int)unloadDiagnostics.sanitizedFlags,
            (unsigned int)unloadDiagnostics.finalFlags,
            (unsigned int)unloadDiagnostics.referenceStatus,
            (unsigned int)unloadDiagnostics.preflightBuildStatus,
            (unsigned int)unloadDiagnostics.preflightStatus,
            (unsigned int)unloadDiagnostics.preflightDenyStatus);

        kswordArkKernelIoctlLog(
            device,
            logLevel,
            "R0 unload diag gates: allow=%u/%u/%u svc=%u unload=%u dyn=%u/%u/%u/%u dev=%u/%u/%u/%u/%u threads=%u/%u callbacks=%u/%u/%u loader=%u/%u image=%u/%u self=%u core=%u.",
            unloadDiagnostics.allowZwUnload ? 1U : 0U,
            unloadDiagnostics.allowDirectUnload ? 1U : 0U,
            unloadDiagnostics.allowDestructiveCleanup ? 1U : 0U,
            unloadDiagnostics.hasServiceRegistryPath ? 1U : 0U,
            unloadDiagnostics.hasDriverUnload ? 1U : 0U,
            unloadDiagnostics.hasValidDynData ? 1U : 0U,
            unloadDiagnostics.hasPdbBackedDynData ? 1U : 0U,
            unloadDiagnostics.hasValidDriverObjectOffsets ? 1U : 0U,
            unloadDiagnostics.hasValidLoaderEvidence ? 1U : 0U,
            unloadDiagnostics.hasDeviceChain ? 1U : 0U,
            unloadDiagnostics.hasAttachedDevice ? 1U : 0U,
            unloadDiagnostics.hasBusyDeviceReference ? 1U : 0U,
            unloadDiagnostics.hasCrossDriverAttach ? 1U : 0U,
            unloadDiagnostics.hasDeviceLoop ? 1U : 0U,
            unloadDiagnostics.hasThreadScan ? 1U : 0U,
            unloadDiagnostics.hasModuleResidentThreads ? 1U : 0U,
            unloadDiagnostics.hasCallbackScan ? 1U : 0U,
            unloadDiagnostics.hasModuleCallbacks ? 1U : 0U,
            unloadDiagnostics.hasNonRemovableModuleCallbacks ? 1U : 0U,
            unloadDiagnostics.hasLoaderLinkCheck ? 1U : 0U,
            unloadDiagnostics.hasLoaderLinkMismatch ? 1U : 0U,
            unloadDiagnostics.hasImageHeaderCheck ? 1U : 0U,
            unloadDiagnostics.hasInvalidImageHeader ? 1U : 0U,
            unloadDiagnostics.isSelfModule ? 1U : 0U,
            unloadDiagnostics.isCoreKernelModule ? 1U : 0U);

        kswordArkKernelIoctlLog(
            device,
            logLevel,
            "R0 unload diag thread-evidence: status=0x%08X processes=%lu threads=%lu resident=%lu.",
            (unsigned int)unloadDiagnostics.threadScanStatus,
            (unsigned long)unloadDiagnostics.scannedProcessCount,
            (unsigned long)unloadDiagnostics.scannedThreadCount,
            (unsigned long)unloadDiagnostics.moduleResidentThreadCount);

        kswordArkKernelIoctlLog(
            device,
            logLevel,
            "R0 unload diag callback-evidence: status=0x%08X enumerated=%lu module=%lu removable=%lu nonremovable=%lu.",
            (unsigned int)unloadDiagnostics.callbackScanStatus,
            (unsigned long)unloadDiagnostics.callbackEnumeratedCount,
            (unsigned long)unloadDiagnostics.moduleCallbackCount,
            (unsigned long)unloadDiagnostics.removableModuleCallbackCount,
            (unsigned long)unloadDiagnostics.nonRemovableModuleCallbackCount);

        kswordArkKernelIoctlLog(
            device,
            logLevel,
            "R0 unload diag loader-image: link=0x%08X image=0x%08X headerSize=0x%08X ntOff=0x%08X.",
            (unsigned int)unloadDiagnostics.loaderLinkStatus,
            (unsigned int)unloadDiagnostics.imageHeaderStatus,
            (unsigned int)unloadDiagnostics.imageHeaderSizeOfImage,
            (unsigned int)unloadDiagnostics.imageNtHeaderOffset);

        kswordArkKernelIoctlLog(
            device,
            logLevel,
            "R0 unload diag zw: run=0x%08X wait=0x%08X unload=0x%08X verify=0x%08X start=0x%I64X ldr=0x%I64X.",
            (unsigned int)unloadDiagnostics.zwRunStatus,
            (unsigned int)unloadDiagnostics.zwWaitStatus,
            (unsigned int)unloadDiagnostics.zwUnloadStatus,
            (unsigned int)unloadDiagnostics.zwVerifyStatus,
            unloadDiagnostics.driverStart,
            unloadDiagnostics.loaderDllBase);

        kswordArkKernelIoctlLog(
            device,
            logLevel,
            "R0 unload diag direct: run=0x%08X wait=0x%08X unload=0x%08X cleanup=0x%08X verify=0x%08X ldrEntry=0x%I64X ldrSize=0x%08X.",
            (unsigned int)unloadDiagnostics.directRunStatus,
            (unsigned int)unloadDiagnostics.directWaitStatus,
            (unsigned int)unloadDiagnostics.directUnloadStatus,
            (unsigned int)unloadDiagnostics.directCleanupStatus,
            (unsigned int)unloadDiagnostics.directVerifyStatus,
            unloadDiagnostics.loaderEntryAddress,
            (unsigned int)unloadDiagnostics.loaderSizeOfImage);
    }

    return STATUS_SUCCESS;
}
