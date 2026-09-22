#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>

#include "ark/ark_driver.h"
#include "ark/ark_ioctl.h"
#include "ark/ark_safety.h"
#include "../../dispatch/ioctl_validation.h"
#include "cpu_power_runtime.h"

// ============================================================
// cpu_power_ioctl.c
// Purpose:
// - Only responsible for WDF buffers, security policies, and fixed response lengths.
// - Real CPUID/MSR probing and modification are located in cpu_power_runtime.c;
// - The control path must pass through FILE_WRITE_ACCESS, UI confirmation, and security policy simultaneously.
// ============================================================

C_ASSERT(sizeof(KSWORD_ARK_CPU_POWER_CONTROL_REQUEST) == 144U);
C_ASSERT(sizeof(KSWORD_ARK_CPU_POWER_RESPONSE) == 352U);

// kswordArkCpuPowerLogControlResult: Writes the control failure reason and original request value to a unified R0 log.
static VOID
kswordArkCpuPowerLogControlResult(
    _In_ WDFDEVICE device,
    _In_ const KSWORD_ARK_CPU_POWER_CONTROL_REQUEST* controlRequest,
    _In_ const KSWORD_ARK_CPU_POWER_RESPONSE* response,
    _In_ NTSTATUS status
    )
{
    // logMessage retains a complete diagnostic record that mainWindow can display as-is.
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    // formatStatus: Prevents submitting incomplete text to the log queue in case of formatting failure.
    NTSTATUS formatStatus = STATUS_SUCCESS;

    // Record structured fields only after obtaining a complete request and response.
    if (device == NULL || controlRequest == NULL || response == NULL) {
        return;
    }

    // Also log reason, request value, concurrent snapshot, and response capability so the next failure doesn't require guessing the UI state.
    formatStatus = RtlStringCbPrintfA(
        logMessage,
        sizeof(logMessage),
        "CPU power control result: status=0x%08X, reason=%lu, apply=0x%08lX, request=0x%08lX, "
        "pl1=%lu/%lu/%lu, pl2=%lu/%lu/%lu, turbo=%lu, hwp=%lu/%lu/%lu/%lu, ratio=%lu, perf=%lu, "
        "expected=%016I64X/%016I64X/%016I64X/%016I64X/%016I64X, fields=0x%08lX, response=0x%08lX, "
        "capability=0x%016I64X, updated=%lu, failed=%lu.",
        (unsigned int)status,
        response->failureReason,
        controlRequest->applyFlags,
        controlRequest->requestFlags,
        controlRequest->pl1Milliwatts,
        controlRequest->pl1Enabled,
        controlRequest->pl1ClampEnabled,
        controlRequest->pl2Milliwatts,
        controlRequest->pl2Enabled,
        controlRequest->pl2ClampEnabled,
        controlRequest->turboEnabled,
        controlRequest->hwpMinimumPerformance,
        controlRequest->hwpMaximumPerformance,
        controlRequest->hwpDesiredPerformance,
        controlRequest->hwpEnergyPerformancePreference,
        controlRequest->turboRatio,
        controlRequest->requestedMultiplier,
        controlRequest->expectedPackagePowerLimit,
        controlRequest->expectedMiscEnable,
        controlRequest->expectedHwpRequest,
        controlRequest->expectedTurboRatioLimit,
        controlRequest->expectedPerfControl,
        response->fieldFlags,
        response->responseFlags,
        response->capabilityFlags,
        response->updatedProcessorCount,
        response->failedProcessorCount);
    // Use Warn on failure and Info on success; both log to the existing mainWindow R0 channel.
    if (NT_SUCCESS(formatStatus)) {
        (void)kswordArkDriverEnqueueLogFrame(
            device,
            NT_SUCCESS(status) ? "Info" : "Warn",
            logMessage);
    }
}

// kswordArkCpuPowerIoctlQuery: returns current CPU power capabilities and a snapshot of whitelisted MSRs.
NTSTATUS
kswordArkCpuPowerIoctlQuery(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    // response points to a fixed METHOD_BUFFERED output packet.
    KSWORD_ARK_CPU_POWER_RESPONSE* response = NULL;
    // actualOutputLength receives the actual buffer length from WDF.
    size_t actualOutputLength = 0U;
    // status: Stores the results of buffer validation and runtime queries.
    NTSTATUS status = STATUS_SUCCESS;

    // This handler requires no device extension or input buffer.
    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    // Byte count output must be valid and zeroed first.
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    // Obtain the complete fixed-size response buffer.
    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(*response),
        (PVOID*)&response,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Returns partial/unsupported semantics in a fixed packet at runtime.
    status = kswordArkCpuPowerQuerySnapshot(response);
    // Once the response packet is established, report the full length to WDF.
    *bytesReturned = sizeof(*response);
    return status;
}

// kswordArkCpuPowerIoctlControl: performs structured CPU power control after the security gate.
NTSTATUS
kswordArkCpuPowerIoctlControl(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    // controlRequest points to the complete fixed input packet.
    KSWORD_ARK_CPU_POWER_CONTROL_REQUEST* controlRequest = NULL;
    // Saves the complete input in controlRequestCopy before clearing the METHOD_BUFFERED shared output buffer.
    KSWORD_ARK_CPU_POWER_CONTROL_REQUEST controlRequestCopy;
    // response points to a fixed output snapshot.
    KSWORD_ARK_CPU_POWER_RESPONSE* response = NULL;
    // safetyContext delegates UI confirmation to a unified R0 safety policy.
    KswordArkSafetyContext safetyContext;
    // actualInputLength/actualOutputLength receive the actual length from WDF.
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    // status: stores results for each gating and runtime operation.
    NTSTATUS status = STATUS_SUCCESS;
    // targetText: A fixed target description used for security auditing.
    static const WCHAR kTargetText[] =
        L"CPU RAPL HWP Turbo ratio and performance-control MSRs";

    // Length is re-validated by the unified retrieval helper.
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    // Byte count output must be valid and zeroed first.
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    // Cross-processor affinity and MSR modifications are executed only at PASSIVE_LEVEL.
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    // Retrieve complete control request.
    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(*controlRequest),
        (PVOID*)&controlRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    // METHOD_BUFFERED input and output may point to the same SystemBuffer; the request must be copied first.
    RtlCopyMemory(
        &controlRequestCopy,
        controlRequest,
        sizeof(controlRequestCopy));
    // Subsequent validation and application only read the stack copy; response initialization will not overwrite request fields.
    controlRequest = &controlRequestCopy;
    // Obtain the complete fixed-size response buffer.
    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(*response),
        (PVOID*)&response,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // initialize a minimal failure response first; any gated exit carries versioned semantics.
    RtlZeroMemory(response, sizeof(*response));
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_CPU_POWER_PROTOCOL_VERSION;

    // The protocol header and UI confirmation are validated before entering the general security policy.
    if (controlRequest->size < sizeof(*controlRequest) ||
        controlRequest->version != KSWORD_ARK_CPU_POWER_PROTOCOL_VERSION ||
        (controlRequest->requestFlags &
            KSWORD_ARK_CPU_POWER_REQUEST_FLAG_UI_CONFIRMED) == 0UL) {
        response->failureReason =
            KSWORD_ARK_CPU_POWER_FAILURE_REQUEST_HEADER;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        *bytesReturned = sizeof(*response);
        // Persist the exact protocol header failure context before returning.
        kswordArkCpuPowerLogControlResult(
            device,
            controlRequest,
            response,
            STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    // Construct a unified high-risk kernel modification safety context.
    RtlZeroMemory(&safetyContext, sizeof(safetyContext));
    safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
    safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
    safetyContext.targetText = kTargetText;
    safetyContext.targetTextChars =
        (USHORT)(RTL_NUMBER_OF(kTargetText) - 1U);
    // Unifiedly check the current caller against dangerous feature switches via device security policies.
    status = kswordArkSafetyEvaluate(device, &safetyContext);
    if (!NT_SUCCESS(status)) {
        response->failureReason =
            KSWORD_ARK_CPU_POWER_FAILURE_SAFETY_POLICY;
        response->lastStatus = status;
        *bytesReturned = sizeof(*response);
        // Even if the security policy is denied, the reason and request fields must be included.
        kswordArkCpuPowerLogControlResult(
            device,
            controlRequest,
            response,
            status);
        return status;
    }

    // Runtime execution capability, lock bits, expected snapshot, per-CPU write and readback verification.
    status = kswordArkCpuPowerApply(controlRequest, response);
    // A fixed response is available for new clients to interpret regardless of whether the semantics succeeded or failed.
    *bytesReturned = sizeof(*response);
    // Control results enter a unified R0 log, including precise reasons from runtime validation or processor write stages.
    kswordArkCpuPowerLogControlResult(
        device,
        controlRequest,
        response,
        status);
    return status;
}
