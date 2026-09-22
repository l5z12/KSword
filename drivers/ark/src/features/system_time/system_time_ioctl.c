/*++

Module Name:

    system_time_ioctl.c

Abstract:

    WDF query and high-risk control adapter for system-wide variable speed.

Third-Party Notice:

    The license and archival notes for the referenced mechanism are located at:
    third_party/SystemWideTransmission/LICENSE.txt
    third_party/SystemWideTransmission/NOTICE.md

Environment:

    Kernel-mode Driver Framework.

--*/

#include "ark/ark_driver.h"
#include "ark/ark_system_time.h"
#include "../../dispatch/ioctl_validation.h"

/* Query adapter: read only versioned fixed requests and return current virtual timer state. */
NTSTATUS
kswordArkSystemTimeIoctlQuery(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    const KSWORD_ARK_QUERY_SYSTEM_TIME_REQUEST* queryRequest = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(device);
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    /* Even for fixed requests, explicitly require version/size to prevent silent misreads between old and new R3 versions. */
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_SYSTEM_TIME_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status) ||
        inputBufferLength <
            sizeof(KSWORD_ARK_QUERY_SYSTEM_TIME_REQUEST) ||
        actualInputLength <
            sizeof(KSWORD_ARK_QUERY_SYSTEM_TIME_REQUEST)) {
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    queryRequest =
        (const KSWORD_ARK_QUERY_SYSTEM_TIME_REQUEST*)inputBuffer;
    if (queryRequest->version !=
            KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION ||
        queryRequest->size != sizeof(*queryRequest)) {
        return STATUS_REVISION_MISMATCH;
    }

    /* The output buffer must fully contain all status and parsing evidence. */
    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status) ||
        outputBufferLength <
            sizeof(KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE) ||
        actualOutputLength <
            sizeof(KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE)) {
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }

    status = kswordArkSystemTimeQuery(
        (KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE*)outputBuffer);
    if (NT_SUCCESS(status)) {
        *bytesReturned =
            sizeof(KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE);
    }
    return status;
}

/*
 * The control adapter first validates write permissions and fixed buffers, then enters the central high-risk kernel patching policy.
 * RESET is a recovery action that does not require re-authorization of the risk policy.
 */
NTSTATUS
kswordArkSystemTimeIoctlControl(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    const KSWORD_ARK_CONTROL_SYSTEM_TIME_REQUEST* controlRequest = NULL;
    KSWORD_ARK_CONTROL_SYSTEM_TIME_REQUEST controlRequestSnapshot = { 0 };
    KSWORD_ARK_CONTROL_SYSTEM_TIME_RESPONSE* controlResponse = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    /* Speed control commands can only be issued from a KswordARK device handle with GENERIC_WRITE access. */
    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_CONTROL_SYSTEM_TIME_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status) ||
        inputBufferLength <
            sizeof(KSWORD_ARK_CONTROL_SYSTEM_TIME_REQUEST) ||
        actualInputLength <
            sizeof(KSWORD_ARK_CONTROL_SYSTEM_TIME_REQUEST)) {
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }

    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_CONTROL_SYSTEM_TIME_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status) ||
        outputBufferLength <
            sizeof(KSWORD_ARK_CONTROL_SYSTEM_TIME_RESPONSE) ||
        actualOutputLength <
            sizeof(KSWORD_ARK_CONTROL_SYSTEM_TIME_RESPONSE)) {
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }

    controlRequest =
        (const KSWORD_ARK_CONTROL_SYSTEM_TIME_REQUEST*)inputBuffer;
    controlResponse =
        (KSWORD_ARK_CONTROL_SYSTEM_TIME_RESPONSE*)outputBuffer;
    if (controlRequest->version !=
            KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION ||
        controlRequest->size != sizeof(*controlRequest)) {
        return STATUS_REVISION_MISMATCH;
    }

    /*
     * Input and output for METHOD_BUFFERED may share the same SystemBuffer.
     * At runtime, the response is zeroed first; therefore, the request must be copied beforehand to avoid the response initialization overwriting the request.
     */
    RtlCopyMemory(
        &controlRequestSnapshot,
        controlRequest,
        sizeof(controlRequestSnapshot));
    controlRequest = &controlRequestSnapshot;

    /*
     * Acceleration and deceleration take over all system performance counters, requiring entry into unified
     * KERNEL_PATCH auditing; UI_CONFIRMED is verified separately by both protocol tokens and central policies.
     */
    if (controlRequest->command !=
        KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET) {
        KswordArkSafetyContext safetyContext = { 0 };

        safetyContext.operation =
            KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        safetyContext.contextFlags =
            (controlRequest->flags &
                KSWORD_ARK_SYSTEM_TIME_CONTROL_FLAG_UI_CONFIRMED) != 0UL
            ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
            : 0UL;
        safetyContext.targetText =
            L"System-wide performance-counter time remapping";
        safetyContext.targetTextChars =
            (USHORT)(RTL_NUMBER_OF(
                L"System-wide performance-counter time remapping") -
                1U);
        status = kswordArkSafetyEvaluate(
            device,
            &safetyContext);
        if (!NT_SUCCESS(status)) {
            RtlZeroMemory(
                controlResponse,
                sizeof(*controlResponse));
            controlResponse->version =
                KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION;
            controlResponse->size =
                sizeof(*controlResponse);
            controlResponse->status =
                KSWORD_ARK_SYSTEM_TIME_STATUS_CONFIRMATION_REQUIRED;
            controlResponse->lastStatus = status;
            *bytesReturned = sizeof(*controlResponse);
            return status;
        }
    }

    /* Returns a stable business status at runtime; actual IOCTL transmission maintains a fixed response size. */
    status = kswordArkSystemTimeControl(
        controlRequest,
        controlResponse);
    *bytesReturned = sizeof(*controlResponse);
    return status;
}
