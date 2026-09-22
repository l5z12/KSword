/*++

Module Name:

    driver_blind_ioctl.c

Abstract:

    IOCTL boundary for reversible DriverObject communication blocking.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>

/* Note: Log a communication control result; a logging failure does not alter the actual IOCTL status. */
static VOID
kswordArkDriverCommunicationLogResult(
    _In_ WDFDEVICE device,
    _In_ const KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* response
    )
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    NTSTATUS formatStatus = STATUS_SUCCESS;

    /* Note: Defend against null response to prevent diagnostic path from affecting control path. */
    if (response == NULL) {
        /* Note: No fields can be safely recorded when a response is missing. */
        return;
    }

    /* Note: Only record the address, action, status, and mask; do not record user-provided display text. */
    formatStatus = RtlStringCbPrintfA(
        logMessage,
        sizeof(logMessage),
        "R0 driver-communication: action=%lu state=%lu status=0x%08X "
        "target=0x%I64X changed=0x%08X active=0x%08X owned=0x%08X "
        "conflict=0x%08X generation=%lu.",
        (unsigned long)response->action,
        (unsigned long)response->state,
        (unsigned int)response->lastStatus,
        response->driverStart,
        (unsigned int)response->changedMask,
        (unsigned int)response->activeMask,
        (unsigned int)response->ownedMask,
        (unsigned int)response->conflictMask,
        (unsigned long)response->generation);
    /* Note: Send the result to the existing R0 logging channel upon successful formatting. */
    if (NT_SUCCESS(formatStatus)) {
        /* Note: Use 'Warn' for failure results and 'Info' for success results. */
        (VOID)kswordArkDriverEnqueueLogFrame(
            device,
            NT_SUCCESS((NTSTATUS)response->lastStatus) ? "Info" : "Warn",
            logMessage);
    }
}

/* Note: The fixed display name must be null-terminated within the array bounds to prevent safety policy out-of-bounds reads. */
static BOOLEAN
kswordArkDriverCommunicationHasTerminatedName(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* driverName
    )
{
    ULONG nameIndex = 0UL;

    /* Note: Fixed request layout guarantees pointer validity, but null-pointer defense is retained. */
    if (driverName == NULL) {
        /* Note: A null pointer cannot serve as the target text for a security policy. */
        return FALSE;
    }

    /* Note: Search for the first NUL within the fixed array; do not call unbounded string functions. */
    for (nameIndex = 0UL;
        nameIndex < KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS;
        ++nameIndex) {
        /* Note: Empty display names and normal termination names are both treated as boundary-safe. */
        if (driverName[nameIndex] == L'\0') {
            /* Note: Allow subsequent semantic checks after finding the terminator. */
            return TRUE;
        }
    }

    /* Note: Reject the entire request when the array lacks a terminator. */
    return FALSE;
}

NTSTATUS
kswordArkKernelIoctlControlDriverCommunication(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Validates the fixed v1 request, applies the BLIND safety gate, and invokes
    the transactional DriverObject backend. QUERY and RESTORE intentionally
    bypass the mutation safety gate so recovery remains available.

Arguments:

    Device - WDF device used by safety policy and logging.
    Request - Current METHOD_BUFFERED request.
    InputBufferLength - Dispatcher-reported input length.
    OutputBufferLength - Dispatcher-reported output length.
    BytesReturned - Receives the fixed response size after output retrieval.

Return Value:

    Validation, safety-policy, or backend NTSTATUS.

--*/
{
    KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST* requestBuffer = NULL;
    KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* responseBuffer = NULL;
    KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST requestSnapshot;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    /* Note: Actual length is validated by the unified WDF helper; these dispatch parameters exist solely to maintain the handler ABI. */
    UNREFERENCED_PARAMETER(inputBufferLength);
    /* Note: Output length is also authoritative and obtained via the WDF buffer helper. */
    UNREFERENCED_PARAMETER(outputBufferLength);

    /* Note: Cannot safely complete the request without a return length pointer. */
    if (bytesReturned == NULL) {
        /* Note: Return a fixed parameter error without touching any state. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Note: Do not return data before obtaining the output buffer. */
    *bytesReturned = 0U;
    /* Note: Communication control backend and FAST_MUTEX only allow PASSIVE_LEVEL. */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        /* Note: On invalid IRQL, do not attempt WDF buffer or object directory operations. */
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* Note: Even for QUERY/RESTORE, the device must be opened with write access. */
    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    /* Note: Do not leak target state when access validation fails. */
    if (!NT_SUCCESS(status)) {
        /* Note: Pass access denied directly to the framework to handle. */
        return status;
    }

    /* Note: First retrieve and copy METHOD_BUFFERED input to avoid zeroing the output buffer overwriting the same system buffer. */
    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(requestSnapshot),
        (PVOID*)&requestBuffer,
        &actualInputLength);
    /* Note: Reject execution when the request is incomplete. */
    if (!NT_SUCCESS(status)) {
        /* Note: Preserve the exact length error from the unified helper. */
        return status;
    }
    /* Note: Copy the untrusted shared buffer to the stack to form a stable snapshot. */
    RtlCopyMemory(
        &requestSnapshot,
        requestBuffer,
        sizeof(requestSnapshot));

    /* Note: Obtain a METHOD_BUFFERED output buffer capable of holding the complete fixed response. */
    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(*responseBuffer),
        (PVOID*)&responseBuffer,
        &actualOutputLength);
    /* Note: Cannot return an interpretable status if the output is insufficient. */
    if (!NT_SUCCESS(status)) {
        /* Note: No target modifications are performed. */
        return status;
    }
    /* Note: The output buffer is zeroed immediately after acquisition to prevent leaking previous system buffer contents. */
    RtlZeroMemory(responseBuffer, sizeof(*responseBuffer));
    /* Note: All subsequent failures return a complete v1 response. */
    responseBuffer->version =
        KSWORD_ARK_DRIVER_COMMUNICATION_PROTOCOL_VERSION;
    /* Note: Echo back the action to facilitate R3 operation correlation. */
    responseBuffer->action = requestSnapshot.action;
    /* Note: The fixed implementation always targets only the five public communication entry points. */
    responseBuffer->targetedMask =
        KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_ALL;
    /* Note: The fixed response is already initialized; subsequent paths can report its size. */
    *bytesReturned = sizeof(*responseBuffer);

    /* Note: The name must be terminated; QUERY/RESTORE may be null, while BLIND validates evidence identity in the backend. */
    if (!kswordArkDriverCommunicationHasTerminatedName(
        requestSnapshot.driverName)) {
        /* Note: Record stable parameter error for R3 display. */
        responseBuffer->lastStatus = STATUS_INVALID_PARAMETER;
        /* Note: prevents the safety policy from reading an un-terminated name. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Note: Only BLIND is a high-risk mutation requiring a central safety gate. */
    if (requestSnapshot.action ==
        KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_BLIND) {
        KswordArkSafetyContext safetyContext;
        static const WCHAR kFallbackTarget[] = L"DriverObject MajorFunction";

        /* Note: High-risk actions must be explicitly confirmed via a secondary UI prompt. */
        if ((requestSnapshot.flags &
            KSWORD_ARK_DRIVER_COMMUNICATION_FLAG_UI_CONFIRMED) == 0UL) {
            /* Note: Return a fixed parameter error if confirmation is missing; do not downgrade it to a legacy request. */
            responseBuffer->lastStatus = STATUS_INVALID_PARAMETER;
            /* Note: Log business rejections lacking UI confirmation based on lastStatus. */
            kswordArkDriverCommunicationLogResult(device, responseBuffer);
            /* Note: The complete business response has been formed and passed to R3 for display as transport success. */
            return STATUS_SUCCESS;
        }

        /* Note: Zero the safety context to fix future extension fields. */
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        /* Note: MajorFunction replacement is classified as a kernel patch. */
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        /* Note: Map explicit confirmation from the request to a unified safety flag. */
        safetyContext.contextFlags =
            KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        /* Note: Use the BLIND evidence canonical name for both security policy audit text. */
        safetyContext.targetText =
            requestSnapshot.driverName[0] != L'\0'
            ? requestSnapshot.driverName
            : kFallbackTarget;
        /* Note: Fixed upper bound prevents the safety policy from performing unbounded reads. */
        safetyContext.targetTextChars =
            requestSnapshot.driverName[0] != L'\0'
            ? (USHORT)KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS
            : (USHORT)(RTL_NUMBER_OF(kFallbackTarget) - 1U);
        /* Note: Central policy governs advanced modes, operation switches, and confirmation requirements. */
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        /* Note: When a policy is denied, keep the target dispatch table completely unchanged. */
        if (!NT_SUCCESS(status)) {
            /* Note: Write the policy status to the fixed response. */
            responseBuffer->lastStatus = status;
            /* Log the result of a rejected control. */
            kswordArkDriverCommunicationLogResult(device, responseBuffer);
            /* Note: Business rejection is located in lastStatus; transport success guarantees R3 can read the response. */
            return STATUS_SUCCESS;
        }
    }

    /* Note: The backend re-validates protocol fields and executes the QUERY/BLIND/RESTORE state machine. */
    status = kswordArkDriverControlCommunication(
        &requestSnapshot,
        responseBuffer);
    /* Note: The evidence page issues batch QUERY requests. Do not log successful inactive responses, so polling does not drown out real events. */
    if (requestSnapshot.action != KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_QUERY ||
        responseBuffer->state != KSWORD_ARK_DRIVER_COMMUNICATION_STATE_INACTIVE ||
        !NT_SUCCESS((NTSTATUS)responseBuffer->lastStatus)) {
        /* Note: Failures, BLIND/RESTORE, and ACTIVE/CONFLICT queries retain full audit trails. */
        kswordArkDriverCommunicationLogResult(device, responseBuffer);
    }
    /* Note: Backend business status is saved in lastStatus; after the fixed response is formed, transport success is returned uniformly. */
    return STATUS_SUCCESS;
}
