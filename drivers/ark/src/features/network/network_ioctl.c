/*++

Module Name:

    network_ioctl.c

Abstract:

    IOCTL handlers for KswordARK network filter and port-hide rules.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

static VOID
kswordArkNetworkIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Output network IOCTL logs. Note: Rule changes are security-sensitive
    operations; recording status and rule counts facilitates R3 log panel auditing.

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
kswordArkNetworkIoctlSetRules(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_NETWORK_SET_RULES. Note: This IOCTL requires write permissions;
    the rule backend is responsible for full validation and one-time snapshot replacement.

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
    KSWORD_ARK_NETWORK_SET_RULES_REQUEST* setRequest = NULL;
    // requestSnapshot: Saves the complete request before zeroing the shared SystemBuffer in the backend.
    KSWORD_ARK_NETWORK_SET_RULES_REQUEST requestSnapshot;
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
        kswordArkNetworkIoctlLog(device, "Warn", "R0 network set-rules denied, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_NETWORK_SET_RULES_REQUEST),
        (PVOID*)&setRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkNetworkIoctlLog(device, "Error", "R0 network set-rules input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * For METHOD_BUFFERED, input and output share the same SystemBuffer. The backend first calls RtlZeroMemory
     * on the output, then iterates and copies rules[] according to ruleCount. Without a snapshot, response
     * header bytes would be misinterpreted as rule count and rule content, corrupting the firewall table.
     */
    RtlCopyMemory(&requestSnapshot, setRequest, sizeof(requestSnapshot));
    setRequest = &requestSnapshot;

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_NETWORK_SET_RULES_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkNetworkIoctlLog(device, "Error", "R0 network set-rules output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkNetworkSetRules(
        setRequest,
        outputBuffer,
        actualOutputLength,
        bytesReturned);
    if (NT_SUCCESS(status) && *bytesReturned >= sizeof(KSWORD_ARK_NETWORK_SET_RULES_RESPONSE)) {
        KSWORD_ARK_NETWORK_SET_RULES_RESPONSE* response =
            (KSWORD_ARK_NETWORK_SET_RULES_RESPONSE*)outputBuffer;
        kswordArkNetworkIoctlLog(
            device,
            response->status == KSWORD_ARK_NETWORK_STATUS_APPLIED ? "Info" : "Warn",
            "R0 network set-rules status=%lu rules=%lu block=%lu hide=%lu last=0x%08X.",
            (unsigned long)response->status,
            (unsigned long)response->appliedCount,
            (unsigned long)response->blockedRuleCount,
            (unsigned long)response->hiddenPortRuleCount,
            (unsigned int)response->lastStatus);
    }

    return status;
}

NTSTATUS
kswordArkNetworkIoctlQueryStatus(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_NETWORK_QUERY_STATUS. Note: Return a fixed status
    response containing WFP registration status, rule snapshots, and classify counts.

Arguments:

    Device - The WDF device object.
    Request - current WDF request.
    InputBufferLength - Input length.
    OutputBufferLength - Output length.
    BytesReturned - Returns the number of bytes written.

Return Value:

    NTSTATUS from buffer retrieval or backend.

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
        sizeof(KSWORD_ARK_NETWORK_STATUS_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkNetworkIoctlLog(device, "Error", "R0 network status output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkNetworkQueryStatus(
        outputBuffer,
        actualOutputLength,
        bytesReturned);
    if (NT_SUCCESS(status) && *bytesReturned >= sizeof(KSWORD_ARK_NETWORK_STATUS_RESPONSE)) {
        KSWORD_ARK_NETWORK_STATUS_RESPONSE* response =
            (KSWORD_ARK_NETWORK_STATUS_RESPONSE*)outputBuffer;
        kswordArkNetworkIoctlLog(
            device,
            "Info",
            "R0 network status flags=0x%08X rules=%lu blockedHits=%I64u.",
            (unsigned int)response->runtimeFlags,
            (unsigned long)response->ruleCount,
            (unsigned long long)response->blockedCount);
    }

    return status;
}

static NTSTATUS
kswordArkNetworkIoctlRetrieveAuditBuffers(
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t requiredOutputLength,
    _Outptr_result_maybenull_ KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST** queryRequestOut,
    _Outptr_result_bytebuffer_(*actualOutputLengthOut) PVOID* outputBufferOut,
    _Out_ size_t* actualOutputLengthOut
    )
/*++

Routine Description:

    Extract optional requests and required output buffers for network audit IOCTLs. Note: The four read-only
    audit handlers share the same buffer rules to avoid duplicating WDF retrieval branches in each handler.

Arguments:

    Request - current WDF request.
    InputBufferLength: input length provided by the dispatch.
    RequiredOutputLength - The minimum length of the response header.
    QueryRequestOut - Receives an optional request; returns NULL if not provided.
    OutputBufferOut - Received output buffer.
    ActualOutputLengthOut: The actual length of the received output buffer.

Return Value:

    NTSTATUS from shared validation helpers.

--*/
{
    PVOID inputBuffer = NULL;
    size_t actualInputLength = 0U;
    BOOLEAN inputPresent = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (queryRequestOut == NULL || outputBufferOut == NULL || actualOutputLengthOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *queryRequestOut = NULL;
    *outputBufferOut = NULL;
    *actualOutputLengthOut = 0U;

    status = kswordArkRetrieveOptionalInputBuffer(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &inputPresent);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (inputPresent) {
        UNREFERENCED_PARAMETER(actualInputLength);
        *queryRequestOut = (KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST*)inputBuffer;
    }

    return kswordArkRetrieveRequiredOutputBuffer(
        request,
        requiredOutputLength,
        outputBufferOut,
        actualOutputLengthOut);
}

NTSTATUS
kswordArkNetworkIoctlQueryTcpEndpoints(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS. Note: This is a read-only audit entry point; the
    handler only performs buffer retrieval, while TCP table traversal is handled by the network_audit.c backend.

Arguments:

    Device - The WDF device object.
    Request - current WDF request.
    InputBufferLength - Input length.
    OutputBufferLength - Output length.
    BytesReturned - Returns the number of bytes written.

Return Value:

    NTSTATUS from buffer retrieval or backend.

--*/
{
    KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST* queryRequest = NULL;
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkNetworkIoctlRetrieveAuditBuffers(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_ENDPOINT_ROW),
        &queryRequest,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkNetworkIoctlLog(device, "Error", "R0 network TCP audit buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkNetworkQueryTcpEndpoints(
        queryRequest,
        outputBuffer,
        actualOutputLength,
        bytesReturned);
    if (NT_SUCCESS(status) && *bytesReturned >= sizeof(KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_ENDPOINT_ROW)) {
        KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE* response =
            (KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE*)outputBuffer;
        kswordArkNetworkIoctlLog(device, "Info", "R0 network TCP audit status=%lu rows=%lu/%lu.", response->status, response->returnedRowCount, response->totalRowCount);
    }

    return status;
}

NTSTATUS
kswordArkNetworkIoctlQueryUdpEndpoints(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_NETWORK_QUERY_UDP_ENDPOINTS. Note: This entry point returns a read-only
    UDP endpoint audit response; it does not delete connections or alter port hiding policies.

Arguments:

    Device - The WDF device object.
    Request - current WDF request.
    InputBufferLength - Input length.
    OutputBufferLength - Output length.
    BytesReturned - Returns the number of bytes written.

Return Value:

    NTSTATUS from buffer retrieval or backend.

--*/
{
    KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST* queryRequest = NULL;
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkNetworkIoctlRetrieveAuditBuffers(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_ENDPOINT_ROW),
        &queryRequest,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkNetworkIoctlLog(device, "Error", "R0 network UDP audit buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkNetworkQueryUdpEndpoints(
        queryRequest,
        outputBuffer,
        actualOutputLength,
        bytesReturned);
    if (NT_SUCCESS(status) && *bytesReturned >= sizeof(KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_ENDPOINT_ROW)) {
        KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE* response =
            (KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE*)outputBuffer;
        kswordArkNetworkIoctlLog(device, "Info", "R0 network UDP audit status=%lu rows=%lu/%lu.", response->status, response->returnedRowCount, response->totalRowCount);
    }

    return status;
}

NTSTATUS
kswordArkNetworkIoctlQueryWfpInventory(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handles IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_INVENTORY. Note: This entry point only reads and returns the
    WFP provider/sublayer/filter/callout inventory skeleton; it does not disable or delete WFP objects.

Arguments:

    Device - The WDF device object.
    Request - current WDF request.
    InputBufferLength - Input length.
    OutputBufferLength - Output length.
    BytesReturned - Returns the number of bytes written.

Return Value:

    NTSTATUS from buffer retrieval or backend.

--*/
{
    KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST* queryRequest = NULL;
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkNetworkIoctlRetrieveAuditBuffers(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW),
        &queryRequest,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkNetworkIoctlLog(device, "Error", "R0 network WFP audit buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkNetworkQueryWfpInventory(
        queryRequest,
        outputBuffer,
        actualOutputLength,
        bytesReturned);
    if (NT_SUCCESS(status) && *bytesReturned >= sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW)) {
        KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE* response =
            (KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE*)outputBuffer;
        kswordArkNetworkIoctlLog(device, "Info", "R0 network WFP audit status=%lu rows=%lu/%lu.", response->status, response->returnedRowCount, response->totalRowCount);
    }

    return status;
}

NTSTATUS
kswordArkNetworkIoctlQueryWfpEvents(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handling IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_EVENTS. Note: For METHOD_BUFFERED, the input and output
    may point to the same SystemBuffer, so cursor/maxRows must be copied before writing the response.

Arguments:

    Device - The WDF device object.
    Request - current WDF request.
    InputBufferLength - Input length.
    OutputBufferLength - Output length.
    BytesReturned - Returns the number of bytes written.

Return Value:

    NTSTATUS from buffer retrieval or versioned event backend.

--*/
{
    // Note: Points to a METHOD_BUFFERED input request; do not use after copying.
    KSWORD_ARK_NETWORK_WFP_EVENT_QUERY_REQUEST* inputRequest = NULL;
    // Note: Local request prevents output zeroing from overwriting afterSequence/maxRows.
    KSWORD_ARK_NETWORK_WFP_EVENT_QUERY_REQUEST localRequest = { 0 };
    // Note: Receives METHOD_BUFFERED output SystemBuffer.
    PVOID outputBuffer = NULL;
    // Note: Save the actual input length returned by WDF; the helper does not accept a null output length parameter.
    size_t actualInputLength = 0U;
    // Note: Save the WDF actual output buffer length.
    size_t actualOutputLength = 0U;
    // Note: Save the retrieval or backend status.
    NTSTATUS status = STATUS_SUCCESS;
    // Note: The event response header does not include the placeholder row for entries[1].
    const size_t kResponseHeaderSize =
        sizeof(KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE) -
        sizeof(KSWORD_ARK_NETWORK_WFP_EVENT_ROW);

    // Note: The dispatch output length is re-validated by the WDF retrieval result.
    UNREFERENCED_PARAMETER(outputBufferLength);

    // Note: Caller must provide a pointer to return byte count.
    if (bytesReturned == NULL) {
        // Reject the request when unable to report the completion length.
        return STATUS_INVALID_PARAMETER;
    }
    // Note: Default output bytes are zero.
    *bytesReturned = 0U;

    // Note: Event query requires fully versioned input; older drivers reject unknown IOCTLs at the registry layer.
    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_NETWORK_WFP_EVENT_QUERY_REQUEST),
        (PVOID*)&inputRequest,
        &actualInputLength);
    // Note: Do not access SystemBuffer if the input retrieval fails.
    if (!NT_SUCCESS(status)) {
        // Note: Only log failures; avoid generating high-frequency logs on the successful polling path.
        kswordArkNetworkIoctlLog(
            device,
            "Error",
            "R0 WFP event query input invalid, status=0x%08X.",
            (unsigned int)status);
        // Note: Return WDF retrieval errors to dispatch.
        return status;
    }
    // Note: The dispatch-provided input length must also cover the stable request ABI.
    if (inputBufferLength < sizeof(localRequest) ||
        actualInputLength < sizeof(localRequest)) {
        // Note: Reject on length mismatch to avoid truncating the copied request.
        return STATUS_BUFFER_TOO_SMALL;
    }
    // Note: Copy the METHOD_BUFFERED request with alias before any output retrieval or zeroing.
    RtlCopyMemory(&localRequest, inputRequest, sizeof(localRequest));

    // Note: Output must be large enough to hold a zero-row response header.
    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        kResponseHeaderSize,
        &outputBuffer,
        &actualOutputLength);
    // Note: On retrieval failure, retain the copied request but do not call the backend.
    if (!NT_SUCCESS(status)) {
        // Note: Record the actual buffer error.
        kswordArkNetworkIoctlLog(
            device,
            "Error",
            "R0 WFP event query output invalid, status=0x%08X.",
            (unsigned int)status);
        // Note: Return WDF retrieval errors to dispatch.
        return status;
    }

    // Note: The backend reads the local request and writes to an output buffer that may alias the original input.
    status = kswordArkNetworkQueryWfpEvents(
        &localRequest,
        outputBuffer,
        actualOutputLength,
        bytesReturned);
    // Note: Successful polling does not write driver logs to avoid polluting the log ring with continuous network activity.
    if (!NT_SUCCESS(status)) {
        // Note: log diagnostics only when the backend fails.
        kswordArkNetworkIoctlLog(
            device,
            "Error",
            "R0 WFP event query backend failed, status=0x%08X.",
            (unsigned int)status);
    }
    // Note: Return backend transport status.
    return status;
}

NTSTATUS
kswordArkNetworkIoctlControlTrafficCapture(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_NETWORK_CONTROL_TRAFFIC_CAPTURE. This write-permission IOCTL only
    starts/stops packet-level data plane copying, without unregistering WFP filters or callouts.

--*/
{
    KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_REQUEST* inputRequest = NULL;
    KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_REQUEST localRequest = { 0 };
    KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_RESPONSE* outputResponse = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(outputBufferLength);
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(localRequest),
        (PVOID*)&inputRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (inputBufferLength < sizeof(localRequest) ||
        actualInputLength < sizeof(localRequest)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlCopyMemory(&localRequest, inputRequest, sizeof(localRequest));

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(*outputResponse),
        (PVOID*)&outputResponse,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = kswordArkNetworkControlTrafficCapture(
        &localRequest,
        outputResponse);
    if (NT_SUCCESS(status)) {
        *bytesReturned = sizeof(*outputResponse);
        kswordArkNetworkIoctlLog(
            device,
            outputResponse->status == KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED
                ? "Warn"
                : "Info",
            "R0 WFP traffic capture control action=%lu enabled=%lu generation=%lu status=%lu last=0x%08X.",
            (unsigned long)localRequest.action,
            (unsigned long)outputResponse->enabled,
            (unsigned long)outputResponse->generation,
            (unsigned long)outputResponse->status,
            (unsigned int)outputResponse->lastStatus);
    }
    return status;
}

NTSTATUS
kswordArkNetworkIoctlQueryTrafficPackets(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handles IOCTL_KSWORD_ARK_NETWORK_QUERY_TRAFFIC_PACKETS. Note: METHOD_BUFFERED input and output share
    the SystemBuffer, so copy cursor/maxRows first, then let the backend write packet-by-packet responses.

Arguments:

    Device - The WDF device object.
    Request - current WDF request.
    InputBufferLength - Input length.
    OutputBufferLength - Output length.
    BytesReturned - Returns the number of bytes written.

Return Value:

    NTSTATUS from buffer retrieval or versioned packet backend.

--*/
{
    // Note: Points to a METHOD_BUFFERED input request; do not access after copying.
    KSWORD_ARK_NETWORK_TRAFFIC_QUERY_REQUEST* inputRequest = NULL;
    // Note: Local request prevents output zeroing from overwriting cursor/maxRows.
    KSWORD_ARK_NETWORK_TRAFFIC_QUERY_REQUEST localRequest = { 0 };
    // Note: Receives METHOD_BUFFERED output SystemBuffer.
    PVOID outputBuffer = NULL;
    // Note: Save the actual input length returned by WDF.
    size_t actualInputLength = 0U;
    // Note: Save the actual output length returned by WDF.
    size_t actualOutputLength = 0U;
    // Note: Save the retrieval or backend status.
    NTSTATUS status = STATUS_SUCCESS;
    // Note: The variable-length per-packet response header does not include a placeholder row for entries[1].
    const size_t kResponseHeaderSize =
        sizeof(KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE) -
        sizeof(KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW);

    // Note: The actual output length is re-validated by the WDF retrieval result.
    UNREFERENCED_PARAMETER(outputBufferLength);

    // Note: Must be able to report the number of completed bytes.
    if (bytesReturned == NULL) {
        // Note: Reject the request if the output-count pointer is null.
        return STATUS_INVALID_PARAMETER;
    }
    // Note: The default failure path produces no output.
    *bytesReturned = 0U;

    // Note: New per-packet IOCTL requires a fully versioned request; older drivers return 'not supported' at the registry layer.
    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_NETWORK_TRAFFIC_QUERY_REQUEST),
        (PVOID*)&inputRequest,
        &actualInputLength);
    // Note: Do not access SystemBuffer if the input retrieval fails.
    if (!NT_SUCCESS(status)) {
        // Note: Log only the failure path; do not pollute the log ring with successful polling.
        kswordArkNetworkIoctlLog(
            device,
            "Error",
            "R0 WFP traffic query input invalid, status=0x%08X.",
            (unsigned int)status);
        // Note: Return WDF retrieval error.
        return status;
    }
    // Note: Both dispatch and actual WDF input length must cover the stable ABI.
    if (inputBufferLength < sizeof(localRequest) ||
        actualInputLength < sizeof(localRequest)) {
        // Note: Reject truncated copy when lengths are inconsistent.
        return STATUS_BUFFER_TOO_SMALL;
    }
    // Note: Copy the alias input before any output retrieval or zeroing.
    RtlCopyMemory(&localRequest, inputRequest, sizeof(localRequest));

    // Note: Output must accommodate at least the no-row response header.
    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        kResponseHeaderSize,
        &outputBuffer,
        &actualOutputLength);
    // Note: Do not call the backend when retrieval fails.
    if (!NT_SUCCESS(status)) {
        // Note: Log the actual output buffer error.
        kswordArkNetworkIoctlLog(
            device,
            "Error",
            "R0 WFP traffic query output invalid, status=0x%08X.",
            (unsigned int)status);
        // Note: Return WDF retrieval error.
        return status;
    }

    // Note: The backend reads the local request and writes to an output buffer that may alias the original input.
    status = kswordArkNetworkQueryTrafficPackets(
        &localRequest,
        outputBuffer,
        actualOutputLength,
        bytesReturned);
    // Note: Poll success remains silent; diagnostic logs are written only on backend failure.
    if (!NT_SUCCESS(status)) {
        // Note: Log backend exception.
        kswordArkNetworkIoctlLog(
            device,
            "Error",
            "R0 WFP traffic query backend failed, status=0x%08X.",
            (unsigned int)status);
    }
    // Note: Return backend transport status.
    return status;
}

NTSTATUS
kswordArkNetworkIoctlQueryNdisChain(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_NETWORK_QUERY_NDIS_CHAIN. Note: This entry point only reads and
    returns the NDIS chain skeleton; it does not detach, pause, or reorder any NDIS components.

Arguments:

    Device - The WDF device object.
    Request - current WDF request.
    InputBufferLength - Input length.
    OutputBufferLength - Output length.
    BytesReturned - Returns the number of bytes written.

Return Value:

    NTSTATUS from buffer retrieval or backend.

--*/
{
    KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST* queryRequest = NULL;
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkNetworkIoctlRetrieveAuditBuffers(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW),
        &queryRequest,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkNetworkIoctlLog(device, "Error", "R0 network NDIS audit buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkNetworkQueryNdisChain(
        queryRequest,
        outputBuffer,
        actualOutputLength,
        bytesReturned);
    if (NT_SUCCESS(status) && *bytesReturned >= sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW)) {
        KSWORD_ARK_NETWORK_NDIS_CHAIN_RESPONSE* response =
            (KSWORD_ARK_NETWORK_NDIS_CHAIN_RESPONSE*)outputBuffer;
        kswordArkNetworkIoctlLog(device, "Info", "R0 network NDIS audit status=%lu rows=%lu/%lu.", response->status, response->returnedRowCount, response->totalRowCount);
    }

    return status;
}
