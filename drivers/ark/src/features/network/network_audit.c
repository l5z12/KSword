/*++

Module Name:

    network_audit.c

Abstract:

    Read-only network audit IOCTL backends for TCP, UDP, WFP and NDIS skeleton
    queries.

Environment:

    Kernel-mode Driver Framework

--*/

#include "network_internal.h"
#include "network_inventory.h"

#define KSWORD_ARK_NETWORK_ENDPOINT_HEADER_SIZE \
    (sizeof(KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_ENDPOINT_ROW))

#define KSWORD_ARK_NETWORK_WFP_HEADER_SIZE \
    (sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW))

#define KSWORD_ARK_NETWORK_NDIS_HEADER_SIZE \
    (sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW))

#define KSWORD_ARK_NETWORK_AUDIT_DEFAULT_BUDGET_ROWS 256UL

static ULONG
kswordArkNetworkAuditCapacityFromBuffer(
    _In_ size_t outputBufferLength,
    _In_ size_t headerSize,
    _In_ size_t rowSize
    )
/*++

Routine Description:

    Calculate the number of complete rows a variable-length network response can hold, capped at the protocol's maximum budget.

--*/
{
    size_t payloadLength = 0U;
    size_t rowCapacity = 0U;

    if (outputBufferLength <= headerSize || rowSize == 0U) {
        return 0UL;
    }

    payloadLength = outputBufferLength - headerSize;
    rowCapacity = payloadLength / rowSize;
    if (rowCapacity > KSWORD_ARK_NETWORK_AUDIT_MAX_REQUESTED_ROWS) {
        rowCapacity = KSWORD_ARK_NETWORK_AUDIT_MAX_REQUESTED_ROWS;
    }
    return (ULONG)rowCapacity;
}

// {D2B28BC6-9E08-4D07-9F7B-2BA821D8AA51}
static const GUID kKswordArkAuditWfpSublayer =
{ 0xd2b28bc6, 0x9e08, 0x4d07, { 0x9f, 0x7b, 0x2b, 0xa8, 0x21, 0xd8, 0xaa, 0x51 } };

// {9CEBA6FD-DC43-4E48-A013-FDB83823674B}
static const GUID kKswordArkAuditWfpConnectCallout =
{ 0x9ceba6fd, 0xdc43, 0x4e48, { 0xa0, 0x13, 0xfd, 0xb8, 0x38, 0x23, 0x67, 0x4b } };

// {75FCE1D8-0E28-4C58-9957-90181B75B6AA}
static const GUID kKswordArkAuditWfpRecvAcceptCallout =
{ 0x75fce1d8, 0x0e28, 0x4c58, { 0x99, 0x57, 0x90, 0x18, 0x1b, 0x75, 0xb6, 0xaa } };

// {C38D57D1-05A7-4C33-904F-7FBCEEE60E82}
static const GUID kKswordArkAuditFwpmLayerAleAuthConnectV4 =
{ 0xc38d57d1, 0x05a7, 0x4c33, { 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82 } };

// {E1CD9FE7-F4B5-4273-96C0-592E487B8650}
static const GUID kKswordArkAuditFwpmLayerAleAuthRecvAcceptV4 =
{ 0xe1cd9fe7, 0xf4b5, 0x4273, { 0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50 } };

#define KSWORD_ARK_AUDIT_FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4 43UL
#define KSWORD_ARK_AUDIT_FWPS_LAYER_ALE_AUTH_CONNECT_V4 47UL

static ULONG
kswordArkNetworkAuditNormalizeBudget(
    _In_opt_ const KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST* request
    )
/*++

Routine Description:

    Calculate the network audit return budget. Note: 0 indicates using the conservative default value; oversized requests
    are capped at the protocol limit to ensure that subsequent PDB traversal integration remains budget-limited.

Arguments:

    Request - Optional audit request.

Return Value:

    Returns the maximum number of rows allowed for this query.

--*/
{
    ULONG budgetRows = KSWORD_ARK_NETWORK_AUDIT_DEFAULT_BUDGET_ROWS;

    if (request != NULL && request->maxRows != 0UL) {
        budgetRows = request->maxRows;
    }
    if (budgetRows > KSWORD_ARK_NETWORK_AUDIT_MAX_REQUESTED_ROWS) {
        budgetRows = KSWORD_ARK_NETWORK_AUDIT_MAX_REQUESTED_ROWS;
    }

    return budgetRows;
}

static ULONG
kswordArkNetworkAuditNormalizeFlags(
    _In_opt_ const KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST* request
    )
/*++

Routine Description:

    normalize network audit flags. Note: If the caller does not provide an address family,
    default to IPv4+IPv6; subsequent endpoint traversal can directly filter using this mask.

Arguments:

    Request - Optional audit request.

Return Value:

    Returns a mask containing only known audit query flags.

--*/
{
    ULONG flags = KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL;

    if (request != NULL && (request->flags & KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL) != 0UL) {
        flags = request->flags & KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL;
    }

    return flags;
}

static NTSTATUS
kswordArkNetworkAuditValidateRequest(
    _In_opt_ const KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST* request
    )
/*++

Routine Description:

    Validate the network audit request header. Note: In the skeleton phase, only the protocol version and known flags are
    accepted; unknown bits are rejected immediately to prevent future R3 code from mistakenly assuming hidden switches are active.

Arguments:

    Request - Optional audit request.

Return Value:

    STATUS_SUCCESS indicates the request is usable; failure status indicates the handler should return a parameter error.

--*/
{
    if (request == NULL) {
        return STATUS_SUCCESS;
    }
    if (request->size != 0UL && request->size < sizeof(*request)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (request->version != KSWORD_ARK_NETWORK_PROTOCOL_VERSION) {
        return STATUS_REVISION_MISMATCH;
    }
    if ((request->flags & ~KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL) != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

static VOID
kswordArkNetworkAuditFillEndpointHeader(
    _Out_writes_bytes_(KSWORD_ARK_NETWORK_ENDPOINT_HEADER_SIZE) PVOID responseBuffer,
    _In_ ULONG flags,
    _In_ ULONG budgetRows,
    _In_ ULONG runtimeGeneration,
    _In_ NTSTATUS lastStatus
    )
/*++

Routine Description:

    Populate the base response header for TCP/UDP endpoints. If the collector succeeds, the caller overwrites the
    count, source, and APPLIED status; if the collector fails, retain AUDIT_UNAVAILABLE and the actual error code.

Arguments:

    Response - endpoint response header.
    Flags - Normalized query flags.
    BudgetRows - The query budget for this operation.
    RuntimeGeneration: network runtime generation.
    LastStatus - Specific downgrade status.

Return Value:

    None. This function has no return value.

--*/
{
    KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE* response =
        (KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE*)responseBuffer;

    response->version = KSWORD_ARK_NETWORK_PROTOCOL_VERSION;
    response->size = (ULONG)KSWORD_ARK_NETWORK_ENDPOINT_HEADER_SIZE;
    response->status = KSWORD_ARK_NETWORK_STATUS_AUDIT_UNAVAILABLE;
    response->flags = flags;
    response->totalRowCount = 0UL;
    response->returnedRowCount = 0UL;
    response->entrySize = sizeof(KSWORD_ARK_NETWORK_ENDPOINT_ROW);
    response->sourceFlags = KSWORD_ARK_NETWORK_AUDIT_SOURCE_NONE;
    response->budgetRows = budgetRows;
    response->generation = runtimeGeneration;
    response->lastStatus = lastStatus;
}

NTSTATUS
kswordArkNetworkQueryTcpEndpoints(
    _In_opt_ const KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Construct a read-only TCP endpoint audit response. Note: Real data comes from the netio.sys NSI
    TCP provider table; unavailable private tcpip object fields are explicitly marked via row flags.

Arguments:

    Request - Optional query request.
    OutputBuffer - R3 output buffer.
    OutputBufferLength - Output buffer length.
    BytesWrittenOut - Bytes written returned.

Return Value:

    STATUS_SUCCESS indicates writing to a degraded response; parameter or buffer errors return failure directly.

--*/
{
    KswordArkNetworkRuntime* runtime = kswordArkNetworkGetRuntime();
    KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE* response = NULL;
    ULONG generation = 0UL;
    ULONG queryFlags = 0UL;
    ULONG budgetRows = 0UL;
    ULONG rowCapacity = 0UL;
    ULONG rowsAllowed = 0UL;
    ULONG totalRows = 0UL;
    ULONG returnedRows = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSWORD_ARK_NETWORK_ENDPOINT_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = kswordArkNetworkAuditValidateRequest(request);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    kswordArkAcquirePushLockShared(&runtime->lock);
    generation = runtime->generation;
    kswordArkReleasePushLockShared(&runtime->lock);

    queryFlags = kswordArkNetworkAuditNormalizeFlags(request);
    budgetRows = kswordArkNetworkAuditNormalizeBudget(request);
    rowCapacity = kswordArkNetworkAuditCapacityFromBuffer(
        outputBufferLength,
        KSWORD_ARK_NETWORK_ENDPOINT_HEADER_SIZE,
        sizeof(KSWORD_ARK_NETWORK_ENDPOINT_ROW));
    rowsAllowed = (budgetRows < rowCapacity) ? budgetRows : rowCapacity;

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE*)outputBuffer;
    kswordArkNetworkAuditFillEndpointHeader(
        response,
        queryFlags,
        budgetRows,
        generation,
        STATUS_NOT_SUPPORTED);

    status = kswordArkNetworkCollectNsiEndpoints(
        TRUE,
        queryFlags,
        (rowsAllowed != 0UL) ? response->entries : NULL,
        rowsAllowed,
        &totalRows,
        &returnedRows);
    response->lastStatus = status;
    if (status == STATUS_SUCCESS) {
        response->status = KSWORD_ARK_NETWORK_STATUS_APPLIED;
        response->totalRowCount = totalRows;
        response->returnedRowCount = returnedRows;
        response->sourceFlags = KSWORD_ARK_NETWORK_AUDIT_SOURCE_RUNTIME_STATE;
    }

    *bytesWrittenOut = KSWORD_ARK_NETWORK_ENDPOINT_HEADER_SIZE +
        ((size_t)returnedRows * sizeof(KSWORD_ARK_NETWORK_ENDPOINT_ROW));
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkNetworkQueryUdpEndpoints(
    _In_opt_ const KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Construct a read-only audit response for UDP endpoints. Note: Real data comes from the netio.sys NSI
    UDP provider table; the private tcpip table is not read, and endpoint object addresses are not forged.

Arguments:

    Request - Optional query request.
    OutputBuffer - R3 output buffer.
    OutputBufferLength - Output buffer length.
    BytesWrittenOut - Bytes written returned.

Return Value:

    STATUS_SUCCESS indicates writing to a degraded response; parameter or buffer errors return failure directly.

--*/
{
    KswordArkNetworkRuntime* runtime = kswordArkNetworkGetRuntime();
    KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE* response = NULL;
    ULONG generation = 0UL;
    ULONG queryFlags = 0UL;
    ULONG budgetRows = 0UL;
    ULONG rowCapacity = 0UL;
    ULONG rowsAllowed = 0UL;
    ULONG totalRows = 0UL;
    ULONG returnedRows = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSWORD_ARK_NETWORK_ENDPOINT_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = kswordArkNetworkAuditValidateRequest(request);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    kswordArkAcquirePushLockShared(&runtime->lock);
    generation = runtime->generation;
    kswordArkReleasePushLockShared(&runtime->lock);

    queryFlags = kswordArkNetworkAuditNormalizeFlags(request);
    budgetRows = kswordArkNetworkAuditNormalizeBudget(request);
    rowCapacity = kswordArkNetworkAuditCapacityFromBuffer(
        outputBufferLength,
        KSWORD_ARK_NETWORK_ENDPOINT_HEADER_SIZE,
        sizeof(KSWORD_ARK_NETWORK_ENDPOINT_ROW));
    rowsAllowed = (budgetRows < rowCapacity) ? budgetRows : rowCapacity;

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE*)outputBuffer;
    kswordArkNetworkAuditFillEndpointHeader(
        response,
        queryFlags,
        budgetRows,
        generation,
        STATUS_NOT_SUPPORTED);

    status = kswordArkNetworkCollectNsiEndpoints(
        FALSE,
        queryFlags,
        (rowsAllowed != 0UL) ? response->entries : NULL,
        rowsAllowed,
        &totalRows,
        &returnedRows);
    response->lastStatus = status;
    if (status == STATUS_SUCCESS) {
        response->status = KSWORD_ARK_NETWORK_STATUS_APPLIED;
        response->totalRowCount = totalRows;
        response->returnedRowCount = returnedRows;
        response->sourceFlags = KSWORD_ARK_NETWORK_AUDIT_SOURCE_RUNTIME_STATE;
    }

    *bytesWrittenOut = KSWORD_ARK_NETWORK_ENDPOINT_HEADER_SIZE +
        ((size_t)returnedRows * sizeof(KSWORD_ARK_NETWORK_ENDPOINT_ROW));
    return STATUS_SUCCESS;
}

static ULONG
kswordArkNetworkAuditWfpCapacityFromBuffer(
    _In_ size_t outputBufferLength
    )
/*++

Routine Description:

    Calculate the number of rows the WFP inventory output buffer can hold. Note: The response structure
    declares entries[1] at the tail, but the actual METHOD_BUFFERED buffer is interpreted as header + N * row.

Arguments:

    OutputBufferLength - Output buffer length provided by R3.

Return Value:

    Return the maximum number of WFP rows that can currently be written to the buffer.

--*/
{
    size_t payloadLength = 0U;
    size_t rowCapacity = 0U;

    if (outputBufferLength <= KSWORD_ARK_NETWORK_WFP_HEADER_SIZE) {
        return 0UL;
    }

    payloadLength = outputBufferLength - KSWORD_ARK_NETWORK_WFP_HEADER_SIZE;
    rowCapacity = payloadLength / sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW);
    if (rowCapacity > 0xFFFFFFFFULL) {
        return 0xFFFFFFFFUL;
    }

    return (ULONG)rowCapacity;
}

static VOID
kswordArkNetworkAuditCopyGuid(
    _Out_writes_bytes_(16) UCHAR* destination,
    _In_ const GUID* source
    )
/*++

Routine Description:

    Copy GUID to the 16-byte raw field of the shared protocol. Note: The protocol layer uses
    byte[16] to avoid additional dependencies on GUID type definitions between R3 and R0 structures.

Arguments:

    Destination: 16-byte target buffer.
    Source: source GUID.

Return Value:

    None. This function has no return value.

--*/
{
    if (destination == NULL || source == NULL) {
        return;
    }

    RtlCopyMemory(destination, source, sizeof(GUID));
}

static VOID
kswordArkNetworkAuditCopyName(
    _Out_writes_(KSWORD_ARK_NETWORK_NAME_CHARS) WCHAR* destination,
    _In_z_ PCWSTR source
    )
/*++

Routine Description:

    Copy fixed-length diagnostic name. Note: All owner/name fields are guaranteed to
    be NUL-terminated to prevent out-of-bounds reads by the R3 presentation layer.

Arguments:

    Destination - Fixed-width character buffer in the protocol line.
    Source - Read-only constant string.

Return Value:

    None. This function has no return value.

--*/
{
    if (destination == NULL || source == NULL) {
        return;
    }

    (VOID)RtlStringCchCopyW(destination, KSWORD_ARK_NETWORK_NAME_CHARS, source);
}

static VOID
kswordArkNetworkAuditFillWfpSublayerRow(
    _Out_ KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW* row,
    _In_ ULONG rowId
    )
/*++

Routine Description:

    Populate a KswordARK-owned WFP sublayer row. Note: This evidence comes from the fixed GUID used
    during driver registration; it does not read BFE private structures or modify any WFP objects.

Arguments:

    Row - Output row.
    RowId - Row ID within this response.

Return Value:

    None. This function has no return value.

--*/
{
    RtlZeroMemory(row, sizeof(*row));
    row->rowId = rowId;
    row->objectKind = KSWORD_ARK_NETWORK_WFP_OBJECT_SUBLAYER;
    row->flags = KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING;
    row->fieldMask = 0UL;
    kswordArkNetworkAuditCopyGuid(row->objectKey, &kKswordArkAuditWfpSublayer);
    kswordArkNetworkAuditCopyName(row->ownerModule, L"KswordARK.sys runtime sublayer");
}

static VOID
kswordArkNetworkAuditFillWfpCalloutRow(
    _Out_ KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW* row,
    _In_ ULONG rowId,
    _In_ const GUID* calloutKey,
    _In_ const GUID* layerKey,
    _In_ ULONG layerId,
    _In_ ULONG calloutId,
    _In_z_ PCWSTR nameText
    )
/*++

Routine Description:

    Populate the KswordARK-specific WFP callout row. Note: calloutId comes from the runtime registration result; the
    classify function address is not exported to the protocol row to avoid treating an undeclared ABI as complete evidence.

Arguments:

    Row - Output row.
    RowId - Row ID within this response.
    CalloutKey - BFE callout GUID。
    LayerKey - WFP layer GUID。
    LayerId - FWPS layer numeric ID.
    CalloutId — the callout ID returned by FwpsCalloutRegister.
    NameText - diagnostic name.

Return Value:

    None. This function has no return value.

--*/
{
    RtlZeroMemory(row, sizeof(*row));
    row->rowId = rowId;
    row->objectKind = KSWORD_ARK_NETWORK_WFP_OBJECT_CALLOUT;
    row->flags = KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING;
    row->layerId = layerId;
    row->calloutId = calloutId;
    row->fieldMask = 0UL;
    kswordArkNetworkAuditCopyGuid(row->subLayerKey, layerKey);
    kswordArkNetworkAuditCopyGuid(row->objectKey, calloutKey);
    kswordArkNetworkAuditCopyName(row->ownerModule, nameText);
}

static VOID
kswordArkNetworkAuditFillWfpFilterRow(
    _Out_ KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW* row,
    _In_ ULONG rowId,
    _In_ const GUID* calloutKey,
    _In_ const GUID* layerKey,
    _In_ ULONG layerId,
    _In_ ULONG calloutId,
    _In_ UINT64 filterId,
    _In_z_ PCWSTR nameText
    )
/*++

Routine Description:

    Populate the KswordARK proprietary WFP filter row. Note: filterId comes from FwpmFilterAdd0 output; it can be used in R3
    to confirm whether this driver's filter registered successfully, but this query does not delete or disable the filter.

Arguments:

    Row - Output row.
    RowId - Row ID within this response.
    CalloutKey - the callout GUID referenced by the filter action.
    LayerKey - the layer GUID to which the filter belongs.
    LayerId - FWPS layer numeric ID.
    CalloutId - corresponds to the callout ID.
    FilterId - BFE filter id。
    NameText - diagnostic name.

Return Value:

    None. This function has no return value.

--*/
{
    RtlZeroMemory(row, sizeof(*row));
    row->rowId = rowId;
    row->objectKind = KSWORD_ARK_NETWORK_WFP_OBJECT_FILTER;
    row->flags = KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING;
    row->layerId = layerId;
    row->calloutId = calloutId;
    row->filterId = filterId;
    row->fieldMask = 0UL;
    kswordArkNetworkAuditCopyGuid(row->providerKey, calloutKey);
    kswordArkNetworkAuditCopyGuid(row->subLayerKey, &kKswordArkAuditWfpSublayer);
    kswordArkNetworkAuditCopyGuid(row->objectKey, layerKey);
    kswordArkNetworkAuditCopyName(row->ownerModule, nameText);
}

NTSTATUS
kswordArkNetworkQueryWfpInventory(
    _In_opt_ const KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Construct WFP provider/sublayer/filter/callout inventory response. Prefer returning global objects via the BFE
    public read-only enumerator; only fall back to KswordARK's own runtime objects if the enumerator is unavailable.

Arguments:

    Request - Optional query request.
    OutputBuffer - R3 output buffer.
    OutputBufferLength - Output buffer length.
    BytesWrittenOut - Bytes written returned.

Return Value:

    STATUS_SUCCESS indicates writing to a read-only response; parameter or buffer errors return failure directly.

--*/
{
    KswordArkNetworkRuntime* runtime = kswordArkNetworkGetRuntime();
    KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE* response = NULL;
    ULONG generation = 0UL;
    ULONG runtimeFlags = 0UL;
    ULONG connectCalloutId = 0UL;
    ULONG recvAcceptCalloutId = 0UL;
    UINT64 connectFilterId = 0ULL;
    UINT64 recvAcceptFilterId = 0ULL;
    ULONG queryFlags = 0UL;
    ULONG budgetRows = 0UL;
    ULONG rowCapacity = 0UL;
    ULONG totalRows = 0UL;
    ULONG rowsToWrite = 0UL;
    ULONG rowsAllowed = 0UL;
    ULONG rowIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSWORD_ARK_NETWORK_WFP_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = kswordArkNetworkAuditValidateRequest(request);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    kswordArkAcquirePushLockShared(&runtime->lock);
    generation = runtime->generation;
    runtimeFlags = runtime->runtimeFlags;
    connectCalloutId = runtime->connectCalloutId;
    recvAcceptCalloutId = runtime->recvAcceptCalloutId;
    connectFilterId = runtime->connectFilterId;
    recvAcceptFilterId = runtime->recvAcceptFilterId;
    kswordArkReleasePushLockShared(&runtime->lock);

    queryFlags = kswordArkNetworkAuditNormalizeFlags(request);
    budgetRows = kswordArkNetworkAuditNormalizeBudget(request);
    rowCapacity = kswordArkNetworkAuditWfpCapacityFromBuffer(outputBufferLength);
    rowsAllowed = (budgetRows < rowCapacity) ? budgetRows : rowCapacity;

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE*)outputBuffer;
    status = kswordArkNetworkCollectWfpInventory(
        (rowsAllowed != 0UL) ? response->entries : NULL,
        rowsAllowed,
        &totalRows,
        &rowsToWrite);
    if (status == STATUS_SUCCESS ||
        status == STATUS_PARTIAL_COPY ||
        status == STATUS_BUFFER_OVERFLOW ||
        totalRows != 0UL) {
        response->version = KSWORD_ARK_NETWORK_PROTOCOL_VERSION;
        response->size = (ULONG)KSWORD_ARK_NETWORK_WFP_HEADER_SIZE;
        response->status = (status == STATUS_SUCCESS) ?
            KSWORD_ARK_NETWORK_STATUS_APPLIED :
            KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED;
        response->flags = queryFlags;
        response->totalRowCount = totalRows;
        response->returnedRowCount = rowsToWrite;
        response->entrySize = sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW);
        response->sourceFlags = KSWORD_ARK_NETWORK_AUDIT_SOURCE_RUNTIME_STATE;
        response->budgetRows = budgetRows;
        response->generation = generation;
        response->lastStatus = status;
        *bytesWrittenOut = KSWORD_ARK_NETWORK_WFP_HEADER_SIZE +
            ((size_t)rowsToWrite * sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW));
        return STATUS_SUCCESS;
    }

    totalRows = 0UL;
    rowsToWrite = 0UL;
    if ((runtimeFlags & KSWORD_ARK_NETWORK_RUNTIME_WFP_STARTED) != 0UL) {
        totalRows = 5UL;
    }
    rowsToWrite = totalRows;
    if (rowsToWrite > budgetRows) {
        rowsToWrite = budgetRows;
    }
    if (rowsToWrite > rowCapacity) {
        rowsToWrite = rowCapacity;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_NETWORK_PROTOCOL_VERSION;
    response->size = (ULONG)KSWORD_ARK_NETWORK_WFP_HEADER_SIZE;
    response->status = (totalRows != 0UL) ?
        KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED :
        KSWORD_ARK_NETWORK_STATUS_AUDIT_UNAVAILABLE;
    response->flags = queryFlags;
    response->totalRowCount = totalRows;
    response->returnedRowCount = rowsToWrite;
    response->entrySize = sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW);
    response->sourceFlags = (totalRows != 0UL) ?
        KSWORD_ARK_NETWORK_AUDIT_SOURCE_RUNTIME_STATE :
        KSWORD_ARK_NETWORK_AUDIT_SOURCE_NONE;
    response->budgetRows = budgetRows;
    response->generation = generation;
    response->lastStatus = status;

    if (rowIndex < rowsToWrite) {
        kswordArkNetworkAuditFillWfpSublayerRow(&response->entries[rowIndex], rowIndex);
        rowIndex += 1UL;
    }
    if (rowIndex < rowsToWrite) {
        kswordArkNetworkAuditFillWfpCalloutRow(
            &response->entries[rowIndex],
            rowIndex,
            &kKswordArkAuditWfpConnectCallout,
            &kKswordArkAuditFwpmLayerAleAuthConnectV4,
            KSWORD_ARK_AUDIT_FWPS_LAYER_ALE_AUTH_CONNECT_V4,
            connectCalloutId,
            L"KswordARK ALE connect callout");
        rowIndex += 1UL;
    }
    if (rowIndex < rowsToWrite) {
        kswordArkNetworkAuditFillWfpCalloutRow(
            &response->entries[rowIndex],
            rowIndex,
            &kKswordArkAuditWfpRecvAcceptCallout,
            &kKswordArkAuditFwpmLayerAleAuthRecvAcceptV4,
            KSWORD_ARK_AUDIT_FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            recvAcceptCalloutId,
            L"KswordARK ALE recv-accept callout");
        rowIndex += 1UL;
    }
    if (rowIndex < rowsToWrite) {
        kswordArkNetworkAuditFillWfpFilterRow(
            &response->entries[rowIndex],
            rowIndex,
            &kKswordArkAuditWfpConnectCallout,
            &kKswordArkAuditFwpmLayerAleAuthConnectV4,
            KSWORD_ARK_AUDIT_FWPS_LAYER_ALE_AUTH_CONNECT_V4,
            connectCalloutId,
            connectFilterId,
            L"KswordARK ALE connect filter");
        rowIndex += 1UL;
    }
    if (rowIndex < rowsToWrite) {
        kswordArkNetworkAuditFillWfpFilterRow(
            &response->entries[rowIndex],
            rowIndex,
            &kKswordArkAuditWfpRecvAcceptCallout,
            &kKswordArkAuditFwpmLayerAleAuthRecvAcceptV4,
            KSWORD_ARK_AUDIT_FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            recvAcceptCalloutId,
            recvAcceptFilterId,
            L"KswordARK ALE recv-accept filter");
    }

    *bytesWrittenOut = KSWORD_ARK_NETWORK_WFP_HEADER_SIZE +
        ((size_t)rowsToWrite * sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW));
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkNetworkQueryNdisChain(
    _In_opt_ const KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Constructs read-only responses for the NDIS miniport/filter device stack. The collector uses only public interface
    classes and reference-count-safe device stack traversal, without detaching, pausing, or reordering NDIS components.

Arguments:

    Request - Optional query request.
    OutputBuffer - R3 output buffer.
    OutputBufferLength - Output buffer length.
    BytesWrittenOut - Bytes written returned.

Return Value:

    STATUS_SUCCESS indicates writing to a degraded response; parameter or buffer errors return failure directly.

--*/
{
    KswordArkNetworkRuntime* runtime = kswordArkNetworkGetRuntime();
    KSWORD_ARK_NETWORK_NDIS_CHAIN_RESPONSE* response = NULL;
    ULONG generation = 0UL;
    ULONG queryFlags = 0UL;
    ULONG budgetRows = 0UL;
    ULONG rowCapacity = 0UL;
    ULONG rowsAllowed = 0UL;
    ULONG totalRows = 0UL;
    ULONG returnedRows = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSWORD_ARK_NETWORK_NDIS_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = kswordArkNetworkAuditValidateRequest(request);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    kswordArkAcquirePushLockShared(&runtime->lock);
    generation = runtime->generation;
    kswordArkReleasePushLockShared(&runtime->lock);

    queryFlags = kswordArkNetworkAuditNormalizeFlags(request);
    budgetRows = kswordArkNetworkAuditNormalizeBudget(request);
    rowCapacity = kswordArkNetworkAuditCapacityFromBuffer(
        outputBufferLength,
        KSWORD_ARK_NETWORK_NDIS_HEADER_SIZE,
        sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW));
    rowsAllowed = (budgetRows < rowCapacity) ? budgetRows : rowCapacity;

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_NETWORK_NDIS_CHAIN_RESPONSE*)outputBuffer;
    status = kswordArkNetworkCollectNdisDeviceStacks(
        (rowsAllowed != 0UL) ? response->entries : NULL,
        rowsAllowed,
        &totalRows,
        &returnedRows);
    response->version = KSWORD_ARK_NETWORK_PROTOCOL_VERSION;
    response->size = (ULONG)KSWORD_ARK_NETWORK_NDIS_HEADER_SIZE;
    response->status = (status == STATUS_SUCCESS) ?
        KSWORD_ARK_NETWORK_STATUS_APPLIED :
        ((totalRows != 0UL) ?
            KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED :
            KSWORD_ARK_NETWORK_STATUS_AUDIT_UNAVAILABLE);
    response->flags = queryFlags;
    response->totalRowCount = totalRows;
    response->returnedRowCount = returnedRows;
    response->entrySize = sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW);
    response->sourceFlags = (status == STATUS_SUCCESS || totalRows != 0UL) ?
        KSWORD_ARK_NETWORK_AUDIT_SOURCE_RUNTIME_STATE :
        KSWORD_ARK_NETWORK_AUDIT_SOURCE_NONE;
    response->budgetRows = budgetRows;
    response->generation = generation;
    response->lastStatus = status;
    *bytesWrittenOut = KSWORD_ARK_NETWORK_NDIS_HEADER_SIZE +
        ((size_t)returnedRows * sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW));
    return STATUS_SUCCESS;
}
