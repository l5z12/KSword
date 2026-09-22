/*++

Module Name:

    network_runtime.c

Abstract:

    KswordARK WFP network rule runtime and status IOCTL backend.

Environment:

    Kernel-mode WFP callout driver

--*/

#include "network_internal.h"

#include <stdarg.h>

static KswordArkNetworkRuntime gKswordArkNetworkRuntime;

KswordArkNetworkRuntime*
kswordArkNetworkGetRuntime(
    VOID
    )
/*++

Routine Description:

    Return: The global network runtime object. Note: Rule table access must be held
    by the caller via Lock; counters can be updated via interlocked operations.

Arguments:

    None.

Return Value:

    Pointer to KswordArkNetworkRuntime.

--*/
{
    return &gKswordArkNetworkRuntime;
}

static VOID
kswordArkNetworkIpv4HostOrderToBytes(
    _In_ ULONG addressHostOrder,
    _Out_writes_(4) UCHAR addressBytes[4]
    )
/*++

Routine Description:

    Convert WFP FWP_UINT32 IPv4 address to a stable network-order byte array. Note: WFP's FWP_UINT32
    addresses are host-order, while shared/driver event rows use byte-order compatible with InetNtop.

Arguments:

    AddressHostOrder - Host-order IPv4 value provided by WFP.
    AddressBytes - receives 4 network-order address bytes.

Return Value:

    None. This function has no return value.

--*/
{
    // Note: Null output pointers must not enter the classify hot path for writing.
    if (addressBytes == NULL) {
        // Note: Return immediately if no target buffer is provided.
        return;
    }

    // Note: Most significant byte corresponds to the first segment of IPv4.
    addressBytes[0] = (UCHAR)((addressHostOrder >> 24U) & 0xFFUL);
    // Note: The second-highest significant byte corresponds to the second segment of the IPv4 address.
    addressBytes[1] = (UCHAR)((addressHostOrder >> 16U) & 0xFFUL);
    // Note: The third valid byte corresponds to the third octet of the IPv4 address.
    addressBytes[2] = (UCHAR)((addressHostOrder >> 8U) & 0xFFUL);
    // Note: The least significant byte corresponds to the fourth octet of the IPv4 address.
    addressBytes[3] = (UCHAR)(addressHostOrder & 0xFFUL);
}

VOID
kswordArkNetworkRecordWfpAleEvent(
    _In_ ULONG direction,
    _In_ ULONG protocol,
    _In_ ULONG localAddressV4HostOrder,
    _In_ ULONG remoteAddressV4HostOrder,
    _In_ USHORT localPort,
    _In_ USHORT remotePort,
    _In_ ULONG processId,
    _In_ ULONG flags
    )
/*++

Routine Description:

    Record real WFP ALE IPv4 flow authorization events in the fixed non-paged ring. Note: This function uses
    only KSPIN_LOCK, allowing classify to be called at DISPATCH_LEVEL; events explicitly exclude packet payload.

Arguments:

    Direction - inbound or outbound direction.
    Protocol - IP protocol number.
    LocalAddressV4HostOrder: Local IPv4 host-order value.
    RemoteAddressV4HostOrder - Remote IPv4 value in host byte order.
    LocalPort - Local port in host byte order.
    RemotePort - Host-order remote port.
    ProcessId - WFP metadata PID; 0 if unknown.
    Flags: ALE layer, block, and action-write status flags.

Return Value:

    None. This function has no return value.

--*/
{
    // Note: The runtime object resides in driver static non-paged storage.
    KswordArkNetworkRuntime* runtime = kswordArkNetworkGetRuntime();
    // Note: Fully construct the event on the stack first to minimize spinlock hold time.
    KSWORD_ARK_NETWORK_WFP_EVENT_ROW eventRow = { 0 };
    // Note: Save the 1601 UTC 100ns time returned by KeQuerySystemTime.
    LARGE_INTEGER systemTime = { 0 };
    // Note: Save the IRQL prior to acquiring the event spinlock.
    KIRQL oldIrql = PASSIVE_LEVEL;
    // Note: Save the ring slot for this write.
    ULONG writeIndex = 0UL;

    // Note: Defensive check for the static runtime pointer.
    if (runtime == NULL) {
        // Note: Skip this diagnostic event if the runtime is unavailable; this does not affect WFP judgment.
        return;
    }

    // Note: Read system UTC time; this kernel routine is callable at classify IRQL.
    KeQuerySystemTime(&systemTime);
    // Note: Write event protocol version for R3 to independently verify per-row ABI.
    eventRow.version = KSWORD_ARK_NETWORK_WFP_EVENT_PROTOCOL_VERSION;
    // Note: Write the current event row size to support future protocol tail extensions.
    eventRow.size = sizeof(eventRow);
    // Note: Sequence numbers must be allocated within the lock; keep as 0 here.
    eventRow.sequence = 0ULL;
    // Note: Save time in 100ns units since 1601 UTC.
    eventRow.timestamp100ns = (ULONG64)systemTime.QuadPart;
    // Note: Save the direction inferred from connect/recv-accept.
    eventRow.direction = direction;
    // Note: Save WFP FWP_UINT8 protocol number.
    eventRow.protocol = protocol;
    // Note: Save the WFP metadata process ID.
    eventRow.processId = processId;
    // Note: Explicitly declare no payload and IPv4; the caller supplies ALE/action flags.
    eventRow.flags = flags |
        KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_NO_PAYLOAD |
        KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_IPV4;
    // Note: Save the host-order local port.
    eventRow.localPort = localPort;
    // Note: Save the host-order remote port.
    eventRow.remotePort = remotePort;
    // Note: Convert local host-order IPv4 to network-order byte array.
    kswordArkNetworkIpv4HostOrderToBytes(localAddressV4HostOrder, eventRow.localAddress);
    // Note: Convert remote host-order IPv4 to network-order byte array.
    kswordArkNetworkIpv4HostOrderToBytes(remoteAddressV4HostOrder, eventRow.remoteAddress);

    // Note: Spin lock covers sequence assignment, count overwrite, and single-slot complete write.
    KeAcquireSpinLock(&runtime->eventLock, &oldIrql);
    // Note: Read the next write slot.
    writeIndex = runtime->eventWriteIndex;
    // Note: Allocate strictly increasing sequence number within the lock.
    eventRow.sequence = runtime->nextEventSequence;
    // Note: Advance to the next sequence number; 64-bit wraparound is unreachable during a realistic lifetime.
    runtime->nextEventSequence += 1ULL;
    // Note: Fully copy initialized events so the reader side never observes a partially written row.
    RtlCopyMemory(&runtime->eventRing[writeIndex], &eventRow, sizeof(eventRow));
    // Note: Advance the write pointer and wrap around at the fixed capacity.
    runtime->eventWriteIndex = (writeIndex + 1UL) % KSWORD_ARK_NETWORK_EVENT_RING_CAPACITY;
    // Note: Increment valid row count when not full.
    if (runtime->eventCount < KSWORD_ARK_NETWORK_EVENT_RING_CAPACITY) {
        // Note: The new event occupies a previously unused slot.
        runtime->eventCount += 1UL;
    }
    else {
        // Note: When full, overwrite the oldest row and accumulate dropped counts.
        runtime->droppedEventCount += 1ULL;
    }
    // Note: Restore IRQL after updating the event row and all ring metadata.
    KeReleaseSpinLock(&runtime->eventLock, oldIrql);
}

NTSTATUS
kswordArkNetworkQueryWfpEvents(
    _In_ const KSWORD_ARK_NETWORK_WFP_EVENT_QUERY_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Read the fixed WFP ALE event ring incrementally based on afterSequence. Note: Results are ordered from
    old to new by sequence, and report cumulative dropped coverage and the current cursor gap separately.

Arguments:

    Request: the query request already copied to local storage by the METHOD_BUFFERED handler.
    OutputBuffer: METHOD_BUFFERED output buffer.
    OutputBufferLength - Actual length of the output buffer.
    BytesWrittenOut - Bytes written returned.

Return Value:

    STATUS_SUCCESS indicates a versioned response has been formed; failure is returned if parameters or output buffers are invalid.

--*/
{
    // Note: Event response header does not include placeholder entries[1].
    const size_t kResponseHeaderSize =
        sizeof(KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE) -
        sizeof(KSWORD_ARK_NETWORK_WFP_EVENT_ROW);
    // Note: The runtime object holds a fixed non-paged ring.
    KswordArkNetworkRuntime* runtime = kswordArkNetworkGetRuntime();
    // Note: The output buffer is interpreted as a response after basic validation.
    KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE* response = NULL;
    // Note: Request normalized results for maxRows.
    ULONG maxRows = 0UL;
    // Note: Number of events the output buffer can hold.
    ULONG outputRowCapacity = 0UL;
    // Note: Store the division result in size_t first to avoid wraparound when narrowing to ULONG for large buffers.
    size_t outputRowCapacitySize = 0U;
    // Note: A snapshot of the current number of valid rows in the ring.
    ULONG eventCount = 0UL;
    // Note: The current index of the oldest slot in the ring.
    ULONG oldestIndex = 0UL;
    // Note: Iterate over the logical offset of valid events.
    ULONG scanIndex = 0UL;
    // Note: The number of rows available in this batch, which may not be fully returned due to maxRows.
    ULONG availableCount = 0UL;
    // Note: The number of rows actually copied to the response this time.
    ULONG returnedCount = 0UL;
    // Note: Handle the effective afterSequence after the driver reload cursor.
    ULONG64 effectiveAfterSequence = 0ULL;
    // Note: Save the IRQL prior to acquiring the event spinlock.
    KIRQL oldIrql = PASSIVE_LEVEL;

    // Note: All required parameters must exist.
    if (request == NULL || outputBuffer == NULL || bytesWrittenOut == NULL || runtime == NULL) {
        // Note: Null parameters cannot form a secure response.
        return STATUS_INVALID_PARAMETER;
    }
    // Note: By default, there are no response bytes; the failure path keeps the value at 0.
    *bytesWrittenOut = 0U;
    // Note: Output must at least accommodate the response header without placeholder rows.
    if (outputBufferLength < kResponseHeaderSize) {
        // Note: Let WDF return a clear buffer too small status.
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Note: Only clear the response header; each returned event line will be fully overwritten, avoiding a 4MB buffer zero-fill.
    RtlZeroMemory(outputBuffer, kResponseHeaderSize);
    // Bind versioned response header.
    response = (KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE*)outputBuffer;
    // Note: The response always reports the event sub-protocol version.
    response->version = KSWORD_ARK_NETWORK_WFP_EVENT_PROTOCOL_VERSION;
    // Note: The response row size is the current stable event ABI.
    response->entrySize = sizeof(KSWORD_ARK_NETWORK_WFP_EVENT_ROW);
    // Note: Expose the driver's fixed ring capacity to R3.
    response->capacity = KSWORD_ARK_NETWORK_EVENT_RING_CAPACITY;
    // Note: Return a clear capability status when the WFP filter is not started.
    response->status =
        ((runtime->runtimeFlags & KSWORD_ARK_NETWORK_RUNTIME_WFP_STARTED) != 0UL) ?
        KSWORD_ARK_NETWORK_STATUS_APPLIED :
        KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE;
    // Note: Return the full callout/filter registration result when WFP is unavailable.
    response->lastStatus =
        (response->status == KSWORD_ARK_NETWORK_STATUS_APPLIED) ?
        STATUS_SUCCESS :
        runtime->registerStatus;

    // Note: v1 uses a precise, fixed request header; rejects unknown versions, trailing extensions, reserved bits, and query flags.
    if (request->version != KSWORD_ARK_NETWORK_WFP_EVENT_PROTOCOL_VERSION ||
        request->size != sizeof(*request) ||
        request->flags != KSWORD_ARK_NETWORK_WFP_EVENT_QUERY_FLAG_NONE ||
        request->reserved != 0ULL) {
        // Note: Protocol errors are expressed via a fixed response to allow R3 to distinguish transport failures.
        response->status = KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED;
        // Note: Records stable revision/parameter errors.
        response->lastStatus =
            (request->version != KSWORD_ARK_NETWORK_WFP_EVENT_PROTOCOL_VERSION) ?
            STATUS_REVISION_MISMATCH :
            STATUS_INVALID_PARAMETER;
        // Note: Error responses contain only the header.
        response->size = (ULONG)kResponseHeaderSize;
        // Note: Report the error response header length.
        *bytesWrittenOut = kResponseHeaderSize;
        // Note: METHOD_BUFFERED transfer itself succeeded.
        return STATUS_SUCCESS;
    }

    // Note: maxRows=0 uses a conservative default budget.
    maxRows = request->maxRows == 0UL ?
        KSWORD_ARK_NETWORK_WFP_EVENT_DEFAULT_REQUESTED_ROWS :
        request->maxRows;
    // Note: Limit the amount copied while holding the lock.
    if (maxRows > KSWORD_ARK_NETWORK_WFP_EVENT_MAX_REQUESTED_ROWS) {
        // Note: Clamp oversized requests to the stable protocol limit.
        maxRows = KSWORD_ARK_NETWORK_WFP_EVENT_MAX_REQUESTED_ROWS;
    }
    // Note: Calculate capacity via division to avoid size_t multiplication/addition overflow.
    outputRowCapacitySize = (outputBufferLength - kResponseHeaderSize) /
        sizeof(KSWORD_ARK_NETWORK_WFP_EVENT_ROW);
    // Note: Output capacity must not exceed caller's budget.
    if (outputRowCapacitySize > (size_t)maxRows) {
        // Note: Narrow to maxRows.
        outputRowCapacitySize = (size_t)maxRows;
    }
    // Note: maxRows is already below the ULONG limit; narrowing here is safe.
    outputRowCapacity = (ULONG)outputRowCapacitySize;
    // Note: Default to the request cursor; update to the last row's sequence if rows are returned.
    response->nextSequence = request->afterSequence;
    // Note: Prepare to read a consistent ring snapshot within the event spinlock.
    effectiveAfterSequence = request->afterSequence;

    // Note: The read side and classify write side share a spinlock, allowing concurrent CPU-safe snapshots.
    KeAcquireSpinLock(&runtime->eventLock, &oldIrql);
    // Note: Capture the current valid row count.
    eventCount = runtime->eventCount;
    // Note: Capture cumulative overwrite count.
    response->droppedEventCount = runtime->droppedEventCount;
    // Note: An empty ring has no oldest/newest index.
    if (eventCount != 0UL) {
        // Note: The write pointer points to the next slot; subtracting eventCount yields the oldest slot.
        oldestIndex =
            (runtime->eventWriteIndex +
                KSWORD_ARK_NETWORK_EVENT_RING_CAPACITY -
                eventCount) %
            KSWORD_ARK_NETWORK_EVENT_RING_CAPACITY;
        // Note: Report the oldest sequence number in the currently recoverable window.
        response->oldestSequence = runtime->eventRing[oldestIndex].sequence;
        // Note: The last written slot is located one position before the write pointer.
        response->newestSequence =
            runtime->eventRing[
                (runtime->eventWriteIndex +
                    KSWORD_ARK_NETWORK_EVENT_RING_CAPACITY -
                    1UL) %
                KSWORD_ARK_NETWORK_EVENT_RING_CAPACITY].sequence;

        // Note: After driver reload, the R3 cursor may exceed the new ring's latest sequence.
        if (effectiveAfterSequence > response->newestSequence) {
            // Note: Mark the cursor as reset to prevent R3 from waiting indefinitely for new events.
            response->flags |= KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_CURSOR_RESET;
            // Note: After reset, re-read from the oldest row in the current ring.
            effectiveAfterSequence = 0ULL;
            // Note: Reset response cursor, then advanced by returned rows.
            response->nextSequence = 0ULL;
        }

        // Note: Precisely report an unrecoverable gap when afterSequence falls behind the reserved window.
        if (effectiveAfterSequence < response->oldestSequence &&
            (response->oldestSequence - effectiveAfterSequence) > 1ULL) {
            // Mark cursor gap.
            response->flags |= KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_CURSOR_GAP;
            // Note: Calculates the number of sequence numbers overwritten between after and oldest.
            response->cursorGapCount =
                response->oldestSequence -
                effectiveAfterSequence -
                1ULL;
        }

        // Note: Scan in ring logical order to ensure the response sequence strictly increments.
        for (scanIndex = 0UL; scanIndex < eventCount; ++scanIndex) {
            // Note: Map logical offset to physical slot.
            const ULONG kRingIndex =
                (oldestIndex + scanIndex) %
                KSWORD_ARK_NETWORK_EVENT_RING_CAPACITY;
            // Note: Read stable event row under lock protection.
            const KSWORD_ARK_NETWORK_WFP_EVENT_ROW* eventRow =
                &runtime->eventRing[kRingIndex];

            // Note: Skip events already consumed by the cursor.
            if (eventRow->sequence <= effectiveAfterSequence) {
                // Note: Continue scanning subsequent larger sequence numbers.
                continue;
            }

            // Note: Count all available events after the cursor, even if the output budget is insufficient.
            availableCount += 1UL;
            // Note: Copy only the first maxRows rows allowed by the output capacity.
            if (returnedCount < outputRowCapacity) {
                // Note: Fully copy stable event ABI to avoid leaking uninitialized padding.
                RtlCopyMemory(
                    &response->entries[returnedCount],
                    eventRow,
                    sizeof(*eventRow));
                // Note: Advance the response cursor to the last actually returned sequence number.
                response->nextSequence = eventRow->sequence;
                // Note: Increment returned row count.
                returnedCount += 1UL;
            }
        }
    }
    // Note: ring snapshot read and response row copy complete; restore caller IRQL.
    KeReleaseSpinLock(&runtime->eventLock, oldIrql);

    // Note: Record the total number of available rows after recording the cursor.
    response->availableEventCount = availableCount;
    // Note: Record the actual number of rows written.
    response->returnedEventCount = returnedCount;
    // Note: Mark as truncated when events remain unreturned; resume reading from nextSequence in the next round.
    if (availableCount > returnedCount) {
        // Note: Response has subsequent pages.
        response->flags |= KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_TRUNCATED;
    }
    // Note: The multiplication upper bound is guaranteed by the division calculation of outputRowCapacity.
    response->size = (ULONG)(kResponseHeaderSize +
        ((size_t)returnedCount * sizeof(KSWORD_ARK_NETWORK_WFP_EVENT_ROW)));
    // Note: Report the exact response byte count.
    *bytesWrittenOut = (size_t)response->size;
    // Note: Versioned response has been formed.
    return STATUS_SUCCESS;
}

VOID
kswordArkNetworkLogFormat(
    _In_z_ PCSTR levelText,
    _In_z_ _Printf_format_string_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Write to the network module log. Note: The WFP classify hot path only records rule switches
    and exceptions to avoid log channel congestion caused by high-frequency network packets.

Arguments:

    levelText - Log level.
    FormatText - printf-style format string.
    ... - Format arguments.

Return Value:

    None. This function has no return value.

--*/
{
    KswordArkNetworkRuntime* runtime = kswordArkNetworkGetRuntime();
    CHAR logBuffer[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    if (runtime == NULL || runtime->device == WDF_NO_HANDLE || formatText == NULL) {
        return;
    }

    va_start(arguments, formatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logBuffer, sizeof(logBuffer), formatText, arguments))) {
        (VOID)kswordArkDriverEnqueueLogFrame(
            runtime->device,
            levelText != NULL ? levelText : "Info",
            logBuffer);
    }
    va_end(arguments);
}

BOOLEAN
kswordArkNetworkRuleMatchesLocked(
    _In_ const KSWORD_ARK_NETWORK_RULE* rule,
    _In_ ULONG direction,
    _In_ ULONG protocol,
    _In_ USHORT localPort,
    _In_ USHORT remotePort,
    _In_ ULONG processId
    )
/*++

Routine Description:

    Check if the network five-tuple summary matches a rule. Note: Port 0 indicates a
    wildcard, protocol ANY indicates a wildcard, and processId 0 indicates all processes.

Arguments:

    Rule - Rule snapshot item.
    Direction - Current direction mask.
    Protocol - IPPROTO_* protocol number.
    LocalPort - Local port.
    RemotePort: Remote port.
    ProcessId - Process ID, 0 if unknown.

Return Value:

    TRUE indicates a match; FALSE indicates no match.

--*/
{
    if (rule == NULL || (rule->flags & KSWORD_ARK_NETWORK_RULE_FLAG_ENABLED) == 0UL) {
        return FALSE;
    }
    if ((rule->directionMask & direction) == 0UL) {
        return FALSE;
    }
    if (rule->protocol != KSWORD_ARK_NETWORK_PROTOCOL_ANY && rule->protocol != protocol) {
        return FALSE;
    }
    if (rule->processId != 0UL && rule->processId != processId) {
        return FALSE;
    }
    if (rule->localPort != 0U && rule->localPort != localPort) {
        return FALSE;
    }
    if (rule->remotePort != 0U && rule->remotePort != remotePort) {
        return FALSE;
    }

    return TRUE;
}

static NTSTATUS
kswordArkNetworkValidateRule(
    _In_ const KSWORD_ARK_NETWORK_RULE* rule
    )
/*++

Routine Description:

    Validate a single network rule. Note: Only allow/block/hide-port are accepted;
    direction must include inbound or outbound; protocol must be ANY/TCP/UDP.

Arguments:

    Rule - Rule to validate.

Return Value:

    STATUS_SUCCESS indicates the rule is usable; a failure status indicates the rule should be rejected.

--*/
{
    if (rule == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((rule->flags & KSWORD_ARK_NETWORK_RULE_FLAG_ENABLED) == 0UL) {
        return STATUS_SUCCESS;
    }
    if (rule->action != KSWORD_ARK_NETWORK_RULE_ACTION_ALLOW &&
        rule->action != KSWORD_ARK_NETWORK_RULE_ACTION_BLOCK &&
        rule->action != KSWORD_ARK_NETWORK_RULE_ACTION_HIDE_PORT) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((rule->directionMask & KSWORD_ARK_NETWORK_DIRECTION_BOTH) == 0UL ||
        (rule->directionMask & ~KSWORD_ARK_NETWORK_DIRECTION_BOTH) != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (rule->protocol != KSWORD_ARK_NETWORK_PROTOCOL_ANY &&
        rule->protocol != KSWORD_ARK_NETWORK_PROTOCOL_TCP &&
        rule->protocol != KSWORD_ARK_NETWORK_PROTOCOL_UDP) {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

static VOID
kswordArkNetworkRefreshCountersLocked(
    _Inout_ KswordArkNetworkRuntime* runtime
    )
/*++

Routine Description:

    Refresh rule count and runtime flags. Note: WFP registration status is preserved;
    rule active status is automatically calculated based on the current snapshot.

Arguments:

    Runtime: Network runtime.

Return Value:

    None. This function has no return value.

--*/
{
    ULONG ruleIndex = 0UL;
    ULONG registeredFlags = 0UL;

    if (runtime == NULL) {
        return;
    }

    registeredFlags = runtime->runtimeFlags &
        (KSWORD_ARK_NETWORK_RUNTIME_WFP_REGISTERED |
            KSWORD_ARK_NETWORK_RUNTIME_WFP_STARTED |
            KSWORD_ARK_NETWORK_RUNTIME_PACKET_CAPTURE_STARTED);
    runtime->runtimeFlags = registeredFlags;
    runtime->ruleCount = 0UL;
    runtime->blockedRuleCount = 0UL;
    runtime->hiddenPortRuleCount = 0UL;

    for (ruleIndex = 0UL; ruleIndex < KSWORD_ARK_NETWORK_MAX_RULES; ++ruleIndex) {
        const KSWORD_ARK_NETWORK_RULE* rule = &runtime->rules[ruleIndex];
        if ((rule->flags & KSWORD_ARK_NETWORK_RULE_FLAG_ENABLED) == 0UL) {
            continue;
        }
        runtime->ruleCount += 1UL;
        if (rule->action == KSWORD_ARK_NETWORK_RULE_ACTION_BLOCK) {
            runtime->blockedRuleCount += 1UL;
        }
        if (rule->action == KSWORD_ARK_NETWORK_RULE_ACTION_HIDE_PORT) {
            runtime->hiddenPortRuleCount += 1UL;
        }
    }

    if (runtime->ruleCount != 0UL) {
        runtime->runtimeFlags |= KSWORD_ARK_NETWORK_RUNTIME_RULES_ACTIVE;
    }
    if (runtime->hiddenPortRuleCount != 0UL) {
        runtime->runtimeFlags |= KSWORD_ARK_NETWORK_RUNTIME_PORT_HIDE;
    }
}

static VOID
kswordArkNetworkPublishClassifyRulesLocked(
    _Inout_ KswordArkNetworkRuntime* runtime
    )
/*++

Routine Description:

    Publish low-frequency rule state as an independent snapshot readable at DISPATCH_LEVEL. Note: Caller holds the lock.
    Runtime->Lock; this function copies a fixed 32-item rule set only within a brief spin-lock critical section.

Arguments:

    Runtime: Network runtime.

Return Value:

    None. This function has no return value.

--*/
{
    KIRQL oldIrql = PASSIVE_LEVEL;

    if (runtime == NULL) {
        return;
    }

    KeAcquireSpinLock(&runtime->classifyRuleLock, &oldIrql);
    RtlCopyMemory(
        runtime->classifyRules,
        runtime->rules,
        sizeof(runtime->classifyRules));
    InterlockedExchange(
        &runtime->classifyRulesActive,
        runtime->blockedRuleCount != 0UL ? 1L : 0L);
    KeReleaseSpinLock(&runtime->classifyRuleLock, oldIrql);
}

NTSTATUS
kswordArkNetworkInitialize(
    _In_ PDRIVER_OBJECT driverObject,
    _In_opt_ WDFDEVICE device
    )
/*++

Routine Description:

    initialize network runtime and register WFP callout. Note: WFP registration failure should not
    block the driver's main functionality, so the caller may log a warning and continue loading.

Arguments:

    DriverObject.
    Device: WDF control device, used for logging.

Return Value:

    STATUS_SUCCESS or a WFP registration failure status.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(&gKswordArkNetworkRuntime, sizeof(gKswordArkNetworkRuntime));
    ExInitializePushLock(&gKswordArkNetworkRuntime.lock);
    // Note: WFP classify rule snapshots must support read access at DISPATCH_LEVEL.
    KeInitializeSpinLock(&gKswordArkNetworkRuntime.classifyRuleLock);
    // Note: The event ring uses an independent spinlock at DISPATCH_LEVEL, which is reachable by classify.
    KeInitializeSpinLock(&gKswordArkNetworkRuntime.eventLock);
    // Note: IP packets use an independent spinlock for per-packet ring buffering to prevent ALE rule events from blocking each other.
    KeInitializeSpinLock(&gKswordArkNetworkRuntime.trafficLock);
    // Note: Event sequence starts at 1; 0 is reserved for 'no cursor'.
    gKswordArkNetworkRuntime.nextEventSequence = 1ULL;
    // Note: Per-packet sequence numbers also start from 1; 0 indicates the cursor is not established.
    gKswordArkNetworkRuntime.nextTrafficSequence = 1ULL;
    gKswordArkNetworkRuntime.device = device;
    gKswordArkNetworkRuntime.driverObject = driverObject;
    if (device != WDF_NO_HANDLE) {
        gKswordArkNetworkRuntime.deviceObject = WdfDeviceWdmGetDeviceObject(device);
    }
    gKswordArkNetworkRuntime.registerStatus = STATUS_NOT_SUPPORTED;
    gKswordArkNetworkRuntime.engineStatus = STATUS_NOT_SUPPORTED;
    // Note: Return explicit NOT_SUPPORTED status before packet objects are registered.
    gKswordArkNetworkRuntime.trafficCaptureStatus = STATUS_NOT_SUPPORTED;
    // Note: Per-packet filters are resident but do not copy packets by default; explicit enablement by R3 is required.
    InterlockedExchange(
        &gKswordArkNetworkRuntime.trafficCaptureEnabled,
        0L);

    status = kswordArkNetworkWfpRegister(&gKswordArkNetworkRuntime);
    gKswordArkNetworkRuntime.registerStatus = status;
    if (NT_SUCCESS(status)) {
        gKswordArkNetworkRuntime.runtimeFlags |= KSWORD_ARK_NETWORK_RUNTIME_WFP_REGISTERED;
        kswordArkNetworkLogFormat("Info", "Network WFP callouts registered.");
        return STATUS_SUCCESS;
    }

    kswordArkNetworkLogFormat(
        "Warn",
        "Network WFP callout registration failed, status=0x%08X.",
        (unsigned int)status);
    return status;
}

VOID
kswordArkNetworkUninitialize(
    VOID
    )
/*++

Routine Description:

    Clean up the network runtime. Note: Clear rules first, then unregister WFP callouts
    and filters to prevent classify from referencing the rule table after unloading.

Arguments:

    None.

Return Value:

    None. This function has no return value.

--*/
{
    KswordArkNetworkRuntime* runtime = kswordArkNetworkGetRuntime();

    if (runtime == NULL) {
        return;
    }

    InterlockedExchange(&runtime->trafficCaptureEnabled, 0L);

    kswordArkAcquirePushLockExclusive(&runtime->lock);
    RtlZeroMemory(runtime->rules, sizeof(runtime->rules));
    runtime->ruleCount = 0UL;
    runtime->blockedRuleCount = 0UL;
    runtime->hiddenPortRuleCount = 0UL;
    runtime->runtimeFlags &=
        (KSWORD_ARK_NETWORK_RUNTIME_WFP_REGISTERED |
            KSWORD_ARK_NETWORK_RUNTIME_WFP_STARTED |
            KSWORD_ARK_NETWORK_RUNTIME_PACKET_CAPTURE_STARTED);
    runtime->generation += 1UL;
    kswordArkNetworkPublishClassifyRulesLocked(runtime);
    kswordArkReleasePushLockExclusive(&runtime->lock);

    kswordArkNetworkWfpUnregister(runtime);
    runtime->runtimeFlags = 0UL;
    runtime->registerStatus = STATUS_NOT_SUPPORTED;
    runtime->engineStatus = STATUS_NOT_SUPPORTED;
    runtime->trafficCaptureStatus = STATUS_NOT_SUPPORTED;
}

NTSTATUS
kswordArkNetworkControlTrafficCapture(
    _In_ const KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_REQUEST* request,
    _Out_ KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_RESPONSE* response
    )
/*++

Routine Description:

    Explicitly start/stop WFP IP packet per-packet copying. The filter/callout remains registered; in the
    disabled state, classify returns immediately, so no parsing or ring filling occurs after the UI is stopped.

--*/
{
    KswordArkNetworkRuntime* runtime = kswordArkNetworkGetRuntime();
    KIRQL oldIrql = PASSIVE_LEVEL;
    BOOLEAN enable = FALSE;

    if (request == NULL || response == NULL || runtime == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_NETWORK_TRAFFIC_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    if (request->version != KSWORD_ARK_NETWORK_TRAFFIC_PROTOCOL_VERSION ||
        request->size != sizeof(*request) ||
        request->flags != KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_FLAG_NONE ||
        (request->action != KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_DISABLE &&
            request->action != KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_ENABLE)) {
        response->status = KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    enable = request->action == KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_ENABLE;
    if (enable &&
        (runtime->runtimeFlags &
            KSWORD_ARK_NETWORK_RUNTIME_PACKET_CAPTURE_STARTED) == 0UL) {
        response->status = KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE;
        response->lastStatus = runtime->trafficCaptureStatus;
        response->generation = (ULONG)InterlockedCompareExchange(
            &runtime->trafficCaptureGeneration,
            0L,
            0L);
        return STATUS_SUCCESS;
    }

    // Note: Disable the data plane first, then wait for writers that have passed the classify fast path to exit the lock.
    InterlockedExchange(&runtime->trafficCaptureEnabled, 0L);
    KeAcquireSpinLock(&runtime->trafficLock, &oldIrql);
    runtime->trafficWriteIndex = 0UL;
    runtime->trafficCount = 0UL;
    runtime->nextTrafficSequence = 1ULL;
    runtime->droppedTrafficCount = 0ULL;
    response->generation = (ULONG)InterlockedIncrement(
        &runtime->trafficCaptureGeneration);
    KeReleaseSpinLock(&runtime->trafficLock, oldIrql);

    if (enable) {
        InterlockedExchange(&runtime->trafficCaptureEnabled, 1L);
    }
    response->enabled = enable ? 1UL : 0UL;
    response->status = enable
        ? KSWORD_ARK_NETWORK_STATUS_APPLIED
        : KSWORD_ARK_NETWORK_STATUS_DISABLED;
    response->lastStatus = STATUS_SUCCESS;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkNetworkSetRules(
    _In_ const KSWORD_ARK_NETWORK_SET_RULES_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Replace the network filtering rule snapshot. Note: The rule snapshot is replaced only once after a
    complete validation succeeds to prevent the classify path from observing partially updated content.

Arguments:

    Request: R3 rule request.
    OutputBuffer - Response buffer.
    OutputBufferLength - Response buffer length.
    BytesWrittenOut - Bytes written returned.

Return Value:

    STATUS_SUCCESS indicates the response has been written; buffer errors return failure directly.

--*/
{
    KswordArkNetworkRuntime* runtime = kswordArkNetworkGetRuntime();
    KSWORD_ARK_NETWORK_SET_RULES_RESPONSE* response = NULL;
    KSWORD_ARK_NETWORK_RULE newRules[KSWORD_ARK_NETWORK_MAX_RULES] = { 0 };
    ULONG ruleIndex = 0UL;
    ULONG appliedCount = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (request == NULL || outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(*response)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_NETWORK_SET_RULES_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_NETWORK_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_NETWORK_STATUS_UNKNOWN;
    response->rejectedIndex = 0xFFFFFFFFUL;
    response->lastStatus = STATUS_SUCCESS;
    *bytesWrittenOut = sizeof(*response);

    if (request->version != KSWORD_ARK_NETWORK_PROTOCOL_VERSION) {
        response->status = KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        return STATUS_SUCCESS;
    }

    if (request->action == KSWORD_ARK_NETWORK_ACTION_REPLACE) {
        if (request->ruleCount > KSWORD_ARK_NETWORK_MAX_RULES) {
            response->status = KSWORD_ARK_NETWORK_STATUS_INVALID_RULE;
            response->lastStatus = STATUS_INVALID_PARAMETER;
            return STATUS_SUCCESS;
        }

        for (ruleIndex = 0UL; ruleIndex < request->ruleCount; ++ruleIndex) {
            status = kswordArkNetworkValidateRule(&request->rules[ruleIndex]);
            if (!NT_SUCCESS(status)) {
                response->status = KSWORD_ARK_NETWORK_STATUS_INVALID_RULE;
                response->rejectedIndex = ruleIndex;
                response->lastStatus = status;
                return STATUS_SUCCESS;
            }
            RtlCopyMemory(&newRules[ruleIndex], &request->rules[ruleIndex], sizeof(newRules[ruleIndex]));
            if ((newRules[ruleIndex].flags & KSWORD_ARK_NETWORK_RULE_FLAG_ENABLED) != 0UL) {
                appliedCount += 1UL;
            }
        }
    }
    else if (request->action != KSWORD_ARK_NETWORK_ACTION_CLEAR &&
        request->action != KSWORD_ARK_NETWORK_ACTION_DISABLE) {
        response->status = KSWORD_ARK_NETWORK_STATUS_INVALID_RULE;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    kswordArkAcquirePushLockExclusive(&runtime->lock);
    RtlZeroMemory(runtime->rules, sizeof(runtime->rules));
    if (request->action == KSWORD_ARK_NETWORK_ACTION_REPLACE && appliedCount != 0UL) {
        RtlCopyMemory(runtime->rules, newRules, sizeof(newRules));
    }
    runtime->generation += 1UL;
    kswordArkNetworkRefreshCountersLocked(runtime);
    kswordArkNetworkPublishClassifyRulesLocked(runtime);
    response->runtimeFlags = runtime->runtimeFlags;
    response->appliedCount = runtime->ruleCount;
    response->blockedRuleCount = runtime->blockedRuleCount;
    response->hiddenPortRuleCount = runtime->hiddenPortRuleCount;
    response->generation = runtime->generation;
    kswordArkReleasePushLockExclusive(&runtime->lock);

    if (request->action == KSWORD_ARK_NETWORK_ACTION_REPLACE) {
        response->status = NT_SUCCESS(runtime->registerStatus) ?
            KSWORD_ARK_NETWORK_STATUS_APPLIED :
            KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE;
        response->lastStatus = runtime->registerStatus;
    }
    else if (request->action == KSWORD_ARK_NETWORK_ACTION_DISABLE) {
        response->status = KSWORD_ARK_NETWORK_STATUS_DISABLED;
        response->lastStatus = STATUS_SUCCESS;
    }
    else {
        response->status = KSWORD_ARK_NETWORK_STATUS_CLEARED;
        response->lastStatus = STATUS_SUCCESS;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkNetworkQueryStatus(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Query the network filtering runtime. Note: Returns WFP registration status, rule snapshots,
    block counts, and the number of port-hiding rules; R3 can use this to filter port table display.

Arguments:

    OutputBuffer - Response buffer.
    OutputBufferLength - Response buffer length.
    BytesWrittenOut - Bytes written returned.

Return Value:

    STATUS_SUCCESS or buffer error.

--*/
{
    KswordArkNetworkRuntime* runtime = kswordArkNetworkGetRuntime();
    KSWORD_ARK_NETWORK_STATUS_RESPONSE* response = NULL;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(*response)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_NETWORK_STATUS_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_NETWORK_PROTOCOL_VERSION;
    response->status = NT_SUCCESS(runtime->registerStatus) ?
        KSWORD_ARK_NETWORK_STATUS_APPLIED :
        KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE;

    kswordArkAcquirePushLockShared(&runtime->lock);
    response->runtimeFlags = runtime->runtimeFlags;
    response->ruleCount = runtime->ruleCount;
    response->blockedRuleCount = runtime->blockedRuleCount;
    response->hiddenPortRuleCount = runtime->hiddenPortRuleCount;
    response->generation = runtime->generation;
    response->classifyCount = (ULONG64)runtime->classifyCount;
    response->blockedCount = (ULONG64)runtime->blockedCount;
    response->registerStatus = runtime->registerStatus;
    response->engineStatus = runtime->engineStatus;
    RtlCopyMemory(response->rules, runtime->rules, sizeof(response->rules));
    kswordArkReleasePushLockShared(&runtime->lock);

    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}

BOOLEAN
kswordArkNetworkShouldHidePort(
    _In_ ULONG protocol,
    _In_ USHORT localPort,
    _In_ USHORT remotePort,
    _In_ ULONG processId
    )
/*++

Routine Description:

    Determines whether a port should be hidden from R3/R0 query results. Note: The current repository lacks an R0 TCP table
    enumeration module; this function provides a reusable policy entry point, and port list queries will take effect once integrated.

Arguments:

    Protocol - TCP/UDP protocol number.
    LocalPort - Local port.
    RemotePort: Remote port.
    ProcessId - Process ID.

Return Value:

    TRUE indicates the port should be hidden; FALSE indicates normal display.

--*/
{
    KswordArkNetworkRuntime* runtime = kswordArkNetworkGetRuntime();
    ULONG ruleIndex = 0UL;
    BOOLEAN shouldHide = FALSE;

    if ((runtime->runtimeFlags & KSWORD_ARK_NETWORK_RUNTIME_PORT_HIDE) == 0UL) {
        return FALSE;
    }

    kswordArkAcquirePushLockShared(&runtime->lock);
    for (ruleIndex = 0UL; ruleIndex < KSWORD_ARK_NETWORK_MAX_RULES; ++ruleIndex) {
        const KSWORD_ARK_NETWORK_RULE* rule = &runtime->rules[ruleIndex];
        if (rule->action != KSWORD_ARK_NETWORK_RULE_ACTION_HIDE_PORT) {
            continue;
        }
        if (kswordArkNetworkRuleMatchesLocked(
            rule,
            KSWORD_ARK_NETWORK_DIRECTION_BOTH,
            protocol,
            localPort,
            remotePort,
            processId)) {
            shouldHide = TRUE;
            break;
        }
    }
    kswordArkReleasePushLockShared(&runtime->lock);

    return shouldHide;
}
