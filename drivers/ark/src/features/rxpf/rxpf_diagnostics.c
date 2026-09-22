/*++

Module Name:

    rxpf_diagnostics.c

Abstract:

    Preallocated per-processor event rings and aggregate RXPF counters.

Environment:

    Event production is safe on the vector-14 path and never allocates.

--*/

#include "rxpf_diagnostics.h"
#include "src/platform/pool_compat.h"

#define KSW_RXPF_DIAGNOSTICS_TAG 'dPxR'

typedef struct KswRxpfDiagnosticsState
{
    PkswRxpfEventRing rings;
    ULONG processorCapacity;
    volatile LONG initialized;
    volatile LONG activeHandlers;
    DECLSPEC_ALIGN(8) volatile LONG64 nextSequence;
    DECLSPEC_ALIGN(8) volatile LONG64 totalFaults;
    DECLSPEC_ALIGN(8) volatile LONG64 managedFaults;
    DECLSPEC_ALIGN(8) volatile LONG64 emulatedInstructions;
    DECLSPEC_ALIGN(8) volatile LONG64 chainedFaults;
    DECLSPEC_ALIGN(8) volatile LONG64 recursiveFaults;
    DECLSPEC_ALIGN(8) volatile LONG64 unsupportedInstructions;
    DECLSPEC_ALIGN(8) volatile LONG64 droppedEvents;
    volatile LONG lastStatus;
} KswRxpfDiagnosticsState;

static KswRxpfDiagnosticsState gKswRxpfDiagnostics;

NTSTATUS
kswRxpfDiagnosticsInitialize(
    _In_ ULONG maximumProcessorCount
    )
{
    SIZE_T allocationBytes = 0U;
    PkswRxpfEventRing rings = NULL;

    /* Repeated initialization is idempotent for DriverEntry rollback paths. */
    if (InterlockedCompareExchange(
            &gKswRxpfDiagnostics.initialized,
            1,
            1) != 0) {
        return STATUS_SUCCESS;
    }
    if (maximumProcessorCount == 0UL ||
        maximumProcessorCount > MAXULONG_PTR /
            sizeof(KswRxpfEventRing)) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Allocate every ring before vector 14 can be replaced. */
    allocationBytes =
        (SIZE_T)maximumProcessorCount * sizeof(KswRxpfEventRing);
    rings = (PkswRxpfEventRing)kswordArkAllocateNonPagedPool(
        allocationBytes,
        KSW_RXPF_DIAGNOSTICS_TAG);
    if (rings == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(rings, allocationBytes);

    /* Publish the complete immutable ring array with zeroed counters. */
    RtlZeroMemory(
        &gKswRxpfDiagnostics,
        sizeof(gKswRxpfDiagnostics));
    gKswRxpfDiagnostics.rings = rings;
    gKswRxpfDiagnostics.processorCapacity = maximumProcessorCount;
    KeMemoryBarrier();
    InterlockedExchange(&gKswRxpfDiagnostics.initialized, 1);
    return STATUS_SUCCESS;
}

VOID
kswRxpfDiagnosticsUninitialize(
    VOID
    )
{
    PkswRxpfEventRing rings = gKswRxpfDiagnostics.rings;

    /* Unpublish producer state before releasing the backing allocation. */
    InterlockedExchange(&gKswRxpfDiagnostics.initialized, 0);
    KeMemoryBarrier();
    RtlZeroMemory(
        &gKswRxpfDiagnostics,
        sizeof(gKswRxpfDiagnostics));
    if (rings != NULL) {
        ExFreePoolWithTag(rings, KSW_RXPF_DIAGNOSTICS_TAG);
    }
}

VOID
kswRxpfDiagnosticsEnterHandler(
    VOID
    )
{
    /* One global reader count protects page resources during removal. */
    InterlockedIncrement(&gKswRxpfDiagnostics.activeHandlers);
    KeMemoryBarrier();
}

VOID
kswRxpfDiagnosticsLeaveHandler(
    VOID
    )
{
    /* Publish all record accesses before leaving the lifecycle read side. */
    KeMemoryBarrier();
    InterlockedDecrement(&gKswRxpfDiagnostics.activeHandlers);
}

LONG
kswRxpfDiagnosticsActiveHandlers(
    VOID
    )
{
    /* Return an atomic snapshot without taking a control-path lock. */
    return InterlockedCompareExchange(
        &gKswRxpfDiagnostics.activeHandlers,
        0,
        0);
}

NTSTATUS
kswRxpfDiagnosticsWaitForHandlers(
    _In_ ULONG timeoutMilliseconds
    )
{
    ULONG waitedMilliseconds = 0UL;
    LARGE_INTEGER interval;

    /* A one-millisecond relative delay bounds normal control-path waiting. */
    interval.QuadPart = -10LL * 1000LL;
    while (kswRxpfDiagnosticsActiveHandlers() != 0) {
        if (waitedMilliseconds >= timeoutMilliseconds) {
            return STATUS_IO_TIMEOUT;
        }
        (void)KeDelayExecutionThread(
            KernelMode,
            FALSE,
            &interval);
        waitedMilliseconds += 1UL;
    }
    return STATUS_SUCCESS;
}

VOID
kswRxpfDiagnosticsRecord(
    _In_ ULONG processorIndex,
    _In_ ULONGLONG cr2,
    _In_ ULONGLONG rip,
    _In_ ULONGLONG errorCode,
    _In_ ULONGLONG recordId,
    _In_ ULONG decodedInstruction,
    _In_ ULONG emulationResult,
    _In_ ULONGLONG newRip,
    _In_ NTSTATUS status
    )
{
    PkswRxpfEventRing ring = NULL;
    PkswRxpfEventSlot slot = NULL;
    LONG head = 0;
    LONG64 sequence = 0;

    /* Drop events rather than touching an absent or out-of-range ring. */
    if (InterlockedCompareExchange(
            &gKswRxpfDiagnostics.initialized,
            1,
            1) == 0 ||
        processorIndex >= gKswRxpfDiagnostics.processorCapacity) {
        InterlockedIncrement64(&gKswRxpfDiagnostics.droppedEvents);
        return;
    }

    /* A processor owns its ring while interrupts are disabled in the stub. */
    ring = &gKswRxpfDiagnostics.rings[processorIndex];
    head = InterlockedIncrement(&ring->head) - 1;
    slot = &ring->slots[((ULONG)head) &
        (KSW_RXPF_EVENT_RING_CAPACITY - 1UL)];
    sequence = InterlockedIncrement64(
        &gKswRxpfDiagnostics.nextSequence);

    /* Zero Sequence while a reader-visible row is being replaced. */
    InterlockedExchange64(&slot->sequence, 0);
    slot->row.sequence = (ULONGLONG)sequence;
    slot->row.timestamp = __rdtsc();
    slot->row.cr2 = cr2;
    slot->row.rip = rip;
    slot->row.errorCode = errorCode;
    slot->row.recordId = recordId;
    slot->row.newRip = newRip;
    slot->row.processorIndex = processorIndex;
    slot->row.decodedInstruction = decodedInstruction;
    slot->row.emulationResult = emulationResult;
    slot->row.status = status;
    KeMemoryBarrier();
    InterlockedExchange64(&slot->sequence, sequence);
}

VOID
kswRxpfDiagnosticsCountTotalFault(
    VOID
    )
{
    InterlockedIncrement64(&gKswRxpfDiagnostics.totalFaults);
}

VOID
kswRxpfDiagnosticsCountManagedFault(
    VOID
    )
{
    InterlockedIncrement64(&gKswRxpfDiagnostics.managedFaults);
}

VOID
kswRxpfDiagnosticsCountEmulatedInstruction(
    VOID
    )
{
    InterlockedIncrement64(
        &gKswRxpfDiagnostics.emulatedInstructions);
}

VOID
kswRxpfDiagnosticsCountChainedFault(
    VOID
    )
{
    InterlockedIncrement64(&gKswRxpfDiagnostics.chainedFaults);
}

VOID
kswRxpfDiagnosticsCountRecursiveFault(
    VOID
    )
{
    InterlockedIncrement64(&gKswRxpfDiagnostics.recursiveFaults);
}

VOID
kswRxpfDiagnosticsCountUnsupportedInstruction(
    VOID
    )
{
    InterlockedIncrement64(
        &gKswRxpfDiagnostics.unsupportedInstructions);
}

VOID
kswRxpfDiagnosticsSetLastStatus(
    _In_ NTSTATUS status
    )
{
    InterlockedExchange(
        &gKswRxpfDiagnostics.lastStatus,
        status);
}

VOID
kswRxpfDiagnosticsQueryStats(
    _In_ ULONG generation,
    _In_ ULONG registeredPages,
    _In_ ULONG enabledPages,
    _In_ ULONG idtInstalled,
    _In_ ULONG processorCount,
    _Out_ KSWORD_ARK_RXPF_STATS_RESPONSE* response
    )
{
    /* Copy aligned atomic counters into a fixed user-mode response. */
    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_RXPF_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->generation = generation;
    response->registeredPages = registeredPages;
    response->enabledPages = enabledPages;
    response->idtInstalled = idtInstalled;
    response->processorCount = processorCount;
    response->activeHandlers =
        (ULONG)kswRxpfDiagnosticsActiveHandlers();
    response->totalFaults =
        (ULONGLONG)InterlockedCompareExchange64(
            &gKswRxpfDiagnostics.totalFaults,
            0,
            0);
    response->managedFaults =
        (ULONGLONG)InterlockedCompareExchange64(
            &gKswRxpfDiagnostics.managedFaults,
            0,
            0);
    response->emulatedInstructions =
        (ULONGLONG)InterlockedCompareExchange64(
            &gKswRxpfDiagnostics.emulatedInstructions,
            0,
            0);
    response->chainedFaults =
        (ULONGLONG)InterlockedCompareExchange64(
            &gKswRxpfDiagnostics.chainedFaults,
            0,
            0);
    response->recursiveFaults =
        (ULONGLONG)InterlockedCompareExchange64(
            &gKswRxpfDiagnostics.recursiveFaults,
            0,
            0);
    response->unsupportedInstructions =
        (ULONGLONG)InterlockedCompareExchange64(
            &gKswRxpfDiagnostics.unsupportedInstructions,
            0,
            0);
    response->droppedEvents =
        (ULONGLONG)InterlockedCompareExchange64(
            &gKswRxpfDiagnostics.droppedEvents,
            0,
            0);
    response->lastStatus =
        InterlockedCompareExchange(
            &gKswRxpfDiagnostics.lastStatus,
            0,
            0);
}

static VOID
kswRxpfDiagnosticsInsertSorted(
    _Inout_updates_(capacity) KSWORD_ARK_RXPF_EVENT_ROW* rows,
    _Inout_ ULONG* count,
    _In_ ULONG capacity,
    _In_ const KSWORD_ARK_RXPF_EVENT_ROW* candidate
    )
{
    ULONG insertIndex = 0UL;
    ULONG moveIndex = 0UL;

    /* Keep only the earliest requested rows when the fixed response is full. */
    if (*count >= capacity &&
        candidate->sequence >= rows[capacity - 1UL].sequence) {
        return;
    }
    insertIndex = *count < capacity ? *count : capacity - 1UL;
    while (insertIndex > 0UL &&
        rows[insertIndex - 1UL].sequence > candidate->sequence) {
        insertIndex -= 1UL;
    }
    moveIndex = *count < capacity ? *count : capacity - 1UL;
    while (moveIndex > insertIndex) {
        rows[moveIndex] = rows[moveIndex - 1UL];
        moveIndex -= 1UL;
    }
    rows[insertIndex] = *candidate;
    if (*count < capacity) {
        *count += 1UL;
    }
}

VOID
kswRxpfDiagnosticsDrain(
    _In_ const KSWORD_ARK_RXPF_DRAIN_EVENTS_REQUEST* request,
    _Out_ KSWORD_ARK_RXPF_DRAIN_EVENTS_RESPONSE* response
    )
{
    ULONG processorIndex = 0UL;
    ULONG slotIndex = 0UL;
    ULONG rowCapacity = 0UL;
    ULONG returnedRows = 0UL;
    ULONG availableRows = 0UL;
    ULONGLONG newestSequence = 0ULL;

    /* initialize a complete response even when no ring has been published. */
    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_RXPF_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    rowCapacity = request->maxRows;
    if (rowCapacity == 0UL ||
        rowCapacity > KSWORD_ARK_RXPF_MAX_EVENT_ROWS) {
        rowCapacity = KSWORD_ARK_RXPF_MAX_EVENT_ROWS;
    }
    if (InterlockedCompareExchange(
            &gKswRxpfDiagnostics.initialized,
            1,
            1) == 0) {
        return;
    }

    /* Read each slot with a sequence-before/after stability check. */
    for (processorIndex = 0UL;
         processorIndex < gKswRxpfDiagnostics.processorCapacity;
         ++processorIndex) {
        PkswRxpfEventRing ring =
            &gKswRxpfDiagnostics.rings[processorIndex];

        for (slotIndex = 0UL;
             slotIndex < KSW_RXPF_EVENT_RING_CAPACITY;
             ++slotIndex) {
            PkswRxpfEventSlot slot = &ring->slots[slotIndex];
            LONG64 before = InterlockedCompareExchange64(
                &slot->sequence,
                0,
                0);
            KSWORD_ARK_RXPF_EVENT_ROW candidate;
            LONG64 after = 0;

            if (before == 0) {
                continue;
            }
            RtlCopyMemory(&candidate, &slot->row, sizeof(candidate));
            KeMemoryBarrier();
            after = InterlockedCompareExchange64(
                &slot->sequence,
                0,
                0);
            if (before != after ||
                candidate.sequence != (ULONGLONG)before) {
                continue;
            }
            if (candidate.sequence > newestSequence) {
                newestSequence = candidate.sequence;
            }
            if (candidate.sequence <= request->afterSequence) {
                continue;
            }
            availableRows += 1UL;
            kswRxpfDiagnosticsInsertSorted(
                response->rows,
                &returnedRows,
                rowCapacity,
                &candidate);
        }
    }

    /* Publish bounded row counts and the global overwrite counter. */
    response->returnedRows = returnedRows;
    response->availableRows = availableRows;
    response->newestSequence = newestSequence;
    response->droppedRows =
        (ULONGLONG)InterlockedCompareExchange64(
            &gKswRxpfDiagnostics.droppedEvents,
            0,
            0);
}
