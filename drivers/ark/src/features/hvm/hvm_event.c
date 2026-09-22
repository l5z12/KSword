/*++

Module Name:

    hvm_event.c

Abstract:

    Implements a fixed nonpaged HVM event ring with sequence-validated slots.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_event.h"

/*
 * Bound retained VM-exit evidence without allocation in VMX root.
 *
 * Sized from a measurement rather than a round number: a guest hypervisor
 * starting a virtual machine underneath us produced 6,960 nested-VMX events
 * before the run ended, and at 1,024 slots the whole configuration phase -
 * the part that says which fields it wrote into which VMCS - had already been
 * evicted by its own idle retry loop, leaving only the loop.  Eight thousand
 * holds that run whole.
 *
 * The cost is static: this is one nonpaged array in the image, 88 bytes a slot,
 * about 704 KiB.  Bought deliberately, because the alternative is a ring that
 * is present, healthy, never drops a write, and cannot answer the one question
 * being asked of it.
 */
#define KSW_HVM_EVENT_RING_CAPACITY 8192UL
/* Reserve the high state bit for one nonblocking writer ownership claim. */
#define KSW_HVM_EVENT_SLOT_BUSY 0x8000000000000000ULL
/* Keep completed public sequences separate from the writer ownership bit. */
#define KSW_HVM_EVENT_SEQUENCE_MASK 0x7FFFFFFFFFFFFFFFULL

/* Wrap one public row with an atomic busy-plus-sequence publication state. */
typedef struct KswHvmEventSlot
{
    /* Publish BUSY|sequence while owned and sequence alone when complete. */
    DECLSPEC_ALIGN(8) volatile LONG64 publicationState;
    /* Retain the protocol-visible event payload. */
    KSWORD_ARK_HVM_EVENT_ROW row;
} KswHvmEventSlot;

/* Own the monotonic sequence and fixed nonpaged event slots. */
typedef struct KswHvmEventRing
{
    /* Allocate the next protocol-visible event sequence atomically. */
    DECLSPEC_ALIGN(8) volatile LONG64 nextSequence;
    /* Count writers that could not claim their wrapped slot without waiting. */
    DECLSPEC_ALIGN(8) volatile LONG64 droppedPublications;
    /* Retain every bounded ring slot in nonpaged driver storage. */
    KswHvmEventSlot slots[KSW_HVM_EVENT_RING_CAPACITY];
} KswHvmEventRing;

/* Require the 64-bit interlocked operands to remain naturally aligned. */
C_ASSERT(__alignof(KswHvmEventSlot) >= 8);
C_ASSERT(__alignof(KswHvmEventRing) >= 8);
C_ASSERT((FIELD_OFFSET(
    KswHvmEventSlot,
    publicationState) & 0x7) == 0);
C_ASSERT((FIELD_OFFSET(
    KswHvmEventRing,
    droppedPublications) & 0x7) == 0);

/* Store the process-wide nonpaged HVM event ring. */
static KswHvmEventRing gKswordHvmEvents;

VOID
kswordArkHvmEventInitialize(
    VOID
    )
{
    /* initialize the full event ring before HVM becomes observable. */
    RtlZeroMemory(
        &gKswordHvmEvents,
        sizeof(gKswordHvmEvents));
}

VOID
kswordArkHvmEventReset(
    VOID
    )
{
    /* Reset the full ring only after lifecycle serialization stops writers. */
    RtlZeroMemory(
        &gKswordHvmEvents,
        sizeof(gKswordHvmEvents));
}

VOID
kswordArkHvmEventPublish(
    _In_ const KSWORD_ARK_HVM_EVENT_ROW* event
    )
{
    ULONGLONG sequence = 0ULL;

    /* Publish without caring which sequence the row received. */
    (void)kswordArkHvmEventPublishTracked(event, &sequence);
}

BOOLEAN
kswordArkHvmEventPublishTracked(
    _In_ const KSWORD_ARK_HVM_EVENT_ROW* event,
    _Out_ ULONGLONG* publishedSequence
    )
{
    LONG64 sequence = 0;
    LONG64 observedState = 0;
    LONG64 busyState = 0;
    ULONGLONG observedBits = 0ULL;
    ULONG slotIndex = 0UL;
    KswHvmEventSlot* slot = NULL;
    LARGE_INTEGER timestamp = { 0 };

    /* Publish no sequence before the ring is touched. */
    if (publishedSequence != NULL) {
        /* Report "not published" until a slot is actually claimed. */
        *publishedSequence = 0ULL;
    }
    /* Reject a missing event without touching the ring. */
    if (event == NULL ||
        publishedSequence == NULL) {
        /* Return immediately on an invalid VM-exit publication contract. */
        return FALSE;
    }
    /* Allocate one monotonic sequence with full interlocked ordering. */
    sequence = InterlockedIncrement64(
        &gKswordHvmEvents.nextSequence);
    /*
     * The high bit belongs to slot ownership.  Refuse the theoretical signed
     * sequence rollover instead of aliasing a public sequence with BUSY.
     */
    if (sequence <= 0) {
        /* Account for the sequence that cannot be represented safely. */
        InterlockedIncrement64(
            &gKswordHvmEvents.droppedPublications);
        /* Return without indexing the ring with a wrapped value. */
        return FALSE;
    }
    /* Convert the positive sequence to a bounded ring slot. */
    slotIndex = (ULONG)(
        ((ULONGLONG)sequence - 1ULL) %
        KSW_HVM_EVENT_RING_CAPACITY);
    /* Select the exact slot owned by this sequence. */
    slot = &gKswordHvmEvents.slots[slotIndex];
    /* Snapshot the current slot owner or completed sequence. */
    observedState = InterlockedCompareExchange64(
        &slot->publicationState,
        0,
        0);
    observedBits = (ULONGLONG)observedState;
    /*
     * Never wait in VMX root.  A busy slot means a wrapped writer caught an
     * earlier publisher in flight; a newer completed sequence means this
     * writer was delayed and must not overwrite newer evidence.
     */
    if ((observedBits & KSW_HVM_EVENT_SLOT_BUSY) != 0ULL ||
        (observedBits & KSW_HVM_EVENT_SEQUENCE_MASK) >=
            (ULONGLONG)sequence) {
        /* Account for the intentionally discarded publication. */
        InterlockedIncrement64(
            &gKswordHvmEvents.droppedPublications);
        /* Return without spinning or modifying another writer's slot. */
        return FALSE;
    }
    /* Encode this sequence as the single-writer ownership state. */
    busyState = (LONG64)(
        KSW_HVM_EVENT_SLOT_BUSY |
        (ULONGLONG)sequence);
    /* Claim the slot exactly once; a failed claim is a bounded drop. */
    if (InterlockedCompareExchange64(
            &slot->publicationState,
            busyState,
            observedState) != observedState) {
        /* Account for the losing writer without retrying in VMX root. */
        InterlockedIncrement64(
            &gKswordHvmEvents.droppedPublications);
        /* Preserve the concurrent winner's publication. */
        return FALSE;
    }
    /* Copy the caller-provided fixed payload without allocation. */
    slot->row = *event;
    /* Publish the authoritative monotonic sequence in the payload. */
    slot->row.sequence = (ULONGLONG)sequence;
    /* Capture one nonblocking interrupt-time timestamp when absent. */
    if (slot->row.timestamp == 0ULL) {
        /* Read the monotonically increasing interrupt time. */
        timestamp = KeQueryPerformanceCounter(NULL);
        /* Preserve the performance-counter tick value. */
        slot->row.timestamp =
            (ULONGLONG)timestamp.QuadPart;
    }
    /* Order the entire payload before the publication sequence. */
    KeMemoryBarrier();
    /* Publish the completed slot to concurrent readers. */
    InterlockedExchange64(
        &slot->publicationState,
        sequence);
    /* Report the sequence a reader can use to find this exact row. */
    *publishedSequence = (ULONGLONG)sequence;
    /* Report that the evidence reached the ring. */
    return TRUE;
}

NTSTATUS
kswordArkHvmEventQuery(
    _In_ const KSWORD_ARK_HVM_EVENT_QUERY_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE* response
    )
{
    ULONGLONG newest = 0ULL;
    ULONGLONG oldest = 0ULL;
    ULONGLONG next = 0ULL;
    ULONGLONG available = 0ULL;
    ULONG rowLimit = 0UL;

    /* Validate the complete versioned query contract. */
    if (request == NULL ||
        response == NULL ||
        request->version != KSWORD_ARK_HVM_PROTOCOL_VERSION ||
        request->size != sizeof(*request) ||
        request->operation != KSWORD_ARK_HVM_EVENT_QUERY_READ) {
        /* Return the exact fixed-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* initialize the complete response before reading concurrent slots. */
    RtlZeroMemory(response, sizeof(*response));
    /* Publish the protocol identity immediately. */
    response->version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    /* Publish the complete fixed response size. */
    response->size = sizeof(*response);
    /* Bound the caller row request to the fixed response capacity. */
    rowLimit = request->maxRows;
    /* Replace zero with the full fixed batch capacity. */
    if (rowLimit == 0UL ||
        rowLimit > KSWORD_ARK_HVM_MAX_EVENT_ROWS) {
        /* Clamp the row limit to the complete response array. */
        rowLimit = KSWORD_ARK_HVM_MAX_EVENT_ROWS;
    }
    /* Snapshot the newest assigned sequence with interlocked ordering. */
    newest = (ULONGLONG)InterlockedCompareExchange64(
        &gKswordHvmEvents.nextSequence,
        0,
        0);
    /* Publish the newest sequence even when no row is retained. */
    response->newestSequence = newest;
    /* Return an empty valid response before the first publication. */
    if (newest == 0ULL) {
        /* Complete the empty query successfully. */
        return STATUS_SUCCESS;
    }
    /* Compute the oldest sequence that can still occupy the fixed ring. */
    oldest = newest >= KSW_HVM_EVENT_RING_CAPACITY
        ? newest - KSW_HVM_EVENT_RING_CAPACITY + 1ULL
        : 1ULL;
    /* Start strictly after the caller-provided sequence. */
    next = request->afterSequence + 1ULL;
    /* Detect caller sequence overflow explicitly. */
    if (next == 0ULL) {
        /* Return the exact sequence-overflow contract failure. */
        return STATUS_INTEGER_OVERFLOW;
    }
    /* Account for rows overwritten before the requested starting point. */
    if (next < oldest) {
        ULONGLONG overwritten = oldest - next;

        /* Saturate overwritten evidence at the protocol counter width. */
        response->droppedRows = overwritten > MAXULONG
            ? MAXULONG
            : (ULONG)overwritten;
        /* Continue from the oldest sequence that remains readable. */
        next = oldest;
    }
    /* Compute the number of retained rows after the adjusted cursor. */
    available = next <= newest
        ? newest - next + 1ULL
        : 0ULL;
    /* Publish the bounded number available before the response row limit. */
    response->availableRows = available > MAXULONG
        ? MAXULONG
        : (ULONG)available;
    /* Copy sequence-validated slots until the caller's row limit is reached. */
    while (next <= newest &&
           response->returnedRows < rowLimit) {
        ULONG slotIndex = (ULONG)(
            ((next - 1ULL) %
                KSW_HVM_EVENT_RING_CAPACITY));
        KswHvmEventSlot* slot =
            &gKswordHvmEvents.slots[slotIndex];
        LONG64 before = 0;
        KSWORD_ARK_HVM_EVENT_ROW row = { 0 };
        LONG64 after = 0;

        /* Snapshot the busy-plus-sequence state before copying the payload. */
        before = InterlockedCompareExchange64(
            &slot->publicationState,
            0,
            0);
        /* Copy only a completed slot for the exact requested sequence. */
        if (((ULONGLONG)before &
                KSW_HVM_EVENT_SLOT_BUSY) == 0ULL &&
            ((ULONGLONG)before &
                KSW_HVM_EVENT_SEQUENCE_MASK) == next) {
            /* Copy the fixed payload optimistically. */
            row = slot->row;
            /* Order the payload read before rechecking publication. */
            KeMemoryBarrier();
            /* Recheck that no concurrent writer replaced the slot. */
            after = InterlockedCompareExchange64(
                &slot->publicationState,
                0,
                0);
            /* Publish only a stable two-phase slot snapshot. */
            if (before == after &&
                ((ULONGLONG)after &
                    KSW_HVM_EVENT_SLOT_BUSY) == 0ULL &&
                row.sequence == next) {
                /* Append the stable row to the fixed response batch. */
                response->rows[response->returnedRows] = row;
                /* Publish one additional returned row. */
                response->returnedRows += 1UL;
            } else if (response->droppedRows != MAXULONG) {
                /* Count a row unavailable in this concurrent snapshot. */
                response->droppedRows += 1UL;
            }
        } else if (response->droppedRows != MAXULONG) {
            /* Count an unclaimed, busy, stale, or wrapped slot as unavailable. */
            response->droppedRows += 1UL;
        }
        /* Advance to the next monotonic event sequence. */
        next += 1ULL;
    }
    /* Complete the bounded snapshot successfully. */
    return STATUS_SUCCESS;
}

VOID
kswordArkHvmEventGetCounts(
    _Out_ ULONG* retainedCount,
    _Out_ ULONG* publicationDropCount,
    _Out_ ULONG* overwrittenCount,
    _Out_ ULONGLONG* publishedCount
    )
{
    ULONGLONG newest = 0ULL;
    ULONGLONG oldest = 0ULL;
    ULONGLONG retained = 0ULL;
    ULONGLONG overwritten = 0ULL;
    ULONGLONG publicationDrops = 0ULL;
    ULONG slotIndex = 0UL;

    /* Reject any missing fixed output pointer. */
    if (retainedCount == NULL ||
        publicationDropCount == NULL ||
        overwrittenCount == NULL ||
        publishedCount == NULL) {
        /* Return without publishing a partial count set. */
        return;
    }
    /* Snapshot the newest assigned sequence with interlocked ordering. */
    newest = (ULONGLONG)InterlockedCompareExchange64(
        &gKswordHvmEvents.nextSequence,
        0,
        0);
    /* Snapshot exact failed ownership claims for a conservative loss floor. */
    publicationDrops = (ULONGLONG)InterlockedCompareExchange64(
        &gKswordHvmEvents.droppedPublications,
        0,
        0);
    /* Compute the oldest sequence that can still occupy the fixed ring. */
    oldest = newest >= KSW_HVM_EVENT_RING_CAPACITY
        ? newest - KSW_HVM_EVENT_RING_CAPACITY + 1ULL
        : 1ULL;
    /*
     * Count only completed states in the current retention window.  This
     * bounded scan avoids reporting assigned-but-dropped sequences as rows.
     */
    for (slotIndex = 0UL;
         slotIndex < KSW_HVM_EVENT_RING_CAPACITY;
         ++slotIndex) {
        LONG64 before = InterlockedCompareExchange64(
            &gKswordHvmEvents.slots[slotIndex].publicationState,
            0,
            0);
        ULONGLONG sequence =
            (ULONGLONG)before &
            KSW_HVM_EVENT_SEQUENCE_MASK;

        /* Count only one completed sequence inside the current window. */
        if (((ULONGLONG)before &
                KSW_HVM_EVENT_SLOT_BUSY) == 0ULL &&
            sequence >= oldest &&
            sequence <= newest) {
            /* Publish one additional currently retained event. */
            retained += 1ULL;
        }
    }
    /*
     * Displacement by ring wrap is reported apart from publication loss.
     *
     * These two numbers answer different questions and were previously folded
     * together by a max(), which made the result unreadable: a 1024-slot ring
     * that has carried a million events reports "999k displaced" even when the
     * consumer read every one of them before it was overwritten.  Only the
     * publication drop count is evidence that an event was never written at
     * all, and only that number justifies changing the ring's structure.
     *
     * Whether displacement is an actual loss depends on the reader's polling
     * interval, which the driver cannot see - so the driver reports the raw
     * displacement and leaves that judgement to the caller.
     */
    overwritten = newest > retained
        ? newest - retained
        : 0ULL;
    /* Publish the retained count within protocol width. */
    *retainedCount = retained > MAXULONG
        ? MAXULONG
        : (ULONG)retained;
    /* Publish exact failed nonblocking ownership claims within protocol width. */
    *publicationDropCount = publicationDrops > MAXULONG
        ? MAXULONG
        : (ULONG)publicationDrops;
    /* Saturate the wrap-displaced sequence count within protocol width. */
    *overwrittenCount = overwritten > MAXULONG
        ? MAXULONG
        : (ULONG)overwritten;
    /* Publish the full-width total so the two counters have a denominator. */
    *publishedCount = newest;
}
