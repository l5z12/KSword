/*++

Module Name:

    page_state_table.c

Abstract:

    Fixed-capacity page-keyed table with lock-free exception-path lookups.

Environment:

    Kernel mode.  Lookup is nonpaged and performs no allocation or waiting.

--*/

#include "page_state_table.h"

static ULONG
kswRxpfPageTableHash(
    _In_ ULONGLONG pageBase
    )
{
    ULONGLONG pageNumber = pageBase >> PAGE_SHIFT;

    /* Fold high address bits before applying the power-of-two table mask. */
    pageNumber ^= pageNumber >> 17;
    pageNumber ^= pageNumber >> 31;
    return (ULONG)pageNumber & KSW_RXPF_PAGE_TABLE_MASK;
}

VOID
kswRxpfPageTableInitialize(
    _Out_ PkswRxpfPageTable table
    )
{
    /* Publish a completely empty table before accepting any control request. */
    RtlZeroMemory(table, sizeof(*table));
    ExInitializePushLock(&table->controlLock);
    table->nextRecordId = 0;
    InterlockedExchange(&table->accepting, 1);
}

VOID
kswRxpfPageTableStopAccepting(
    _Inout_ PkswRxpfPageTable table
    )
{
    /* Prevent all future insertions before records enter termination. */
    InterlockedExchange(&table->accepting, 0);
    KeMemoryBarrier();
}

VOID
kswRxpfPageTableAcquireExclusive(
    _Inout_ PkswRxpfPageTable table
    )
{
    /* Control-path writers may wait; vector 14 never calls this routine. */
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&table->controlLock);
}

VOID
kswRxpfPageTableReleaseExclusive(
    _Inout_ PkswRxpfPageTable table
    )
{
    /* Release the writer lock before restoring normal kernel APC delivery. */
    ExReleasePushLockExclusive(&table->controlLock);
    KeLeaveCriticalRegion();
}

NTSTATUS
kswRxpfPageTableInsertLocked(
    _Inout_ PkswRxpfPageTable table,
    _In_ const KswRxpfPageRecord* source,
    _Outptr_ PkswRxpfPageRecord* recordOut
    )
{
    ULONG startIndex = 0UL;
    ULONG probe = 0UL;
    PkswRxpfPageRecord firstTombstone = NULL;

    /* Reject invalid contracts before inspecting fixed table slots. */
    if (table == NULL || source == NULL || recordOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *recordOut = NULL;

    /* Insertions stop permanently once unload begins. */
    if (InterlockedCompareExchange(&table->accepting, 1, 1) == 0) {
        return STATUS_DELETE_PENDING;
    }
    if (source->pageBase <= (LONG64)KSW_RXPF_PAGE_TOMBSTONE ||
        (((ULONGLONG)source->pageBase) & (PAGE_SIZE - 1ULL)) != 0ULL) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    /* Probe the complete bounded open-addressing sequence. */
    startIndex = kswRxpfPageTableHash((ULONGLONG)source->pageBase);
    for (probe = 0UL; probe < KSW_RXPF_PAGE_TABLE_CAPACITY; ++probe) {
        PkswRxpfPageRecord slot =
            &table->slots[(startIndex + probe) & KSW_RXPF_PAGE_TABLE_MASK];
        ULONGLONG observedPage = (ULONGLONG)slot->pageBase;

        /* Duplicate virtual-page keys are never ambiguous. */
        if (observedPage == (ULONGLONG)source->pageBase) {
            return STATUS_OBJECT_NAME_COLLISION;
        }
        /* Remember the first reusable tombstone but continue duplicate checks. */
        if (observedPage == KSW_RXPF_PAGE_TOMBSTONE &&
            firstTombstone == NULL) {
            firstTombstone = slot;
            continue;
        }
        /* An empty slot terminates the probe chain and can accept the record. */
        if (observedPage == 0ULL) {
            PkswRxpfPageRecord destination =
                firstTombstone != NULL ? firstTombstone : slot;
            KswRxpfPageRecord unpublished;
            LONG64 recordId = InterlockedIncrement64(&table->nextRecordId);

            /* Copy unpublished fields while PageBase remains empty/tombstone. */
            RtlCopyMemory(&unpublished, source, sizeof(unpublished));
            unpublished.pageBase = destination->pageBase;
            unpublished.recordId = recordId;
            unpublished.referenceCount = 1;
            unpublished.emulationEnabled = 0;
            unpublished.state = KSWORD_ARK_RXPF_PAGE_STATE_RX;
            RtlCopyMemory(destination, &unpublished, sizeof(*destination));
            KeMemoryBarrier();
            InterlockedExchange64(
                &destination->pageBase,
                source->pageBase);
            InterlockedIncrement(&table->registeredCount);
            *recordOut = destination;
            return STATUS_SUCCESS;
        }
    }

    /* A table containing only occupied/tombstone slots may reuse a tombstone. */
    if (firstTombstone != NULL) {
        KswRxpfPageRecord unpublished;
        LONG64 recordId = InterlockedIncrement64(&table->nextRecordId);

        /* Publish immutable record fields before restoring the page key. */
        RtlCopyMemory(&unpublished, source, sizeof(unpublished));
        unpublished.pageBase = firstTombstone->pageBase;
        unpublished.recordId = recordId;
        unpublished.referenceCount = 1;
        unpublished.emulationEnabled = 0;
        unpublished.state = KSWORD_ARK_RXPF_PAGE_STATE_RX;
        RtlCopyMemory(firstTombstone, &unpublished, sizeof(*firstTombstone));
        KeMemoryBarrier();
        InterlockedExchange64(
            &firstTombstone->pageBase,
            source->pageBase);
        InterlockedIncrement(&table->registeredCount);
        *recordOut = firstTombstone;
        return STATUS_SUCCESS;
    }

    /* Fixed capacity is intentional so the exception path never allocates. */
    return STATUS_INSUFFICIENT_RESOURCES;
}

PkswRxpfPageRecord
kswRxpfPageTableFindByIdLocked(
    _In_ PkswRxpfPageTable table,
    _In_ ULONGLONG recordId
    )
{
    ULONG index = 0UL;

    /* Record identifiers start at one and never alias an empty slot. */
    if (table == NULL || recordId == 0ULL) {
        return NULL;
    }
    for (index = 0UL; index < KSW_RXPF_PAGE_TABLE_CAPACITY; ++index) {
        PkswRxpfPageRecord slot = &table->slots[index];

        /* Return only a published, non-terminating record. */
        if ((ULONGLONG)slot->pageBase > KSW_RXPF_PAGE_TOMBSTONE &&
            (ULONGLONG)slot->recordId == recordId &&
            slot->state != KSWORD_ARK_RXPF_PAGE_STATE_TERMINATING) {
            return slot;
        }
    }
    return NULL;
}

PkswRxpfPageRecord
kswRxpfPageTableLookupFault(
    _In_ PkswRxpfPageTable table,
    _In_ ULONGLONG pageBase
    )
{
    ULONG startIndex = 0UL;
    ULONG probe = 0UL;

    /* Reject malformed keys without touching shared slots. */
    if (table == NULL ||
        pageBase <= KSW_RXPF_PAGE_TOMBSTONE ||
        (pageBase & (PAGE_SIZE - 1ULL)) != 0ULL) {
        return NULL;
    }

    /* Readers use immutable page keys and acquire publication via a barrier. */
    startIndex = kswRxpfPageTableHash(pageBase);
    for (probe = 0UL; probe < KSW_RXPF_PAGE_TABLE_CAPACITY; ++probe) {
        PkswRxpfPageRecord slot =
            &table->slots[(startIndex + probe) & KSW_RXPF_PAGE_TABLE_MASK];
        ULONGLONG observedPage = (ULONGLONG)slot->pageBase;

        /* Empty terminates this open-addressing chain; tombstone does not. */
        if (observedPage == 0ULL) {
            return NULL;
        }
        if (observedPage != pageBase) {
            continue;
        }
        KeMemoryBarrier();
        /* Only a fully transitioned and explicitly enabled page is usable. */
        if (slot->state == KSWORD_ARK_RXPF_PAGE_STATE_RW_NX &&
            InterlockedCompareExchange(
                &slot->emulationEnabled,
                1,
                1) != 0) {
            return slot;
        }
        return NULL;
    }
    return NULL;
}

VOID
kswRxpfPageTableBeginRemoveLocked(
    _Inout_ PkswRxpfPageTable table,
    _Inout_ PkswRxpfPageRecord record
    )
{
    LONG wasEnabled = 0;

    /* Unpublish eligibility before the caller waits for active handlers. */
    wasEnabled = InterlockedExchange(&record->emulationEnabled, 0);
    InterlockedExchange(
        &record->state,
        KSWORD_ARK_RXPF_PAGE_STATE_TERMINATING);
    KeMemoryBarrier();
    if (wasEnabled != 0) {
        InterlockedDecrement(&table->enabledCount);
    }
}

VOID
kswRxpfPageTableClearRemovedLocked(
    _Inout_ PkswRxpfPageTable table,
    _Inout_ PkswRxpfPageRecord record
    )
{
    /* Replace the key with a tombstone before clearing private resources. */
    InterlockedExchange64(
        &record->pageBase,
        (LONG64)KSW_RXPF_PAGE_TOMBSTONE);
    KeMemoryBarrier();
    RtlZeroMemory(
        (PUCHAR)record + sizeof(record->state) +
            sizeof(record->emulationEnabled),
        FIELD_OFFSET(KswRxpfPageRecord, pageBase) -
            sizeof(record->state) - sizeof(record->emulationEnabled));
    RtlZeroMemory(
        (PUCHAR)record + FIELD_OFFSET(KswRxpfPageRecord, pageBase) +
            sizeof(record->pageBase),
        sizeof(*record) - FIELD_OFFSET(KswRxpfPageRecord, pageBase) -
            sizeof(record->pageBase));
    record->state = KSWORD_ARK_RXPF_PAGE_STATE_EMPTY;
    record->emulationEnabled = 0;
    InterlockedDecrement(&table->registeredCount);
}
