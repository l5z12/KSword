/*++

Module Name:

    hvm_event.h

Abstract:

    Defines the nonblocking HVM VM-exit and EPT event ring.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"

EXTERN_C_START

/* initialize the nonpaged event ring before any VM-exit can publish. */
VOID
kswordArkHvmEventInitialize(
    VOID
    );

/* Reset the event ring only while no resident processor is active. */
VOID
kswordArkHvmEventReset(
    VOID
    );

/* Publish one event without allocation, waiting, or pageable code. */
VOID
kswordArkHvmEventPublish(
    _In_ const KSWORD_ARK_HVM_EVENT_ROW* event
    );

/*
 * Publish one event and report whether the ring actually took it.
 *
 * The ring never waits in VMX root, so a publication can be dropped: the slot
 * may be held by a wrapped writer, or a newer sequence may already own it.
 * For routine telemetry that is a counter and nothing more, which is why the
 * plain publisher returns nothing.
 *
 * A watch hit is the opposite case.  "No event" and "the event was lost" look
 * identical in the event list but mean opposite things - the target was not
 * touched, versus the target was touched and the evidence is gone.  A caller
 * that has to tell those apart needs the sequence and the outcome, so it gets
 * them here rather than inferring from a global drop counter that every other
 * publisher also moves.
 */
BOOLEAN
kswordArkHvmEventPublishTracked(
    _In_ const KSWORD_ARK_HVM_EVENT_ROW* event,
    _Out_ ULONGLONG* publishedSequence
    );

/* Snapshot a bounded event batch after one caller-provided sequence. */
NTSTATUS
kswordArkHvmEventQuery(
    _In_ const KSWORD_ARK_HVM_EVENT_QUERY_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE* response
    );

/*
 * Return the four event-ring counts as separate numbers.
 *
 * PublicationDropCount is the only one that means an event was never written.
 * OverwrittenCount is ring wrap, which is a loss only if the reader is slower
 * than the ring; PublishedCount is the denominator for both.
 */
VOID
kswordArkHvmEventGetCounts(
    _Out_ ULONG* retainedCount,
    _Out_ ULONG* publicationDropCount,
    _Out_ ULONG* overwrittenCount,
    _Out_ ULONGLONG* publishedCount
    );

EXTERN_C_END
