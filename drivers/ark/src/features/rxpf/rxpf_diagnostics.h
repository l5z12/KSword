#pragma once

#include <ntddk.h>

#include "driver/KswordArkRxPfIoctl.h"

EXTERN_C_START

#define KSW_RXPF_EVENT_RING_CAPACITY 128UL

typedef struct KswRxpfEventSlot
{
    DECLSPEC_ALIGN(8) volatile LONG64 sequence;
    KSWORD_ARK_RXPF_EVENT_ROW row;
} KswRxpfEventSlot, *PkswRxpfEventSlot;

typedef struct KswRxpfEventRing
{
    volatile LONG head;
    KswRxpfEventSlot slots[KSW_RXPF_EVENT_RING_CAPACITY];
} KswRxpfEventRing, *PkswRxpfEventRing;

NTSTATUS
kswRxpfDiagnosticsInitialize(
    _In_ ULONG maximumProcessorCount
    );

VOID
kswRxpfDiagnosticsUninitialize(
    VOID
    );

VOID
kswRxpfDiagnosticsEnterHandler(
    VOID
    );

VOID
kswRxpfDiagnosticsLeaveHandler(
    VOID
    );

LONG
kswRxpfDiagnosticsActiveHandlers(
    VOID
    );

NTSTATUS
kswRxpfDiagnosticsWaitForHandlers(
    _In_ ULONG timeoutMilliseconds
    );

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
    );

VOID
kswRxpfDiagnosticsCountTotalFault(
    VOID
    );

VOID
kswRxpfDiagnosticsCountManagedFault(
    VOID
    );

VOID
kswRxpfDiagnosticsCountEmulatedInstruction(
    VOID
    );

VOID
kswRxpfDiagnosticsCountChainedFault(
    VOID
    );

VOID
kswRxpfDiagnosticsCountRecursiveFault(
    VOID
    );

VOID
kswRxpfDiagnosticsCountUnsupportedInstruction(
    VOID
    );

VOID
kswRxpfDiagnosticsSetLastStatus(
    _In_ NTSTATUS status
    );

VOID
kswRxpfDiagnosticsQueryStats(
    _In_ ULONG generation,
    _In_ ULONG registeredPages,
    _In_ ULONG enabledPages,
    _In_ ULONG idtInstalled,
    _In_ ULONG processorCount,
    _Out_ KSWORD_ARK_RXPF_STATS_RESPONSE* response
    );

VOID
kswRxpfDiagnosticsDrain(
    _In_ const KSWORD_ARK_RXPF_DRAIN_EVENTS_REQUEST* request,
    _Out_ KSWORD_ARK_RXPF_DRAIN_EVENTS_RESPONSE* response
    );

EXTERN_C_END
