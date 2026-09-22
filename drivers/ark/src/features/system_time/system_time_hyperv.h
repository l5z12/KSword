/*
 * License and archival notes for the referenced mechanism:
 * third_party/SystemWideTransmission/LICENSE.txt
 * third_party/SystemWideTransmission/NOTICE.md
 */
#pragma once

#include "ark/ark_system_time.h"

/* Hyper-V diagnostic snapshots flow only within the system_time feature. */
typedef struct KswordArkSystemTimeHypervDiagnostics
{
    ULONG stateFlags;
    PVOID sharedUserVa;
    ULONGLONG timeUpdateLock;
    ULONGLONG originalMultiplier;
    ULONGLONG originalBias;
    ULONGLONG currentMultiplier;
    ULONGLONG currentBias;
} KswordArkSystemTimeHypervDiagnostics;

/* initialize shared page synchronization state without querying or modifying Hyper-V. */
VOID
kswordArkSystemTimeHypervInitialize(
    VOID
    );

/* Read-only probe of the Hyper-V shared QPC page, returning limited diagnostic evidence. */
NTSTATUS
kswordArkSystemTimeHypervQuery(
    _Out_ KswordArkSystemTimeHypervDiagnostics* diagnostics
    );

/* Before activation, fix the shared page physical mapping and save a recoverable snapshot of the multiplier and offset. */
NTSTATUS
kswordArkSystemTimeHypervPrepare(
    VOID
    );

/* After the HAL hook is ready, publish the first Hyper-V multiplier based on its continuous QPC snapshots. */
NTSTATUS
kswordArkSystemTimeHypervActivate(
    _In_ ULONG command,
    _In_ ULONG factor
    );

/* Maintain continuity in the active state and atomically switch the Hyper-V multiplier. */
NTSTATUS
kswordArkSystemTimeHypervReconfigure(
    _In_ ULONG command,
    _In_ ULONG factor
    );

/* Periodically verify that the shared page still belongs to this feature and republish it when the system restores original values. */
NTSTATUS
kswordArkSystemTimeHypervMaintain(
    VOID
    );

/* Restore snapshot and unmap physical address only if the shared page is still at its original value or this feature's value. */
NTSTATUS
kswordArkSystemTimeHypervRestore(
    VOID
    );