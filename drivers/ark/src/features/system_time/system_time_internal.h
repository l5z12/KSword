/*
 * License and archival notes for the referenced mechanism:
 * third_party/SystemWideTransmission/LICENSE.txt
 * third_party/SystemWideTransmission/NOTICE.md
 */
#pragma once

#include "ark/ark_system_time.h"

/*
 * The resolution result is used internally within the driver only.
 * primarySlot/secondarySlot: Point to HAL counter function pointer slots, not the functions themselves.
 */
typedef struct KswordArkSystemTimeResolution
{
    volatile PVOID* primarySlot;
    volatile PVOID* secondarySlot;
    volatile LONG* internalFlags;
    PVOID counterDescriptor;
    ULONG osBuildNumber;
    BOOLEAN usesHandlerTable;
    UCHAR reserved[3];
} KswordArkSystemTimeResolution, *PkswordArkSystemTimeResolution;

/*
 * Resolve RIP-relative references within KeQueryPerformanceCounter.
 * ResolutionMode selects between compatible positioning or enhanced verification positioning.
 */
NTSTATUS
kswordArkSystemTimeResolve(
    _In_ ULONG resolutionMode,
    _Out_ KswordArkSystemTimeResolution* resolution
    );
