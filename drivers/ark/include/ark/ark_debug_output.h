#pragma once

#include <wdf.h>

#include "driver/KswordArkDebugOutputIoctl.h"

EXTERN_C_START

// Internal slots use commit sequence to protect snapshot replication; negative values indicate in-progress writes, positive values indicate committed.
typedef struct KswordArkDebugOutputSlot
{
    volatile LONG64 commitSequence;
    KSWORD_ARK_DEBUG_OUTPUT_RECORD record;
} KswordArkDebugOutputSlot, *PkswordArkDebugOutputSlot;

// initialize the fixed buffer within the specified device context; this function does not immediately register system callbacks.
NTSTATUS
kswordArkDebugOutputInitialize(
    _In_ WDFDEVICE device
    );

// Execute START/STOP/QUERY and return a runtime status snapshot ready for display.
NTSTATUS
kswordArkDebugOutputControl(
    _In_ WDFDEVICE device,
    _In_ const KSWORD_ARK_DEBUG_OUTPUT_CONTROL_REQUEST* controlRequest,
    _Out_ KSWORD_ARK_DEBUG_OUTPUT_CONTROL_RESPONSE* controlResponse
    );

// Copies records in ascending order starting from afterSequence, without allocating memory or waiting for locks in the callback path.
NTSTATUS
kswordArkDebugOutputDrain(
    _In_ WDFDEVICE device,
    _In_ const KSWORD_ARK_DEBUG_OUTPUT_DRAIN_REQUEST* drainRequest,
    _Out_writes_bytes_(outputBufferLength) KSWORD_ARK_DEBUG_OUTPUT_DRAIN_RESPONSE* outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

// Unregister callbacks before driver unloading to ensure global callbacks no longer reference device contexts.
VOID
kswordArkDebugOutputUninitialize(
    VOID
    );

EXTERN_C_END
