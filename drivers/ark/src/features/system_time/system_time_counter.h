/*
 * License and archival notes for the referenced mechanism:
 * third_party/SystemWideTransmission/LICENSE.txt
 * third_party/SystemWideTransmission/NOTICE.md
 */
#pragma once

#include "ark/ark_system_time.h"

/* initialize independent atomic time pairs and control words without touching any HAL pointers. */
VOID
kswordArkSystemTimeCounterInitialize(
    VOID
    );

/* On activation, publish the original counter, start value, command, and multiplier. */
VOID
kswordArkSystemTimeCounterActivate(
    _In_ PVOID originalCounter,
    _In_ LONGLONG initialCounter,
    _In_ ULONG command,
    _In_ ULONG factor
    );

/* Settle the old rate continuously while active and switch to the new command. */
NTSTATUS
kswordArkSystemTimeCounterReconfigure(
    _In_ ULONG command,
    _In_ ULONG factor
    );

/* In the restore path, switch the control word back to 1x; the original function address is retained until in-flight calls are drained. */
VOID
kswordArkSystemTimeCounterReset(
    VOID
    );

/* Return a non-paged hook address writable to the HAL slot. */
PVOID
kswordArkSystemTimeCounterHookAddress(
    VOID
    );

/* Returns the count of calls currently entered into the hook but not yet exited. */
LONG
kswordArkSystemTimeCounterInFlight(
    VOID
    );
