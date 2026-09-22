#pragma once

#include "../dyndata/dyndata_v4_internal.h"
#include "driver/KswordArkThreadIoctl.h"

EXTERN_C_START

// On optional thread field read failure, uniformly mark the current response row.
VOID
kswordArkThreadMarkFailure(
    _Inout_ KSWORD_ARK_THREAD_ENTRY* entry,
    _In_ NTSTATUS status
    );

// Reads the ActiveExWorker bit from an ETHREAD and writes to the shared thread response flag.
VOID
kswordArkThreadPopulateWorkerField(
    _Inout_ KSWORD_ARK_THREAD_ENTRY* entry,
    _In_ PETHREAD threadObject,
    _In_ const KswDynV4BitFieldLayout* activeExWorkerField
    );

EXTERN_C_END
