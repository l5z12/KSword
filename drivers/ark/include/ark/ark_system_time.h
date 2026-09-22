/*
 * License and archival notes for the referenced mechanism:
 * third_party/SystemWideTransmission/LICENSE.txt
 * third_party/SystemWideTransmission/NOTICE.md
 */
#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "driver/KswordArkSystemTimeIoctl.h"

EXTERN_C_START

/* initialize the global variable-speed synchronization object and periodic maintenance DPC without modifying the time source during loading. */
VOID
kswordArkSystemTimeInitialize(
    VOID
    );

/* Stop maintenance, restore original timer pointers, and wait for in-flight calls to exit before driver unloading. */
VOID
kswordArkSystemTimeUninitialize(
    VOID
    );

/* Query the current parsed result, multiplier, takeover status, and finite diagnostic address. */
NTSTATUS
kswordArkSystemTimeQuery(
    _Out_ KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE* response
    );

/* Execute a speed-change control command after verifying version, generation, and security. */
NTSTATUS
kswordArkSystemTimeControl(
    _In_ const KSWORD_ARK_CONTROL_SYSTEM_TIME_REQUEST* request,
    _Out_ KSWORD_ARK_CONTROL_SYSTEM_TIME_RESPONSE* response
    );

EXTERN_C_END
