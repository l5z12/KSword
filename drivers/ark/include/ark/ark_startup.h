#pragma once

#include <ntddk.h>

#include "KswordArkStartupProtocol.h"

EXTERN_C_START

//
// initialize the breadcrumb module. Before every critical step in DriverEntry, register the phase number.
// On failure, persist the phase number and the original NTSTATUS to the service's Parameters key, enabling
// offline diagnosis of load failures that occur on only a few machines (where SCM reports only Win32 31).
//

VOID
kswordArkStartupBreadcrumbInitialize(
    _In_opt_ PDRIVER_OBJECT driverObject,
    _In_opt_ PCUNICODE_STRING registryPath
    );

VOID
kswordArkStartupStage(
    _In_ KSWORD_ARK_START_STAGE stage
    );

NTSTATUS
kswordArkStartupFailure(
    _In_ KSWORD_ARK_START_STAGE stage,
    _In_ NTSTATUS status
    );

VOID
kswordArkStartupNoteCallbackMask(
    _In_ ULONG callbackMask
    );

VOID
kswordArkStartupReady(
    VOID
    );

ULONG
kswordArkStartupGetOsBuildNumber(
    VOID
    );

EXTERN_C_END
