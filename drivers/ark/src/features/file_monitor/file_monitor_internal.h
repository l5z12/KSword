#pragma once

#include <fltKernel.h>

#include "ark/ark_file_monitor.h"
#include "driver/KswordArkCallbackIoctl.h"

EXTERN_C_START

ULONG
kswordArkMinifilterMapMajorToOperation(
    _In_ UCHAR majorFunction,
    _In_ UCHAR minorFunction,
    _In_opt_ PFLT_PARAMETERS parameters
    );

ULONG
kswordArkFileMonitorMapMajorToOperation(
    _In_ UCHAR majorFunction,
    _In_ UCHAR minorFunction,
    _In_opt_ PFLT_PARAMETERS parameters
    );

FLT_PREOP_CALLBACK_STATUS
kswordArkMinifilterApplyRule(
    _In_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ ULONG operationType
    );

VOID
kswordArkMinifilterCallbackUpdateState(
    _In_opt_ PFLT_FILTER filterHandle,
    _In_ NTSTATUS registerStatus,
    _In_ NTSTATUS startStatus,
    _In_ BOOLEAN started
    );

NTSTATUS
kswordArkRedirectTryRewriteFileCreate(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _Out_ BOOLEAN* redirectedOut
    );

// Ensure the shared Minifilter has executed FltStartFiltering once, without altering the old file monitoring collection flag.
NTSTATUS
kswordArkFileMonitorEnsureFilteringStarted(
    VOID
    );

EXTERN_C_END
