#pragma once

#include <ntddk.h>
#include "driver/KswordArkSecurityAuditIoctl.h"

EXTERN_C_START

// Query CI/VBS/Secure Kernel/SKCI posture into a fixed METHOD_BUFFERED response.
NTSTATUS
kswordArkSecurityAuditQuerySecurityStatus(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

// Query loaded-driver trust cross-view rows into a bounded variable response.
NTSTATUS
kswordArkSecurityAuditQueryDriverTrustView(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

// Query Hyper-V layer availability and module-backed status skeleton.
NTSTATUS
kswordArkSecurityAuditQueryHyperVSummary(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

// Query AppID/AppLocker/mssecflt presence and owner status skeleton.
NTSTATUS
kswordArkSecurityAuditQueryAppControlStatus(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

EXTERN_C_END
