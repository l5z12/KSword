#pragma once

#include <ntddk.h>

typedef struct KswordArkBugcheckDiagnostics
    KswordArkBugcheckDiagnostics;
typedef KswordArkBugcheckDiagnostics*
    PkswordArkBugcheckDiagnostics;

NTSTATUS
kswordArkBugcheckPanelInitialize(
    VOID
    );

VOID
kswordArkBugcheckPanelShutdown(
    VOID
    );

NTSTATUS
kswordArkBugcheckPanelInstallVerdictResources(
    _In_reads_bytes_(packetLength) const VOID* packet,
    _In_ ULONG packetLength
    );

NTSTATUS
kswordArkBugcheckPanelDraw(
    _In_ const KswordArkBugcheckDiagnostics* diagnostics,
    _In_ ULONG callbackMask,
    _In_ ULONG moduleCount
    );
