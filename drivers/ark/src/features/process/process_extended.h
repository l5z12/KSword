#pragma once

#include "ark/ark_driver.h"

EXTERN_C_START

VOID
kswordArkProcessPopulateExtendedEntry(
    _Inout_ KSWORD_ARK_PROCESS_ENTRY* entry,
    _In_ PEPROCESS processObject
    );

NTSTATUS
kswordArkProcessPatchProtectionByDynData(
    _In_ ULONG processId,
    _In_ UCHAR protectionLevel,
    _In_ UCHAR signatureLevel,
    _In_ UCHAR sectionSignatureLevel
    );

NTSTATUS
kswordArkProcessPatchProtectionByDynDataObject(
    _In_ PEPROCESS processObject,
    _In_ UCHAR protectionLevel,
    _In_ UCHAR signatureLevel,
    _In_ UCHAR sectionSignatureLevel
    );

// PP guard inspection: Re-reads the current Protection byte using the same offset parsing order as the write path.
NTSTATUS
kswordArkProcessReadProtectionByte(
    _In_ PEPROCESS processObject,
    _Out_ UCHAR* protectionByteOut
    );

// PP hardening: clear EPROCESS.DebugPort.
NTSTATUS
kswordArkProcessClearDebugPortByObject(
    _In_ PEPROCESS processObject
    );

EXTERN_C_END
