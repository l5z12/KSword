#pragma once

#include <ntddk.h>

#include "page_state_table.h"

EXTERN_C_START

#ifndef KSW_RXPF_ENABLE_EXTERNAL_IMAGE_TARGETS
#define KSW_RXPF_ENABLE_EXTERNAL_IMAGE_TARGETS 0
#endif

#define KSW_RXPF_SELF_TEST_EXPECTED_VALUE 0x0000000012345679ULL

NTSTATUS
kswRxpfImageProtectionInitialize(
    _In_ PDRIVER_OBJECT driverObject
    );

VOID
kswRxpfImageProtectionUninitialize(
    VOID
    );

VOID
kswRxpfImageProtectionQuerySupport(
    _Out_ KSWORD_ARK_RXPF_QUERY_SUPPORT_RESPONSE* response
    );

BOOLEAN
kswRxpfImageProtectionBuildSupported(
    VOID
    );

PVOID
kswRxpfImageProtectionSelfTestPage(
    VOID
    );

NTSTATUS
kswRxpfImageProtectionCreateRecord(
    _In_ ULONG targetKind,
    _In_ ULONGLONG requestedAddress,
    _In_ ULONG flags,
    _Out_ KswRxpfPageRecord* recordSource
    );

NTSTATUS
kswRxpfImageProtectionChangeToRwNx(
    _Inout_ PkswRxpfPageRecord record
    );

NTSTATUS
kswRxpfImageProtectionWrite(
    _Inout_ PkswRxpfPageRecord record,
    _In_ ULONG offset,
    _In_reads_bytes_(length) const UCHAR* bytes,
    _In_ ULONG length
    );

VOID
kswRxpfImageProtectionReleaseRecord(
    _Inout_ PkswRxpfPageRecord record
    );

EXTERN_C_END
