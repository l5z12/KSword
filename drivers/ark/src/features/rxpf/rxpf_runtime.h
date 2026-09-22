#pragma once

#include <ntddk.h>

#include "driver/KswordArkRxPfIoctl.h"

EXTERN_C_START

NTSTATUS
kswRxpfRuntimeInitialize(
    _In_ PDRIVER_OBJECT driverObject
    );

VOID
kswRxpfRuntimeUninitialize(
    VOID
    );

NTSTATUS
kswRxpfRuntimeQuerySupport(
    _Out_ KSWORD_ARK_RXPF_QUERY_SUPPORT_RESPONSE* response
    );

NTSTATUS
kswRxpfRuntimeRegisterPage(
    _In_ const KSWORD_ARK_RXPF_REGISTER_PAGE_REQUEST* request,
    _Out_ KSWORD_ARK_RXPF_PAGE_RESPONSE* response
    );

NTSTATUS
kswRxpfRuntimeChangePage(
    _In_ const KSWORD_ARK_RXPF_RECORD_REQUEST* request,
    _Out_ KSWORD_ARK_RXPF_PAGE_RESPONSE* response
    );

NTSTATUS
kswRxpfRuntimeQueryPage(
    _In_ const KSWORD_ARK_RXPF_RECORD_REQUEST* request,
    _Out_ KSWORD_ARK_RXPF_PAGE_RESPONSE* response
    );

NTSTATUS
kswRxpfRuntimeWritePage(
    _In_ const KSWORD_ARK_RXPF_WRITE_PAGE_REQUEST* request,
    _Out_ KSWORD_ARK_RXPF_PAGE_RESPONSE* response
    );

NTSTATUS
kswRxpfRuntimeSetEmulation(
    _In_ const KSWORD_ARK_RXPF_SET_EMULATION_REQUEST* request,
    _Out_ KSWORD_ARK_RXPF_PAGE_RESPONSE* response
    );

NTSTATUS
kswRxpfRuntimeQueryStats(
    _Out_ KSWORD_ARK_RXPF_STATS_RESPONSE* response
    );

NTSTATUS
kswRxpfRuntimeDrainEvents(
    _In_ const KSWORD_ARK_RXPF_DRAIN_EVENTS_REQUEST* request,
    _Out_ KSWORD_ARK_RXPF_DRAIN_EVENTS_RESPONSE* response
    );

NTSTATUS
kswRxpfRuntimeUnregisterPage(
    _In_ const KSWORD_ARK_RXPF_RECORD_REQUEST* request,
    _Out_ KSWORD_ARK_RXPF_PAGE_RESPONSE* response
    );

NTSTATUS
kswRxpfRuntimeRunSelfTest(
    _In_ const KSWORD_ARK_RXPF_RECORD_REQUEST* request,
    _Out_ KSWORD_ARK_RXPF_SELF_TEST_RESPONSE* response
    );

ULONGLONG
KswRxpfInvokeTestPage(
    _In_ PVOID pageAddress
    );

EXTERN_C_END
