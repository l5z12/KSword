#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "driver/KswordArkNetworkIoctl.h"

EXTERN_C_START

NTSTATUS
kswordArkNetworkInitialize(
    _In_ PDRIVER_OBJECT driverObject,
    _In_opt_ WDFDEVICE device
    );

VOID
kswordArkNetworkUninitialize(
    VOID
    );

NTSTATUS
kswordArkNetworkSetRules(
    _In_ const KSWORD_ARK_NETWORK_SET_RULES_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkNetworkQueryStatus(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkNetworkQueryTcpEndpoints(
    _In_opt_ const KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkNetworkQueryUdpEndpoints(
    _In_opt_ const KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkNetworkQueryWfpInventory(
    _In_opt_ const KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkNetworkQueryNdisChain(
    _In_opt_ const KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkNetworkQueryWfpEvents(
    _In_ const KSWORD_ARK_NETWORK_WFP_EVENT_QUERY_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkNetworkQueryTrafficPackets(
    _In_ const KSWORD_ARK_NETWORK_TRAFFIC_QUERY_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkNetworkControlTrafficCapture(
    _In_ const KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_REQUEST* request,
    _Out_ KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_RESPONSE* response
    );

BOOLEAN
kswordArkNetworkShouldHidePort(
    _In_ ULONG protocol,
    _In_ USHORT localPort,
    _In_ USHORT remotePort,
    _In_ ULONG processId
    );

EXTERN_C_END
