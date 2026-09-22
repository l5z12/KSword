#pragma once

#include "network_internal.h"

EXTERN_C_START

// Note: Return a read-only snapshot of TCP/UDP endpoints via netio NSI; do not guess tcpip private linked lists.
NTSTATUS
kswordArkNetworkCollectNsiEndpoints(
    _In_ BOOLEAN tcpTable,
    _In_ ULONG queryFlags,
    _Out_writes_opt_(rowCapacity) KSWORD_ARK_NETWORK_ENDPOINT_ROW* rows,
    _In_ ULONG rowCapacity,
    _Out_ ULONG* totalRowsOut,
    _Out_ ULONG* returnedRowsOut
    );

// Note: enumerate global providers, sublayers, callouts, and filters via the official BFE/WFP management interfaces.
NTSTATUS
kswordArkNetworkCollectWfpInventory(
    _Out_writes_opt_(rowCapacity) KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW* rows,
    _In_ ULONG rowCapacity,
    _Out_ ULONG* totalRowsOut,
    _Out_ ULONG* returnedRowsOut
    );

// Note: Traverse and return diagnostic chains via enabled NDIS interfaces with reference-counted safety for device stacks.
NTSTATUS
kswordArkNetworkCollectNdisDeviceStacks(
    _Out_writes_opt_(rowCapacity) KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW* rows,
    _In_ ULONG rowCapacity,
    _Out_ ULONG* totalRowsOut,
    _Out_ ULONG* returnedRowsOut
    );

EXTERN_C_END
