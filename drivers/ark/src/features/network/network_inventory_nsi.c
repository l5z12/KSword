/*++

Module Name:

    network_inventory_nsi.c

Abstract:

    Read-only TCP and UDP endpoint collection through the netio NSI provider.

Environment:

    Kernel mode, PASSIVE_LEVEL only

--*/

#include "network_inventory_internal.h"

#define KSWORD_ARK_NSI_STORE_ACTIVE 1UL
#define KSWORD_ARK_NSI_TCP_ALL_TABLE 3UL
#define KSWORD_ARK_NSI_UDP_ENDPOINT_TABLE 1UL
#define KSWORD_ARK_NSI_TCP_DYNAMIC_BYTES_CURRENT 24UL
#define KSWORD_ARK_NSI_TCP_DYNAMIC_BYTES_LEGACY 16UL
#define KSWORD_ARK_NSI_TCP_STATIC_BYTES 32UL
#define KSWORD_ARK_NSI_UDP_STATIC_BYTES 32UL
#define KSWORD_ARK_NSI_MODULE_ID_GUID 1UL

#define KSWORD_ARK_NSI_AF_INET 2U
#define KSWORD_ARK_NSI_AF_INET6 23U
#define KSWORD_ARK_NSI_IPPROTO_TCP 6UL
#define KSWORD_ARK_NSI_IPPROTO_UDP 17UL

typedef struct KswordArkNsiModuleId
{
    USHORT length;
    ULONG type;
    GUID guid;
} KswordArkNsiModuleId;

typedef struct KswordArkNsiSockaddrV4
{
    USHORT family;
    USHORT port;
    ULONG address;
    UCHAR zero[8];
} KswordArkNsiSockaddrV4;

typedef struct KswordArkNsiSockaddrV6
{
    USHORT family;
    USHORT port;
    ULONG flowInfo;
    UCHAR address[16];
    ULONG scopeId;
} KswordArkNsiSockaddrV6;

typedef union KswordArkNsiSockaddr
{
    KswordArkNsiSockaddrV4 ipv4;
    KswordArkNsiSockaddrV6 ipv6;
    UCHAR bytes[28];
} KswordArkNsiSockaddr;

typedef struct KswordArkNsiTcpKey
{
    KswordArkNsiSockaddr local;
    KswordArkNsiSockaddr remote;
} KswordArkNsiTcpKey;

typedef struct KswordArkNsiTcpStatic
{
    ULONG reserved0[3];
    ULONG processId;
    ULONG64 createTime;
    ULONG64 moduleInfo;
} KswordArkNsiTcpStatic;

typedef struct KswordArkNsiUdpStatic
{
    ULONG processId;
    ULONG reserved0;
    ULONG64 createTime;
    ULONG flags;
    ULONG reserved1;
    ULONG64 moduleInfo;
} KswordArkNsiUdpStatic;

// Note: NSI's undocumented ABI must be protected by strict layout assertions; compilation fails immediately if the size drifts.
C_ASSERT(FIELD_OFFSET(KswordArkNsiModuleId, type) == 4);
C_ASSERT(FIELD_OFFSET(KswordArkNsiModuleId, guid) == 8);
C_ASSERT(sizeof(KswordArkNsiModuleId) == 24);
C_ASSERT(sizeof(KswordArkNsiSockaddrV4) == 16);
C_ASSERT(sizeof(KswordArkNsiSockaddrV6) == 28);
C_ASSERT(sizeof(KswordArkNsiSockaddr) == 28);
C_ASSERT(sizeof(KswordArkNsiTcpKey) == 56);
C_ASSERT(FIELD_OFFSET(KswordArkNsiTcpStatic, processId) == 12);
C_ASSERT(sizeof(KswordArkNsiTcpStatic) == 32);
C_ASSERT(sizeof(KswordArkNsiUdpStatic) == 32);

// {EB004A03-9B1A-11D4-9123-0050047759BC}
static const KswordArkNsiModuleId kKswordArkNsiTcpModuleId =
{
    sizeof(KswordArkNsiModuleId),
    KSWORD_ARK_NSI_MODULE_ID_GUID,
    { 0xeb004a03, 0x9b1a, 0x11d4, { 0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xbc } }
};

// {EB004A02-9B1A-11D4-9123-0050047759BC}
static const KswordArkNsiModuleId kKswordArkNsiUdpModuleId =
{
    sizeof(KswordArkNsiModuleId),
    KSWORD_ARK_NSI_MODULE_ID_GUID,
    { 0xeb004a02, 0x9b1a, 0x11d4, { 0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xbc } }
};

// Note: netio.lib exports this undocumented read-only entry; all sizes are protected by the C_ASSERT above
// and runtime ERROR_INSUFFICIENT_BUFFER failures, never parsing the return buffer based on unknown layouts.
NTSYSAPI
NTSTATUS
NTAPI
NsiAllocateAndGetTable(
    _In_ ULONG store,
    _In_ const KswordArkNsiModuleId* moduleId,
    _In_ ULONG tableId,
    _Outptr_result_bytebuffer_maybenull_(*countOut * keyEntrySize) PVOID* keyTableOut,
    _In_ ULONG keyEntrySize,
    _Outptr_result_bytebuffer_maybenull_(*countOut * readWriteEntrySize) PVOID* readWriteTableOut,
    _In_ ULONG readWriteEntrySize,
    _Outptr_result_bytebuffer_maybenull_(*countOut * dynamicEntrySize) PVOID* dynamicTableOut,
    _In_ ULONG dynamicEntrySize,
    _Outptr_result_bytebuffer_maybenull_(*countOut * staticEntrySize) PVOID* staticTableOut,
    _In_ ULONG staticEntrySize,
    _Out_ ULONG* countOut,
    _In_ ULONG reserved
    );

NTSYSAPI
VOID
NTAPI
NsiFreeTable(
    _In_opt_ PVOID keyTable,
    _In_opt_ PVOID readWriteTable,
    _In_opt_ PVOID dynamicTable,
    _In_opt_ PVOID staticTable
    );

static ULONG
kswordArkNetworkNsiAddressFamily(
    _In_ const KswordArkNsiSockaddr* address
    )
{
    if (address == NULL) {
        return KSWORD_ARK_NETWORK_ADDRESS_FAMILY_UNKNOWN;
    }
    if (address->ipv4.family == KSWORD_ARK_NSI_AF_INET) {
        return KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4;
    }
    if (address->ipv6.family == KSWORD_ARK_NSI_AF_INET6) {
        return KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6;
    }
    return KSWORD_ARK_NETWORK_ADDRESS_FAMILY_UNKNOWN;
}

static BOOLEAN
kswordArkNetworkNsiFamilyRequested(
    _In_ ULONG addressFamily,
    _In_ ULONG queryFlags
    )
{
    if (addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4) {
        return (queryFlags & KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_IPV4) != 0UL;
    }
    if (addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6) {
        return (queryFlags & KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_IPV6) != 0UL;
    }
    return FALSE;
}

static VOID
kswordArkNetworkNsiCopyAddress(
    _Out_writes_(16) UCHAR destination[16],
    _In_ const KswordArkNsiSockaddr* source,
    _In_ ULONG addressFamily
    )
{
    RtlZeroMemory(destination, 16U);
    if (addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4) {
        RtlCopyMemory(destination, &source->ipv4.address, sizeof(source->ipv4.address));
    }
    else if (addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6) {
        RtlCopyMemory(destination, source->ipv6.address, sizeof(source->ipv6.address));
    }
}

static USHORT
kswordArkNetworkNsiHostPort(
    _In_ const KswordArkNsiSockaddr* address
    )
{
    return (address != NULL) ? RtlUshortByteSwap(address->ipv4.port) : 0U;
}

static VOID
kswordArkNetworkNsiFreeSnapshot(
    _In_opt_ PVOID keyTable,
    _In_opt_ PVOID readWriteTable,
    _In_opt_ PVOID dynamicTable,
    _In_opt_ PVOID staticTable
    )
{
    if (keyTable != NULL || readWriteTable != NULL || dynamicTable != NULL || staticTable != NULL) {
        NsiFreeTable(keyTable, readWriteTable, dynamicTable, staticTable);
    }
}

NTSTATUS
kswordArkNetworkCollectNsiEndpoints(
    _In_ BOOLEAN tcpTable,
    _In_ ULONG queryFlags,
    _Out_writes_opt_(rowCapacity) KSWORD_ARK_NETWORK_ENDPOINT_ROW* rows,
    _In_ ULONG rowCapacity,
    _Out_ ULONG* totalRowsOut,
    _Out_ ULONG* returnedRowsOut
    )
/*++

Routine Description:

    Obtain TCP/UDP tables using the read-only NSI provider snapshot from netio.sys. This path
    shares the same data source as IP Helper and does not traverse private tcpip linked lists;
    unprovable object/LUID fields remain zero and are marked with PDB_UNAVAILABLE/FIELD_MISSING.

Return Value:

    STATUS_SUCCESS only indicates a complete NSI snapshot succeeded. In cases of size mismatch or provider
    failure, do not return partially parsed rows; the caller must write an explicit downgrade status.

--*/
{
    const KswordArkNsiModuleId* moduleId =
        tcpTable ? &kKswordArkNsiTcpModuleId : &kKswordArkNsiUdpModuleId;
    const ULONG kTableId = tcpTable ? KSWORD_ARK_NSI_TCP_ALL_TABLE : KSWORD_ARK_NSI_UDP_ENDPOINT_TABLE;
    const ULONG kKeySize = tcpTable ? sizeof(KswordArkNsiTcpKey) : sizeof(KswordArkNsiSockaddr);
    const ULONG kStaticSize = tcpTable ? KSWORD_ARK_NSI_TCP_STATIC_BYTES : KSWORD_ARK_NSI_UDP_STATIC_BYTES;
    const ULONG kDynamicCandidates[] =
    {
        KSWORD_ARK_NSI_TCP_DYNAMIC_BYTES_CURRENT,
        KSWORD_ARK_NSI_TCP_DYNAMIC_BYTES_LEGACY
    };
    PVOID keyTable = NULL;
    PVOID readWriteTable = NULL;
    PVOID dynamicTable = NULL;
    PVOID staticTable = NULL;
    ULONG dynamicSize = tcpTable ? kDynamicCandidates[0] : 0UL;
    ULONG count = 0UL;
    ULONG recognizedFamilyRows = 0UL;
    ULONG candidateIndex = 0UL;
    ULONG index = 0UL;
    ULONG totalRows = 0UL;
    ULONG returnedRows = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (totalRowsOut == NULL || returnedRowsOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *totalRowsOut = 0UL;
    *returnedRowsOut = 0UL;
    if (rows == NULL && rowCapacity != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    for (candidateIndex = 0UL;
         candidateIndex < (tcpTable ? RTL_NUMBER_OF(kDynamicCandidates) : 1UL);
         ++candidateIndex) {
        dynamicSize = tcpTable ? kDynamicCandidates[candidateIndex] : 0UL;
        keyTable = NULL;
        readWriteTable = NULL;
        dynamicTable = NULL;
        staticTable = NULL;
        count = 0UL;

        status = NsiAllocateAndGetTable(
            KSWORD_ARK_NSI_STORE_ACTIVE,
            moduleId,
            kTableId,
            &keyTable,
            kKeySize,
            &readWriteTable,
            0UL,
            &dynamicTable,
            dynamicSize,
            &staticTable,
            kStaticSize,
            &count,
            0UL);
        if (status == STATUS_SUCCESS) {
            break;
        }

        kswordArkNetworkNsiFreeSnapshot(keyTable, readWriteTable, dynamicTable, staticTable);
    }

    if (status != STATUS_SUCCESS) {
        return status;
    }
    if (count != 0UL &&
        (keyTable == NULL || staticTable == NULL || (tcpTable && dynamicTable == NULL))) {
        kswordArkNetworkNsiFreeSnapshot(keyTable, readWriteTable, dynamicTable, staticTable);
        return STATUS_DATA_ERROR;
    }

    // First validate the key ABI, then perform the address family filter; a valid but unrequested address family is not an ABI error.
    for (index = 0UL; index < count; ++index) {
        const UCHAR* keyBytes = (const UCHAR*)keyTable + ((SIZE_T)index * kKeySize);
        const KswordArkNsiSockaddr* localAddress =
            (const KswordArkNsiSockaddr*)keyBytes;
        const ULONG kAddressFamily = kswordArkNetworkNsiAddressFamily(localAddress);

        if (kAddressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4 ||
            kAddressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6) {
            recognizedFamilyRows += 1UL;
        }
    }
    if (count != 0UL && recognizedFamilyRows == 0UL) {
        kswordArkNetworkNsiFreeSnapshot(keyTable, readWriteTable, dynamicTable, staticTable);
        return STATUS_DATA_ERROR;
    }

    for (index = 0UL; index < count; ++index) {
        const UCHAR* keyBytes = (const UCHAR*)keyTable + ((SIZE_T)index * kKeySize);
        const KswordArkNsiSockaddr* localAddress = (const KswordArkNsiSockaddr*)keyBytes;
        const KswordArkNsiSockaddr* remoteAddress = tcpTable ?
            (const KswordArkNsiSockaddr*)(keyBytes + sizeof(KswordArkNsiSockaddr)) : NULL;
        const ULONG kAddressFamily = kswordArkNetworkNsiAddressFamily(localAddress);
        KSWORD_ARK_NETWORK_ENDPOINT_ROW* row = NULL;

        if (!kswordArkNetworkNsiFamilyRequested(kAddressFamily, queryFlags)) {
            continue;
        }

        totalRows += 1UL;
        if (rows == NULL || returnedRows >= rowCapacity) {
            continue;
        }

        row = &rows[returnedRows];
        RtlZeroMemory(row, sizeof(*row));
        row->rowId = returnedRows;
        row->addressFamily = kAddressFamily;
        row->protocol = tcpTable ? KSWORD_ARK_NSI_IPPROTO_TCP : KSWORD_ARK_NSI_IPPROTO_UDP;
        row->flags =
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING;
        row->sourceFlags = KSWORD_ARK_NETWORK_AUDIT_SOURCE_RUNTIME_STATE;
        row->localPort = kswordArkNetworkNsiHostPort(localAddress);
        kswordArkNetworkNsiCopyAddress(row->localAddress, localAddress, kAddressFamily);

        if (tcpTable) {
            const UCHAR* dynamicBytes = (const UCHAR*)dynamicTable + ((SIZE_T)index * dynamicSize);
            const KswordArkNsiTcpStatic* staticRow =
                (const KswordArkNsiTcpStatic*)((const UCHAR*)staticTable +
                    ((SIZE_T)index * kStaticSize));
            RtlCopyMemory(&row->state, dynamicBytes, sizeof(row->state));
            row->owningPid = staticRow->processId;
            row->remotePort = kswordArkNetworkNsiHostPort(remoteAddress);
            kswordArkNetworkNsiCopyAddress(row->remoteAddress, remoteAddress, kAddressFamily);
        }
        else {
            const KswordArkNsiUdpStatic* staticRow =
                (const KswordArkNsiUdpStatic*)((const UCHAR*)staticTable +
                    ((SIZE_T)index * kStaticSize));
            row->state = KSWORD_ARK_NETWORK_TCP_STATE_UNKNOWN;
            row->owningPid = staticRow->processId;
        }

        if (row->owningPid == 0UL) {
            row->flags |= KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN;
        }
        returnedRows += 1UL;
    }

    if (totalRows > returnedRows && rows != NULL) {
        for (index = 0UL; index < returnedRows; ++index) {
            rows[index].flags |= KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_BUDGET_LIMITED;
        }
    }

    kswordArkNetworkNsiFreeSnapshot(keyTable, readWriteTable, dynamicTable, staticTable);
    *totalRowsOut = totalRows;
    *returnedRowsOut = returnedRows;
    return STATUS_SUCCESS;
}
