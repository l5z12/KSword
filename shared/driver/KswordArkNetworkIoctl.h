#pragma once

#include "KswordArkProcessIoctl.h"

// ============================================================
// KswordArkNetworkIoctl.h
// Purpose:
// - Defines the R3/R0 network filtering, port hiding control protocol, and read-only network audit query protocol;
// - R0 executes port-level block/allow policies via WFP callouts;
// - Port hiding is expressed via rule snapshots and query interfaces, allowing R3 to filter and display accordingly.
// - Network audit IOCTLs only return snapshot/skeleton status; they do not delete connections, disable WFP, or detach NDIS.
// ============================================================

#define KSWORD_ARK_NETWORK_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_IOCTL_FUNCTION_NETWORK_SET_RULES   0x829UL
#define KSWORD_ARK_IOCTL_FUNCTION_NETWORK_QUERY_STATUS 0x82AUL
#define KSWORD_ARK_IOCTL_FUNCTION_NETWORK_QUERY_TCP_ENDPOINTS 0x8A0UL
#define KSWORD_ARK_IOCTL_FUNCTION_NETWORK_QUERY_UDP_ENDPOINTS 0x8A1UL
#define KSWORD_ARK_IOCTL_FUNCTION_NETWORK_QUERY_WFP_INVENTORY 0x8A2UL
#define KSWORD_ARK_IOCTL_FUNCTION_NETWORK_QUERY_NDIS_CHAIN    0x8A3UL
#define KSWORD_ARK_IOCTL_FUNCTION_NETWORK_QUERY_WFP_EVENTS    0x8A9UL
#define KSWORD_ARK_IOCTL_FUNCTION_NETWORK_QUERY_TRAFFIC_PACKETS 0x8AAUL
#define KSWORD_ARK_IOCTL_FUNCTION_NETWORK_CONTROL_TRAFFIC_CAPTURE 0x8ACUL

#define IOCTL_KSWORD_ARK_NETWORK_SET_RULES \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_NETWORK_SET_RULES, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define IOCTL_KSWORD_ARK_NETWORK_QUERY_STATUS \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_NETWORK_QUERY_STATUS, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_NETWORK_QUERY_TCP_ENDPOINTS, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_NETWORK_QUERY_UDP_ENDPOINTS \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_NETWORK_QUERY_UDP_ENDPOINTS, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_INVENTORY \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_NETWORK_QUERY_WFP_INVENTORY, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_NETWORK_QUERY_NDIS_CHAIN \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_NETWORK_QUERY_NDIS_CHAIN, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_EVENTS \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_NETWORK_QUERY_WFP_EVENTS, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_NETWORK_QUERY_TRAFFIC_PACKETS \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_NETWORK_QUERY_TRAFFIC_PACKETS, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_NETWORK_CONTROL_TRAFFIC_CAPTURE \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_NETWORK_CONTROL_TRAFFIC_CAPTURE, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define KSWORD_ARK_NETWORK_ACTION_DISABLE 0UL
#define KSWORD_ARK_NETWORK_ACTION_REPLACE 1UL
#define KSWORD_ARK_NETWORK_ACTION_CLEAR   2UL

#define KSWORD_ARK_NETWORK_RULE_ACTION_ALLOW     1UL
#define KSWORD_ARK_NETWORK_RULE_ACTION_BLOCK     2UL
#define KSWORD_ARK_NETWORK_RULE_ACTION_HIDE_PORT 3UL

#define KSWORD_ARK_NETWORK_DIRECTION_INBOUND  0x00000001UL
#define KSWORD_ARK_NETWORK_DIRECTION_OUTBOUND 0x00000002UL
#define KSWORD_ARK_NETWORK_DIRECTION_BOTH \
    (KSWORD_ARK_NETWORK_DIRECTION_INBOUND | KSWORD_ARK_NETWORK_DIRECTION_OUTBOUND)

#define KSWORD_ARK_NETWORK_PROTOCOL_ANY 0UL
#define KSWORD_ARK_NETWORK_PROTOCOL_TCP 6UL
#define KSWORD_ARK_NETWORK_PROTOCOL_UDP 17UL

#define KSWORD_ARK_NETWORK_RULE_FLAG_ENABLED 0x00000001UL

#define KSWORD_ARK_NETWORK_RUNTIME_WFP_REGISTERED 0x00000001UL
#define KSWORD_ARK_NETWORK_RUNTIME_WFP_STARTED    0x00000002UL
#define KSWORD_ARK_NETWORK_RUNTIME_RULES_ACTIVE   0x00000004UL
#define KSWORD_ARK_NETWORK_RUNTIME_PORT_HIDE      0x00000008UL
#define KSWORD_ARK_NETWORK_RUNTIME_PACKET_CAPTURE_STARTED 0x00000010UL

#define KSWORD_ARK_NETWORK_STATUS_UNKNOWN          0UL
#define KSWORD_ARK_NETWORK_STATUS_APPLIED          1UL
#define KSWORD_ARK_NETWORK_STATUS_CLEARED          2UL
#define KSWORD_ARK_NETWORK_STATUS_DISABLED         3UL
#define KSWORD_ARK_NETWORK_STATUS_INVALID_RULE     4UL
#define KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE  5UL
#define KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED 6UL
#define KSWORD_ARK_NETWORK_STATUS_AUDIT_UNAVAILABLE 7UL
#define KSWORD_ARK_NETWORK_STATUS_AUDIT_STUB        8UL

#define KSWORD_ARK_NETWORK_MAX_RULES 32UL
#define KSWORD_ARK_NETWORK_AUDIT_MAX_REQUESTED_ROWS 1024UL
#define KSWORD_ARK_NETWORK_WFP_EVENT_PROTOCOL_VERSION 1UL
#define KSWORD_ARK_NETWORK_WFP_EVENT_MAX_REQUESTED_ROWS 512UL
#define KSWORD_ARK_NETWORK_WFP_EVENT_DEFAULT_REQUESTED_ROWS 256UL

#define KSWORD_ARK_NETWORK_TRAFFIC_PROTOCOL_VERSION 1UL
#define KSWORD_ARK_NETWORK_TRAFFIC_MAX_CAPTURE_BYTES 512UL
#define KSWORD_ARK_NETWORK_TRAFFIC_MAX_REQUESTED_ROWS 256UL
#define KSWORD_ARK_NETWORK_TRAFFIC_DEFAULT_REQUESTED_ROWS 128UL

#define KSWORD_ARK_NETWORK_WFP_EVENT_QUERY_FLAG_NONE 0x00000000UL

#define KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_CURSOR_GAP 0x00000001UL
#define KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_TRUNCATED  0x00000002UL
#define KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_CURSOR_RESET 0x00000004UL

#define KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_NO_PAYLOAD             0x00000001UL
#define KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_BLOCKED                0x00000002UL
#define KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ACTION_WRITE_UNAVAILABLE 0x00000004UL
#define KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ALE_CONNECT            0x00000008UL
#define KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ALE_RECV_ACCEPT        0x00000010UL
#define KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_IPV4                   0x00000020UL

#define KSWORD_ARK_NETWORK_TRAFFIC_QUERY_FLAG_NONE 0x00000000UL

#define KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_DISABLE 0UL
#define KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_ENABLE  1UL
#define KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_FLAG_NONE 0x00000000UL

#define KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_CURSOR_GAP   0x00000001UL
#define KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_TRUNCATED    0x00000002UL
#define KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_CURSOR_RESET 0x00000004UL

#define KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_IPV4       0x00000001UL
#define KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_IPV6       0x00000002UL
#define KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_TRUNCATED  0x00000004UL
#define KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_FRAGMENTED 0x00000008UL

#define KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_IPV4 0x00000001UL
#define KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_IPV6 0x00000002UL
#define KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL \
    (KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_IPV4 | \
     KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_IPV6)

#define KSWORD_ARK_NETWORK_AUDIT_SOURCE_NONE          0x00000000UL
#define KSWORD_ARK_NETWORK_AUDIT_SOURCE_TCPIP_PDB     0x00000001UL
#define KSWORD_ARK_NETWORK_AUDIT_SOURCE_NETIO_PDB     0x00000002UL
#define KSWORD_ARK_NETWORK_AUDIT_SOURCE_NDIS_PDB      0x00000004UL
#define KSWORD_ARK_NETWORK_AUDIT_SOURCE_RUNTIME_STATE 0x00000008UL

#define KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE 0x00000001UL
#define KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING   0x00000002UL
#define KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_BUDGET_LIMITED  0x00000004UL
#define KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN   0x00000008UL
#define KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN  0x00000010UL

#define KSWORD_ARK_NETWORK_ADDRESS_FAMILY_UNKNOWN 0UL
#define KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4    4UL
#define KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6    6UL

#define KSWORD_ARK_NETWORK_TCP_STATE_UNKNOWN     0UL
#define KSWORD_ARK_NETWORK_TCP_STATE_CLOSED      1UL
#define KSWORD_ARK_NETWORK_TCP_STATE_LISTEN      2UL
#define KSWORD_ARK_NETWORK_TCP_STATE_SYN_SENT    3UL
#define KSWORD_ARK_NETWORK_TCP_STATE_SYN_RCVD    4UL
#define KSWORD_ARK_NETWORK_TCP_STATE_ESTABLISHED 5UL
#define KSWORD_ARK_NETWORK_TCP_STATE_FIN_WAIT_1  6UL
#define KSWORD_ARK_NETWORK_TCP_STATE_FIN_WAIT_2  7UL
#define KSWORD_ARK_NETWORK_TCP_STATE_CLOSE_WAIT  8UL
#define KSWORD_ARK_NETWORK_TCP_STATE_CLOSING     9UL
#define KSWORD_ARK_NETWORK_TCP_STATE_LAST_ACK    10UL
#define KSWORD_ARK_NETWORK_TCP_STATE_TIME_WAIT   11UL
#define KSWORD_ARK_NETWORK_TCP_STATE_DELETE_TCB  12UL

#define KSWORD_ARK_NETWORK_WFP_OBJECT_PROVIDER  1UL
#define KSWORD_ARK_NETWORK_WFP_OBJECT_SUBLAYER  2UL
#define KSWORD_ARK_NETWORK_WFP_OBJECT_FILTER    3UL
#define KSWORD_ARK_NETWORK_WFP_OBJECT_CALLOUT   4UL

#define KSWORD_ARK_NETWORK_NDIS_OBJECT_UNKNOWN  0UL
#define KSWORD_ARK_NETWORK_NDIS_OBJECT_MINIPORT 1UL
#define KSWORD_ARK_NETWORK_NDIS_OBJECT_FILTER   2UL
#define KSWORD_ARK_NETWORK_NDIS_OBJECT_PROTOCOL 3UL
#define KSWORD_ARK_NETWORK_NDIS_OBJECT_BINDING  4UL

#define KSWORD_ARK_NETWORK_NAME_CHARS 96U

// Network audit generic request. maxRows is the R0 return budget; 0 indicates R0 should use a conservative default budget.
typedef struct _KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long flags;
    unsigned long maxRows;
} KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST;

// WFP ALE event incremental query. If afterSequence=0, read from the oldest event retained by the driver.
typedef struct _KSWORD_ARK_NETWORK_WFP_EVENT_QUERY_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long flags;
    unsigned long maxRows;
    unsigned long long afterSequence;
    unsigned long long reserved;
} KSWORD_ARK_NETWORK_WFP_EVENT_QUERY_REQUEST;

// WFP ALE IPv4 stream authorization event. Addresses are stored as network-byte-order byte arrays; ports are stored in host-byte-order.
// timestamp100ns is the 100ns system time counted from 1601-01-01 UTC; this protocol never carries a payload.
typedef struct _KSWORD_ARK_NETWORK_WFP_EVENT_ROW
{
    unsigned long version;
    unsigned long size;
    unsigned long long sequence;
    unsigned long long timestamp100ns;
    unsigned long direction;
    unsigned long protocol;
    unsigned long processId;
    unsigned long flags;
    unsigned short localPort;
    unsigned short remotePort;
    unsigned char localAddress[4];
    unsigned char remoteAddress[4];
    unsigned long reserved0;
    unsigned long reserved1;
} KSWORD_ARK_NETWORK_WFP_EVENT_ROW;

// WFP ALE event variable-length response. droppedEventCount is the ring's cumulative coverage count; cursorGapCount is the
// number of events that have fallen behind the current oldest event afterSequence and cannot be recovered in this batch.
typedef struct _KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long flags;
    unsigned long availableEventCount;
    unsigned long returnedEventCount;
    unsigned long entrySize;
    unsigned long capacity;
    unsigned long long oldestSequence;
    unsigned long long newestSequence;
    unsigned long long nextSequence;
    unsigned long long droppedEventCount;
    unsigned long long cursorGapCount;
    long lastStatus;
    unsigned long reserved;
    KSWORD_ARK_NETWORK_WFP_EVENT_ROW entries[1];
} KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE;

// WFP IP packet layer incremental query. afterSequence=0 indicates reading from the oldest packet retained by the driver.
typedef struct _KSWORD_ARK_NETWORK_TRAFFIC_QUERY_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long flags;
    unsigned long maxRows;
    unsigned long long afterSequence;
    unsigned long long reserved;
} KSWORD_ARK_NETWORK_TRAFFIC_QUERY_REQUEST;

// WFP IP packet layer per-packet capture start/stop request. Disabling clears the ring to prevent data accumulation after the UI stops.
typedef struct _KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long action;
    unsigned long flags;
} KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_REQUEST;

// WFP per-packet capture start/stop response. Generation increments on each successful start/stop; enabled indicates the actual data plane state.
typedef struct _KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long enabled;
    unsigned long generation;
    long lastStatus;
    unsigned long reserved0;
    unsigned long reserved1;
} KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_RESPONSE;

// WFP IPv4/IPv6 per-packet records. Addresses are stored as network-byte-order arrays, ports as host-byte-order.
// capturedBytes retains only the packet prefix; totalPacketLength/payloadLength always express the complete IP packet.
typedef struct _KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW
{
    unsigned long version;
    unsigned long size;
    unsigned long long sequence;
    unsigned long long timestamp100ns;
    unsigned long addressFamily;
    unsigned long direction;
    unsigned long protocol;
    unsigned long processId;
    unsigned long flags;
    unsigned long totalPacketLength;
    unsigned long capturedLength;
    unsigned long payloadOffset;
    unsigned long payloadLength;
    unsigned short localPort;
    unsigned short remotePort;
    unsigned char localAddress[16];
    unsigned char remoteAddress[16];
    unsigned long reserved0;
    unsigned long reserved1;
    unsigned char capturedBytes[KSWORD_ARK_NETWORK_TRAFFIC_MAX_CAPTURE_BYTES];
} KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW;

// WFP per-packet capture variable-length response. droppedPacketCount is the ring's cumulative overwrite count;
// cursorGapCount is the number of packets that have fallen behind the reserved window afterSequence and cannot be recovered.
typedef struct _KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long flags;
    unsigned long availablePacketCount;
    unsigned long returnedPacketCount;
    unsigned long entrySize;
    unsigned long capacity;
    unsigned long long oldestSequence;
    unsigned long long newestSequence;
    unsigned long long nextSequence;
    unsigned long long droppedPacketCount;
    unsigned long long cursorGapCount;
    long lastStatus;
    unsigned long reserved;
    KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW entries[1];
} KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE;

// TCP/UDP endpoint row. Addresses are stored in 16 bytes; IPv4 uses the first 4 bytes.
typedef struct _KSWORD_ARK_NETWORK_ENDPOINT_ROW
{
    unsigned long rowId;
    unsigned long addressFamily;
    unsigned long protocol;
    unsigned long state;
    unsigned long owningPid;
    unsigned long compartmentId;
    unsigned long interfaceIndex;
    unsigned long flags;
    unsigned short localPort;
    unsigned short remotePort;
    unsigned long sourceFlags;
    unsigned long fieldMask;
    unsigned long reserved0;
    unsigned long reserved1;
    unsigned long long endpointObject;
    unsigned long long owningProcessObject;
    unsigned long long transportObject;
    unsigned long long interfaceLuid;
    unsigned char localAddress[16];
    unsigned char remoteAddress[16];
} KSWORD_ARK_NETWORK_ENDPOINT_ROW;

// TCP/UDP endpoint query response. totalRowCount supports count-first; returnedRowCount is limited by output buffer size.
typedef struct _KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long flags;
    unsigned long totalRowCount;
    unsigned long returnedRowCount;
    unsigned long entrySize;
    unsigned long sourceFlags;
    unsigned long budgetRows;
    unsigned long generation;
    long lastStatus;
    unsigned long reserved;
    KSWORD_ARK_NETWORK_ENDPOINT_ROW entries[1];
} KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE;

// WFP inventory row. GUID fields are stored as raw 16 bytes; function addresses are used for subsequent owner module attribution.
typedef struct _KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW
{
    unsigned long rowId;
    unsigned long objectKind;
    unsigned long flags;
    unsigned long fieldMask;
    unsigned long layerId;
    unsigned long calloutId;
    unsigned long long filterId;
    unsigned long long weight;
    unsigned long long objectAddress;
    unsigned long long classifyAddress;
    unsigned long long notifyAddress;
    unsigned long long flowDeleteAddress;
    unsigned long long ownerImageBase;
    unsigned char providerKey[16];
    unsigned char subLayerKey[16];
    unsigned char objectKey[16];
    wchar_t ownerModule[KSWORD_ARK_NETWORK_NAME_CHARS];
} KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW;

// WFP inventory response. In the skeleton phase, it can return 0 rows and the AUDIT_STUB status.
typedef struct _KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long flags;
    unsigned long totalRowCount;
    unsigned long returnedRowCount;
    unsigned long entrySize;
    unsigned long sourceFlags;
    unsigned long budgetRows;
    unsigned long generation;
    long lastStatus;
    unsigned long reserved;
    KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW entries[1];
} KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE;

// NDIS chain row. The name is a diagnostic tag and does not guarantee inclusion of the full device instance path.
typedef struct _KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW
{
    unsigned long rowId;
    unsigned long objectKind;
    unsigned long flags;
    unsigned long fieldMask;
    unsigned long ifIndex;
    unsigned long filterOrder;
    unsigned long reserved0;
    unsigned long reserved1;
    unsigned long long adapterLuid;
    unsigned long long objectAddress;
    unsigned long long parentObjectAddress;
    unsigned long long driverObject;
    unsigned long long imageBase;
    wchar_t componentName[KSWORD_ARK_NETWORK_NAME_CHARS];
    wchar_t ownerModule[KSWORD_ARK_NETWORK_NAME_CHARS];
} KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW;

// NDIS chain query response. The public device stack can only prove DEVICE_OBJECT attachment
// relationships; except for the provable FILE_DEVICE_PHYSICAL_NETCARD boundary, objectKind must
// be UNKNOWN. Subsequent PDB traversal must maintain bounded traversal and count-first semantics.
typedef struct _KSWORD_ARK_NETWORK_NDIS_CHAIN_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long flags;
    unsigned long totalRowCount;
    unsigned long returnedRowCount;
    unsigned long entrySize;
    unsigned long sourceFlags;
    unsigned long budgetRows;
    unsigned long generation;
    long lastStatus;
    unsigned long reserved;
    KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW entries[1];
} KSWORD_ARK_NETWORK_NDIS_CHAIN_RESPONSE;

// Single network rule. A port value of 0 matches any port; a processId value of 0 matches any process.
typedef struct _KSWORD_ARK_NETWORK_RULE
{
    unsigned long ruleId;
    unsigned long action;
    unsigned long directionMask;
    unsigned long protocol;
    unsigned long processId;
    unsigned long flags;
    unsigned short localPort;
    unsigned short remotePort;
    unsigned long reserved0;
    unsigned long reserved1;
} KSWORD_ARK_NETWORK_RULE;

// Network rule set request. REPLACE overwrites the entire rule snapshot; CLEAR/DISABLE clears the rules.
typedef struct _KSWORD_ARK_NETWORK_SET_RULES_REQUEST
{
    unsigned long version;
    unsigned long action;
    unsigned long ruleCount;
    unsigned long flags;
    KSWORD_ARK_NETWORK_RULE rules[KSWORD_ARK_NETWORK_MAX_RULES];
} KSWORD_ARK_NETWORK_SET_RULES_REQUEST;

// Network rule set response. blockedCount/hiddenPortCount facilitate R3 in quickly displaying capability status.
typedef struct _KSWORD_ARK_NETWORK_SET_RULES_RESPONSE
{
    unsigned long version;
    unsigned long status;
    unsigned long runtimeFlags;
    unsigned long appliedCount;
    unsigned long blockedRuleCount;
    unsigned long hiddenPortRuleCount;
    unsigned long rejectedIndex;
    unsigned long generation;
    long lastStatus;
    unsigned long reserved;
} KSWORD_ARK_NETWORK_SET_RULES_RESPONSE;

// Query network runtime response. The 'rules' field is the current R0 snapshot, allowing R3 to perform port hiding and display filtering based on it.
typedef struct _KSWORD_ARK_NETWORK_STATUS_RESPONSE
{
    unsigned long version;
    unsigned long status;
    unsigned long runtimeFlags;
    unsigned long ruleCount;
    unsigned long blockedRuleCount;
    unsigned long hiddenPortRuleCount;
    unsigned long generation;
    unsigned long reserved;
    unsigned long long classifyCount;
    unsigned long long blockedCount;
    long registerStatus;
    long engineStatus;
    KSWORD_ARK_NETWORK_RULE rules[KSWORD_ARK_NETWORK_MAX_RULES];
} KSWORD_ARK_NETWORK_STATUS_RESPONSE;
