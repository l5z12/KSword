/*++

Module Name:

    network_wfp.c

Abstract:

    WFP callout registration and classify implementation for KswordARK.

Environment:

    Kernel-mode WFP

--*/

#include "network_internal.h"



// This file declares only the minimal WFP ABI actually used by the current implementation to avoid directly including
// fwpsk.h/ndis.h, which would trigger warnings from third-party headers under the current WDK/project Werror combination.
#define KSWORD_ARK_FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4 44U
#define KSWORD_ARK_FWPS_LAYER_ALE_AUTH_CONNECT_V4 48U
#define KSWORD_ARK_FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS 2U
#define KSWORD_ARK_FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT 4U
#define KSWORD_ARK_FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL 5U
#define KSWORD_ARK_FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS 6U
#define KSWORD_ARK_FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT 7U
#define KSWORD_ARK_FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS 2U
#define KSWORD_ARK_FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT 4U
#define KSWORD_ARK_FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL 5U
#define KSWORD_ARK_FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS 6U
#define KSWORD_ARK_FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT 7U
#define KSWORD_ARK_FWPS_METADATA_FIELD_PROCESS_ID 0x00000020U
#define KSWORD_ARK_FWPS_RIGHT_ACTION_WRITE 0x00000001U
#define KSWORD_ARK_FWPS_CLASSIFY_OUT_FLAG_ABSORB 0x00000001U
#define KSWORD_ARK_FWPM_SESSION_FLAG_DYNAMIC 0x00000001U
#define KSWORD_ARK_FWP_EMPTY 0U
#define KSWORD_ARK_FWP_UINT8 1U
#define KSWORD_ARK_FWP_UINT16 2U
#define KSWORD_ARK_FWP_UINT32 3U

// Note: The following three action types are fixed ABI values exposed by WDK fwptypes.h to BFE.
// Note: FWP_ACTION_* values are formed by combining low-order action codes with TERMINATING/CALLOUT flags; they cannot be
// manually constructed as other combinations. Invalid values cause FwpmFilterAdd0 to return STATUS_FWP_INVALID_ACTION_TYPE.
#define KSWORD_ARK_FWP_ACTION_BLOCK 0x00001001U
#define KSWORD_ARK_FWP_ACTION_PERMIT 0x00001002U
#define KSWORD_ARK_FWP_ACTION_CALLOUT_TERMINATING 0x00005003U
#ifndef RPC_C_AUTHN_WINNT
#define RPC_C_AUTHN_WINNT 10U
#endif

typedef VOID* SecWinntAuthIdentityWPtr;
typedef UINT32 KswordArkFwpActionType;
typedef UINT32 KswordArkFwpDataType;
typedef enum KswordArkFwpsCalloutNotifyType
{
    kKswordArkFwpsCalloutNotifyAddFilter = 0,
    kKswordArkFwpsCalloutNotifyDeleteFilter = 1,
    kKswordArkFwpsCalloutNotifyTypeMax = 2
} KswordArkFwpsCalloutNotifyType;

typedef struct KswordArkFwpByteBlob
{
    UINT32 size;
    UINT8* data;
} KswordArkFwpByteBlob;

typedef struct KswordArkFwpByteArraY16
{
    UINT8 byteArray16[16];
} KswordArkFwpByteArraY16;

typedef struct KswordArkFwpValuE0
{
    KswordArkFwpDataType type;
    union
    {
        UINT8 uint8;
        UINT16 uint16;
        UINT32 uint32;
        UINT64* uint64;
        INT8 int8;
        INT16 int16;
        INT32 int32;
        INT64* int64;
        float float32;
        double* double64;
        KswordArkFwpByteArraY16* byteArray16;
        KswordArkFwpByteBlob* byteBlob;
        VOID* sid;
        UINT8* sd;
        VOID* tokenInformation;
        UINT64* tokenAccessInformation;
        LPWSTR unicodeString;
        KswordArkFwpByteBlob* byteBlobArray6;
        VOID* bitmapArray64;
    } value;
} KswordArkFwpValuE0;

typedef struct KswordArkFwpsIncomingValuE0
{
    UINT16 fieldId;
    KswordArkFwpValuE0 value;
} KswordArkFwpsIncomingValuE0;

typedef struct KswordArkFwpsIncomingValueS0
{
    UINT16 layerId;
    UINT32 valueCount;
    KswordArkFwpsIncomingValuE0* incomingValue;
} KswordArkFwpsIncomingValueS0;

// Note: FWPS_INCOMING_METADATA_VALUES0 includes a fixed FWPS_DISCARD_METADATA0 before processId. Even if this
// feature does not read the discard reason, it cannot be omitted, otherwise subsequent processId reads would occur
// at an incorrect offset. Here, only the official prefix layout is copied, without relying on versioned fields.
typedef struct KswordArkFwpsDiscardMetadatA0
{
    UINT32 discardModule;
    UINT32 discardReason;
    UINT64 filterId;
} KswordArkFwpsDiscardMetadatA0;

typedef struct KswordArkFwpsIncomingMetadataValueS0
{
    UINT32 currentMetadataValues;
    UINT32 flags;
    UINT64 reserved;
    KswordArkFwpsDiscardMetadatA0 discardMetadata;
    UINT64 flowHandle;
    UINT32 ipHeaderSize;
    UINT32 transportHeaderSize;
    VOID* processPath;
    UINT64 token;
    UINT64 processId;
} KswordArkFwpsIncomingMetadataValueS0;

// Note: In the official stable prefix of FWPS_INCOMING_METADATA_VALUES0, processId is located at offset 64 bytes.
// Compile-time protection prevents future 'simplification' of unused fields from breaking the classify ABI again.
C_ASSERT(FIELD_OFFSET(KswordArkFwpsIncomingMetadataValueS0, processId) == 64);

typedef struct KswordArkFwpsFilteR0
{
    UINT64 filterId;
    UINT64 weight;
    UINT16 subLayerWeight;
    UINT16 flags;
    UINT32 numFilterConditions;
    VOID* filterCondition;
    KswordArkFwpActionType actionType;
    UINT64 context;
    GUID* providerContextKey;
} KswordArkFwpsFilteR0;

typedef struct KswordArkFwpsClassifyOuT0
{
    KswordArkFwpActionType actionType;
    UINT64 outContext;
    UINT64 filterId;
    UINT32 rights;
    UINT32 flags;
    UINT32 reserved;
} KswordArkFwpsClassifyOuT0;

typedef VOID (NTAPI* KswordArkFwpsCalloutClassifyFN0)(
    _In_ const KswordArkFwpsIncomingValueS0* inFixedValues,
    _In_ const KswordArkFwpsIncomingMetadataValueS0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_ const KswordArkFwpsFilteR0* filter,
    _In_ UINT64 flowContext,
    _Inout_ KswordArkFwpsClassifyOuT0* classifyOut);

typedef NTSTATUS (NTAPI* KswordArkFwpsCalloutNotifyFN0)(
    _In_ KswordArkFwpsCalloutNotifyType notifyType,
    _In_ const GUID* filterKey,
    _Inout_ const KswordArkFwpsFilteR0* filter);

typedef VOID (NTAPI* KswordArkFwpsCalloutFlowDeleteNotifyFN0)(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext);

typedef struct KswordArkFwpsCallouT0
{
    GUID calloutKey;
    UINT32 flags;
    KswordArkFwpsCalloutClassifyFN0 classifyFn;
    KswordArkFwpsCalloutNotifyFN0 notifyFn;
    KswordArkFwpsCalloutFlowDeleteNotifyFN0 flowDeleteFn;
} KswordArkFwpsCallouT0;

typedef struct KswordArkFwpmDisplayDatA0
{
    WCHAR* name;
    WCHAR* description;
} KswordArkFwpmDisplayDatA0;

typedef struct KswordArkFwpmSessioN0
{
    GUID sessionKey;
    KswordArkFwpmDisplayDatA0 displayData;
    UINT32 flags;
    UINT32 txnWaitTimeoutInMSec;
    UINT32 processId;
    VOID* sid;
    WCHAR* username;
    BOOLEAN kernelMode;
} KswordArkFwpmSessioN0;

typedef struct KswordArkFwpmCallouT0
{
    GUID calloutKey;
    KswordArkFwpmDisplayDatA0 displayData;
    UINT32 flags;
    GUID* providerKey;
    KswordArkFwpByteBlob providerData;
    GUID applicableLayer;
    UINT32 calloutId;
} KswordArkFwpmCallouT0;

// Note: The type field of FWPM_ACTION0 is independent; the GUID union follows, interpreted based on type.
// Note: Declaring the entire object as a union is not allowed; writing to calloutKey would overwrite type and trigger an issue.
// STATUS_FWP_INVALID_ACTION_TYPE。
typedef struct KswordArkFwpmActioN0
{
    // Note: type preserves the FWP_ACTION_TYPE validated by BFE, avoiding shared storage with GUID.
    KswordArkFwpActionType type;
    union
    {
        // Note: filterType is used only for standard filter actions.
        GUID filterType;
        // Note: calloutKey identifies the kernel callout corresponding to the CALLOUT action.
        GUID calloutKey;
    } actionKey;
} KswordArkFwpmActioN0;

// Note: Fixed check of WDK FWPM_ACTION0 ABI to prevent GUID from overwriting type in future refactoring.
C_ASSERT(FIELD_OFFSET(KswordArkFwpmActioN0, actionKey) == sizeof(KswordArkFwpActionType));
C_ASSERT(sizeof(KswordArkFwpmActioN0) == (sizeof(KswordArkFwpActionType) + sizeof(GUID)));

typedef struct KswordArkFwpmFilteR0
{
    GUID filterKey;
    KswordArkFwpmDisplayDatA0 displayData;
    UINT32 flags;
    GUID* providerKey;
    KswordArkFwpByteBlob providerData;
    GUID layerKey;
    GUID subLayerKey;
    KswordArkFwpValuE0 weight;
    UINT32 numFilterConditions;
    VOID* filterCondition;
    KswordArkFwpmActioN0 action;
    union
    {
        UINT64 rawContext;
        GUID providerContextKey;
    } rawContextUnion;
    GUID* reserved;
    UINT64 filterId;
    KswordArkFwpValuE0 effectiveWeight;
} KswordArkFwpmFilteR0;

typedef struct KswordArkFwpmSublayeR0
{
    GUID subLayerKey;
    KswordArkFwpmDisplayDatA0 displayData;
    UINT32 flags;
    GUID* providerKey;
    KswordArkFwpByteBlob providerData;
    UINT16 weight;
} KswordArkFwpmSublayeR0;

NTSYSAPI
NTSTATUS
NTAPI
FwpsCalloutRegister0(
    _Inout_ PDEVICE_OBJECT deviceObject,
    _In_ const KswordArkFwpsCallouT0* callout,
    _Out_opt_ UINT32* calloutId);

NTSYSAPI
NTSTATUS
NTAPI
FwpsCalloutUnregisterById0(
    _In_ UINT32 calloutId);

NTSYSAPI
NTSTATUS
NTAPI
FwpmEngineOpen0(
    _In_opt_ const WCHAR* serverName,
    _In_ UINT32 authnService,
    _In_opt_ SecWinntAuthIdentityWPtr authIdentity,
    _In_opt_ const KswordArkFwpmSessioN0* session,
    _Out_ HANDLE* engineHandle);

NTSYSAPI
NTSTATUS
NTAPI
FwpmEngineClose0(
    _In_ HANDLE engineHandle);

NTSYSAPI
NTSTATUS
NTAPI
FwpmTransactionBegin0(
    _In_ HANDLE engineHandle,
    _In_ UINT32 flags);

NTSYSAPI
NTSTATUS
NTAPI
FwpmTransactionCommit0(
    _In_ HANDLE engineHandle);

NTSYSAPI
NTSTATUS
NTAPI
FwpmTransactionAbort0(
    _In_ HANDLE engineHandle);

NTSYSAPI
NTSTATUS
NTAPI
FwpmSubLayerAdd0(
    _In_ HANDLE engineHandle,
    _In_ const KswordArkFwpmSublayeR0* subLayer,
    _In_opt_ PSECURITY_DESCRIPTOR sd);

NTSYSAPI
NTSTATUS
NTAPI
FwpmSubLayerDeleteByKey0(
    _In_ HANDLE engineHandle,
    _In_ const GUID* key);

NTSYSAPI
NTSTATUS
NTAPI
FwpmCalloutAdd0(
    _In_ HANDLE engineHandle,
    _In_ const KswordArkFwpmCallouT0* callout,
    _In_opt_ PSECURITY_DESCRIPTOR sd,
    _Out_opt_ UINT32* id);

NTSYSAPI
NTSTATUS
NTAPI
FwpmCalloutDeleteByKey0(
    _In_ HANDLE engineHandle,
    _In_ const GUID* key);

NTSYSAPI
NTSTATUS
NTAPI
FwpmFilterAdd0(
    _In_ HANDLE engineHandle,
    _In_ const KswordArkFwpmFilteR0* filter,
    _In_opt_ PSECURITY_DESCRIPTOR sd,
    _Out_opt_ UINT64* id);

NTSYSAPI
NTSTATUS
NTAPI
FwpmFilterDeleteById0(
    _In_ HANDLE engineHandle,
    _In_ UINT64 id);

// {D2B28BC6-9E08-4D07-9F7B-2BA821D8AA51}
static const GUID kKswordArkWfpSublayer =
{ 0xd2b28bc6, 0x9e08, 0x4d07, { 0x9f, 0x7b, 0x2b, 0xa8, 0x21, 0xd8, 0xaa, 0x51 } };

// {9CEBA6FD-DC43-4E48-A013-FDB83823674B}
static const GUID kKswordArkWfpConnectCallout =
{ 0x9ceba6fd, 0xdc43, 0x4e48, { 0xa0, 0x13, 0xfd, 0xb8, 0x38, 0x23, 0x67, 0x4b } };

// {75FCE1D8-0E28-4C58-9957-90181B75B6AA}
static const GUID kKswordArkWfpRecvAcceptCallout =
{ 0x75fce1d8, 0x0e28, 0x4c58, { 0x99, 0x57, 0x90, 0x18, 0x1b, 0x75, 0xb6, 0xaa } };

// {C38D57D1-05A7-4C33-904F-7FBCEEE60E82}
static const GUID kKswordArkFwpmLayerAleAuthConnectV4 =
{ 0xc38d57d1, 0x05a7, 0x4c33, { 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82 } };

// {E1CD9FE7-F4B5-4273-96C0-592E487B8650}
static const GUID kKswordArkFwpmLayerAleAuthRecvAcceptV4 =
{ 0xe1cd9fe7, 0xf4b5, 0x4273, { 0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50 } };

static UINT16
kswordArkNetworkReadHostOrderPort(
    _In_ UINT16 hostOrderValue
    )
/*++

Routine Description:

    Read WFP FWP_UINT16 port. Note: The WFP specification explicitly states that
    FWP_UINT16 IP ports use host byte order and must not be byte-swapped again.

Arguments:

    HostOrderValue: 16-bit port in host byte order provided by WFP.

Return Value:

    Host byte order port.

--*/
{
    // Note: WFP already provides host order; return directly to avoid port reversal.
    return hostOrderValue;
}

static ULONG
kswordArkNetworkReadUint32Field(
    _In_ const KswordArkFwpsIncomingValueS0* values,
    _In_ UINT32 fieldIndex
    )
/*++

Routine Description:

    Read UINT32 fields from WFP incoming values. Note: The caller provides the
    layer-specific field index; the function performs only bounds and type width protection.

Arguments:

    Values: WFP classification input field set.
    FieldIndex - Field index.

Return Value:

    Field value; returns 0 if the field does not exist.

--*/
{
    // Note: The WFP array pointer, index, and stable FWP_UINT32 type must all be valid simultaneously.
    if (values == NULL ||
        values->incomingValue == NULL ||
        fieldIndex >= values->valueCount ||
        values->incomingValue[fieldIndex].value.type != KSWORD_ARK_FWP_UINT32) {
        // Note: Return 0 when field is missing or union type mismatch; disallow erroneous union interpretation.
        return 0UL;
    }
    // Note: Type validated; safe to read uint32 union member.
    return values->incomingValue[fieldIndex].value.value.uint32;
}

static ULONG
kswordArkNetworkReadUint16Field(
    _In_ const KswordArkFwpsIncomingValueS0* values,
    _In_ UINT32 fieldIndex
    )
/*++

Routine Description:

    Read a UINT16 field from WFP incoming values. Note: The port field is read per
    WFP definition; the caller decides whether to perform byte-order conversion.

Arguments:

    Values: WFP classification input field set.
    FieldIndex - Field index.

Return Value:

    Field value; returns 0 if the field does not exist.

--*/
{
    // Note: The WFP array pointer, index, and stable FWP_UINT16 type must all be valid simultaneously.
    if (values == NULL ||
        values->incomingValue == NULL ||
        fieldIndex >= values->valueCount ||
        values->incomingValue[fieldIndex].value.type != KSWORD_ARK_FWP_UINT16) {
        // Note: Return 0 when the field is missing or the union type does not match.
        return 0UL;
    }
    // Note: The type is validated, so it is safe to read the uint16 union member.
    return (ULONG)values->incomingValue[fieldIndex].value.value.uint16;
}

static ULONG
kswordArkNetworkReadUint8Field(
    _In_ const KswordArkFwpsIncomingValueS0* values,
    _In_ UINT32 fieldIndex
    )
/*++

Routine Description:

    Read the UINT8 field from WFP incoming values. Note: ALE IP_PROTOCOL
    is FWP_UINT8 and cannot be interpreted using a UINT32 union member.

Arguments:

    Values: WFP classification input field set.
    FieldIndex - Field index.

Return Value:

    Field value; returns 0 if the field does not exist.

--*/
{
    // Note: Validate WFP field array bounds first.
    if (values == NULL ||
        values->incomingValue == NULL ||
        fieldIndex >= values->valueCount ||
        values->incomingValue[fieldIndex].value.type != KSWORD_ARK_FWP_UINT8) {
        // Note: Return 0 when the field is unavailable or the union type does not match.
        return 0UL;
    }
    // Note: Protocol fields are read as FWP_UINT8 and expanded to ULONG.
    return (ULONG)values->incomingValue[fieldIndex].value.value.uint8;
}

static ULONG
kswordArkNetworkReadProcessId(
    _In_ const KswordArkFwpsIncomingMetadataValueS0* metadata
    )
/*++

Routine Description:

    Extract the process ID from WFP metadata. Note: Not all layers provide a processId;
    if missing, return 0 so rules matching only on port/protocol still work.

Arguments:

    Metadata - WFP metadata。

Return Value:

    Process ID; returns 0 if unknown.

--*/
{
    if (metadata == NULL) {
        return 0UL;
    }
    if ((metadata->currentMetadataValues & KSWORD_ARK_FWPS_METADATA_FIELD_PROCESS_ID) == 0ULL) {
        return 0UL;
    }
    return (ULONG)(ULONG_PTR)metadata->processId;
}

static BOOLEAN
kswordArkNetworkClassifyExtractTuple(
    _In_ const KswordArkFwpsIncomingValueS0* values,
    _In_ const KswordArkFwpsIncomingMetadataValueS0* metadata,
    _Out_ ULONG* directionOut,
    _Out_ ULONG* protocolOut,
    _Out_ ULONG* localAddressV4Out,
    _Out_ ULONG* remoteAddressV4Out,
    _Out_ USHORT* localPortOut,
    _Out_ USHORT* remotePortOut,
    _Out_ ULONG* processIdOut
    )
/*++

Routine Description:

    Extract rule matching and event summaries from the ALE connect/recv-accept layer. Note: Currently covers only IPv4;
    the driver retains the original protocol number, while the R3 monitoring page currently displays only TCP/UDP.

Arguments:

    Values: WFP classification input field set.
    Metadata - WFP metadata。
    DirectionOut - Returns inbound/outbound direction.
    ProtocolOut - Returns the protocol number.
    LocalAddressV4Out - Returns the host-order local IPv4 address.
    RemoteAddressV4Out: Returns host-order remote IPv4 address.
    LocalPortOut - Returns the local port.
    RemotePortOut - Returns the remote port.
    ProcessIdOut - Returns the process ID.

Return Value:

    TRUE indicates successful field extraction; FALSE indicates the layer is unsupported.

--*/
{
    // Note: Save the local port provided by WFP in host order.
    UINT16 localPortHost = 0U;
    // Note: Save the remote port provided by WFP in host order.
    UINT16 remotePortHost = 0U;

    // Note: All output fields must be writable to avoid partial initialization in the classify hot path.
    if (values == NULL || directionOut == NULL || protocolOut == NULL ||
        localAddressV4Out == NULL || remoteAddressV4Out == NULL ||
        localPortOut == NULL || remotePortOut == NULL || processIdOut == NULL) {
        // Note: Reject event formation when parameters are invalid.
        return FALSE;
    }

    // Note: ALE_AUTH_CONNECT_V4 indicates outbound flow authorization.
    if (values->layerId == KSWORD_ARK_FWPS_LAYER_ALE_AUTH_CONNECT_V4) {
        // Note: The connect layer is fixedly mapped to outbound.
        *directionOut = KSWORD_ARK_NETWORK_DIRECTION_OUTBOUND;
        // Note: The protocol field is read as FWP_UINT8.
        *protocolOut = kswordArkNetworkReadUint8Field(values, KSWORD_ARK_FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL);
        // Note: IPv4 address fields are read in host byte order as FWP_UINT32.
        *localAddressV4Out = kswordArkNetworkReadUint32Field(values, KSWORD_ARK_FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS);
        // Note: Read host-order remote IPv4.
        *remoteAddressV4Out = kswordArkNetworkReadUint32Field(values, KSWORD_ARK_FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS);
        // Note: Read host-order local port.
        localPortHost = (UINT16)kswordArkNetworkReadUint16Field(values, KSWORD_ARK_FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT);
        // Note: Read host-order remote port.
        remotePortHost = (UINT16)kswordArkNetworkReadUint16Field(values, KSWORD_ARK_FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT);
    }
    // Note: ALE_AUTH_RECV_ACCEPT_V4 indicates inbound flow authorization.
    else if (values->layerId == KSWORD_ARK_FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4) {
        // Note: The recv-accept layer is fixedly mapped to inbound traffic.
        *directionOut = KSWORD_ARK_NETWORK_DIRECTION_INBOUND;
        // Note: The protocol field is read as FWP_UINT8.
        *protocolOut = kswordArkNetworkReadUint8Field(values, KSWORD_ARK_FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL);
        // Note: Read host-order local IPv4.
        *localAddressV4Out = kswordArkNetworkReadUint32Field(values, KSWORD_ARK_FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS);
        // Note: Read host-order remote IPv4.
        *remoteAddressV4Out = kswordArkNetworkReadUint32Field(values, KSWORD_ARK_FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS);
        // Note: Read host-order local port.
        localPortHost = (UINT16)kswordArkNetworkReadUint16Field(values, KSWORD_ARK_FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT);
        // Note: Read host-order remote port.
        remotePortHost = (UINT16)kswordArkNetworkReadUint16Field(values, KSWORD_ARK_FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT);
    }
    else {
        // Note: IPv6 and other layer versions do not write to the IPv4 event ring.
        return FALSE;
    }

    // Note: WFP port is already in host byte order; the helper explicitly avoids a second byte-order swap.
    *localPortOut = kswordArkNetworkReadHostOrderPort(localPortHost);
    // Note: Preserve the host-order value of the remote port.
    *remotePortOut = kswordArkNetworkReadHostOrderPort(remotePortHost);
    // Note: The helper returns 0 when the PID is missing.
    *processIdOut = kswordArkNetworkReadProcessId(metadata);
    // Note: The complete IPv4 ALE summary has been formed.
    return TRUE;
}

static BOOLEAN
kswordArkNetworkShouldBlockClassify(
    _In_ ULONG direction,
    _In_ ULONG protocol,
    _In_ USHORT localPort,
    _In_ USHORT remotePort,
    _In_ ULONG processId
    )
/*++

Routine Description:

    Find a blocking rule in the snapshot. Matching allow rules take precedence and return FALSE;
    matching block rules return TRUE. hide-port rules do not affect whether network traffic is allowed.

Arguments:

    Direction - Current direction.
    Protocol - protocol number.
    LocalPort - Local port.
    RemotePort: Remote port.
    ProcessId - Process ID.

Return Value:

    TRUE indicates block; FALSE indicates allow.

--*/
{
    KswordArkNetworkRuntime* runtime = kswordArkNetworkGetRuntime();
    KIRQL oldIrql = PASSIVE_LEVEL;
    ULONG ruleIndex = 0UL;
    BOOLEAN shouldBlock = FALSE;

    if (InterlockedCompareExchange(
            &runtime->classifyRulesActive,
            0L,
            0L) == 0L) {
        return FALSE;
    }

    KeAcquireSpinLock(&runtime->classifyRuleLock, &oldIrql);
    for (ruleIndex = 0UL; ruleIndex < KSWORD_ARK_NETWORK_MAX_RULES; ++ruleIndex) {
        const KSWORD_ARK_NETWORK_RULE* rule = &runtime->classifyRules[ruleIndex];
        if (rule->action != KSWORD_ARK_NETWORK_RULE_ACTION_ALLOW &&
            rule->action != KSWORD_ARK_NETWORK_RULE_ACTION_BLOCK) {
            continue;
        }
        if (!kswordArkNetworkRuleMatchesLocked(
            rule,
            direction,
            protocol,
            localPort,
            remotePort,
            processId)) {
            continue;
        }
        shouldBlock = (rule->action == KSWORD_ARK_NETWORK_RULE_ACTION_BLOCK) ? TRUE : FALSE;
        break;
    }
    KeReleaseSpinLock(&runtime->classifyRuleLock, oldIrql);

    return shouldBlock;
}

VOID NTAPI
kswordArkNetworkClassifyFn(
    _In_ const KswordArkFwpsIncomingValueS0* inFixedValues,
    _In_ const KswordArkFwpsIncomingMetadataValueS0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_ const KswordArkFwpsFilteR0* filter,
    _In_ UINT64 flowContext,
    _Inout_ KswordArkFwpsClassifyOuT0* classifyOut
    )
/*++

Routine Description:

    WFP ALE classify callback. Note: Record real payload-less stream events for every supported IPv4
    connect/recv-accept authorization; set BLOCK only when ACTION_WRITE is present and the rule matches.

Arguments:

    inFixedValues: WFP input fields.
    inMetaValues - WFP metadata。
    layerData - Unused.
    filter - unused.
    flowContext - Unused.
    classifyOut: WFP action output.

Return Value:

    None. This function has no return value.

--*/
{
    // Note: Retrieve static non-paged network runtime.
    KswordArkNetworkRuntime* runtime = kswordArkNetworkGetRuntime();
    // Note: saves the inbound/outbound direction derived from the ALE layer.
    ULONG direction = 0UL;
    // Note: Save the FWP_UINT8 IP protocol number.
    ULONG protocol = 0UL;
    // Note: Save FWP_UINT32 host-order local IPv4.
    ULONG localAddressV4 = 0UL;
    // Note: Save FWP_UINT32 host-order remote IPv4.
    ULONG remoteAddressV4 = 0UL;
    // Note: Save the FWP_UINT16 host-order local port.
    USHORT localPort = 0U;
    // Note: Save the FWP_UINT16 host-order remote port.
    USHORT remotePort = 0U;
    // Note: Save the WFP metadata PID.
    ULONG processId = 0UL;
    // Note: Save whether this callout actually blocked the traffic.
    BOOLEAN shouldBlock = FALSE;
    // Note: Save whether the current classify allows writing the action.
    BOOLEAN actionWritable = FALSE;
    // Note: Save the semantic flags for writing to the shared event row.
    ULONG eventFlags = 0UL;

    // Note: The current ALE event channel does not read layerData.
    UNREFERENCED_PARAMETER(layerData);
    // Note: The current ALE event channel does not read the filter context.
    UNREFERENCED_PARAMETER(filter);
    // Note: The current ALE event channel does not allocate a flow context.
    UNREFERENCED_PARAMETER(flowContext);

    // Note: The static runtime theoretically always exists; do not access counters if the value is null.
    if (runtime == NULL) {
        // Note: Do not interfere with other WFP policies.
        return;
    }

    // Note: Count all classify calls reaching this callout, including read-only arbitration calls.
    InterlockedIncrement64(&runtime->classifyCount);
    // Note: Extract full metadata only for supported IPv4 connect/recv-accept layers.
    if (!kswordArkNetworkClassifyExtractTuple(
        inFixedValues,
        inMetaValues,
        &direction,
        &protocol,
        &localAddressV4,
        &remoteAddressV4,
        &localPort,
        &remotePort,
        &processId)) {
        // Note: Maintain default allow behavior when the field is unsupported but action is writable.
        if (classifyOut != NULL &&
            (classifyOut->rights & KSWORD_ARK_FWPS_RIGHT_ACTION_WRITE) != 0U) {
            // Note: Unknown layer is not blocked by this callout.
            classifyOut->actionType = KSWORD_ARK_FWP_ACTION_PERMIT;
        }
        // Note: Do not forge events for classify operations that cannot form a complete IPv4 five-tuple.
        return;
    }

    // Note: Only a non-null classifyOut holding ACTION_WRITE can modify the arbitration result.
    actionWritable =
        classifyOut != NULL &&
        (classifyOut->rights & KSWORD_ARK_FWPS_RIGHT_ACTION_WRITE) != 0U;
    // Note: Execute existing rule checks only for writable actions to avoid marking blocks that were not actually executed.
    if (actionWritable) {
        // Note: Read rule snapshot and compute final block decision.
        shouldBlock = kswordArkNetworkShouldBlockClassify(
            direction,
            protocol,
            localPort,
            remotePort,
            processId);
    }

    // Note: Mark the event source based on the actual ALE layer.
    eventFlags =
        (inFixedValues->layerId == KSWORD_ARK_FWPS_LAYER_ALE_AUTH_CONNECT_V4) ?
        KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ALE_CONNECT :
        KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ALE_RECV_ACCEPT;
    // Note: Explicitly mark as read-only observation without modification when action write permission is unavailable.
    if (!actionWritable) {
        // Note: R3 uses this to avoid mistaking rule pre-evaluation for actual actions.
        eventFlags |= KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ACTION_WRITE_UNAVAILABLE;
    }
    // Note: Write the blocked flag only when actually preparing to set BLOCK.
    if (shouldBlock) {
        // Note: The event semantics are consistent with the actual action below.
        eventFlags |= KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_BLOCKED;
    }

    // Note: Write to a fixed non-paged ring before modifying classifyOut; this function uses only spin locks.
    kswordArkNetworkRecordWfpAleEvent(
        direction,
        protocol,
        localAddressV4,
        remoteAddressV4,
        localPort,
        remotePort,
        processId,
        eventFlags);

    // Note: If no action write permission exists, only log the event without interfering with existing arbitration results.
    if (!actionWritable) {
        // Note: event completed, return immediately.
        return;
    }

    // Note: Execute existing block action when rule is matched.
    if (shouldBlock) {
        // Note: Set terminating block.
        classifyOut->actionType = KSWORD_ARK_FWP_ACTION_BLOCK;
        // Note: Clear action write permissions to prevent lower-weight filters from modifying the state later.
        classifyOut->rights &= ~KSWORD_ARK_FWPS_RIGHT_ACTION_WRITE;
        // Note: Absorb hit traffic to maintain existing blocking behavior.
        classifyOut->flags |= KSWORD_ARK_FWPS_CLASSIFY_OUT_FLAG_ABSORB;
        // Accumulate actual block count.
        InterlockedIncrement64(&runtime->blockedCount);
    }
    else {
        // Note: Explicitly permit when no block rule is matched.
        classifyOut->actionType = KSWORD_ARK_FWP_ACTION_PERMIT;
    }
}

NTSTATUS NTAPI
kswordArkNetworkNotifyFn(
    _In_ KswordArkFwpsCalloutNotifyType notifyType,
    _In_ const GUID* filterKey,
    _Inout_ const KswordArkFwpsFilteR0* filter
    )
/*++

Routine Description:

    WFP notify callback. Note: Flow context is not maintained, so notifications are accepted and success is returned.

Arguments:

    notifyType - Notification type.
    filterKey: Filter key.
    filter: Filter object.

Return Value:

    STATUS_SUCCESS。

--*/
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

VOID NTAPI
kswordArkNetworkFlowDeleteFn(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
    )
/*++

Routine Description:

    WFP flow-delete callback. Note: No flow context is allocated, so no resources need to be released.

Arguments:

    layerId - WFP layer ID.
    calloutId - callout ID。
    flowContext: The flow context.

Return Value:

    None. This function has no return value.

--*/
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowContext);
}

static NTSTATUS
kswordArkNetworkRegisterCallout(
    _In_ KswordArkNetworkRuntime* runtime,
    _In_ const GUID* calloutKey,
    _Out_ UINT32* calloutIdOut
    )
/*++

Routine Description:

    Register the kernel classify entry point via FwpsCalloutRegister. Note:
    Two ALE layers share the same classify function, distinguished by layerId.

Arguments:

    Runtime: Network runtime.
    CalloutKey - callout GUID。
    CalloutIdOut - Returns the callout ID.

Return Value:

    Returns status from FwpsCalloutRegister0.

--*/
{
    KswordArkFwpsCallouT0 callout;

    if (runtime == NULL || runtime->deviceObject == NULL || calloutKey == NULL || calloutIdOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = *calloutKey;
    callout.classifyFn = kswordArkNetworkClassifyFn;
    callout.notifyFn = kswordArkNetworkNotifyFn;
    callout.flowDeleteFn = kswordArkNetworkFlowDeleteFn;
    return FwpsCalloutRegister0(
        runtime->deviceObject,
        &callout,
        calloutIdOut);
}

static NTSTATUS
kswordArkNetworkAddCalloutToEngine(
    _In_ KswordArkNetworkRuntime* runtime,
    _In_ const GUID* calloutKey,
    _In_ const GUID* layerKey,
    _In_z_ PCWSTR displayName
    )
/*++

Routine Description:

    Add a callout object to BFE. Note: An FWPM callout must be
    bound to a specific layer before filters can reference it.

Arguments:

    Runtime: Network runtime.
    CalloutKey - callout GUID。
    LayerKey - WFP layer GUID。
    DisplayName - Display name.

Return Value:

    Returns the status from FwpmCalloutAdd0.

--*/
{
    KswordArkFwpmCallouT0 callout;

    if (runtime == NULL || runtime->engineHandle == NULL || calloutKey == NULL || layerKey == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = *calloutKey;
    callout.displayData.name = (PWSTR)displayName;
    callout.applicableLayer = *layerKey;
    return FwpmCalloutAdd0(runtime->engineHandle, &callout, NULL, NULL);
}

static NTSTATUS
kswordArkNetworkAddFilter(
    _In_ KswordArkNetworkRuntime* runtime,
    _In_ const GUID* calloutKey,
    _In_ const GUID* layerKey,
    _In_z_ PCWSTR displayName,
    _Out_ UINT64* filterIdOut
    )
/*++

Routine Description:

    Add a callout filter matching all traffic. Note: Specific allow/block decisions are determined
    by the KswordARK rule table inside classify; the filter itself does not store user rules.

Arguments:

    Runtime: Network runtime.
    CalloutKey - callout GUID。
    LayerKey - WFP layer GUID。
    DisplayName - Display name.
    FilterIdOut - Returns the filter ID.

Return Value:

    Return status of FwpmFilterAdd0.

--*/
{
    KswordArkFwpmFilteR0 filter;

    if (runtime == NULL || runtime->engineHandle == NULL || calloutKey == NULL ||
        layerKey == NULL || filterIdOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&filter, sizeof(filter));
    filter.layerKey = *layerKey;
    filter.displayData.name = (PWSTR)displayName;
    filter.action.type = KSWORD_ARK_FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.actionKey.calloutKey = *calloutKey;
    filter.subLayerKey = kKswordArkWfpSublayer;
    filter.weight.type = KSWORD_ARK_FWP_EMPTY;
    filter.numFilterConditions = 0U;
    filter.filterCondition = NULL;
    return FwpmFilterAdd0(runtime->engineHandle, &filter, NULL, filterIdOut);
}

static NTSTATUS
kswordArkNetworkAddSublayer(
    _In_ KswordArkNetworkRuntime* runtime
    )
/*++

Routine Description:

    Add KswordARK sublayer to BFE. Note: Sublayer weight is set to a medium value to avoid overriding
    critical system security policies while ensuring this driver's filters can be grouped and cleaned up.

Arguments:

    Runtime: Network runtime.

Return Value:

    Return status of FwpmSubLayerAdd0.

--*/
{
    KswordArkFwpmSublayeR0 subLayer;

    if (runtime == NULL || runtime->engineHandle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&subLayer, sizeof(subLayer));
    subLayer.subLayerKey = kKswordArkWfpSublayer;
    subLayer.displayData.name = L"KswordARK Network Filter";
    subLayer.weight = 0x4000U;
    return FwpmSubLayerAdd0(runtime->engineHandle, &subLayer, NULL);
}

NTSTATUS
kswordArkNetworkWfpRegister(
    _Inout_ KswordArkNetworkRuntime* runtime
    )
/*++

Routine Description:

    Register KswordARK WFP callout, sublayer, and filter. Note: If any step fails, the cleanup
    path is invoked to unregister and remove created objects, preventing residual BFE entries.

Arguments:

    Runtime: Network runtime.

Return Value:

    STATUS_SUCCESS or the status returned by the WFP API.

--*/
{
    KswordArkFwpmSessioN0 session;
    NTSTATUS status = STATUS_SUCCESS;

    if (runtime == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkNetworkRegisterCallout(
        runtime,
        &kKswordArkWfpConnectCallout,
        &runtime->connectCalloutId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = kswordArkNetworkRegisterCallout(
        runtime,
        &kKswordArkWfpRecvAcceptCallout,
        &runtime->recvAcceptCalloutId);
    if (!NT_SUCCESS(status)) {
        kswordArkNetworkWfpUnregister(runtime);
        return status;
    }

    // Note: After registering ALE rule callouts, register the IPv4/IPv6 four per-packet observation callouts.
    status = kswordArkNetworkTrafficRegisterRuntimeCallouts(runtime);
    // Note: Any per-packet runtime callout failure triggers unified cleanup to avoid partial direction coverage.
    if (!NT_SUCCESS(status)) {
        // Note: Unregister the created ALE and per-packet runtime callouts.
        kswordArkNetworkWfpUnregister(runtime);
        // Note: Return precise WFP registration error.
        return status;
    }

    RtlZeroMemory(&session, sizeof(session));
    session.flags = KSWORD_ARK_FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen0(
        NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        &session,
        &runtime->engineHandle);
    runtime->engineStatus = status;
    if (!NT_SUCCESS(status)) {
        kswordArkNetworkWfpUnregister(runtime);
        return status;
    }

    status = FwpmTransactionBegin0(runtime->engineHandle, 0U);
    if (!NT_SUCCESS(status)) {
        kswordArkNetworkWfpUnregister(runtime);
        return status;
    }

    status = kswordArkNetworkAddSublayer(runtime);
    if (NT_SUCCESS(status)) {
        status = kswordArkNetworkAddCalloutToEngine(
            runtime,
            &kKswordArkWfpConnectCallout,
            &kKswordArkFwpmLayerAleAuthConnectV4,
            L"KswordARK ALE connect callout");
    }
    if (NT_SUCCESS(status)) {
        status = kswordArkNetworkAddCalloutToEngine(
            runtime,
            &kKswordArkWfpRecvAcceptCallout,
            &kKswordArkFwpmLayerAleAuthRecvAcceptV4,
            L"KswordARK ALE recv-accept callout");
    }
    // Note: Add four IPPACKET callouts and inspection filters within the same transaction.
    if (NT_SUCCESS(status)) {
        // Note: The per-packet module uses a single dynamic engine and the KswordARK sublayer.
        status = kswordArkNetworkTrafficAddEngineObjects(runtime);
    }
    if (NT_SUCCESS(status)) {
        status = kswordArkNetworkAddFilter(
            runtime,
            &kKswordArkWfpConnectCallout,
            &kKswordArkFwpmLayerAleAuthConnectV4,
            L"KswordARK ALE connect filter",
            &runtime->connectFilterId);
    }
    if (NT_SUCCESS(status)) {
        status = kswordArkNetworkAddFilter(
            runtime,
            &kKswordArkWfpRecvAcceptCallout,
            &kKswordArkFwpmLayerAleAuthRecvAcceptV4,
            L"KswordARK ALE recv-accept filter",
            &runtime->recvAcceptFilterId);
    }

    if (NT_SUCCESS(status)) {
        status = FwpmTransactionCommit0(runtime->engineHandle);
        if (NT_SUCCESS(status)) {
            // Note: ALE rules and per-packet Layer 4 objects are submitted in the same transaction, ensuring capability flags are synchronously visible.
            runtime->runtimeFlags |=
                KSWORD_ARK_NETWORK_RUNTIME_WFP_STARTED |
                KSWORD_ARK_NETWORK_RUNTIME_PACKET_CAPTURE_STARTED;
            // Log that per-packet data plane submission succeeded.
            runtime->trafficCaptureStatus = STATUS_SUCCESS;
            return STATUS_SUCCESS;
        }
    }
    else {
        (VOID)FwpmTransactionAbort0(runtime->engineHandle);
    }

    // Note: If submission or any object addition fails, per-packet queries should report the exact failure status.
    runtime->trafficCaptureStatus = status;
    // Note: Clean up runtime callouts outside the transaction and any residual dynamic engine objects.
    kswordArkNetworkWfpUnregister(runtime);
    return status;
}

VOID
kswordArkNetworkWfpUnregister(
    _Inout_ KswordArkNetworkRuntime* runtime
    )
/*++

Routine Description:

    Unregister WFP filters, callouts, and engine handles. Note: All deletion operations are guarded by null/zero
    checks, ensuring that both the initialization failure path and the normal unload path are re-entrant.

Arguments:

    Runtime: Network runtime.

Return Value:

    None. This function has no return value.

--*/
{
    if (runtime == NULL) {
        return;
    }

    if (runtime->engineHandle != NULL) {
        // Note: Delete per-packet filters/callouts first to avoid losing the explicit cleanup opportunity after closing the engine.
        kswordArkNetworkTrafficDeleteEngineObjects(runtime);
        if (runtime->connectFilterId != 0ULL) {
            (VOID)FwpmFilterDeleteById0(runtime->engineHandle, runtime->connectFilterId);
            runtime->connectFilterId = 0ULL;
        }
        if (runtime->recvAcceptFilterId != 0ULL) {
            (VOID)FwpmFilterDeleteById0(runtime->engineHandle, runtime->recvAcceptFilterId);
            runtime->recvAcceptFilterId = 0ULL;
        }
        (VOID)FwpmCalloutDeleteByKey0(runtime->engineHandle, &kKswordArkWfpConnectCallout);
        (VOID)FwpmCalloutDeleteByKey0(runtime->engineHandle, &kKswordArkWfpRecvAcceptCallout);
        (VOID)FwpmSubLayerDeleteByKey0(runtime->engineHandle, &kKswordArkWfpSublayer);
        FwpmEngineClose0(runtime->engineHandle);
        runtime->engineHandle = NULL;
    }

    if (runtime->connectCalloutId != 0U) {
        (VOID)FwpsCalloutUnregisterById0(runtime->connectCalloutId);
        runtime->connectCalloutId = 0U;
    }
    if (runtime->recvAcceptCalloutId != 0U) {
        (VOID)FwpsCalloutUnregisterById0(runtime->recvAcceptCalloutId);
        runtime->recvAcceptCalloutId = 0U;
    }

    // Note: Unregister the four per-packet runtime callouts; the function supports partial initialization.
    kswordArkNetworkTrafficUnregisterRuntimeCallouts(runtime);

    runtime->runtimeFlags &= ~(
        KSWORD_ARK_NETWORK_RUNTIME_WFP_REGISTERED |
        KSWORD_ARK_NETWORK_RUNTIME_WFP_STARTED |
        KSWORD_ARK_NETWORK_RUNTIME_PACKET_CAPTURE_STARTED);
}
