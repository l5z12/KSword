#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>

#include "ark/ark_network.h"
#include "ark/ark_log.h"
#include "ark/ark_push_lock.h"

#ifndef RPC_C_AUTHN_WINNT
#define RPC_C_AUTHN_WINNT 10U
#endif

#define KSWORD_ARK_NETWORK_EVENT_RING_CAPACITY 2048UL
#define KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY 2048UL
#define KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_COUNT 4UL

typedef struct KswordArkNetworkRuntime
{
    EX_PUSH_LOCK lock; // Lock: Protects low-frequency rule snapshots, adhering to the existing rule lifecycle.
    KSPIN_LOCK classifyRuleLock; // ClassifyRuleLock: Protects the DISPATCH_LEVEL classification snapshot.
    KSPIN_LOCK eventLock; // EventLock: protects the fixed event ring writable at DISPATCH_LEVEL.
    KSPIN_LOCK trafficLock; // TrafficLock: Protects the per-packet ring for IP packet classify writes.
    WDFDEVICE device; // Device: Controls the device and log entry point.
    PDRIVER_OBJECT driverObject; // DriverObject: The driver object used for WFP callout registration.
    PDEVICE_OBJECT deviceObject; // DeviceObject: The device object used by FwpsCalloutRegister0.
    HANDLE engineHandle; // EngineHandle: dynamic WFP engine session.
    UINT32 connectCalloutId; // ConnectCalloutId：ALE_AUTH_CONNECT_V4 runtime callout ID。
    UINT32 recvAcceptCalloutId; // RecvAcceptCalloutId：ALE_AUTH_RECV_ACCEPT_V4 runtime callout ID。
    UINT64 connectFilterId; // ConnectFilterId: Outbound authorization filter ID.
    UINT64 recvAcceptFilterId; // RecvAcceptFilterId: Inbound authorization filter ID.
    UINT32 trafficCalloutIds[KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_COUNT]; // TrafficCalloutIds: IPv4/IPv6 inbound/outbound per-packet runtime callout IDs.
    UINT64 trafficFilterIds[KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_COUNT]; // TrafficFilterIds: per-packet inspection filter IDs.
    NTSTATUS registerStatus; // RegisterStatus: runtime callout registration result.
    NTSTATUS engineStatus; // EngineStatus: BFE engine/filter installation result.
    NTSTATUS trafficCaptureStatus; // TrafficCaptureStatus: Registration result for per-packet callout/filter.
    ULONG runtimeFlags; // RuntimeFlags: WFP and rule capability flags.
    ULONG ruleCount; // RuleCount: Total number of enabled rules.
    ULONG blockedRuleCount; // BlockedRuleCount: Number of enabled blocking rules.
    ULONG hiddenPortRuleCount; // HiddenPortRuleCount: Number of enabled hidden port rules.
    ULONG generation; // Generation: Rule snapshot generation number.
    volatile LONG64 classifyCount; // ClassifyCount: Cumulative count of ALE classify calls.
    volatile LONG64 blockedCount; // BlockedCount: Actual cumulative blocked count.
    ULONG eventWriteIndex; // EventWriteIndex: Next event write slot.
    ULONG eventCount; // EventCount: current number of valid rows in the ring.
    ULONG64 nextEventSequence; // NextEventSequence: Next stable monotonic sequence number.
    ULONG64 droppedEventCount; // DroppedEventCount: Cumulative count of ring buffer overwrites.
    ULONG trafficWriteIndex; // TrafficWriteIndex: The next write slot in the per-packet ring.
    ULONG trafficCount; // TrafficCount: Current valid row count in the per-packet ring.
    volatile LONG trafficCaptureEnabled; // TrafficCaptureEnabled: Allows classify to copy packets only after UI explicitly starts.
    volatile LONG trafficCaptureGeneration; // TrafficCaptureGeneration: Incremented on each successful start/stop cycle.
    volatile LONG classifyRulesActive; // ClassifyRulesActive: Whether the classification snapshot contains active rules.
    ULONG64 nextTrafficSequence; // NextTrafficSequence: The next stable, monotonically increasing per-packet sequence number.
    ULONG64 droppedTrafficCount; // DroppedTrafficCount: cumulative count of rows overwritten by the per-packet ring buffer.
    KSWORD_ARK_NETWORK_RULE rules[KSWORD_ARK_NETWORK_MAX_RULES]; // Rules: Rule snapshot
    KSWORD_ARK_NETWORK_RULE classifyRules[KSWORD_ARK_NETWORK_MAX_RULES]; // ClassifyRules: WFP hot-path read-only copy.
    KSWORD_ARK_NETWORK_WFP_EVENT_ROW eventRing[KSWORD_ARK_NETWORK_EVENT_RING_CAPACITY]; // EventRing: Fixed non-paged ALE event ring.
    KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW trafficRing[KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY]; // TrafficRing: Fixed non-paged IPv4/IPv6 per-packet ring.
} KswordArkNetworkRuntime;

EXTERN_C_START

KswordArkNetworkRuntime*
kswordArkNetworkGetRuntime(
    VOID
    );

VOID
kswordArkNetworkLogFormat(
    _In_z_ PCSTR levelText,
    _In_z_ _Printf_format_string_ PCSTR formatText,
    ...
    );

BOOLEAN
kswordArkNetworkRuleMatchesLocked(
    _In_ const KSWORD_ARK_NETWORK_RULE* rule,
    _In_ ULONG direction,
    _In_ ULONG protocol,
    _In_ USHORT localPort,
    _In_ USHORT remotePort,
    _In_ ULONG processId
    );

VOID
kswordArkNetworkRecordWfpAleEvent(
    _In_ ULONG direction,
    _In_ ULONG protocol,
    _In_ ULONG localAddressV4HostOrder,
    _In_ ULONG remoteAddressV4HostOrder,
    _In_ USHORT localPort,
    _In_ USHORT remotePort,
    _In_ ULONG processId,
    _In_ ULONG flags
    );

NTSTATUS
kswordArkNetworkWfpRegister(
    _Inout_ KswordArkNetworkRuntime* runtime
    );

VOID
kswordArkNetworkWfpUnregister(
    _Inout_ KswordArkNetworkRuntime* runtime
    );

NTSTATUS
kswordArkNetworkTrafficRegisterRuntimeCallouts(
    _Inout_ KswordArkNetworkRuntime* runtime
    );

NTSTATUS
kswordArkNetworkTrafficAddEngineObjects(
    _Inout_ KswordArkNetworkRuntime* runtime
    );

VOID
kswordArkNetworkTrafficDeleteEngineObjects(
    _Inout_ KswordArkNetworkRuntime* runtime
    );

VOID
kswordArkNetworkTrafficUnregisterRuntimeCallouts(
    _Inout_ KswordArkNetworkRuntime* runtime
    );

EXTERN_C_END
