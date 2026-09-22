#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

#include "ArkDriverIoTypes.h"
#include "../driver/KswordArkNetworkIoctl.h"

namespace ksword::ark
{
    // NetworkEndpointAuditResult carries the PDB/R0 read-only audit results for TCP/UDP endpoints.
    // Input: queryNetworkTcpEndpoints/queryNetworkUdpEndpoints return.
    // Handling: entries directly store shared/driver protocol rows to avoid UI redefining fields.
    // Return behavior: io.ok indicates successful transmission and protocol parsing; unsupported indicates the old driver lacks the entry point.
    struct NetworkEndpointAuditResult : VariableAuditResultBase
    {
        bool partial = false;                 // partial: APPLIED but returns only the subset within the budget.
        bool truncated = false;               // truncated: totalCount exceeds returnedCount.
        std::uint32_t sourceFlags = 0;        // sourceFlags: Evidence sources such as tcpip, netio, and runtime.
        std::uint32_t budgetRows = 0;         // budgetRows: Actual row budget accepted by R0.
        std::uint32_t generation = 0;         // generation: R0 snapshot generation number.
        std::vector<KSWORD_ARK_NETWORK_ENDPOINT_ROW> entries;
    };

    // NetworkWfpInventoryResult carries read-only audit results for WFP provider/sublayer/filter/callout.
    // Input: queryNetworkWfpInventory return.
    // Processing: Each line contains object type, GUID, function address, and owner module hints.
    // Return behavior: Does not include any disable, detach, or delete actions.
    struct NetworkWfpInventoryResult : VariableAuditResultBase
    {
        bool partial = false;                 // partial: Collector partially failed, or APPLIED but returned only a subset.
        bool truncated = false;               // truncated: total count vs. returned count or BUFFER_OVERFLOW indicates incomplete results.
        std::uint32_t sourceFlags = 0;
        std::uint32_t budgetRows = 0;
        std::uint32_t generation = 0;
        std::vector<KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW> entries;
    };

    // NetworkWfpEventResult carries the incremental response for real WFP ALE IPv4 stream authorization events.
    // Input: returned by queryNetworkWfpEvents(afterSequence, maxRows).
    // Handling: Strictly validate response/row ABI, byte boundaries, and sequence monotonicity before copying entries.
    // Return behavior: Events contain only five-tuple metadata, excluding packet length, bytes, or payload.
    struct NetworkWfpEventResult : VariableAuditResultBase
    {
        std::uint32_t capacity = 0;           // capacity: Fixed non-paged ring capacity for the driver.
        std::uint64_t oldestSequence = 0;     // oldestSequence: The oldest sequence number still readable.
        std::uint64_t newestSequence = 0;     // newestSequence: Latest sequence number of the current ring.
        std::uint64_t nextSequence = 0;       // nextSequence: The cursor returned last in this response.
        std::uint64_t droppedEventCount = 0;  // droppedEventCount: Cumulative count of ring buffer overwrite events.
        std::uint64_t cursorGapCount = 0;     // cursorGapCount: Number of events for this cursor that are unrecoverable.
        std::vector<KSWORD_ARK_NETWORK_WFP_EVENT_ROW> entries;
    };

    // NetworkTrafficCaptureControlResult carries the explicit start/stop results for the WFP IP packet per-packet data plane.
    // When the old driver lacks the control IOCTL, unsupported=true; the caller must not treat R0 as stopped.
    struct NetworkTrafficCaptureControlResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_RESPONSE response{};
    };

    // NetworkTrafficPacketResult carries the real incremental per-packet response at the WFP IPv4/IPv6 IP packet layer.
    // Input: queryNetworkTrafficPackets(afterSequence, maxRows) return value.
    // Handling: Strictly validate response/row ABI, cursor, packet boundaries, and limited prefixes before copying entries.
    // Return behavior: If the old driver has not registered the new IOCTL, unsupported=true; the caller must fall back to R3 instead of downgrading to ALE stream events.
    struct NetworkTrafficPacketResult : VariableAuditResultBase
    {
        std::uint32_t capacity = 0;            // capacity: fixed non-paged per-packet ring capacity in the driver.
        std::uint64_t oldestSequence = 0;      // oldestSequence: The oldest packet sequence number that can still be read.
        std::uint64_t newestSequence = 0;      // newestSequence: the latest sequence number in the current per-packet ring.
        std::uint64_t nextSequence = 0;        // nextSequence: The cursor returned last in this response.
        std::uint64_t droppedPacketCount = 0;  // droppedPacketCount: Cumulative number of packets overwritten in the ring buffer.
        std::uint64_t cursorGapCount = 0;      // cursorGapCount: Number of packets for this cursor that are unrecoverable.
        std::vector<KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW> entries;
    };

    // NetworkNdisChainResult carries read-only audit results for the NDIS miniport/filter/protocol/binding chain.
    // Input: returned by queryNetworkNdisChain.
    // Processing: retain object address, parent object, driver object, and owner module diagnostic fields per line.
    // Return behavior: does not perform NDIS detach, pause, restart, or filter operations.
    struct NetworkNdisChainResult : VariableAuditResultBase
    {
        bool partial = false;                 // partial: Collector partially failed, or APPLIED but returned only a subset.
        bool truncated = false;               // truncated: total count vs. returned count or BUFFER_OVERFLOW indicates incomplete results.
        std::uint32_t sourceFlags = 0;
        std::uint32_t budgetRows = 0;
        std::uint32_t generation = 0;
        std::vector<KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW> entries;
    };
}
