#pragma once

// ============================================================
// ksword/network/network_nids.h
// Namespace: ks::network
// Purpose:
// - Provide a lightweight, UI-independent NIDS rule engine for PacketRecord.
// - Keep rolling flow state in memory and return structured alerts to callers.
// - Cover practical real-time checks: port scan bursts, suspicious DNS/HTTP,
//   risky remote ports, and abnormal outbound transfer bursts.
// ============================================================

#include "Network.h"

#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ks::network
{
    // NidsAlertSeverity: NIDS alert severity level.
    enum class NidsAlertSeverity : std::uint8_t
    {
        kLow = 0,      // Low risk: worth noting but not necessarily anomalous.
        kMedium = 1,   // Note: Medium risk: Suspicious behavior or weak signal combination detected.
        kHigh = 2,     // High risk: obvious attacks, scans, or suspicious C2 characteristics.
        kCritical = 3  // Critical risk: reserved for future blocking linkage or high-confidence rules.
    };

    // NidsAlert: Single NIDS alert.
    struct NidsAlert
    {
        std::uint64_t timestampMs = 0;          // Alert timestamp (Unix ms).
        std::uint64_t sequenceId = 0;           // Associated packet sequence ID.
        NidsAlertSeverity severity = NidsAlertSeverity::kLow; // Alert severity.
        std::string category;                   // Category, e.g., Scan/DNS/HTTP/Flow.
        std::string ruleId;                     // Rule ID for subsequent filtering and log tracing.
        std::string title;                      // Short title.
        std::string detail;                     // Detailed description.
        std::uint32_t processId = 0;            // Associated PID.
        std::string processName;                // Associated process name.
        // Used solely to securely pre-fill audit evidence as application-level handling rules. Creation time and image path are collected at the
        // moment the alert is generated; prior to subsequent handling, re-verification is mandatory. Do not treat reusable raw PIDs as identity.
        std::uint64_t processCreationTime100ns = 0;
        std::string processImagePath;
        PacketTransportProtocol protocol = PacketTransportProtocol::kTcp; // Protocol.
        PacketDirection direction = PacketDirection::kUnknown;             // Direction
        std::string localAddress;               // Local address.
        std::uint16_t localPort = 0;            // Local port.
        std::string remoteAddress;              // Remote address.
        std::uint16_t remotePort = 0;           // Remote port.
    };

    // NidsEngine: Lightweight rule-based NIDS engine.
    class NidsEngine
    {
    public:
        // analyzePacket：
        // - Input: A single packet capture record;
        // - Output: List of alerts triggered by this packet.
        // - Note: This function updates the internal scroll window state.
        [[nodiscard]] std::vector<NidsAlert> analyzePacket(const PacketRecord& packetRecord);

        // Reset: clear rolling window and deduplication cooldown state.
        void reset();

    public:
        // The following structure is used solely for window maintenance helper functions in network_nids.cpp.
        struct PortEvent
        {
            std::uint64_t timestampMs = 0;
            std::uint16_t port = 0;
        };

        struct PortScanWindow
        {
            std::deque<PortEvent> eventList;
            std::uint64_t lastAlertTimestampMs = 0;
        };

        struct ByteEvent
        {
            std::uint64_t timestampMs = 0;
            std::uint64_t byteCount = 0;
        };

        struct ByteWindow
        {
            std::deque<ByteEvent> eventList;
            std::uint64_t totalBytes = 0;
            std::uint64_t lastAlertTimestampMs = 0;
        };

    private:
        // analyzePortScan: detects short-time probing of many ports from the same source.
        void analyzePortScan(const PacketRecord& packetRecord, std::vector<NidsAlert>& alertList);

        // analyzeDnsPayload: Detect high-risk or anomalous domains in DNS queries.
        void analyzeDnsPayload(const PacketRecord& packetRecord, std::vector<NidsAlert>& alertList);

        // analyzeHttpPayload: Detects attack signatures in plaintext HTTP payloads.
        void analyzeHttpPayload(const PacketRecord& packetRecord, std::vector<NidsAlert>& alertList);

        // analyzeSuspiciousPort: Detect access to high-risk remote service ports.
        void analyzeSuspiciousPort(const PacketRecord& packetRecord, std::vector<NidsAlert>& alertList);

        // analyzeOutboundByteBurst: Detects short-duration high-volume outbound transfers.
        void analyzeOutboundByteBurst(const PacketRecord& packetRecord, std::vector<NidsAlert>& alertList);

        // shouldEmitFlowAlert: Deduplicate based on rule + flow with a cooldown.
        bool shouldEmitFlowAlert(
            const std::string& dedupeKey,
            std::uint64_t nowMs,
            std::uint64_t cooldownMs);

        std::unordered_map<std::string, PortScanWindow> portScanWindowByKey_; // Scan window.
        std::unordered_map<std::string, ByteWindow> outboundByteWindowByKey_; // Outbound byte window.
        std::unordered_map<std::string, std::uint64_t> flowAlertLastTimestampByKey_; // Alert cooldown.
    };

    // nidsAlertSeverityToString: Convert severity enum to stable English text.
    [[nodiscard]] std::string nidsAlertSeverityToString(NidsAlertSeverity severity);
} // namespace ks::network
