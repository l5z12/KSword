#pragma once

// ============================================================
// SoundSourceDetector.h
// Purpose:
// 1) Define Core Audio sound source sampling results;
// 2) Define R0 process Cross-View / Runtime Detail cross-verification evidence;
// 3) Provide a single read-only detection entry point for the Misc page and the Process Details page.
// ============================================================

#include "../../Framework.h"

#include <QString>

#include <cstdint>
#include <vector>

namespace ks::misc
{
    // SoundSourceKernelEvidence：
    // - Input: PID returned by the Core Audio session;
    // - Handling: Perform R0 multi-source process identity verification via ArkDriverClient.
    // - Return: Used only as PID/process object corroboration; do not describe it as an R0 audio stream sample.
    struct SoundSourceKernelEvidence
    {
        bool attempted = false;                 // Whether R0 evidence was requested in this round.
        bool driverAvailable = false;           // Whether the KswordARK device can be opened.
        bool processFound = false;              // R0: Target process located in at least one source.
        bool identityMatched = false;            // Whether R0 PID/Image name matches R3 identity.
        bool corroborated = false;               // Multiple R0 sources are consistent and no anomalies were detected.
        std::uint32_t sourceMask = 0;            // Public/ActiveList/CID source bit.
        std::uint32_t anomalyFlags = 0;          // Cross-View anomaly flags.
        std::uint32_t confidence = 0;            // R0 Cross-View confidence level.
        std::uint32_t runtimeFieldFlags = 0;     // Runtime Detail valid field flags.
        std::uint64_t processObjectAddress = 0; // R0 read-only returned EPROCESS address evidence.
        std::uint64_t objectTableAddress = 0;    // Evidence of ObjectTable address returned as R0 read-only.
        QString imageName;                       // R0 EPROCESS short image name.
        QString statusText;                      // Verification conclusion for the table.
        QString detailText;                      // Degradation, exception, or source details.
    };

    // SoundSourceRecord: a single sample record of an output audio session.
    // Each record uses endpointId + sessionInstanceId as a stable key; the PID is used only for process association.
    struct SoundSourceRecord
    {
        std::uint32_t processId = 0;             // Core Audio session ownership PID.
        std::uint64_t creationTime100ns = 0;     // R3-read process creation time to prevent false positives from PID reuse.
        QString processName;                     // Process filename or "System Sound".
        QString imagePath;                       // R3 QueryFullProcessImageName path.
        QString endpointName;                    // Output endpoint friendly name.
        QString endpointId;                      // MMDevice endpoint ID.
        QString endpointRoleText;                // Default console/multimedia/communication role.
        QString sessionName;                     // Session display name.
        QString sessionIdentifier;               // Core Audio session identifier.
        QString sessionInstanceId;               // Core Audio session instance ID.
        QString stateText;                       // Visible text for Active/Inactive/Expired states.
        QString verdictText;                     // Current, most recent, or silent verdict.
        float peakMaximum = 0.0F;                // Session maximum peak within the sampling window.
        float peakAverage = 0.0F;                // Session average peak within the sampling window.
        float endpointPeakMaximum = 0.0F;        // Maximum peak value for output endpoints within the same window.
        float sessionVolume = 0.0F;              // Session volume 0.0~1.0.
        bool volumeAvailable = false;             // Whether ISimpleAudioVolume was successfully read.
        bool muted = false;                      // Session muted state
        bool systemSounds = false;               // Whether this is a Windows system sound session.
        bool sessionActive = false;              // Whether the Core Audio session state is Active.
        bool meterAvailable = false;             // Whether session-level IAudioMeterInformation has been acquired.
        bool currentlyAudible = false;           // Whether multiple peak samples confirm the device is currently emitting sound.
        bool recentlyAudible = false;            // Whether the UI retains the source within a short-term history window.
        std::int64_t lastAudibleUnixMs = 0;      // Local timestamp of the most recent confirmed audible event.
        SoundSourceKernelEvidence kernel;        // Cross-verified R0 evidence for PID from multiple sources.
    };

    // SoundSourceScanOptions: controls the scope and cost of a single background sampling operation.
    struct SoundSourceScanOptions
    {
        std::uint32_t processIdFilter = 0; // 0 indicates global scope; non-zero indicates process detail page scope.
        std::uint64_t expectedCreationTime100ns = 0; // Process detail identity; 0 means no restriction.
        bool includeKernelEvidence = true; // Whether R0 process identity verification was attempted.
        int sampleCount = 6;               // Peak sample count.
        int sampleIntervalMs = 40;         // Interval between adjacent peak samples.
    };

    // SoundSourceScanResult: Return packet for a complete background scan.
    struct SoundSourceScanResult
    {
        std::vector<SoundSourceRecord> records; // Currently existing output audio sessions.
        QString diagnosticText;                 // Core Audio initialization or enumeration diagnostics.
        QString kernelDiagnosticText;           // R0: Open/query diagnostics
        int sampleWindowMs = 0;                  // Actual scheduled sampling window length.
        bool audioQueryOk = false;               // Core Audio enumeration completion status.
        bool kernelAttempted = false;            // Whether R0 was requested in this round.
        bool kernelAvailable = false;            // Whether KswordARK devices are available in this round.
    };

    // detectSoundSources：
    // - Invocation: Call only from a background thread; the function initializes COM for that thread and waits briefly for peak sampling.
    // - Input: sampling range, count, interval, and R0 switch;
    // - Return: R3 session attribution + R0 process identity attestation; does not modify volume, session, or kernel objects.
    SoundSourceScanResult detectSoundSources(const SoundSourceScanOptions& options);
}
