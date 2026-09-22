#pragma once

#include <QString>
#include <QVector>

#include <cstdint>

namespace ks::process
{
    // DllHijackRisk is evidence severity, not a malware verdict.
    enum class DllHijackRisk : std::uint8_t
    {
        kSafe = 0,
        kInformational,
        kSuspicious,
        kHigh
    };

    enum class DllHijackPresence : std::uint8_t
    {
        kPresentOnly = 0,
        kLoaded
    };

    enum class DllHijackTrustSource : std::uint8_t
    {
        kNone = 0,
        kEmbedded,
        kCatalog
    };

    enum class DllHijackScanStatus : std::uint8_t
    {
        kComplete = 0,
        kProcessIdentityUnavailable,
        kProcessIdentityMismatch,
        kImagePathUnavailable,
        kApplicationDirectoryUnavailable,
        kSystemDirectoryUnavailable
    };

    struct DllFileEvidence
    {
        QString path;
        QString sha256;
        QString signer;
        QString companyName;
        QString originalFilename;
        QString fileVersion;
        std::uint64_t sizeBytes = 0;
        std::uint16_t machine = 0;
        std::int32_t embeddedTrustStatus = 0;
        std::int32_t catalogTrustStatus = 0;
        std::uint32_t catalogLookupError = 0;
        DllHijackTrustSource trustSource = DllHijackTrustSource::kNone;
        bool catalogAttempted = false;
        bool catalogTrustStatusAvailable = false;
        bool trusted = false;
        bool readable = false;
        bool reparsePoint = false;
    };

    struct DllHijackFinding
    {
        DllFileEvidence localFile;
        DllFileEvidence systemFile;
        DllHijackRisk risk = DllHijackRisk::kInformational;
        DllHijackPresence presence = DllHijackPresence::kPresentOnly;
        bool knownDll = false;
        bool dllRedirectionPresent = false;
        bool hashComparable = false;
        bool hashesMatch = false;
        bool signerComparable = false;
        bool signersMatch = false;
        bool companyComparable = false;
        bool companiesMatch = false;
        bool originalFilenameComparable = false;
        bool originalFilenamesMatch = false;
        bool versionComparable = false;
        bool versionsMatch = false;
        bool machineCompatible = true;
    };

    struct DllHijackScanResult
    {
        DllHijackScanStatus status = DllHijackScanStatus::kComplete;
        QString processImagePath;
        QString applicationDirectory;
        QString systemDirectory;
        QString diagnosticText;
        QVector<DllHijackFinding> findings;
        std::uint32_t scannedApplicationDllCount = 0;
        std::uint32_t systemNameCollisionCount = 0;
        std::uint32_t signedSystemBaselineCount = 0;
        std::uint32_t skippedArchitectureMismatchCount = 0;
        bool loadedModuleEvidenceAvailable = false;
        bool directoryEnumerationTruncated = false;
        bool dllRedirectionPresent = false;
    };

    // scanProcessDllHijacking performs a read-only, non-loading analysis:
    // - verifies PID + creation time before attributing evidence;
    // - scans only the executable directory plus already-loaded local modules;
    // - compares same-name DLLs with the architecture-matched signed system copy;
    // - returns language-neutral evidence for UI rendering.
    DllHijackScanResult scanProcessDllHijacking(
        std::uint32_t pid,
        std::uint64_t expectedCreationTime100ns,
        const QString& fallbackImagePath = QString());
}
