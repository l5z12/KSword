#include "ScannerInternal.h"

#include "../file/PeAnalyzer.h"

// ============================================================
// ksword/scanner/attack_path_detector.cpp
// Purpose:
// - Identifies EXIT/GhostSystemDriver attack paths using multi-stage static evidence;
// - Correlate the host within the ISO with the proxy DLL in the same directory, and check the embedded driver in memory.
// - Do not mount containers, do not persist decoded results, and do not invoke any target code.
// ============================================================

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ks::scanner::detail
{
    namespace
    {
        constexpr std::uint32_t kMatchThreshold = 60;
        constexpr std::size_t kMinimumEncodedCharacters = 4096;
        constexpr std::size_t kMaximumEncodedCharacters = 8U * 1024U * 1024U;
        constexpr std::size_t kMaximumDecodedBytes = 64U * 1024U * 1024U;
        constexpr std::size_t kMaximumArtifactScanBytes = 32U * 1024U * 1024U;

        // ArtifactSignals purpose: Cache the boolean behavior flags and the first evidence offset obtained from a single byte scan.
        struct ArtifactSignals
        {
            bool cefExportSurface = false;
            bool cmstpluaElevation = false;
            bool pebMasquerade = false;
            bool ghostDriverService = false;
            bool avpEvasion = false;
            bool defenderRegistryImpairment = false;
            bool securityProcessTermination = false;
            bool driverUnloadAnd360Cleanup = false;
            std::uint64_t cefOffset = 0;
            std::uint64_t elevationOffset = 0;
            std::uint64_t masqueradeOffset = 0;
            std::uint64_t serviceOffset = 0;
            std::uint64_t avpOffset = 0;
            std::uint64_t defenderOffset = 0;
            std::uint64_t terminationOffset = 0;
            std::uint64_t unloadOffset = 0;
        };

        // lowerAscii processes only ASCII in protocols, module names, and file names to avoid locale dependency.
        std::string lowerAscii(std::string value)
        {
            for (char& character : value)
            {
                const unsigned char kByte = static_cast<unsigned char>(character);
                if (kByte >= 'A' && kByte <= 'Z')
                {
                    character = static_cast<char>(kByte - 'A' + 'a');
                }
            }
            return value;
        }

        bool endsWith(const std::string_view value, const std::string_view suffix)
        {
            return value.size() >= suffix.size() &&
                value.substr(value.size() - suffix.size()) == suffix;
        }

        // findAsciiInsensitive returns the first ASCII case-insensitive match; returns size() if not found.
        std::size_t findAsciiInsensitive(
            const std::span<const std::uint8_t> bytes,
            const std::string_view needle)
        {
            if (needle.empty() || needle.size() > bytes.size())
            {
                return bytes.size();
            }

            for (std::size_t offset = 0;
                 offset <= bytes.size() - needle.size();
                 ++offset)
            {
                bool matched = true;
                for (std::size_t index = 0; index < needle.size(); ++index)
                {
                    unsigned char left = bytes[offset + index];
                    unsigned char right = static_cast<unsigned char>(needle[index]);
                    if (left >= 'A' && left <= 'Z')
                    {
                        left = static_cast<unsigned char>(left - 'A' + 'a');
                    }
                    if (right >= 'A' && right <= 'Z')
                    {
                        right = static_cast<unsigned char>(right - 'A' + 'a');
                    }
                    if (left != right)
                    {
                        matched = false;
                        break;
                    }
                }
                if (matched)
                {
                    return offset;
                }
            }
            return bytes.size();
        }

        // findWideAsciiInsensitive checks for ASCII IOCs in UTF-16LE format.
        std::size_t findWideAsciiInsensitive(
            const std::span<const std::uint8_t> bytes,
            const std::string_view needle)
        {
            const std::size_t kEncodedBytes = needle.size() * 2U;
            if (needle.empty() || kEncodedBytes > bytes.size())
            {
                return bytes.size();
            }

            for (std::size_t offset = 0;
                 offset <= bytes.size() - kEncodedBytes;
                 ++offset)
            {
                bool matched = true;
                for (std::size_t index = 0; index < needle.size(); ++index)
                {
                    unsigned char left = bytes[offset + index * 2U];
                    unsigned char right = static_cast<unsigned char>(needle[index]);
                    if (bytes[offset + index * 2U + 1U] != 0)
                    {
                        matched = false;
                        break;
                    }
                    if (left >= 'A' && left <= 'Z')
                    {
                        left = static_cast<unsigned char>(left - 'A' + 'a');
                    }
                    if (right >= 'A' && right <= 'Z')
                    {
                        right = static_cast<unsigned char>(right - 'A' + 'a');
                    }
                    if (left != right)
                    {
                        matched = false;
                        break;
                    }
                }
                if (matched)
                {
                    return offset;
                }
            }
            return bytes.size();
        }

        std::size_t findText(
            const std::span<const std::uint8_t> bytes,
            const std::string_view text)
        {
            const std::size_t kAsciiOffset = findAsciiInsensitive(bytes, text);
            const std::size_t kWideOffset = findWideAsciiInsensitive(bytes, text);
            return std::min(kAsciiOffset, kWideOffset);
        }

        bool containsText(
            const std::span<const std::uint8_t> bytes,
            const std::string_view text)
        {
            return findText(bytes, text) != bytes.size();
        }

        std::size_t countTextSet(
            const std::span<const std::uint8_t> bytes,
            const std::span<const std::string_view> values)
        {
            return static_cast<std::size_t>(std::count_if(
                values.begin(),
                values.end(),
                [bytes](const std::string_view value)
                {
                    return containsText(bytes, value);
                }));
        }

        bool isBase64Character(const std::uint8_t byte)
        {
            return (byte >= 'A' && byte <= 'Z') ||
                (byte >= 'a' && byte <= 'z') ||
                (byte >= '0' && byte <= '9') ||
                byte == '+' ||
                byte == '/' ||
                byte == '=';
        }

        int base64Value(const std::uint8_t byte)
        {
            if (byte >= 'A' && byte <= 'Z') return byte - 'A';
            if (byte >= 'a' && byte <= 'z') return byte - 'a' + 26;
            if (byte >= '0' && byte <= '9') return byte - '0' + 52;
            if (byte == '+') return 62;
            if (byte == '/') return 63;
            return -1;
        }

        // decodeBase64 uses strict 4-byte group validation and tail padding checks, and verifies the upper limit before allocation.
        bool decodeBase64(
            const std::span<const std::uint8_t> input,
            std::vector<std::uint8_t>& output)
        {
            output.clear();
            if (input.empty() || (input.size() % 4U) != 0)
            {
                return false;
            }
            const std::size_t kMaximumOutput = (input.size() / 4U) * 3U;
            if (kMaximumOutput > kMaximumDecodedBytes)
            {
                return false;
            }
            output.reserve(kMaximumOutput);

            for (std::size_t offset = 0; offset < input.size(); offset += 4U)
            {
                const bool kLastGroup = offset + 4U == input.size();
                const std::uint8_t kThird = input[offset + 2U];
                const std::uint8_t kFourth = input[offset + 3U];
                const int kA = base64Value(input[offset]);
                const int kB = base64Value(input[offset + 1U]);
                const int kC = kThird == '=' ? 0 : base64Value(kThird);
                const int kD = kFourth == '=' ? 0 : base64Value(kFourth);
                if (kA < 0 || kB < 0 || kC < 0 || kD < 0 ||
                    (!kLastGroup && (kThird == '=' || kFourth == '=')) ||
                    (kThird == '=' && kFourth != '='))
                {
                    output.clear();
                    return false;
                }

                const std::uint32_t kValue =
                    (static_cast<std::uint32_t>(kA) << 18U) |
                    (static_cast<std::uint32_t>(kB) << 12U) |
                    (static_cast<std::uint32_t>(kC) << 6U) |
                    static_cast<std::uint32_t>(kD);
                output.push_back(static_cast<std::uint8_t>(kValue >> 16U));
                if (kThird != '=')
                {
                    output.push_back(static_cast<std::uint8_t>(kValue >> 8U));
                }
                if (kFourth != '=')
                {
                    output.push_back(static_cast<std::uint8_t>(kValue));
                }
            }
            return true;
        }

        int hexValue(const std::uint8_t byte)
        {
            if (byte >= '0' && byte <= '9') return byte - '0';
            if (byte >= 'a' && byte <= 'f') return byte - 'a' + 10;
            if (byte >= 'A' && byte <= 'F') return byte - 'A' + 10;
            return -1;
        }

        bool decodeHex(
            const std::span<const std::uint8_t> input,
            std::vector<std::uint8_t>& output)
        {
            output.clear();
            if (input.empty() || (input.size() % 2U) != 0 ||
                input.size() / 2U > kMaximumDecodedBytes)
            {
                return false;
            }
            output.reserve(input.size() / 2U);
            for (std::size_t offset = 0; offset < input.size(); offset += 2U)
            {
                const int kHigh = hexValue(input[offset]);
                const int kLow = hexValue(input[offset + 1U]);
                if (kHigh < 0 || kLow < 0)
                {
                    output.clear();
                    return false;
                }
                output.push_back(static_cast<std::uint8_t>((kHigh << 4) | kLow));
            }
            return true;
        }

        // looksLikePe: First verifies the DOS offset and NT signature, rejecting bait data containing only the MZ signature.
        bool looksLikePe(const std::span<const std::uint8_t> bytes)
        {
            if (bytes.size() < 0x40U || bytes[0] != 'M' || bytes[1] != 'Z')
            {
                return false;
            }
            const std::uint32_t kNtOffset =
                static_cast<std::uint32_t>(bytes[0x3CU]) |
                (static_cast<std::uint32_t>(bytes[0x3DU]) << 8U) |
                (static_cast<std::uint32_t>(bytes[0x3EU]) << 16U) |
                (static_cast<std::uint32_t>(bytes[0x3FU]) << 24U);
            return kNtOffset <= bytes.size() &&
                bytes.size() - kNtOffset >= 4U &&
                bytes[kNtOffset] == 'P' &&
                bytes[kNtOffset + 1U] == 'E' &&
                bytes[kNtOffset + 2U] == 0 &&
                bytes[kNtOffset + 3U] == 0;
        }

        // decodeEmbeddedDriver accepts only the complete chain: 'UTF-16 Base64 -> Base64 -> hex -> MZ'.
        bool decodeEmbeddedDriver(
            const std::span<const std::uint8_t> bytes,
            std::vector<std::uint8_t>& driverOut,
            std::uint64_t& encodedOffsetOut)
        {
            driverOut.clear();
            for (std::size_t cursor = 0; cursor + 1U < bytes.size();)
            {
                if (!isBase64Character(bytes[cursor]) || bytes[cursor + 1U] != 0)
                {
                    ++cursor;
                    continue;
                }

                const std::size_t kStart = cursor;
                std::vector<std::uint8_t> firstLayerText;
                while (cursor + 1U < bytes.size() &&
                    isBase64Character(bytes[cursor]) &&
                    bytes[cursor + 1U] == 0 &&
                    firstLayerText.size() <= kMaximumEncodedCharacters)
                {
                    firstLayerText.push_back(bytes[cursor]);
                    cursor += 2U;
                }
                if (firstLayerText.size() < kMinimumEncodedCharacters ||
                    firstLayerText.size() > kMaximumEncodedCharacters)
                {
                    continue;
                }

                // Adjacent ASCII characters may coincidentally form a pair with the first UTF-16LE character;
                // attempting four Base64 phases removes this prefix pollution of up to three characters.
                const std::size_t kMaximumPrefix = std::min<std::size_t>(
                    4U,
                    firstLayerText.size());
                for (std::size_t prefix = 0; prefix < kMaximumPrefix; ++prefix)
                {
                    const auto kAlignedFirstLayer = std::span<const std::uint8_t>(
                        firstLayerText).subspan(prefix);
                    if (kAlignedFirstLayer.size() < kMinimumEncodedCharacters ||
                        (kAlignedFirstLayer.size() % 4U) != 0)
                    {
                        continue;
                    }

                    std::vector<std::uint8_t> secondLayerText;
                    std::vector<std::uint8_t> hexText;
                    std::vector<std::uint8_t> decoded;
                    if (!decodeBase64(kAlignedFirstLayer, secondLayerText) ||
                        !decodeBase64(secondLayerText, hexText) ||
                        !decodeHex(hexText, decoded) ||
                        !looksLikePe(decoded))
                    {
                        continue;
                    }
                    driverOut = std::move(decoded);
                    encodedOffsetOut = kStart + prefix * 2U;
                    return true;
                }
            }
            return false;
        }

        ArtifactSignals collectSignals(const std::span<const std::uint8_t> bytes)
        {
            ArtifactSignals signals{};
            const std::array<std::string_view, 3> kCefNames{
                "cef_execute_process", "cef_initialize", "cef_shutdown"
            };
            signals.cefExportSurface = countTextSet(bytes, kCefNames) == kCefNames.size();
            signals.cefOffset = findText(bytes, "cef_execute_process");

            const bool kHasElevationMoniker =
                containsText(bytes, "Elevation:Administrator!new:") &&
                containsText(bytes, "3E5FC7F9-9A51-4367-9063-A120244FBEC7");
            signals.cmstpluaElevation = kHasElevationMoniker &&
                containsText(bytes, "CoGetObject") &&
                containsText(bytes, "CheckTokenMembership");
            signals.elevationOffset = findText(bytes, "Elevation:Administrator!new:");

            signals.pebMasquerade = containsText(bytes, "explorer.exe") &&
                containsText(bytes, "NtQueryInformationProcess") &&
                containsText(bytes, "ReadProcessMemory");
            signals.masqueradeOffset = findText(bytes, "explorer.exe");

            signals.ghostDriverService = containsText(bytes, "GhostSystemDriver") &&
                containsText(bytes, "CreateServiceW") &&
                containsText(bytes, "StartServiceW");
            signals.serviceOffset = findText(bytes, "GhostSystemDriver");
            signals.avpEvasion = containsText(bytes, "avp.exe");
            signals.avpOffset = findText(bytes, "avp.exe");

            const std::array<std::string_view, 6> kDefenderTerms{
                "TamperProtection", "DisableRealtimeMonitoring", "WdFilter",
                "WdBoot", "WdNisDrv", "WinDefend"
            };
            signals.defenderRegistryImpairment =
                countTextSet(bytes, kDefenderTerms) >= 4U &&
                containsText(bytes, "ZwSetValueKey");
            signals.defenderOffset = findText(bytes, "TamperProtection");

            const std::array<std::string_view, 8> kProcessTargets{
                "MsMpEng.exe", "NisSrv.exe", "360tray.exe", "360Safe.exe",
                "ZhuDongFangYu.exe", "AvastSvc.exe", "AVGSvc.exe", "QQPCTray.exe"
            };
            signals.securityProcessTermination =
                countTextSet(bytes, kProcessTargets) >= 3U &&
                containsText(bytes, "ZwTerminateProcess");
            signals.terminationOffset = findText(bytes, "ZwTerminateProcess");

            signals.driverUnloadAnd360Cleanup =
                containsText(bytes, "ZwUnloadDriver") &&
                containsText(bytes, "\\Registry\\Machine\\SOFTWARE\\360");
            signals.unloadOffset = findText(bytes, "ZwUnloadDriver");
            return signals;
        }

        // addEvidence deduplicates based on code+artifact to ensure container aliases do not artificially inflate the score.
        void addEvidence(
            BinaryScanResult& result,
            std::string code,
            std::string stage,
            std::string artifact,
            std::string technique,
            const AttackPathSeverity severity,
            const std::uint32_t score,
            const bool hasOffset,
            const std::uint64_t offset)
        {
            const auto kDuplicate = std::find_if(
                result.attackPath.evidence.begin(),
                result.attackPath.evidence.end(),
                [&code, &artifact](const AttackPathEvidence& evidence)
                {
                    return evidence.code == code && evidence.artifact == artifact;
                });
            if (kDuplicate != result.attackPath.evidence.end())
            {
                return;
            }

            result.attackPath.ruleId = "KSWORD.EXIT_GHOST_CHAIN.V1";
            result.attackPath.family = "EXIT / GhostSystemDriver";
            result.attackPath.evidence.push_back(AttackPathEvidence{
                std::move(code),
                std::move(stage),
                std::move(artifact),
                std::move(technique),
                severity,
                score,
                hasOffset,
                offset
            });
        }

        void appendSignalEvidence(
            const ArtifactSignals& signals,
            const std::string& artifact,
            const std::uint64_t baseOffset,
            const bool offsetsAreFileOffsets,
            BinaryScanResult& result)
        {
            if (signals.cefExportSurface)
            {
                addEvidence(result, "proxy.cef_surface", "sideload", artifact,
                    "T1574.002", AttackPathSeverity::kSuspicious, 10,
                    offsetsAreFileOffsets,
                    baseOffset + signals.cefOffset);
            }
            if (signals.cmstpluaElevation)
            {
                addEvidence(result, "proxy.cmstplua_uac", "elevation", artifact,
                    "T1548.002", AttackPathSeverity::kCritical, 25,
                    offsetsAreFileOffsets,
                    baseOffset + signals.elevationOffset);
            }
            if (signals.pebMasquerade)
            {
                addEvidence(result, "proxy.peb_masquerade", "masquerade", artifact,
                    "T1036", AttackPathSeverity::kHigh, 15,
                    offsetsAreFileOffsets,
                    baseOffset + signals.masqueradeOffset);
            }
            if (signals.ghostDriverService)
            {
                addEvidence(result, "proxy.driver_service", "persistence", artifact,
                    "T1543.003", AttackPathSeverity::kCritical, 20,
                    offsetsAreFileOffsets,
                    baseOffset + signals.serviceOffset);
            }
            if (signals.avpEvasion &&
                (signals.cmstpluaElevation || signals.ghostDriverService))
            {
                addEvidence(result, "proxy.avp_evasion", "defense_evasion", artifact,
                    "T1562.001", AttackPathSeverity::kSuspicious, 5,
                    offsetsAreFileOffsets,
                    baseOffset + signals.avpOffset);
            }
            if (signals.defenderRegistryImpairment)
            {
                addEvidence(result, "driver.defender_registry", "defense_evasion", artifact,
                    "T1562.001 / T1112", AttackPathSeverity::kCritical, 30,
                    offsetsAreFileOffsets,
                    baseOffset + signals.defenderOffset);
            }
            if (signals.securityProcessTermination)
            {
                addEvidence(result, "driver.security_process_kill", "defense_evasion", artifact,
                    "T1562.001", AttackPathSeverity::kCritical, 20,
                    offsetsAreFileOffsets,
                    baseOffset + signals.terminationOffset);
            }
            if (signals.driverUnloadAnd360Cleanup)
            {
                addEvidence(result, "driver.unload_360", "defense_evasion", artifact,
                    "T1562.001", AttackPathSeverity::kCritical, 15,
                    offsetsAreFileOffsets,
                    baseOffset + signals.unloadOffset);
            }
        }

        bool hasEvidenceCode(
            const BinaryScanResult& result,
            const std::string_view code)
        {
            return std::any_of(
                result.attackPath.evidence.begin(),
                result.attackPath.evidence.end(),
                [code](const AttackPathEvidence& evidence)
                {
                    return evidence.code == code;
                });
        }

        // finalizeDetection requires both high scores and critical phase combinations to suppress false positives from isolated strings.
        void finalizeDetection(BinaryScanResult& result)
        {
            std::uint32_t total = 0;
            for (const AttackPathEvidence& evidence : result.attackPath.evidence)
            {
                total = std::min<std::uint32_t>(100U, total + evidence.score);
            }
            result.attackPath.score = total;

            const bool kDropperPath =
                hasEvidenceCode(result, "proxy.driver_service") &&
                (hasEvidenceCode(result, "proxy.cmstplua_uac") ||
                 hasEvidenceCode(result, "embedded.double_base64_driver"));
            const bool kDriverPath =
                hasEvidenceCode(result, "driver.defender_registry") &&
                hasEvidenceCode(result, "driver.security_process_kill");
            result.attackPath.matched =
                total >= kMatchThreshold && (kDropperPath || kDriverPath);
        }

        bool importsLibcef(const std::span<const std::uint8_t> bytes)
        {
            if (bytes.size() > kMaximumArtifactScanBytes)
            {
                return false;
            }
            const std::vector<std::uint8_t> kCopy(bytes.begin(), bytes.end());
            const ks::file::PeAnalysisResult kAnalysis =
                ks::file::analyzePeBytes(kCopy);
            if (!kAnalysis.success)
            {
                return false;
            }
            return std::any_of(
                kAnalysis.importModules.begin(),
                kAnalysis.importModules.end(),
                [](const ks::file::PeImportModuleSummary& module)
                {
                    const std::string kModuleName = lowerAscii(module.dllName);
                    return kModuleName == "libcef.dll" || kModuleName == "libcef";
                });
        }
    }

    void detectAttackPathInPe(
        const std::span<const std::uint8_t> bytes,
        const std::string_view artifact,
        const std::uint64_t baseOffset,
        const ScanOptions&,
        BinaryScanResult& result)
    {
        if (bytes.size() > kMaximumArtifactScanBytes || !looksLikePe(bytes))
        {
            return;
        }

        const std::string kArtifactName =
            artifact.empty() ? std::string("<selected-file>") : std::string(artifact);
        appendSignalEvidence(
            collectSignals(bytes),
            kArtifactName,
            baseOffset,
            true,
            result);

        // Decoding occurs only in memory; decoded bytes are not written to disk nor passed to the system loader.
        std::vector<std::uint8_t> decodedDriver;
        std::uint64_t encodedOffset = 0;
        if (decodeEmbeddedDriver(bytes, decodedDriver, encodedOffset))
        {
            addEvidence(result, "embedded.double_base64_driver", "payload_decode",
                kArtifactName, "T1140", AttackPathSeverity::kCritical, 20, true,
                baseOffset + encodedOffset);
            appendSignalEvidence(
                collectSignals(decodedDriver),
                kArtifactName + "::<decoded-driver>",
                0,
                false,
                result);
        }
        finalizeDetection(result);
    }

    void detectAttackPathInContainer(
        const std::span<const std::uint8_t> bytes,
        const std::vector<ContainerMember>& members,
        const ScanOptions& options,
        BinaryScanResult& result)
    {
        const ContainerMember* libcefMember = nullptr;
        std::vector<const ContainerMember*> executableMembers;
        for (const ContainerMember& member : members)
        {
            if (member.directory || member.offset > bytes.size() ||
                member.size > bytes.size() - member.offset)
            {
                continue;
            }
            const std::string kLoweredPath = lowerAscii(member.path);
            if (endsWith(kLoweredPath, "/libcef.dll") || kLoweredPath == "libcef.dll")
            {
                libcefMember = &member;
            }
            if (endsWith(kLoweredPath, ".exe"))
            {
                executableMembers.push_back(&member);
            }

            const auto kMemberBytes = bytes.subspan(
                static_cast<std::size_t>(member.offset),
                static_cast<std::size_t>(member.size));
            detectAttackPathInPe(
                kMemberBytes,
                member.path,
                member.offset,
                options,
                result);
        }

        // Only record side-loading association if the resolved PE import table indeed depends on the same-container libcef.dll.
        if (libcefMember != nullptr)
        {
            for (const ContainerMember* executable : executableMembers)
            {
                const auto kExecutableBytes = bytes.subspan(
                    static_cast<std::size_t>(executable->offset),
                    static_cast<std::size_t>(executable->size));
                if (!importsLibcef(kExecutableBytes))
                {
                    continue;
                }
                addEvidence(result, "container.libcef_sideload_pair", "sideload",
                    executable->path + " -> " + libcefMember->path,
                    "T1574.002", AttackPathSeverity::kHigh, 20, true,
                    executable->offset);
                break;
            }
        }
        finalizeDetection(result);
    }
}
