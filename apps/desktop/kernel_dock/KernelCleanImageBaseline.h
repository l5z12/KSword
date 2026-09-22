#pragma once

#include <QString>

#include <atomic>
#include <cstdint>
#include <functional>
#include <vector>

namespace ks::kernel
{
    struct CleanImageBaselineResult
    {
        bool available = false;
        bool identityMatched = false;
        bool diskTrustVerified = false;
        bool codeIntegrityTrusted = false;
        bool relocationApplied = false;
        bool differs = false;
        std::uint64_t moduleBase = 0;
        std::uint64_t preferredImageBase = 0;
        std::uint32_t moduleSize = 0;
        std::uint32_t relativeVirtualAddress = 0;
        std::uint32_t signingLevel = 0;
        QString moduleName;
        QString imagePath;
        QString imageSha256;
        QString signingThumbprint;
        QString statusText;
        std::vector<std::uint8_t> cleanBytes;
        std::vector<std::uint8_t> observedBytes;
    };


    struct IdtHandlerObservation
    {
        std::uint32_t vector = 0;
        std::uint64_t handler = 0;
    };

    struct TrustedIdtBaselineResult
    {
        bool available = false;
        bool identityMatched = false;
        bool diskTrustVerified = false;
        bool codeIntegrityTrusted = false;
        bool profileHashMatched = false;
        bool handlerMatches = false;
        std::uint32_t vector = 0;
        std::uint32_t expectedCandidateCount = 0;
        std::uint64_t observedHandler = 0;
        std::uint64_t expectedHandler = 0;
        QString imagePath;
        QString imageSha256;
        QString profilePath;
        QString sourceSymbol;
        QString statusText;
    };


    // A contiguous interval where a memory region differs from the clean disk image.
    struct KernelTextDiffRange
    {
        // origin: Indicates whether this difference can be explained by a known benign mechanism.
        enum class Origin : int
        {
            // Modifications occurring within points marked in the PE dynamic relocation table (e.g., import
            // optimization, retpoline) are performed by the loader during startup and are considered normal behavior.
            kKnownDynamicRelocation = 0,
            // Code modification that cannot be explained by any known mechanism.
            kUnexplained
        };

        std::uint32_t rva = 0;
        std::uint32_t length = 0;
        std::uint64_t kernelAddress = 0;
        Origin origin = Origin::kUnexplained;
        QString sectionName;
        std::vector<std::uint8_t> cleanBytes;
        std::vector<std::uint8_t> observedBytes;
    };

    // Scan result for executable section integrity of a single module.
    struct KernelTextIntegrityResult
    {
        bool available = false;
        bool identityMatched = false;
        bool diskTrustVerified = false;
        bool relocationApplied = false;
        // This image contains dynamic relocation symbols not parsed by this tool; the 'uninterpretable' judgment should be treated conservatively.
        bool unparsedDynamicRelocations = false;
        std::uint64_t moduleBase = 0;
        std::uint32_t moduleSize = 0;
        std::uint32_t executableSectionCount = 0;
        std::uint64_t scannedBytes = 0;
        std::uint64_t unreadableBytes = 0;
        std::uint64_t differingBytes = 0;
        std::uint32_t knownRangeCount = 0;
        std::uint32_t unexplainedRangeCount = 0;
        std::uint32_t truncatedRangeCount = 0;
        QString moduleName;
        QString imagePath;
        QString imageSha256;
        QString statusText;
        std::vector<KernelTextDiffRange> ranges;
    };

    struct KernelTextScanOptions
    {
        // Empty means scanning all loaded modules; otherwise, filter by base name substring (case-insensitive).
        QString moduleFilter;
        // Maximum number of difference ranges retained per module; excess ranges are counted but their bytes are not retained.
        std::uint32_t maxRangesPerModule = 64U;
        // Maximum bytes retained for a single difference range, used for UI preview.
        std::uint32_t maxRangeBytes = 64U;
        // Chunk size for a single kernel read, constrained by the protocol limit.
        std::uint32_t chunkBytes = 64U * 1024U;
        // Once set, the scan returns early at the next block boundary.
        const std::atomic_bool* cancelFlag = nullptr;
        // Callback once per module completion to allow the UI to display progress incrementally. Called on a worker thread.
        std::function<void(const KernelTextIntegrityResult&)> onModuleComplete;
    };

    class KernelCleanImageBaseline final
    {
    public:
        static CleanImageBaselineResult compareAddress(
            std::uint64_t kernelAddress,
            std::uint32_t byteCount,
            const std::vector<std::uint8_t>& observedBytes = {},
            bool requireTrustedDiskImage = false);

        static bool readKernelBytes(
            std::uint64_t kernelAddress,
            std::uint32_t byteCount,
            std::vector<std::uint8_t>& bytesOut,
            QString& errorTextOut);

        static std::vector<TrustedIdtBaselineResult>
        compareIdtHandlers(
            const std::vector<IdtHandlerObservation>& observations);

        // Iterate through loaded kernel modules and perform a full comparison of the in-memory content of executable sections against the
        // relocated disk clean image. This detection surface targets techniques like changing RX pages to RW and directly modifying code:
        // If code is modified, the comparison will leave difference intervals.
        static std::vector<KernelTextIntegrityResult> scanExecutableSections(
            const KernelTextScanOptions& options);
    };
}
