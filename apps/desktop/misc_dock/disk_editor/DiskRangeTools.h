#pragma once

// ============================================================
// DiskRangeTools.h
// Purpose:
// 1) Provides disk range search, hashing, image export/import, file diff, and bad sector read-sweep capabilities;
// 2) All functions execute synchronously; callers must invoke them from a background thread.
// 3) Write capabilities retain sector alignment parameters for secondary confirmation by the UI.
// ============================================================

#include "DiskAdvancedModels.h"

#include <QCryptographicHash>
#include <QString>

#include <cstdint>

namespace ks::misc
{
    // DiskSearchPatternMode:
    // - Describe how search input is interpreted;
    // - HexBytes supports AA BB ?? wildcards; AsciiText and Utf16Text are used for text search.
    enum class DiskSearchPatternMode : int
    {
        kHexBytes = 0,
        kAsciiText,
        kUtf16Text
    };

    // DiskRangeTools:
    // - Input: physical disk path, offset, length, file path, or search pattern;
    // - Processing logic: Read/write in block order to avoid large memory allocations at once.
    // - Return behavior: returns summary, details, errors, and result set via DiskRangeTaskResult.
    class DiskRangeTools final
    {
    public:
        // searchRange：
        // - Search for byte patterns within the disk range;
        // - maxResults limits the number of hits to prevent UI slowdown from massive results;
        // - Returns task result.
        static DiskRangeTaskResult searchRange(
            const QString& devicePath,
            std::uint64_t offsetBytes,
            std::uint64_t lengthBytes,
            const QString& patternText,
            DiskSearchPatternMode mode,
            int maxResults);

        // hashRange：
        // - Compute the hash for the disk range.
        // - algorithm: algorithm supported by QCryptographicHash
        // - Returns the task result; digestBytes preserves the original digest.
        static DiskRangeTaskResult hashRange(
            const QString& devicePath,
            std::uint64_t offsetBytes,
            std::uint64_t lengthBytes,
            QCryptographicHash::Algorithm algorithm);

        // exportRangeToFile：
        // - Export disk ranges to image files;
        // - filePath is the target file path;
        // - Returns task result.
        static DiskRangeTaskResult exportRangeToFile(
            const QString& devicePath,
            std::uint64_t offsetBytes,
            std::uint64_t lengthBytes,
            const QString& filePath);

        // importFileToRange：
        // - Write file content to disk at specified offset.
        // - When requireSectorAligned is true, requires both offset and file length to be sector-aligned.
        // - Returns task result.
        static DiskRangeTaskResult importFileToRange(
            const QString& devicePath,
            std::uint64_t offsetBytes,
            const QString& filePath,
            std::uint32_t bytesPerSector,
            bool requireSectorAligned);

        // compareRangeWithFile：
        // - Compare disk ranges with files block by block;
        // - maxDifferences limits the number of recorded differences.
        // - Returns task result.
        static DiskRangeTaskResult compareRangeWithFile(
            const QString& devicePath,
            std::uint64_t offsetBytes,
            std::uint64_t lengthBytes,
            const QString& filePath,
            int maxDifferences);

        // scanReadableBlocks：
        // - Perform a fast read scan in units of blockBytes;
        // - Only check read success and throughput, without interpreting the data.
        // - Returns task result.
        static DiskRangeTaskResult scanReadableBlocks(
            const QString& devicePath,
            std::uint64_t offsetBytes,
            std::uint64_t lengthBytes,
            std::uint32_t blockBytes);
    };
}
