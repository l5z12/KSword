#pragma once

// ============================================================
// DiskFileSystemForensics.h
// Purpose:
// 1) Uniformly detect disk-level metadata for common Windows/Linux/macOS file systems;
// 2) Parse VCN/LCN ranges of Windows-mounted files and map them to the physical disk;
// 3) Supports reverse lookup of occupied streams by volume cluster number for disk editor double-click positioning.
// ============================================================

#include "DiskEditorModels.h"

#include <QString>

#include <cstdint>
#include <vector>

namespace ks::misc
{
    enum class ForensicFileSystemKind : int
    {
        kUnknown = 0,
        kNtfs,
        kFat12,
        kFat16,
        kFat32,
        kExFat,
        kReFs,
        kExt2,
        kExt3,
        kExt4,
        kBtrfs,
        kApfs,
        kHfs,
        kHfsPlus
    };

    struct FileSystemProbeField
    {
        QString name;
        QString value;
        QString detail;
        std::uint64_t absoluteOffset = 0;
        std::uint32_t sizeBytes = 0;
    };

    struct FileSystemProbeResult
    {
        bool success = false;
        ForensicFileSystemKind kind = ForensicFileSystemKind::kUnknown;
        QString name;
        QString volumeLabel;
        QString capabilityText;
        QString errorText;
        std::uint32_t logicalSectorSize = 0;
        std::uint32_t blockSize = 0;
        std::uint64_t totalBytes = 0;
        std::uint64_t rootObject = 0;
        std::vector<FileSystemProbeField> fields;
    };

    struct PhysicalFileExtent
    {
        int diskNumber = -1;
        std::uint64_t fileOffset = 0;
        std::uint64_t volumeOffset = 0;
        std::uint64_t physicalOffset = 0;
        std::uint64_t lengthBytes = 0;
        std::int64_t startingVcn = 0;
        std::int64_t startingLcn = -1;
        bool sparse = false;
        bool physicalMappingExact = false;
    };

    struct FileExtentResult
    {
        bool success = false;
        QString filePath;
        QString volumePath;
        QString fileSystemName;
        QString errorText;
        std::uint32_t bytesPerCluster = 0;
        std::uint64_t fileSizeBytes = 0;
        std::vector<PhysicalFileExtent> extents;
    };

    struct ReverseClusterEntry
    {
        std::uint64_t cluster = 0;
        std::uint64_t clusterCount = 0;
        QString streamPath;
    };

    struct ReverseClusterResult
    {
        bool success = false;
        QString volumePath;
        QString errorText;
        std::vector<ReverseClusterEntry> entries;
    };

    class DiskFileSystemForensics final
    {
    public:
        static FileSystemProbeResult probePartition(
            int diskIndex,
            unsigned long backend,
            std::uint64_t partitionOffset,
            std::uint64_t partitionLength,
            std::uint32_t logicalSectorSize);

        static FileExtentResult resolveFileExtents(const QString& filePath);

        static ReverseClusterResult reverseLookupCluster(
            const QString& volumePath,
            std::uint64_t cluster,
            std::uint32_t clusterCount = 1U);

        static QString fileSystemName(ForensicFileSystemKind kind);
    };
}
