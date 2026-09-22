#include "DiskRawFileSystemInternal.h"

#include <QByteArray>
#include <QStringList>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iterator>
#include <limits>
#include <optional>
#include <unordered_set>
#include <utility>
#include <vector>

namespace
{
    constexpr std::uint32_t kDirectoryReadLimit = 64U * 1024U * 1024U;
    constexpr std::uint32_t kNtfsScanChunkBytes = 4U * 1024U * 1024U;
    constexpr std::uint64_t kNtfsRecordScanLimit = 1024U * 1024U;
    constexpr std::uint32_t kNtfsAttributeListReadLimit =
        16U * 1024U * 1024U;
    constexpr std::size_t kNtfsAttributeListEntryLimit = 4096U;
    constexpr std::size_t kNtfsAttributeExtensionRecordLimit = 128U;

    template <typename TValue>
    bool readLe(
        const QByteArray& bytes,
        const std::uint64_t offset,
        TValue& valueOut)
    {
        if (offset > static_cast<std::uint64_t>(bytes.size())
            || sizeof(TValue)
                > static_cast<std::uint64_t>(bytes.size()) - offset)
        {
            return false;
        }
        std::memcpy(
            &valueOut,
            bytes.constData() + static_cast<qsizetype>(offset),
            sizeof(valueOut));
        return true;
    }

    bool isPowerOfTwo(const std::uint32_t value)
    {
        return value != 0U && (value & (value - 1U)) == 0U;
    }

    bool multiplyChecked(
        const std::uint64_t left,
        const std::uint64_t right,
        std::uint64_t& resultOut)
    {
        if (left != 0U
            && right > std::numeric_limits<std::uint64_t>::max() / left)
        {
            return false;
        }
        resultOut = left * right;
        return true;
    }

    void appendExtent(
        std::vector<ks::misc::RawFileExtent>& extents,
        const std::uint64_t logicalOffset,
        const std::uint64_t absoluteOffset,
        const std::uint64_t length,
        const bool sparse)
    {
        if (length == 0U)
        {
            return;
        }
        if (!extents.empty())
        {
            ks::misc::RawFileExtent& previous = extents.back();
            const bool kLogicalContiguous =
                previous.logicalOffset + previous.lengthBytes
                == logicalOffset;
            const bool kPhysicalContiguous = sparse
                ? previous.sparse
                : previous.physicalMappingExact
                    && previous.absoluteOffset + previous.lengthBytes
                        == absoluteOffset;
            if (kLogicalContiguous
                && previous.sparse == sparse
                && kPhysicalContiguous)
            {
                previous.lengthBytes += length;
                return;
            }
        }
        ks::misc::RawFileExtent extent;
        extent.logicalOffset = logicalOffset;
        extent.absoluteOffset = sparse ? 0U : absoluteOffset;
        extent.lengthBytes = length;
        extent.sparse = sparse;
        extent.physicalMappingExact = !sparse;
        extents.push_back(extent);
    }

    bool readMappedExtents(
        const ks::misc::rawfs::VolumeReader& reader,
        const std::vector<ks::misc::RawFileExtent>& extents,
        const std::uint64_t fileSize,
        const std::uint64_t requestedOffset,
        const std::uint32_t requestedLength,
        QByteArray& bytesOut,
        QString& errorTextOut)
    {
        bytesOut.clear();
        errorTextOut.clear();
        if (requestedOffset >= fileSize)
        {
            return true;
        }
        const std::uint32_t kBoundedLength =
            static_cast<std::uint32_t>(
                std::min<std::uint64_t>(
                    fileSize - requestedOffset,
                    requestedLength));
        bytesOut = QByteArray(
            static_cast<qsizetype>(kBoundedLength),
            '\0');
        std::uint64_t completed = 0U;
        for (const ks::misc::RawFileExtent& extent : extents)
        {
            const std::uint64_t kOverlapStart =
                std::max(requestedOffset, extent.logicalOffset);
            const std::uint64_t kOverlapEnd = std::min(
                requestedOffset + kBoundedLength,
                extent.logicalOffset + extent.lengthBytes);
            if (kOverlapStart >= kOverlapEnd)
            {
                continue;
            }
            const std::uint64_t kOverlapLength = kOverlapEnd - kOverlapStart;
            if (extent.sparse || extent.unwritten)
            {
                completed += kOverlapLength;
                continue;
            }
            if (!extent.physicalMappingExact
                || extent.absoluteOffset < reader.partitionOffset())
            {
                bytesOut.clear();
                errorTextOut = QStringLiteral(
                    "文件区间缺少可验证的物理映射。");
                return false;
            }
            QByteArray chunk;
            if (!reader.read(
                    extent.absoluteOffset - reader.partitionOffset()
                        + kOverlapStart - extent.logicalOffset,
                    static_cast<std::uint32_t>(kOverlapLength),
                    chunk,
                    errorTextOut))
            {
                bytesOut.clear();
                return false;
            }
            std::copy(
                chunk.cbegin(),
                chunk.cend(),
                bytesOut.begin()
                    + static_cast<qsizetype>(
                        kOverlapStart - requestedOffset));
            completed += kOverlapLength;
        }
        if (completed < kBoundedLength)
        {
            bytesOut.clear();
            errorTextOut = QStringLiteral(
                "文件簇链未覆盖请求的数据范围。");
            return false;
        }
        return true;
    }

    std::uint64_t physicalOffsetForLogical(
        const std::vector<ks::misc::RawFileExtent>& extents,
        const std::uint64_t logicalOffset)
    {
        for (const ks::misc::RawFileExtent& extent : extents)
        {
            if (extent.physicalMappingExact
                && logicalOffset >= extent.logicalOffset
                && logicalOffset - extent.logicalOffset
                    < extent.lengthBytes)
            {
                return extent.absoluteOffset
                    + logicalOffset - extent.logicalOffset;
            }
        }
        return 0U;
    }

    QStringList pathComponents(const QString& path)
    {
        return ks::misc::rawfs::normalizePath(path).split(
            QChar('\\'),
            Qt::SkipEmptyParts);
    }

    struct FatGeometry
    {
        ks::misc::ForensicFileSystemKind kind =
            ks::misc::ForensicFileSystemKind::kUnknown;
        std::uint32_t bytesPerSector = 0U;
        std::uint32_t clusterBytes = 0U;
        std::uint32_t rootDirectorySectors = 0U;
        std::uint64_t firstFatOffset = 0U;
        std::uint64_t rootDirectoryOffset = 0U;
        std::uint64_t firstDataOffset = 0U;
        std::uint32_t clusterCount = 0U;
        std::uint32_t rootCluster = 0U;
    };

    bool loadFatGeometry(
        const ks::misc::rawfs::VolumeReader& reader,
        const ks::misc::ForensicFileSystemKind expectedKind,
        FatGeometry& geometryOut,
        QString& errorTextOut)
    {
        QByteArray boot;
        if (!reader.read(0U, 512U, boot, errorTextOut))
        {
            return false;
        }
        std::uint16_t bytesPerSector = 0U;
        std::uint16_t reservedSectors = 0U;
        std::uint16_t rootEntryCount = 0U;
        std::uint16_t total16 = 0U;
        std::uint16_t fat16 = 0U;
        std::uint32_t total32 = 0U;
        std::uint32_t fat32 = 0U;
        std::uint32_t rootCluster = 0U;
        std::uint16_t fat32ExtendedFlags = 0U;
        std::uint16_t bootSignature = 0U;
        if (!readLe(boot, 11U, bytesPerSector)
            || !readLe(boot, 14U, reservedSectors)
            || !readLe(boot, 17U, rootEntryCount)
            || !readLe(boot, 19U, total16)
            || !readLe(boot, 22U, fat16)
            || !readLe(boot, 32U, total32)
            || !readLe(boot, 36U, fat32)
            || !readLe(boot, 40U, fat32ExtendedFlags)
            || !readLe(boot, 44U, rootCluster)
            || !readLe(boot, 510U, bootSignature))
        {
            errorTextOut = QStringLiteral("FAT BPB 字段不完整。");
            return false;
        }
        const std::uint32_t kSectorsPerCluster =
            static_cast<unsigned char>(boot.at(13));
        const std::uint32_t kFatCount =
            static_cast<unsigned char>(boot.at(16));
        const std::uint64_t kTotalSectors =
            total16 != 0U ? total16 : total32;
        const std::uint32_t kFatSectors =
            fat16 != 0U ? fat16 : fat32;
        if (!isPowerOfTwo(bytesPerSector)
            || bytesPerSector < 512U
            || bytesPerSector > 4096U
            || !isPowerOfTwo(kSectorsPerCluster)
            || kSectorsPerCluster > 128U
            || reservedSectors == 0U
            || kFatCount == 0U
            || kFatCount > 2U
            || kFatSectors == 0U
            || kTotalSectors == 0U
            || bootSignature != 0xAA55U)
        {
            errorTextOut = QStringLiteral("FAT BPB 几何字段无效。");
            return false;
        }
        const std::uint32_t kRootDirectorySectors =
            (static_cast<std::uint32_t>(rootEntryCount) * 32U
                + bytesPerSector - 1U)
            / bytesPerSector;
        const std::uint64_t kMetadataSectors =
            static_cast<std::uint64_t>(reservedSectors)
            + static_cast<std::uint64_t>(kFatCount) * kFatSectors
            + kRootDirectorySectors;
        std::uint64_t volumeBytes = 0U;
        std::uint64_t oneFatBytes = 0U;
        if (!multiplyChecked(
                kTotalSectors,
                bytesPerSector,
                volumeBytes)
            || !multiplyChecked(
                kFatSectors,
                bytesPerSector,
                oneFatBytes)
            || volumeBytes > reader.partitionLength()
            || static_cast<std::uint64_t>(reservedSectors)
                    * bytesPerSector
                > volumeBytes
            || oneFatBytes > volumeBytes)
        {
            errorTextOut = QStringLiteral(
                "FAT 卷长度或 FAT 区范围无效。");
            return false;
        }
        if (kMetadataSectors >= kTotalSectors)
        {
            errorTextOut = QStringLiteral("FAT 数据区起点越过卷边界。");
            return false;
        }
        const std::uint64_t kClusterCount64 =
            (kTotalSectors - kMetadataSectors) / kSectorsPerCluster;
        if (kClusterCount64 == 0U
            || kClusterCount64
                > std::numeric_limits<std::uint32_t>::max())
        {
            errorTextOut = QStringLiteral("FAT 簇数量无效。");
            return false;
        }
        ks::misc::ForensicFileSystemKind detectedKind =
            ks::misc::ForensicFileSystemKind::kFat32;
        if (kClusterCount64 < 4085U)
        {
            detectedKind = ks::misc::ForensicFileSystemKind::kFat12;
        }
        else if (kClusterCount64 < 65525U)
        {
            detectedKind = ks::misc::ForensicFileSystemKind::kFat16;
        }
        if (detectedKind != expectedKind)
        {
            errorTextOut = QStringLiteral(
                "FAT 簇数判定结果与探测类型不一致。");
            return false;
        }
        const std::uint64_t kFatEntryCapacity =
            detectedKind
                == ks::misc::ForensicFileSystemKind::kFat12
            ? (oneFatBytes * 2U) / 3U
            : detectedKind
                == ks::misc::ForensicFileSystemKind::kFat16
                ? oneFatBytes / 2U
                : oneFatBytes / 4U;
        if (kClusterCount64 + 2U > kFatEntryCapacity)
        {
            errorTextOut = QStringLiteral(
                "FAT 表长度不足以覆盖声明的数据簇。");
            return false;
        }
        FatGeometry geometry;
        geometry.kind = detectedKind;
        geometry.bytesPerSector = bytesPerSector;
        geometry.clusterBytes =
            bytesPerSector * kSectorsPerCluster;
        geometry.rootDirectorySectors = kRootDirectorySectors;
        const std::uint32_t kActiveFat =
            detectedKind
                    == ks::misc::ForensicFileSystemKind::kFat32
                && (fat32ExtendedFlags & 0x0080U) != 0U
            ? fat32ExtendedFlags & 0x000FU
            : 0U;
        if (kActiveFat >= kFatCount)
        {
            errorTextOut = QStringLiteral(
                "FAT32 活动 FAT 索引越界。");
            return false;
        }
        geometry.firstFatOffset =
            (static_cast<std::uint64_t>(reservedSectors)
                + static_cast<std::uint64_t>(kActiveFat)
                    * kFatSectors)
            * bytesPerSector;
        geometry.rootDirectoryOffset =
            (static_cast<std::uint64_t>(reservedSectors)
                + static_cast<std::uint64_t>(kFatCount) * kFatSectors)
            * bytesPerSector;
        geometry.firstDataOffset =
            kMetadataSectors * bytesPerSector;
        geometry.clusterCount =
            static_cast<std::uint32_t>(kClusterCount64);
        geometry.rootCluster =
            detectedKind == ks::misc::ForensicFileSystemKind::kFat32
                ? (rootCluster & 0x0FFFFFFFU)
                : 0U;
        if (detectedKind == ks::misc::ForensicFileSystemKind::kFat32
            && (geometry.rootCluster < 2U
                || geometry.rootCluster
                    >= geometry.clusterCount + 2U))
        {
            errorTextOut = QStringLiteral("FAT32 根目录簇无效。");
            return false;
        }
        geometryOut = geometry;
        return true;
    }

    std::uint64_t fatClusterOffset(
        const FatGeometry& geometry,
        const std::uint32_t cluster)
    {
        return geometry.firstDataOffset
            + static_cast<std::uint64_t>(cluster - 2U)
                * geometry.clusterBytes;
    }

    bool readFatEntry(
        const ks::misc::rawfs::VolumeReader& reader,
        const FatGeometry& geometry,
        const std::uint32_t cluster,
        std::uint32_t& nextOut,
        QString& errorTextOut)
    {
        std::uint64_t offset = geometry.firstFatOffset;
        std::uint32_t length = 4U;
        if (geometry.kind == ks::misc::ForensicFileSystemKind::kFat12)
        {
            offset += cluster + cluster / 2U;
            length = 2U;
        }
        else if (geometry.kind
            == ks::misc::ForensicFileSystemKind::kFat16)
        {
            offset += static_cast<std::uint64_t>(cluster) * 2U;
            length = 2U;
        }
        else
        {
            offset += static_cast<std::uint64_t>(cluster) * 4U;
        }
        QByteArray bytes;
        if (!reader.read(offset, length, bytes, errorTextOut))
        {
            return false;
        }
        if (geometry.kind == ks::misc::ForensicFileSystemKind::kFat12)
        {
            std::uint16_t pair = 0U;
            if (!readLe(bytes, 0U, pair))
            {
                errorTextOut = QStringLiteral("FAT12 表项被截断。");
                return false;
            }
            nextOut = (cluster & 1U) != 0U
                ? (pair >> 4U) & 0x0FFFU
                : pair & 0x0FFFU;
        }
        else if (geometry.kind
            == ks::misc::ForensicFileSystemKind::kFat16)
        {
            std::uint16_t value = 0U;
            if (!readLe(bytes, 0U, value))
            {
                errorTextOut = QStringLiteral("FAT16 表项被截断。");
                return false;
            }
            nextOut = value;
        }
        else
        {
            std::uint32_t value = 0U;
            if (!readLe(bytes, 0U, value))
            {
                errorTextOut = QStringLiteral("FAT32 表项被截断。");
                return false;
            }
            nextOut = value & 0x0FFFFFFFU;
        }
        return true;
    }

    bool fatEndOfChain(
        const FatGeometry& geometry,
        const std::uint32_t cluster)
    {
        if (geometry.kind == ks::misc::ForensicFileSystemKind::kFat12)
        {
            return cluster >= 0x0FF8U;
        }
        if (geometry.kind == ks::misc::ForensicFileSystemKind::kFat16)
        {
            return cluster >= 0xFFF8U;
        }
        return cluster >= 0x0FFFFFF8U;
    }

    bool buildFatExtents(
        const ks::misc::rawfs::VolumeReader& reader,
        const FatGeometry& geometry,
        const std::uint32_t firstCluster,
        const std::uint64_t requiredBytes,
        std::vector<ks::misc::RawFileExtent>& extentsOut,
        QString& errorTextOut)
    {
        extentsOut.clear();
        if (requiredBytes == 0U)
        {
            return true;
        }
        if (firstCluster < 2U
            || firstCluster >= geometry.clusterCount + 2U)
        {
            errorTextOut = QStringLiteral("FAT 起始簇越界。");
            return false;
        }
        std::unordered_set<std::uint32_t> visited;
        std::uint32_t cluster = firstCluster;
        std::uint64_t logicalOffset = 0U;
        while (logicalOffset < requiredBytes)
        {
            if (cluster < 2U
                || cluster >= geometry.clusterCount + 2U
                || !visited.insert(cluster).second)
            {
                errorTextOut = QStringLiteral(
                    "FAT 簇链无效或存在循环。");
                return false;
            }
            appendExtent(
                extentsOut,
                logicalOffset,
                reader.partitionOffset()
                    + fatClusterOffset(geometry, cluster),
                geometry.clusterBytes,
                false);
            logicalOffset += geometry.clusterBytes;
            if (logicalOffset >= requiredBytes)
            {
                break;
            }
            std::uint32_t next = 0U;
            if (!readFatEntry(
                    reader,
                    geometry,
                    cluster,
                    next,
                    errorTextOut))
            {
                return false;
            }
            if (fatEndOfChain(geometry, next))
            {
                errorTextOut = QStringLiteral(
                    "FAT 簇链在文件数据结束前提前终止。");
                return false;
            }
            cluster = next;
        }
        return true;
    }

    QString fatShortName(const char* entry)
    {
        QByteArray base(entry, 8);
        QByteArray extension(entry + 8, 3);
        if (!base.isEmpty()
            && static_cast<unsigned char>(base.at(0)) == 0x05U)
        {
            base[0] = static_cast<char>(0xE5U);
        }
        base = base.trimmed();
        extension = extension.trimmed();
        QString result = QString::fromLatin1(base);
        if (!extension.isEmpty())
        {
            result += QChar('.') + QString::fromLatin1(extension);
        }
        return result;
    }

    QString fatLfnFragment(const char* entry)
    {
        static constexpr std::array<int, 13> kOffsets{
            1, 3, 5, 7, 9,
            14, 16, 18, 20, 22, 24,
            28, 30
        };
        QString fragment;
        for (const int kOffset : kOffsets)
        {
            const std::uint16_t kCharacter =
                static_cast<std::uint16_t>(
                    static_cast<unsigned char>(entry[kOffset]))
                | static_cast<std::uint16_t>(
                    static_cast<unsigned char>(entry[kOffset + 1]))
                    << 8U;
            if (kCharacter == 0U || kCharacter == 0xFFFFU)
            {
                break;
            }
            fragment.append(QChar(kCharacter));
        }
        return fragment;
    }

    unsigned char fatShortNameChecksum(const char* entry)
    {
        unsigned char checksum = 0U;
        for (int index = 0; index < 11; ++index)
        {
            checksum = static_cast<unsigned char>(
                ((checksum & 1U) != 0U ? 0x80U : 0U)
                + (checksum >> 1U)
                + static_cast<unsigned char>(entry[index]));
        }
        return checksum;
    }

    bool readFatDirectoryBytes(
        const ks::misc::rawfs::VolumeReader& reader,
        const FatGeometry& geometry,
        const std::uint32_t directoryCluster,
        const bool rootDirectory,
        QByteArray& bytesOut,
        std::vector<ks::misc::RawFileExtent>& extentsOut,
        QString& errorTextOut)
    {
        extentsOut.clear();
        if (rootDirectory
            && geometry.kind != ks::misc::ForensicFileSystemKind::kFat32)
        {
            const std::uint64_t kLength =
                static_cast<std::uint64_t>(
                    geometry.rootDirectorySectors)
                * geometry.bytesPerSector;
            if (kLength == 0U || kLength > kDirectoryReadLimit)
            {
                errorTextOut = QStringLiteral(
                    "FAT 根目录大小无效或超过上限。");
                return false;
            }
            if (!reader.read(
                    geometry.rootDirectoryOffset,
                    static_cast<std::uint32_t>(kLength),
                    bytesOut,
                    errorTextOut))
            {
                return false;
            }
            appendExtent(
                extentsOut,
                0U,
                reader.partitionOffset()
                    + geometry.rootDirectoryOffset,
                kLength,
                false);
            return true;
        }
        std::unordered_set<std::uint32_t> visited;
        std::uint32_t cluster = rootDirectory
            ? geometry.rootCluster
            : directoryCluster;
        std::uint64_t logicalOffset = 0U;
        while (true)
        {
            if (cluster < 2U
                || cluster >= geometry.clusterCount + 2U
                || !visited.insert(cluster).second)
            {
                errorTextOut = QStringLiteral(
                    "FAT 目录簇链无效或存在循环。");
                return false;
            }
            appendExtent(
                extentsOut,
                logicalOffset,
                reader.partitionOffset()
                    + fatClusterOffset(geometry, cluster),
                geometry.clusterBytes,
                false);
            logicalOffset += geometry.clusterBytes;
            if (logicalOffset > kDirectoryReadLimit)
            {
                errorTextOut = QStringLiteral(
                    "FAT 目录数据超过 64 MiB 取证上限。");
                return false;
            }
            std::uint32_t next = 0U;
            if (!readFatEntry(
                    reader,
                    geometry,
                    cluster,
                    next,
                    errorTextOut))
            {
                return false;
            }
            if (fatEndOfChain(geometry, next))
            {
                break;
            }
            cluster = next;
        }
        return readMappedExtents(
            reader,
            extentsOut,
            logicalOffset,
            0U,
            static_cast<std::uint32_t>(logicalOffset),
            bytesOut,
            errorTextOut);
    }

    bool enumerateFatDirectory(
        const ks::misc::rawfs::VolumeReader& reader,
        const FatGeometry& geometry,
        const std::uint32_t directoryCluster,
        const bool rootDirectory,
        const QString& parentPath,
        std::vector<ks::misc::RawFileEntry>& entriesOut,
        std::uint64_t& scannedOut,
        QString& errorTextOut)
    {
        QByteArray bytes;
        std::vector<ks::misc::RawFileExtent>
            directoryExtents;
        if (!readFatDirectoryBytes(
                reader,
                geometry,
                directoryCluster,
                rootDirectory,
                bytes,
                directoryExtents,
                errorTextOut))
        {
            return false;
        }
        entriesOut.clear();
        scannedOut = 0U;
        std::array<QString, 20> lfnParts{};
        bool hasLfn = false;
        unsigned char lfnChecksum = 0U;
        unsigned int expectedLfnOrdinal = 0U;
        for (qsizetype offset = 0;
             offset + 32 <= bytes.size();
             offset += 32)
        {
            const char* entry = bytes.constData() + offset;
            const unsigned char kFirst =
                static_cast<unsigned char>(entry[0]);
            if (kFirst == 0U)
            {
                break;
            }
            ++scannedOut;
            const unsigned char kAttributes =
                static_cast<unsigned char>(entry[11]);
            if (kAttributes == 0x0FU)
            {
                if (kFirst == 0xE5U)
                {
                    lfnParts.fill(QString());
                    hasLfn = false;
                    expectedLfnOrdinal = 0U;
                    continue;
                }
                const unsigned int kOrdinal = kFirst & 0x1FU;
                const unsigned char kChecksum =
                    static_cast<unsigned char>(entry[13]);
                const bool kValidStructure =
                    kOrdinal >= 1U
                    && kOrdinal <= lfnParts.size()
                    && static_cast<unsigned char>(entry[12]) == 0U
                    && static_cast<unsigned char>(entry[26]) == 0U
                    && static_cast<unsigned char>(entry[27]) == 0U;
                if ((kFirst & 0x40U) != 0U && kValidStructure)
                {
                    lfnParts.fill(QString());
                    hasLfn = true;
                    lfnChecksum = kChecksum;
                    expectedLfnOrdinal = kOrdinal;
                }
                if (!hasLfn
                    || !kValidStructure
                    || kChecksum != lfnChecksum
                    || kOrdinal != expectedLfnOrdinal)
                {
                    lfnParts.fill(QString());
                    hasLfn = false;
                    expectedLfnOrdinal = 0U;
                    continue;
                }
                lfnParts[kOrdinal - 1U] =
                    fatLfnFragment(entry);
                --expectedLfnOrdinal;
                continue;
            }
            if (kFirst == 0xE5U || (kAttributes & 0x08U) != 0U)
            {
                lfnParts.fill(QString());
                hasLfn = false;
                expectedLfnOrdinal = 0U;
                continue;
            }
            QString name;
            if (hasLfn
                && expectedLfnOrdinal == 0U
                && lfnChecksum == fatShortNameChecksum(entry))
            {
                for (const QString& part : lfnParts)
                {
                    name += part;
                }
            }
            if (name.isEmpty())
            {
                name = fatShortName(entry);
            }
            lfnParts.fill(QString());
            hasLfn = false;
            expectedLfnOrdinal = 0U;
            if (name.isEmpty()
                || name == QStringLiteral(".")
                || name == QStringLiteral(".."))
            {
                continue;
            }
            std::uint16_t highCluster = 0U;
            std::uint16_t lowCluster = 0U;
            std::uint32_t fileSize = 0U;
            readLe(bytes, offset + 20U, highCluster);
            readLe(bytes, offset + 26U, lowCluster);
            readLe(bytes, offset + 28U, fileSize);
            const std::uint32_t kFirstCluster =
                geometry.kind
                    == ks::misc::ForensicFileSystemKind::kFat32
                ? (static_cast<std::uint32_t>(highCluster)
                        << 16U)
                    | lowCluster
                : lowCluster;
            const std::uint32_t kNormalizedFirstCluster =
                kFirstCluster & 0x0FFFFFFFU;
            ks::misc::RawFileEntry output;
            output.name = name;
            output.fullPath =
                ks::misc::rawfs::childPath(parentPath, name);
            output.type = (kAttributes & 0x10U) != 0U
                ? ks::misc::RawFileObjectType::kDirectory
                : ks::misc::RawFileObjectType::kRegularFile;
            output.objectId = kNormalizedFirstCluster;
            output.parentObjectId = directoryCluster;
            output.fileSizeBytes = fileSize;
            output.allocatedSizeBytes = fileSize == 0U
                ? 0U
                : ((static_cast<std::uint64_t>(fileSize)
                    + geometry.clusterBytes - 1U)
                    / geometry.clusterBytes)
                    * geometry.clusterBytes;
            output.metadataOffset =
                physicalOffsetForLogical(
                    directoryExtents,
                    static_cast<std::uint64_t>(offset));
            output.modeOrFlags = kAttributes;
            const std::uint64_t kExtentBytes =
                output.type == ks::misc::RawFileObjectType::kDirectory
                ? geometry.clusterBytes
                : fileSize;
            if (kExtentBytes != 0U
                && !buildFatExtents(
                    reader,
                    geometry,
                    kNormalizedFirstCluster,
                    kExtentBytes,
                    output.extents,
                    errorTextOut))
            {
                return false;
            }
            entriesOut.push_back(std::move(output));
        }
        return true;
    }

    bool resolveFatPath(
        const ks::misc::rawfs::VolumeReader& reader,
        const FatGeometry& geometry,
        const QString& path,
        ks::misc::RawFileEntry& entryOut,
        bool& rootOut,
        QString& errorTextOut)
    {
        const QStringList kComponents = pathComponents(path);
        if (kComponents.isEmpty())
        {
            rootOut = true;
            entryOut = {};
            entryOut.fullPath = QStringLiteral("\\");
            entryOut.type = ks::misc::RawFileObjectType::kDirectory;
            entryOut.objectId = geometry.rootCluster;
            return true;
        }
        bool root = true;
        std::uint32_t directoryCluster = geometry.rootCluster;
        QString currentPath = QStringLiteral("\\");
        for (qsizetype index = 0; index < kComponents.size(); ++index)
        {
            std::vector<ks::misc::RawFileEntry> entries;
            std::uint64_t scanned = 0U;
            if (!enumerateFatDirectory(
                    reader,
                    geometry,
                    directoryCluster,
                    root,
                    currentPath,
                    entries,
                    scanned,
                    errorTextOut))
            {
                return false;
            }
            const auto kFound = std::find_if(
                entries.cbegin(),
                entries.cend(),
                [&kComponents, index](
                    const ks::misc::RawFileEntry& candidate)
                {
                    return candidate.name.compare(
                        kComponents.at(index),
                        Qt::CaseInsensitive) == 0;
                });
            if (kFound == entries.cend())
            {
                errorTextOut = QStringLiteral(
                    "FAT 路径组件不存在：%1")
                    .arg(kComponents.at(index));
                return false;
            }
            entryOut = *kFound;
            currentPath = kFound->fullPath;
            root = false;
            directoryCluster =
                static_cast<std::uint32_t>(kFound->objectId);
            if (index + 1 < kComponents.size()
                && kFound->type
                    != ks::misc::RawFileObjectType::kDirectory)
            {
                errorTextOut = QStringLiteral(
                    "FAT 路径中间组件不是目录：%1")
                    .arg(kFound->name);
                return false;
            }
        }
        rootOut = false;
        return true;
    }

    struct ExFatGeometry
    {
        std::uint32_t sectorBytes = 0U;
        std::uint32_t clusterBytes = 0U;
        std::uint64_t fatOffset = 0U;
        std::uint64_t clusterHeapOffset = 0U;
        std::uint32_t clusterCount = 0U;
        std::uint32_t rootCluster = 0U;
    };

    bool loadExFatGeometry(
        const ks::misc::rawfs::VolumeReader& reader,
        ExFatGeometry& geometryOut,
        QString& errorTextOut)
    {
        QByteArray boot;
        if (!reader.read(0U, 512U, boot, errorTextOut))
        {
            return false;
        }
        if (boot.mid(3, 8) != QByteArray("EXFAT   ", 8))
        {
            errorTextOut = QStringLiteral("不是有效的 exFAT 卷。");
            return false;
        }
        const std::uint32_t kSectorShift =
            static_cast<unsigned char>(boot.at(108));
        const std::uint32_t kClusterShift =
            static_cast<unsigned char>(boot.at(109));
        std::uint32_t fatOffsetSectors = 0U;
        std::uint32_t fatLengthSectors = 0U;
        std::uint32_t heapOffsetSectors = 0U;
        std::uint32_t clusterCount = 0U;
        std::uint32_t rootCluster = 0U;
        std::uint64_t volumeLengthSectors = 0U;
        std::uint16_t bootSignature = 0U;
        std::uint16_t volumeFlags = 0U;
        const std::uint32_t kFatCount =
            static_cast<unsigned char>(boot.at(110));
        if (!readLe(boot, 80U, fatOffsetSectors)
            || !readLe(boot, 72U, volumeLengthSectors)
            || !readLe(boot, 84U, fatLengthSectors)
            || !readLe(boot, 88U, heapOffsetSectors)
            || !readLe(boot, 92U, clusterCount)
            || !readLe(boot, 96U, rootCluster)
            || !readLe(boot, 106U, volumeFlags)
            || !readLe(boot, 510U, bootSignature)
            || kSectorShift < 9U
            || kSectorShift > 12U
            || kClusterShift > 25U
            || kSectorShift + kClusterShift > 25U
            || volumeLengthSectors == 0U
            || fatLengthSectors == 0U
            || (kFatCount != 1U && kFatCount != 2U)
            || bootSignature != 0xAA55U)
        {
            errorTextOut = QStringLiteral(
                "exFAT 启动区几何字段无效。");
            return false;
        }
        ExFatGeometry geometry;
        geometry.sectorBytes = 1U << kSectorShift;
        geometry.clusterBytes =
            1U << (kSectorShift + kClusterShift);
        const std::uint64_t kFirstFatOffset =
            static_cast<std::uint64_t>(fatOffsetSectors)
            * geometry.sectorBytes;
        const std::uint32_t kActiveFat =
            kFatCount == 2U && (volumeFlags & 0x0001U) != 0U
            ? 1U
            : 0U;
        geometry.fatOffset =
            kFirstFatOffset
            + static_cast<std::uint64_t>(kActiveFat)
                * fatLengthSectors
                * geometry.sectorBytes;
        geometry.clusterHeapOffset =
            static_cast<std::uint64_t>(heapOffsetSectors)
            * geometry.sectorBytes;
        geometry.clusterCount = clusterCount;
        geometry.rootCluster = rootCluster;
        std::uint64_t volumeBytes = 0U;
        std::uint64_t fatBytes = 0U;
        std::uint64_t allFatBytes = 0U;
        std::uint64_t heapBytes = 0U;
        if (clusterCount == 0U
            || rootCluster < 2U
            || rootCluster >= clusterCount + 2U
            || !multiplyChecked(
                volumeLengthSectors,
                geometry.sectorBytes,
                volumeBytes)
            || !multiplyChecked(
                fatLengthSectors,
                geometry.sectorBytes,
                fatBytes)
            || !multiplyChecked(
                fatBytes,
                kFatCount,
                allFatBytes)
            || !multiplyChecked(
                clusterCount,
                geometry.clusterBytes,
                heapBytes)
            || volumeBytes > reader.partitionLength()
            || kFirstFatOffset > volumeBytes
            || allFatBytes > volumeBytes - kFirstFatOffset
            || kFirstFatOffset > geometry.clusterHeapOffset
            || allFatBytes
                > geometry.clusterHeapOffset - kFirstFatOffset
            || geometry.fatOffset > volumeBytes
            || fatBytes > volumeBytes - geometry.fatOffset
            || (static_cast<std::uint64_t>(clusterCount) + 2U)
                    * 4U
                > fatBytes
            || geometry.clusterHeapOffset > volumeBytes
            || heapBytes
                > volumeBytes - geometry.clusterHeapOffset)
        {
            errorTextOut = QStringLiteral(
                "exFAT 卷范围、FAT、簇堆或根目录簇无效。");
            return false;
        }
        geometryOut = geometry;
        return true;
    }

    std::uint64_t exFatClusterOffset(
        const ExFatGeometry& geometry,
        const std::uint32_t cluster)
    {
        return geometry.clusterHeapOffset
            + static_cast<std::uint64_t>(cluster - 2U)
                * geometry.clusterBytes;
    }

    bool readExFatNext(
        const ks::misc::rawfs::VolumeReader& reader,
        const ExFatGeometry& geometry,
        const std::uint32_t cluster,
        std::uint32_t& nextOut,
        QString& errorTextOut)
    {
        QByteArray bytes;
        if (!reader.read(
                geometry.fatOffset
                    + static_cast<std::uint64_t>(cluster) * 4U,
                4U,
                bytes,
                errorTextOut)
            || !readLe(bytes, 0U, nextOut))
        {
            if (errorTextOut.isEmpty())
            {
                errorTextOut = QStringLiteral(
                    "exFAT FAT 表项被截断。");
            }
            return false;
        }
        return true;
    }

    bool exFatEndOfChain(const std::uint32_t cluster)
    {
        return cluster >= 0xFFFFFFF8U;
    }

    bool buildExFatExtents(
        const ks::misc::rawfs::VolumeReader& reader,
        const ExFatGeometry& geometry,
        const std::uint32_t firstCluster,
        const std::uint64_t requiredBytes,
        const bool noFatChain,
        std::vector<ks::misc::RawFileExtent>& extentsOut,
        QString& errorTextOut)
    {
        extentsOut.clear();
        if (requiredBytes == 0U)
        {
            return true;
        }
        const std::uint64_t kRequiredClusters =
            (requiredBytes + geometry.clusterBytes - 1U)
            / geometry.clusterBytes;
        if (firstCluster < 2U
            || firstCluster >= geometry.clusterCount + 2U
            || kRequiredClusters
                > geometry.clusterCount + 2ULL - firstCluster)
        {
            errorTextOut = QStringLiteral(
                "exFAT 文件簇范围越界。");
            return false;
        }
        if (noFatChain)
        {
            appendExtent(
                extentsOut,
                0U,
                reader.partitionOffset()
                    + exFatClusterOffset(geometry, firstCluster),
                kRequiredClusters * geometry.clusterBytes,
                false);
            return true;
        }
        std::unordered_set<std::uint32_t> visited;
        std::uint32_t cluster = firstCluster;
        for (std::uint64_t index = 0U;
             index < kRequiredClusters;
             ++index)
        {
            if (cluster < 2U
                || cluster >= geometry.clusterCount + 2U
                || !visited.insert(cluster).second)
            {
                errorTextOut = QStringLiteral(
                    "exFAT 簇链无效或存在循环。");
                return false;
            }
            appendExtent(
                extentsOut,
                index * geometry.clusterBytes,
                reader.partitionOffset()
                    + exFatClusterOffset(geometry, cluster),
                geometry.clusterBytes,
                false);
            if (index + 1U == kRequiredClusters)
            {
                break;
            }
            if (!readExFatNext(
                    reader,
                    geometry,
                    cluster,
                    cluster,
                    errorTextOut)
                || exFatEndOfChain(cluster))
            {
                if (errorTextOut.isEmpty())
                {
                    errorTextOut = QStringLiteral(
                        "exFAT 簇链提前结束。");
                }
                return false;
            }
        }
        return true;
    }

    void markUninitializedExtents(
        const std::uint64_t validDataLength,
        std::vector<ks::misc::RawFileExtent>& extents)
    {
        std::vector<ks::misc::RawFileExtent> normalized;
        normalized.reserve(extents.size() + 1U);
        for (const ks::misc::RawFileExtent& extent : extents)
        {
            const std::uint64_t kExtentEnd =
                extent.logicalOffset + extent.lengthBytes;
            if (validDataLength <= extent.logicalOffset)
            {
                ks::misc::RawFileExtent uninitialized = extent;
                uninitialized.unwritten = true;
                normalized.push_back(uninitialized);
                continue;
            }
            if (validDataLength >= kExtentEnd)
            {
                normalized.push_back(extent);
                continue;
            }
            ks::misc::RawFileExtent initialized = extent;
            initialized.lengthBytes =
                validDataLength - extent.logicalOffset;
            normalized.push_back(initialized);
            ks::misc::RawFileExtent uninitialized = extent;
            uninitialized.logicalOffset = validDataLength;
            uninitialized.lengthBytes =
                kExtentEnd - validDataLength;
            if (uninitialized.physicalMappingExact)
            {
                uninitialized.absoluteOffset +=
                    initialized.lengthBytes;
            }
            uninitialized.unwritten = true;
            normalized.push_back(uninitialized);
        }
        extents = std::move(normalized);
    }

    bool readExFatDirectory(
        const ks::misc::rawfs::VolumeReader& reader,
        const ExFatGeometry& geometry,
        const std::uint32_t firstCluster,
        const std::uint64_t dataLength,
        const bool noFatChain,
        QByteArray& bytesOut,
        std::vector<ks::misc::RawFileExtent>& extentsOut,
        QString& errorTextOut)
    {
        extentsOut.clear();
        std::uint64_t boundedLength = dataLength;
        if (dataLength == 0U)
        {
            std::unordered_set<std::uint32_t> visited;
            std::uint32_t cluster = firstCluster;
            while (true)
            {
                if (cluster < 2U
                    || cluster >= geometry.clusterCount + 2U
                    || !visited.insert(cluster).second)
                {
                    errorTextOut = QStringLiteral(
                        "exFAT 根目录簇链无效或存在循环。");
                    return false;
                }
                appendExtent(
                    extentsOut,
                    boundedLength,
                    reader.partitionOffset()
                        + exFatClusterOffset(
                            geometry,
                            cluster),
                    geometry.clusterBytes,
                    false);
                boundedLength += geometry.clusterBytes;
                if (boundedLength > kDirectoryReadLimit)
                {
                    errorTextOut = QStringLiteral(
                        "exFAT 根目录超过 64 MiB 取证上限。");
                    return false;
                }
                if (!readExFatNext(
                        reader,
                        geometry,
                        cluster,
                        cluster,
                        errorTextOut))
                {
                    return false;
                }
                if (exFatEndOfChain(cluster))
                {
                    break;
                }
            }
        }
        else
        {
            boundedLength = std::min<std::uint64_t>(
                dataLength,
                kDirectoryReadLimit);
            if (!buildExFatExtents(
                    reader,
                    geometry,
                    firstCluster,
                    boundedLength,
                    noFatChain,
                    extentsOut,
                    errorTextOut))
            {
                return false;
            }
        }
        if (boundedLength == 0U)
        {
            errorTextOut = QStringLiteral(
                "exFAT 目录长度为 0。");
            return false;
        }
        return readMappedExtents(
            reader,
            extentsOut,
            boundedLength,
            0U,
            static_cast<std::uint32_t>(boundedLength),
            bytesOut,
            errorTextOut);
    }

    bool enumerateExFatDirectory(
        const ks::misc::rawfs::VolumeReader& reader,
        const ExFatGeometry& geometry,
        const std::uint32_t directoryCluster,
        const std::uint64_t directoryLength,
        const bool directoryNoFatChain,
        const QString& parentPath,
        std::vector<ks::misc::RawFileEntry>& entriesOut,
        std::uint64_t& scannedOut,
        QString& errorTextOut)
    {
        QByteArray bytes;
        std::vector<ks::misc::RawFileExtent>
            directoryExtents;
        if (!readExFatDirectory(
                reader,
                geometry,
                directoryCluster,
                directoryLength,
                directoryNoFatChain,
                bytes,
                directoryExtents,
                errorTextOut))
        {
            return false;
        }
        entriesOut.clear();
        scannedOut = 0U;
        for (qsizetype offset = 0;
             offset + 32 <= bytes.size();
             offset += 32)
        {
            const unsigned char kEntryType =
                static_cast<unsigned char>(bytes.at(offset));
            if (kEntryType == 0U)
            {
                break;
            }
            ++scannedOut;
            if (kEntryType != 0x85U)
            {
                continue;
            }
            const unsigned int kSecondaryCount =
                static_cast<unsigned char>(bytes.at(offset + 1));
            if (kSecondaryCount == 0U
                || static_cast<std::uint64_t>(offset)
                        + static_cast<std::uint64_t>(
                            kSecondaryCount + 1U) * 32U
                    > static_cast<std::uint64_t>(bytes.size()))
            {
                errorTextOut = QStringLiteral(
                    "exFAT 文件目录项集合被截断。");
                return false;
            }
            const std::uint64_t kSetBytes =
                static_cast<std::uint64_t>(
                    kSecondaryCount + 1U) * 32U;
            std::uint16_t storedChecksum = 0U;
            if (!readLe(
                    bytes,
                    static_cast<std::uint64_t>(offset) + 2U,
                    storedChecksum))
            {
                errorTextOut = QStringLiteral(
                    "exFAT 文件目录项集合校验和字段被截断。");
                return false;
            }
            std::uint16_t computedChecksum = 0U;
            for (std::uint64_t byteIndex = 0U;
                 byteIndex < kSetBytes;
                 ++byteIndex)
            {
                if (byteIndex == 2U || byteIndex == 3U)
                {
                    continue;
                }
                computedChecksum =
                    static_cast<std::uint16_t>(
                        (computedChecksum >> 1U)
                        | (computedChecksum << 15U));
                computedChecksum =
                    static_cast<std::uint16_t>(
                        computedChecksum
                        + static_cast<unsigned char>(
                            bytes.at(
                                offset
                                + static_cast<qsizetype>(
                                    byteIndex))));
            }
            if (computedChecksum != storedChecksum)
            {
                errorTextOut = QStringLiteral(
                    "exFAT 文件目录项集合 SetChecksum 不匹配。");
                return false;
            }
            const char* stream =
                bytes.constData() + offset + 32;
            if (static_cast<unsigned char>(stream[0]) != 0xC0U)
            {
                errorTextOut = QStringLiteral(
                    "exFAT 文件目录项后未紧随唯一的 Stream Extension。");
                return false;
            }
            const unsigned int kNameLength =
                static_cast<unsigned char>(stream[3]);
            if (kNameLength == 0U)
            {
                errorTextOut = QStringLiteral(
                    "exFAT Stream Extension 的 NameLength 为零。");
                return false;
            }
            const unsigned int kNameEntryCount =
                (kNameLength + 14U) / 15U;
            if (kSecondaryCount != 1U + kNameEntryCount)
            {
                errorTextOut = QStringLiteral(
                    "exFAT 文件目录项的 SecondaryCount 与名称项数量不一致。");
                return false;
            }
            QString name;
            name.reserve(static_cast<qsizetype>(kNameLength));
            for (unsigned int nameEntryIndex = 0U;
                 nameEntryIndex < kNameEntryCount;
                 ++nameEntryIndex)
            {
                const char* item =
                    bytes.constData() + offset
                    + static_cast<qsizetype>(
                        (2U + nameEntryIndex) * 32U);
                const unsigned char kSecondaryType =
                    static_cast<unsigned char>(item[0]);
                if (kSecondaryType != 0xC1U)
                {
                    errorTextOut = QStringLiteral(
                        "exFAT File Name 项不连续或类型无效。");
                    return false;
                }
                for (unsigned int index = 0U;
                     index < 15U
                     && name.size()
                         < static_cast<qsizetype>(
                             kNameLength);
                     ++index)
                {
                    const std::uint16_t kCharacter =
                        static_cast<std::uint16_t>(
                            static_cast<unsigned char>(
                                item[2 + index * 2]))
                        | static_cast<std::uint16_t>(
                            static_cast<unsigned char>(
                                item[3 + index * 2]))
                            << 8U;
                    if (kCharacter == 0U)
                    {
                        errorTextOut = QStringLiteral(
                            "exFAT 文件名在 NameLength 之前出现终止字符。");
                        return false;
                    }
                    name.append(QChar(kCharacter));
                }
            }
            if (name.size()
                != static_cast<qsizetype>(kNameLength))
            {
                errorTextOut = QStringLiteral(
                    "exFAT 文件名长度与 Stream Extension 不一致。");
                return false;
            }
            std::uint16_t attributes = 0U;
            std::uint32_t firstCluster = 0U;
            std::uint64_t dataLength = 0U;
            std::uint64_t validDataLength = 0U;
            readLe(bytes, offset + 4U, attributes);
            std::memcpy(
                &validDataLength,
                stream + 8,
                sizeof(validDataLength));
            std::memcpy(
                &firstCluster,
                stream + 20,
                sizeof(firstCluster));
            std::memcpy(
                &dataLength,
                stream + 24,
                sizeof(dataLength));
            if (validDataLength > dataLength)
            {
                errorTextOut = QStringLiteral(
                    "exFAT ValidDataLength 大于 DataLength。");
                return false;
            }
            const bool kNoFatChain =
                (static_cast<unsigned char>(stream[1]) & 0x02U) != 0U;
            ks::misc::RawFileEntry output;
            output.name = name;
            output.fullPath =
                ks::misc::rawfs::childPath(parentPath, name);
            output.type = (attributes & 0x10U) != 0U
                ? ks::misc::RawFileObjectType::kDirectory
                : ks::misc::RawFileObjectType::kRegularFile;
            output.objectId = firstCluster;
            output.parentObjectId = directoryCluster;
            output.fileSizeBytes = dataLength;
            output.metadataOffset =
                physicalOffsetForLogical(
                    directoryExtents,
                    static_cast<std::uint64_t>(offset));
            output.modeOrFlags =
                static_cast<std::uint32_t>(attributes)
                | (kNoFatChain ? 0x80000000U : 0U);
            if (dataLength != 0U
                && !buildExFatExtents(
                    reader,
                    geometry,
                    firstCluster,
                    dataLength,
                    kNoFatChain,
                    output.extents,
                    errorTextOut))
            {
                return false;
            }
            markUninitializedExtents(
                validDataLength,
                output.extents);
            output.allocatedSizeBytes = 0U;
            for (const ks::misc::RawFileExtent& extent :
                 output.extents)
            {
                output.allocatedSizeBytes +=
                    extent.lengthBytes;
            }
            entriesOut.push_back(std::move(output));
            offset += static_cast<qsizetype>(
                kSecondaryCount * 32U);
        }
        return true;
    }

    bool resolveExFatPath(
        const ks::misc::rawfs::VolumeReader& reader,
        const ExFatGeometry& geometry,
        const QString& path,
        ks::misc::RawFileEntry& entryOut,
        bool& rootOut,
        QString& errorTextOut)
    {
        const QStringList kComponents = pathComponents(path);
        if (kComponents.isEmpty())
        {
            rootOut = true;
            entryOut = {};
            entryOut.fullPath = QStringLiteral("\\");
            entryOut.type = ks::misc::RawFileObjectType::kDirectory;
            entryOut.objectId = geometry.rootCluster;
            return true;
        }
        std::uint32_t directoryCluster = geometry.rootCluster;
        std::uint64_t directoryLength = 0U;
        bool noFatChain = false;
        QString currentPath = QStringLiteral("\\");
        for (qsizetype index = 0; index < kComponents.size(); ++index)
        {
            std::vector<ks::misc::RawFileEntry> entries;
            std::uint64_t scanned = 0U;
            if (!enumerateExFatDirectory(
                    reader,
                    geometry,
                    directoryCluster,
                    directoryLength,
                    noFatChain,
                    currentPath,
                    entries,
                    scanned,
                    errorTextOut))
            {
                return false;
            }
            const auto kFound = std::find_if(
                entries.cbegin(),
                entries.cend(),
                [&kComponents, index](
                    const ks::misc::RawFileEntry& candidate)
                {
                    return candidate.name.compare(
                        kComponents.at(index),
                        Qt::CaseInsensitive) == 0;
                });
            if (kFound == entries.cend())
            {
                errorTextOut = QStringLiteral(
                    "exFAT 路径组件不存在：%1")
                    .arg(kComponents.at(index));
                return false;
            }
            entryOut = *kFound;
            currentPath = kFound->fullPath;
            directoryCluster =
                static_cast<std::uint32_t>(kFound->objectId);
            directoryLength = kFound->fileSizeBytes;
            noFatChain =
                (kFound->modeOrFlags & 0x80000000U) != 0U;
            if (index + 1 < kComponents.size()
                && kFound->type
                    != ks::misc::RawFileObjectType::kDirectory)
            {
                errorTextOut = QStringLiteral(
                    "exFAT 路径中间组件不是目录：%1")
                    .arg(kFound->name);
                return false;
            }
        }
        rootOut = false;
        return true;
    }

    std::uint64_t ntfsReferenceNumber(
        const std::uint64_t reference)
    {
        return reference & 0x0000FFFFFFFFFFFFULL;
    }

    struct NtfsRun
    {
        std::uint64_t vcn = 0U;
        std::int64_t lcn = 0;
        std::uint64_t clusterCount = 0U;
        bool sparse = false;
    };

    struct NtfsDataStream
    {
        QString name;
        bool resident = false;
        bool compressed = false;
        bool encrypted = false;
        std::uint16_t attributeId = 0U;
        std::uint64_t firstVcn = 0U;
        std::uint64_t realSize = 0U;
        std::uint64_t allocatedSize = 0U;
        std::uint64_t validDataLength = 0U;
        QByteArray residentBytes;
        std::vector<NtfsRun> runs;
    };

    struct NtfsAttributeReference
    {
        std::uint32_t type = 0U;
        QString name;
        std::uint64_t lowestVcn = 0U;
        std::uint64_t recordNumber = 0U;
        std::uint16_t sequenceNumber = 0U;
        std::uint16_t attributeId = 0U;
    };

    struct NtfsAttributeIdentity
    {
        std::uint32_t type = 0U;
        QString name;
        std::uint64_t lowestVcn = 0U;
        std::uint16_t attributeId = 0U;
    };

    struct NtfsFileLink
    {
        QString name;
        std::uint64_t parentRecord = 0U;
        std::uint16_t parentSequence = 0U;
        std::uint32_t fileAttributes = 0U;
        unsigned int nameSpace = 0U;
        std::uint16_t attributeId = 0U;
    };

    struct NtfsRecord
    {
        bool valid = false;
        bool inUse = false;
        bool directory = false;
        std::uint64_t recordNumber = 0U;
        std::uint64_t baseRecordNumber = 0U;
        bool hasBaseRecordReference = false;
        std::uint16_t sequenceNumber = 0U;
        std::uint16_t baseRecordSequenceNumber = 0U;
        std::uint64_t parentRecord = 0U;
        std::uint64_t metadataOffset = 0U;
        std::uint32_t fileAttributes = 0U;
        QString name;
        std::vector<NtfsFileLink> links;
        std::vector<NtfsDataStream> streams;
        std::vector<NtfsDataStream>
            attributeListSegments;
        std::vector<NtfsAttributeIdentity>
            attributes;
        std::vector<NtfsAttributeReference>
            attributeReferences;
        bool hasAttributeList = false;
        bool nonResidentAttributeList = false;
        bool attributeListResolved = false;
    };

    struct NtfsGeometry
    {
        std::uint32_t bytesPerSector = 0U;
        std::uint32_t clusterBytes = 0U;
        std::uint32_t recordBytes = 0U;
        std::uint64_t mftOffset = 0U;
        NtfsDataStream mftStream;
    };

    bool readNtfsRecordBase(
        const ks::misc::rawfs::VolumeReader& reader,
        const NtfsGeometry& geometry,
        std::uint64_t recordNumber,
        NtfsRecord& recordOut,
        QString& errorTextOut);

    bool resolveNtfsAttributeList(
        const ks::misc::rawfs::VolumeReader& reader,
        const NtfsGeometry& geometry,
        NtfsRecord& baseRecord,
        QString& errorTextOut);

    bool applyNtfsFixups(
        QByteArray& record,
        const std::uint32_t bytesPerSector,
        QString& errorTextOut)
    {
        std::uint16_t usaOffset = 0U;
        std::uint16_t usaCount = 0U;
        if (!readLe(record, 4U, usaOffset)
            || !readLe(record, 6U, usaCount)
            || usaCount < 2U
            || bytesPerSector == 0U
            || (record.size()
                % static_cast<qsizetype>(bytesPerSector)) != 0
            || usaCount
                != static_cast<std::uint16_t>(
                    record.size()
                        / static_cast<qsizetype>(
                            bytesPerSector)
                    + 1)
            || usaOffset + static_cast<std::uint64_t>(usaCount) * 2U
                > static_cast<std::uint64_t>(record.size()))
        {
            errorTextOut = QStringLiteral(
                "NTFS USA 修复数组无效。");
            return false;
        }
        std::uint16_t sequence = 0U;
        readLe(record, usaOffset, sequence);
        for (std::uint16_t index = 1U; index < usaCount; ++index)
        {
            const std::uint64_t kTrailerOffset =
                static_cast<std::uint64_t>(index)
                    * bytesPerSector
                - 2U;
            std::uint16_t trailer = 0U;
            std::uint16_t replacement = 0U;
            if (!readLe(record, kTrailerOffset, trailer)
                || !readLe(
                    record,
                    usaOffset
                        + static_cast<std::uint64_t>(index) * 2U,
                    replacement)
                || trailer != sequence)
            {
                errorTextOut = QStringLiteral(
                    "NTFS 多扇区记录 USA 校验失败。");
                return false;
            }
            std::memcpy(
                record.data()
                    + static_cast<qsizetype>(kTrailerOffset),
                &replacement,
                sizeof(replacement));
        }
        return true;
    }

    bool parseNtfsRunList(
        const QByteArray& record,
        const std::uint64_t start,
        const std::uint64_t end,
        const std::uint64_t firstVcn,
        std::vector<NtfsRun>& runsOut,
        QString& errorTextOut)
    {
        runsOut.clear();
        std::uint64_t cursor = start;
        std::uint64_t vcn = firstVcn;
        std::int64_t currentLcn = 0;
        while (cursor < end)
        {
            const unsigned char kHeader =
                static_cast<unsigned char>(
                    record.at(static_cast<qsizetype>(cursor++)));
            if (kHeader == 0U)
            {
                return true;
            }
            const unsigned int kLengthBytes = kHeader & 0x0FU;
            const unsigned int kOffsetBytes = kHeader >> 4U;
            if (kLengthBytes == 0U
                || kLengthBytes > 8U
                || kOffsetBytes > 8U
                || cursor + kLengthBytes + kOffsetBytes > end)
            {
                errorTextOut = QStringLiteral(
                    "NTFS runlist 项长度无效。");
                return false;
            }
            std::uint64_t clusterCount = 0U;
            for (unsigned int index = 0U;
                 index < kLengthBytes;
                 ++index)
            {
                clusterCount |=
                    static_cast<std::uint64_t>(
                        static_cast<unsigned char>(
                            record.at(static_cast<qsizetype>(
                                cursor + index))))
                    << (index * 8U);
            }
            cursor += kLengthBytes;
            if (clusterCount == 0U)
            {
                errorTextOut = QStringLiteral(
                    "NTFS runlist 包含零长度区间。");
                return false;
            }
            NtfsRun run;
            run.vcn = vcn;
            run.clusterCount = clusterCount;
            run.sparse = kOffsetBytes == 0U;
            if (!run.sparse)
            {
                std::uint64_t rawDelta = 0U;
                for (unsigned int index = 0U;
                     index < kOffsetBytes;
                     ++index)
                {
                    rawDelta |=
                        static_cast<std::uint64_t>(
                            static_cast<unsigned char>(
                                record.at(static_cast<qsizetype>(
                                    cursor + index))))
                        << (index * 8U);
                }
                if (kOffsetBytes < 8U
                    && (rawDelta
                        & (1ULL
                            << (kOffsetBytes * 8U - 1U))) != 0U)
                {
                    rawDelta |=
                        ~((1ULL << (kOffsetBytes * 8U)) - 1ULL);
                }
                const std::int64_t kDelta =
                    static_cast<std::int64_t>(rawDelta);
                if ((kDelta > 0
                        && currentLcn
                            > std::numeric_limits<
                                std::int64_t>::max() - kDelta)
                    || (kDelta < 0
                        && currentLcn
                            < std::numeric_limits<
                                std::int64_t>::min() - kDelta))
                {
                    errorTextOut = QStringLiteral(
                        "NTFS runlist LCN 增量溢出。");
                    return false;
                }
                currentLcn += kDelta;
                if (currentLcn < 0)
                {
                    errorTextOut = QStringLiteral(
                        "NTFS runlist 指向负 LCN。");
                    return false;
                }
                run.lcn = currentLcn;
            }
            cursor += kOffsetBytes;
            if (clusterCount
                > std::numeric_limits<std::uint64_t>::max()
                    - vcn)
            {
                errorTextOut = QStringLiteral(
                    "NTFS runlist VCN 范围溢出。");
                return false;
            }
            runsOut.push_back(run);
            vcn += clusterCount;
            if (runsOut.size()
                > ks::misc::rawfs::kMaximumExtentCount)
            {
                errorTextOut = QStringLiteral(
                    "NTFS runlist 超过取证上限。");
                return false;
            }
        }
        errorTextOut = QStringLiteral(
            "NTFS runlist 缺少终止项。");
        return false;
    }

    bool parseNtfsAttributeStream(
        const QByteArray& recordBytes,
        const std::uint64_t cursor,
        const std::uint32_t length,
        const bool nonResident,
        const std::uint16_t attributeFlags,
        const std::uint16_t attributeId,
        const QString& attributeName,
        const QString& diagnosticName,
        NtfsDataStream& streamOut,
        QString& errorTextOut)
    {
        NtfsDataStream stream;
        stream.name = attributeName;
        stream.attributeId = attributeId;
        stream.resident = !nonResident;
        stream.compressed =
            (attributeFlags & 0x00FFU) != 0U;
        stream.encrypted =
            (attributeFlags & 0x4000U) != 0U;
        if (!nonResident)
        {
            std::uint32_t valueLength = 0U;
            std::uint16_t valueOffset = 0U;
            if (!readLe(
                    recordBytes,
                    cursor + 16U,
                    valueLength)
                || !readLe(
                    recordBytes,
                    cursor + 20U,
                    valueOffset)
                || valueOffset < 24U
                || static_cast<std::uint64_t>(valueOffset)
                        + valueLength
                    > length)
            {
                errorTextOut = QStringLiteral(
                    "NTFS 驻留 %1 范围无效。")
                    .arg(diagnosticName);
                return false;
            }
            stream.realSize = valueLength;
            stream.allocatedSize = valueLength;
            stream.validDataLength = valueLength;
            stream.residentBytes = recordBytes.mid(
                static_cast<qsizetype>(
                    cursor + valueOffset),
                static_cast<qsizetype>(valueLength));
            streamOut = std::move(stream);
            return true;
        }

        std::uint64_t lastVcn = 0U;
        std::uint16_t runOffset = 0U;
        std::uint64_t allocatedSize = 0U;
        std::uint64_t realSize = 0U;
        std::uint64_t validDataLength = 0U;
        if (!readLe(
                recordBytes,
                cursor + 16U,
                stream.firstVcn)
            || !readLe(
                recordBytes,
                cursor + 24U,
                lastVcn)
            || !readLe(
                recordBytes,
                cursor + 32U,
                runOffset)
            || !readLe(
                recordBytes,
                cursor + 40U,
                allocatedSize)
            || !readLe(
                recordBytes,
                cursor + 48U,
                realSize)
            || !readLe(
                recordBytes,
                cursor + 56U,
                validDataLength)
            || runOffset < 64U
            || runOffset >= length
            || !parseNtfsRunList(
                recordBytes,
                cursor + runOffset,
                cursor + length,
                stream.firstVcn,
                stream.runs,
                errorTextOut))
        {
            if (errorTextOut.isEmpty())
            {
                errorTextOut = QStringLiteral(
                    "NTFS 非驻留 %1 runlist 无效。")
                    .arg(diagnosticName);
            }
            return false;
        }
        if (stream.firstVcn == 0U)
        {
            stream.allocatedSize = allocatedSize;
            stream.realSize = realSize;
            stream.validDataLength = validDataLength;
            if (stream.validDataLength > stream.realSize)
            {
                errorTextOut = QStringLiteral(
                    "NTFS 非驻留 %1 的 ValidDataLength "
                    "大于 FileSize。")
                    .arg(diagnosticName);
                return false;
            }
        }
        if (stream.runs.empty())
        {
            if (stream.firstVcn != 0U
                || stream.realSize != 0U
                || stream.allocatedSize != 0U)
            {
                errorTextOut = QStringLiteral(
                    "NTFS 非驻留 %1 缺少数据区间。")
                    .arg(diagnosticName);
                return false;
            }
        }
        else
        {
            const NtfsRun& finalRun = stream.runs.back();
            if (finalRun.clusterCount
                    > std::numeric_limits<std::uint64_t>::max()
                        - finalRun.vcn
                || finalRun.vcn + finalRun.clusterCount - 1U
                    != lastVcn)
            {
                errorTextOut = QStringLiteral(
                    "NTFS 非驻留 %1 的最高 VCN 与 runlist 不一致。")
                    .arg(diagnosticName);
                return false;
            }
        }
        streamOut = std::move(stream);
        return true;
    }

    bool parseNtfsRecord(
        QByteArray recordBytes,
        const NtfsGeometry& geometry,
        const std::uint64_t recordNumber,
        const std::uint64_t metadataOffset,
        NtfsRecord& recordOut,
        QString& errorTextOut)
    {
        recordOut = {};
        if (recordBytes.size()
                != static_cast<qsizetype>(geometry.recordBytes)
            || recordBytes.mid(0, 4) != QByteArray("FILE", 4))
        {
            return true;
        }
        if (!applyNtfsFixups(
                recordBytes,
                geometry.bytesPerSector,
                errorTextOut))
        {
            return false;
        }
        std::uint16_t firstAttributeOffset = 0U;
        std::uint16_t recordFlags = 0U;
        std::uint32_t bytesInUse = 0U;
        if (!readLe(
                recordBytes,
                20U,
                firstAttributeOffset)
            || !readLe(recordBytes, 22U, recordFlags)
            || !readLe(recordBytes, 24U, bytesInUse)
            || firstAttributeOffset >= recordBytes.size()
            || (firstAttributeOffset & 7U) != 0U
            || firstAttributeOffset > bytesInUse
            || bytesInUse < 48U
            || bytesInUse
                > static_cast<std::uint32_t>(recordBytes.size()))
        {
            errorTextOut = QStringLiteral(
                "NTFS FILE 记录头无效。");
            return false;
        }
        NtfsRecord record;
        record.valid = true;
        record.inUse = (recordFlags & 0x0001U) != 0U;
        record.directory = (recordFlags & 0x0002U) != 0U;
        record.recordNumber = recordNumber;
        record.metadataOffset = metadataOffset;
        std::uint64_t baseRecordReference = 0U;
        if (!readLe(
                recordBytes,
                16U,
                record.sequenceNumber)
            || !readLe(
                recordBytes,
                32U,
                baseRecordReference))
        {
            errorTextOut = QStringLiteral(
                "NTFS FILE 记录引用字段无效。");
            return false;
        }
        record.baseRecordNumber =
            ntfsReferenceNumber(baseRecordReference);
        record.hasBaseRecordReference =
            baseRecordReference != 0U;
        record.baseRecordSequenceNumber =
            static_cast<std::uint16_t>(
                baseRecordReference >> 48U);
        if (record.inUse && record.sequenceNumber == 0U)
        {
            errorTextOut = QStringLiteral(
                "NTFS 已使用 FILE 记录的序列号为零。");
            return false;
        }
        if (record.hasBaseRecordReference
            && record.baseRecordSequenceNumber == 0U)
        {
            errorTextOut = QStringLiteral(
                "NTFS 扩展 FILE 记录使用了保留的零基记录序列号。");
            return false;
        }
        int bestNameRank = -1;
        std::uint64_t cursor = firstAttributeOffset;
        while (cursor + 16U <= bytesInUse)
        {
            std::uint32_t type = 0U;
            std::uint32_t length = 0U;
            readLe(recordBytes, cursor, type);
            readLe(recordBytes, cursor + 4U, length);
            if (type == 0xFFFFFFFFU)
            {
                break;
            }
            if (length < 16U
                || (length & 7U) != 0U
                || cursor + length > bytesInUse)
            {
                errorTextOut = QStringLiteral(
                    "NTFS 属性记录长度无效。");
                return false;
            }
            const bool kNonResident =
                static_cast<unsigned char>(
                    recordBytes.at(static_cast<qsizetype>(
                        cursor + 8U))) != 0U;
            if ((kNonResident && length < 64U)
                || (!kNonResident && length < 24U))
            {
                errorTextOut = QStringLiteral(
                    "NTFS 属性记录头长度无效。");
                return false;
            }
            const unsigned int kNameLength =
                static_cast<unsigned char>(
                    recordBytes.at(static_cast<qsizetype>(
                        cursor + 9U)));
            std::uint16_t nameOffset = 0U;
            std::uint16_t attributeFlags = 0U;
            std::uint16_t attributeId = 0U;
            readLe(recordBytes, cursor + 10U, nameOffset);
            readLe(recordBytes, cursor + 12U, attributeFlags);
            readLe(recordBytes, cursor + 14U, attributeId);
            QString attributeName;
            if (kNameLength != 0U)
            {
                const std::uint64_t kNameBytes =
                    static_cast<std::uint64_t>(kNameLength) * 2U;
                const std::uint16_t kMinimumNameOffset =
                    kNonResident ? 64U : 24U;
                if (nameOffset < kMinimumNameOffset
                    || nameOffset + kNameBytes > length)
                {
                    errorTextOut = QStringLiteral(
                        "NTFS 属性名称范围无效。");
                    return false;
                }
                attributeName = QString::fromUtf16(
                    reinterpret_cast<const char16_t*>(
                        recordBytes.constData()
                        + static_cast<qsizetype>(
                            cursor + nameOffset)),
                    static_cast<qsizetype>(kNameLength));
            }
            NtfsAttributeIdentity identity;
            identity.type = type;
            identity.name = attributeName;
            identity.attributeId = attributeId;
            if (kNonResident
                && !readLe(
                    recordBytes,
                    cursor + 16U,
                    identity.lowestVcn))
            {
                errorTextOut = QStringLiteral(
                    "NTFS 非驻留属性 VCN 字段无效。");
                return false;
            }
            record.attributes.push_back(std::move(identity));
            if (type == 0x30U && !kNonResident)
            {
                std::uint32_t valueLength = 0U;
                std::uint16_t valueOffset = 0U;
                readLe(recordBytes, cursor + 16U, valueLength);
                readLe(recordBytes, cursor + 20U, valueOffset);
                if (valueOffset < 24U
                    || valueOffset > length
                    || valueLength
                        > length - valueOffset)
                {
                    errorTextOut = QStringLiteral(
                        "NTFS $FILE_NAME 值范围超出驻留属性边界。");
                    return false;
                }
                const std::uint64_t kValueStart =
                    cursor + valueOffset;
                if (valueLength < 66U)
                {
                    errorTextOut = QStringLiteral(
                        "NTFS $FILE_NAME 值短于固定字段。");
                    return false;
                }
                std::uint64_t parentReference = 0U;
                std::uint32_t fileAttributes = 0U;
                readLe(
                    recordBytes,
                    kValueStart,
                    parentReference);
                readLe(
                    recordBytes,
                    kValueStart + 56U,
                    fileAttributes);
                const unsigned int kFileNameLength =
                    static_cast<unsigned char>(
                        recordBytes.at(static_cast<qsizetype>(
                            kValueStart + 64U)));
                const unsigned int kNameSpace =
                    static_cast<unsigned char>(
                        recordBytes.at(static_cast<qsizetype>(
                            kValueStart + 65U)));
                const std::uint64_t kRequiredValueLength =
                    66U
                    + static_cast<std::uint64_t>(
                        kFileNameLength) * 2U;
                if (kRequiredValueLength > valueLength)
                {
                    errorTextOut = QStringLiteral(
                        "NTFS $FILE_NAME 名称超出属性值边界。");
                    return false;
                }
                NtfsFileLink link;
                link.name = QString::fromUtf16(
                    reinterpret_cast<const char16_t*>(
                        recordBytes.constData()
                        + static_cast<qsizetype>(
                            kValueStart + 66U)),
                    static_cast<qsizetype>(
                        kFileNameLength));
                link.parentRecord =
                    ntfsReferenceNumber(parentReference);
                link.parentSequence =
                    static_cast<std::uint16_t>(
                        parentReference >> 48U);
                link.fileAttributes = fileAttributes;
                link.nameSpace = kNameSpace;
                link.attributeId = attributeId;
                const auto kDuplicate = std::find_if(
                    record.links.cbegin(),
                    record.links.cend(),
                    [&link](const NtfsFileLink& existing)
                    {
                        return existing.parentRecord
                                == link.parentRecord
                            && existing.parentSequence
                                == link.parentSequence
                            && existing.name.compare(
                                link.name,
                                Qt::CaseInsensitive) == 0;
                    });
                if (kDuplicate == record.links.cend())
                {
                    record.links.push_back(link);
                }
                const int kRank =
                    kNameSpace == 3U ? 3
                    : kNameSpace == 1U ? 2
                    : kNameSpace == 0U ? 1
                    : 0;
                if (kRank > bestNameRank)
                {
                    record.name = link.name;
                    record.parentRecord = link.parentRecord;
                    record.fileAttributes = fileAttributes;
                    bestNameRank = kRank;
                }
            }
            else if (type == 0x20U)
            {
                record.hasAttributeList = true;
                record.nonResidentAttributeList =
                    record.nonResidentAttributeList
                    || kNonResident;
                NtfsDataStream segment;
                if (!parseNtfsAttributeStream(
                        recordBytes,
                        cursor,
                        length,
                        kNonResident,
                        attributeFlags,
                        attributeId,
                        attributeName,
                        QStringLiteral("$ATTRIBUTE_LIST"),
                        segment,
                        errorTextOut))
                {
                    return false;
                }
                record.attributeListSegments.push_back(
                    std::move(segment));
            }
            else if (type == 0x80U)
            {
                NtfsDataStream stream;
                if (!parseNtfsAttributeStream(
                        recordBytes,
                        cursor,
                        length,
                        kNonResident,
                        attributeFlags,
                        attributeId,
                        attributeName,
                        QStringLiteral("$DATA"),
                        stream,
                        errorTextOut))
                {
                    return false;
                }
                record.streams.push_back(std::move(stream));
            }
            cursor += length;
        }
        record.attributeListResolved = !record.hasAttributeList;
        recordOut = std::move(record);
        return true;
    }

    bool ntfsStreamExtents(
        const ks::misc::rawfs::VolumeReader& reader,
        const NtfsGeometry& geometry,
        const NtfsDataStream& stream,
        std::vector<ks::misc::RawFileExtent>& extentsOut,
        QString& errorTextOut)
    {
        extentsOut.clear();
        if (stream.resident)
        {
            return true;
        }
        for (const NtfsRun& run : stream.runs)
        {
            std::uint64_t logicalOffset = 0U;
            std::uint64_t length = 0U;
            std::uint64_t relativePhysical = 0U;
            if (!multiplyChecked(
                    run.vcn,
                    geometry.clusterBytes,
                    logicalOffset)
                || !multiplyChecked(
                    run.clusterCount,
                    geometry.clusterBytes,
                    length)
                || logicalOffset
                    > std::numeric_limits<std::uint64_t>::max()
                        - length
                || (!run.sparse
                    && !multiplyChecked(
                        static_cast<std::uint64_t>(run.lcn),
                        geometry.clusterBytes,
                        relativePhysical))
                || (!run.sparse
                    && (!reader.rangeIsValid(
                            relativePhysical,
                            length)
                        || reader.partitionOffset()
                            > std::numeric_limits<
                                std::uint64_t>::max()
                                - relativePhysical)))
            {
                errorTextOut = QStringLiteral(
                    "NTFS runlist 字节范围溢出。");
                return false;
            }
            appendExtent(
                extentsOut,
                logicalOffset,
                run.sparse
                    ? 0U
                    : reader.partitionOffset() + relativePhysical,
                length,
                run.sparse);
            extentsOut.back().compressed =
                stream.compressed;
        }
        if (stream.validDataLength > stream.realSize)
        {
            errorTextOut = QStringLiteral(
                "NTFS $DATA 的 ValidDataLength 大于 FileSize。");
            return false;
        }
        markUninitializedExtents(
            stream.validDataLength,
            extentsOut);
        return true;
    }

    bool readNtfsStream(
        const ks::misc::rawfs::VolumeReader& reader,
        const NtfsGeometry& geometry,
        const NtfsDataStream& stream,
        const std::uint64_t offset,
        const std::uint32_t length,
        QByteArray& bytesOut,
        std::vector<ks::misc::RawFileExtent>& extentsOut,
        QString& errorTextOut)
    {
        if (!stream.resident
            && (stream.compressed || stream.encrypted)
            && !ntfsStreamExtents(
                reader,
                geometry,
                stream,
                extentsOut,
                errorTextOut))
        {
            return false;
        }
        if (stream.compressed)
        {
            errorTextOut = QStringLiteral(
                "当前原始读取器拒绝猜测 NTFS 压缩单元；"
                "已保留区间证据，但不返回可能错误的解压数据。");
            return false;
        }
        if (stream.encrypted)
        {
            errorTextOut = QStringLiteral(
                "目标 NTFS $DATA 使用 EFS 加密；"
                "原始读取器保留物理区间证据，但不会把密文误报为文件明文。");
            return false;
        }
        if (stream.resident)
        {
            bytesOut = offset >= static_cast<std::uint64_t>(
                    stream.residentBytes.size())
                ? QByteArray()
                : stream.residentBytes.mid(
                    static_cast<qsizetype>(offset),
                    static_cast<qsizetype>(
                        std::min<std::uint64_t>(
                            length,
                            static_cast<std::uint64_t>(
                                stream.residentBytes.size())
                                - offset)));
            extentsOut.clear();
            return true;
        }
        if (!ntfsStreamExtents(
                reader,
                geometry,
                stream,
                extentsOut,
                errorTextOut))
        {
            return false;
        }
        return readMappedExtents(
            reader,
            extentsOut,
            stream.realSize,
            offset,
            length,
            bytesOut,
            errorTextOut);
    }

    std::uint64_t ntfsStreamPhysicalOffset(
        const ks::misc::rawfs::VolumeReader& reader,
        const NtfsGeometry& geometry,
        const NtfsDataStream& stream,
        const std::uint64_t logicalOffset)
    {
        std::vector<ks::misc::RawFileExtent> extents;
        QString ignored;
        if (!ntfsStreamExtents(
                reader,
                geometry,
                stream,
                extents,
                ignored))
        {
            return 0U;
        }
        for (const ks::misc::RawFileExtent& extent : extents)
        {
            if (extent.physicalMappingExact
                && logicalOffset >= extent.logicalOffset
                && logicalOffset
                    < extent.logicalOffset + extent.lengthBytes)
            {
                return extent.absoluteOffset
                    + logicalOffset - extent.logicalOffset;
            }
        }
        return 0U;
    }

    bool loadNtfsGeometry(
        const ks::misc::rawfs::VolumeReader& reader,
        NtfsGeometry& geometryOut,
        QString& errorTextOut)
    {
        QByteArray boot;
        if (!reader.read(0U, 512U, boot, errorTextOut))
        {
            return false;
        }
        if (boot.mid(3, 8) != QByteArray("NTFS    ", 8))
        {
            errorTextOut = QStringLiteral("不是有效的 NTFS 卷。");
            return false;
        }
        std::uint16_t bytesPerSector = 0U;
        std::uint64_t mftLcn = 0U;
        std::uint64_t mftMirrorLcn = 0U;
        std::uint64_t totalSectors = 0U;
        std::uint16_t bootSignature = 0U;
        readLe(boot, 11U, bytesPerSector);
        readLe(boot, 40U, totalSectors);
        readLe(boot, 48U, mftLcn);
        readLe(boot, 56U, mftMirrorLcn);
        readLe(boot, 510U, bootSignature);
        const std::uint32_t kSectorsPerCluster =
            static_cast<unsigned char>(boot.at(13));
        const std::int8_t kClustersPerRecord =
            static_cast<std::int8_t>(boot.at(64));
        if (!isPowerOfTwo(bytesPerSector)
            || bytesPerSector < 512U
            || bytesPerSector > 4096U
            || !isPowerOfTwo(kSectorsPerCluster)
            || kSectorsPerCluster > 128U
            || mftLcn == 0U
            || kClustersPerRecord == 0
            || (kClustersPerRecord < 0
                && -static_cast<int>(kClustersPerRecord) > 31)
            || totalSectors == 0U
            || bootSignature != 0xAA55U)
        {
            errorTextOut = QStringLiteral(
                "NTFS BPB 几何字段无效。");
            return false;
        }
        NtfsGeometry geometry;
        geometry.bytesPerSector = bytesPerSector;
        geometry.clusterBytes =
            bytesPerSector * kSectorsPerCluster;
        geometry.recordBytes = kClustersPerRecord < 0
            ? 1U << static_cast<unsigned int>(
                -kClustersPerRecord)
            : geometry.clusterBytes
                * static_cast<std::uint32_t>(kClustersPerRecord);
        std::uint64_t volumeBytes = 0U;
        if (!multiplyChecked(
                totalSectors,
                bytesPerSector,
                volumeBytes)
            || volumeBytes > reader.partitionLength()
            || !isPowerOfTwo(geometry.recordBytes)
            || geometry.recordBytes < 512U
            || geometry.recordBytes > 64U * 1024U
            || !multiplyChecked(
                mftLcn,
                geometry.clusterBytes,
                geometry.mftOffset)
            || !reader.rangeIsValid(
                geometry.mftOffset,
                geometry.recordBytes))
        {
            errorTextOut = QStringLiteral(
                "NTFS MFT 位置或记录大小无效。");
            return false;
        }
        NtfsRecord mftRecord;
        QByteArray firstRecord;
        QString primaryError;
        bool mftParsed =
            reader.read(
                geometry.mftOffset,
                geometry.recordBytes,
                firstRecord,
                primaryError)
            && parseNtfsRecord(
                firstRecord,
                geometry,
                0U,
                reader.partitionOffset()
                    + geometry.mftOffset,
                mftRecord,
                primaryError)
            && mftRecord.valid;
        if (!mftParsed && mftMirrorLcn != 0U)
        {
            std::uint64_t mirrorOffset = 0U;
            QString mirrorError;
            QByteArray mirrorRecord;
            if (multiplyChecked(
                    mftMirrorLcn,
                    geometry.clusterBytes,
                    mirrorOffset)
                && reader.rangeIsValid(
                    mirrorOffset,
                    geometry.recordBytes)
                && reader.read(
                    mirrorOffset,
                    geometry.recordBytes,
                    mirrorRecord,
                    mirrorError))
            {
                NtfsRecord mirrorMftRecord;
                if (parseNtfsRecord(
                        mirrorRecord,
                        geometry,
                        0U,
                        reader.partitionOffset() + mirrorOffset,
                        mirrorMftRecord,
                        mirrorError)
                    && mirrorMftRecord.valid)
                {
                    mftRecord = std::move(mirrorMftRecord);
                    mftParsed = true;
                }
            }
            if (!mftParsed && primaryError.isEmpty())
            {
                primaryError = mirrorError;
            }
        }
        if (!mftParsed)
        {
            errorTextOut = primaryError.isEmpty()
                ? QStringLiteral(
                    "NTFS $MFT 与 $MFTMirr 首记录均无法解析。")
                : QStringLiteral(
                    "NTFS $MFT 首记录无法解析：%1")
                    .arg(primaryError);
            return false;
        }
        const auto kUnnamed = std::find_if(
            mftRecord.streams.cbegin(),
            mftRecord.streams.cend(),
            [](const NtfsDataStream& stream)
            {
                return stream.name.isEmpty();
            });
        if (kUnnamed == mftRecord.streams.cend()
            || kUnnamed->resident
            || kUnnamed->runs.empty())
        {
            errorTextOut = QStringLiteral(
                "NTFS $MFT 缺少可解析的非驻留 $DATA。");
            return false;
        }
        geometry.mftStream = *kUnnamed;
        if (mftRecord.hasAttributeList)
        {
            QString attributeListError;
            if (!resolveNtfsAttributeList(
                    reader,
                    geometry,
                    mftRecord,
                    attributeListError)
                || !mftRecord.attributeListResolved)
            {
                errorTextOut = QStringLiteral(
                    "NTFS $MFT 的 $ATTRIBUTE_LIST 证据不足，"
                    "无法安全建立完整 MFT 映射：%1")
                    .arg(
                        attributeListError.isEmpty()
                            ? QStringLiteral(
                                "扩展记录或 VCN 区间不完整")
                            : attributeListError);
                return false;
            }
            const auto kResolvedUnnamed = std::find_if(
                mftRecord.streams.cbegin(),
                mftRecord.streams.cend(),
                [](const NtfsDataStream& stream)
                {
                    return stream.name.isEmpty();
                });
            if (kResolvedUnnamed == mftRecord.streams.cend()
                || kResolvedUnnamed->resident
                || kResolvedUnnamed->runs.empty())
            {
                errorTextOut = QStringLiteral(
                    "NTFS $MFT 的扩展属性未形成可验证的未命名 $DATA。");
                return false;
            }
            geometry.mftStream = *kResolvedUnnamed;
        }
        geometryOut = std::move(geometry);
        return true;
    }

    bool readNtfsRecordBase(
        const ks::misc::rawfs::VolumeReader& reader,
        const NtfsGeometry& geometry,
        const std::uint64_t recordNumber,
        NtfsRecord& recordOut,
        QString& errorTextOut)
    {
        std::uint64_t byteOffset = 0U;
        if (!multiplyChecked(
                recordNumber,
                geometry.recordBytes,
                byteOffset))
        {
            errorTextOut = QStringLiteral(
                "NTFS MFT 记录偏移溢出。");
            return false;
        }
        QByteArray bytes;
        std::vector<ks::misc::RawFileExtent> ignored;
        if (!readNtfsStream(
                reader,
                geometry,
                geometry.mftStream,
                byteOffset,
                geometry.recordBytes,
                bytes,
                ignored,
                errorTextOut)
            || bytes.size()
                != static_cast<qsizetype>(geometry.recordBytes))
        {
            if (errorTextOut.isEmpty())
            {
                errorTextOut = QStringLiteral(
                    "NTFS MFT 记录读取被截断。");
            }
            return false;
        }
        return parseNtfsRecord(
            bytes,
            geometry,
            recordNumber,
            ntfsStreamPhysicalOffset(
                reader,
                geometry,
                geometry.mftStream,
                byteOffset),
            recordOut,
            errorTextOut);
    }

    bool normalizeNtfsRuns(
        NtfsDataStream& stream,
        const bool requireFirstVcnZero,
        const QString& diagnosticName,
        QString& errorTextOut)
    {
        if (stream.validDataLength > stream.realSize)
        {
            errorTextOut = QStringLiteral(
                "NTFS %1 的 ValidDataLength 大于逻辑长度。")
                .arg(diagnosticName);
            return false;
        }
        if (stream.resident)
        {
            return true;
        }
        std::sort(
            stream.runs.begin(),
            stream.runs.end(),
            [](const NtfsRun& left, const NtfsRun& right)
            {
                return left.vcn < right.vcn;
            });
        std::vector<NtfsRun> normalized;
        normalized.reserve(stream.runs.size());
        for (const NtfsRun& run : stream.runs)
        {
            if (run.clusterCount == 0U
                || run.clusterCount
                    > std::numeric_limits<std::uint64_t>::max()
                        - run.vcn)
            {
                errorTextOut = QStringLiteral(
                    "NTFS %1 runlist 包含无效 VCN 区间。")
                    .arg(diagnosticName);
                return false;
            }
            if (!normalized.empty())
            {
                const NtfsRun& previous = normalized.back();
                const std::uint64_t kPreviousEnd =
                    previous.vcn + previous.clusterCount;
                if (run.vcn < kPreviousEnd)
                {
                    const bool kDuplicate =
                        run.vcn == previous.vcn
                        && run.clusterCount
                            == previous.clusterCount
                        && run.lcn == previous.lcn
                        && run.sparse == previous.sparse;
                    if (kDuplicate)
                    {
                        continue;
                    }
                    errorTextOut = QStringLiteral(
                        "NTFS %1 扩展 runlist 的 VCN 区间重叠。")
                        .arg(diagnosticName);
                    return false;
                }
                if (requireFirstVcnZero
                    && run.vcn != kPreviousEnd)
                {
                    errorTextOut = QStringLiteral(
                        "NTFS %1 扩展 runlist 存在 VCN 缺口。")
                        .arg(diagnosticName);
                    return false;
                }
            }
            normalized.push_back(run);
            if (normalized.size()
                > ks::misc::rawfs::kMaximumExtentCount)
            {
                errorTextOut = QStringLiteral(
                    "NTFS %1 合并后的 runlist 超过取证上限。")
                    .arg(diagnosticName);
                return false;
            }
        }
        if (requireFirstVcnZero
            && stream.realSize != 0U
            && (normalized.empty()
                || normalized.front().vcn != 0U))
        {
            errorTextOut = QStringLiteral(
                "NTFS %1 扩展 runlist 未从 VCN 0 开始。")
                .arg(diagnosticName);
            return false;
        }
        if (!normalized.empty())
        {
            stream.firstVcn = normalized.front().vcn;
        }
        stream.runs = std::move(normalized);
        return true;
    }

    bool mergeNtfsStreamSegment(
        std::vector<NtfsDataStream>& streams,
        const NtfsDataStream& incoming,
        const QString& diagnosticName,
        QString& errorTextOut)
    {
        const auto kFound = std::find_if(
            streams.begin(),
            streams.end(),
            [&incoming](const NtfsDataStream& existing)
            {
                return existing.name == incoming.name;
            });
        if (kFound == streams.end())
        {
            streams.push_back(incoming);
            return normalizeNtfsRuns(
                streams.back(),
                false,
                diagnosticName,
                errorTextOut);
        }
        if (kFound->resident != incoming.resident)
        {
            errorTextOut = QStringLiteral(
                "NTFS 同名 %1 的驻留类型在扩展记录间不一致。")
                .arg(diagnosticName);
            return false;
        }
        if (incoming.resident)
        {
            if (kFound->residentBytes != incoming.residentBytes)
            {
                errorTextOut = QStringLiteral(
                    "NTFS 扩展记录包含冲突的驻留 %1。")
                    .arg(diagnosticName);
                return false;
            }
            return true;
        }
        kFound->compressed =
            kFound->compressed || incoming.compressed;
        kFound->encrypted =
            kFound->encrypted || incoming.encrypted;
        kFound->realSize =
            std::max(kFound->realSize, incoming.realSize);
        kFound->allocatedSize =
            std::max(
                kFound->allocatedSize,
                incoming.allocatedSize);
        kFound->validDataLength =
            std::max(
                kFound->validDataLength,
                incoming.validDataLength);
        kFound->firstVcn =
            std::min(kFound->firstVcn, incoming.firstVcn);
        kFound->runs.insert(
            kFound->runs.end(),
            incoming.runs.cbegin(),
            incoming.runs.cend());
        return normalizeNtfsRuns(
            *kFound,
            false,
            diagnosticName,
            errorTextOut);
    }

    bool ntfsAttributeReferenceMatches(
        const NtfsAttributeIdentity& identity,
        const NtfsAttributeReference& reference)
    {
        return identity.type == reference.type
            && identity.name == reference.name
            && identity.lowestVcn == reference.lowestVcn
            && identity.attributeId == reference.attributeId;
    }

    bool parseNtfsAttributeListValue(
        const QByteArray& value,
        std::vector<NtfsAttributeReference>& referencesOut,
        QString& errorTextOut)
    {
        referencesOut.clear();
        std::uint64_t cursor = 0U;
        while (cursor < static_cast<std::uint64_t>(value.size()))
        {
            const std::uint64_t kRemaining =
                static_cast<std::uint64_t>(value.size()) - cursor;
            if (kRemaining < 26U)
            {
                const QByteArray kTrailing = value.mid(
                    static_cast<qsizetype>(cursor));
                if (kRemaining <= 7U
                    && std::all_of(
                        kTrailing.cbegin(),
                        kTrailing.cend(),
                        [](const char byte)
                        {
                            return byte == '\0';
                        }))
                {
                    break;
                }
                errorTextOut = QStringLiteral(
                    "NTFS $ATTRIBUTE_LIST 尾部不足一个完整项目。");
                return false;
            }
            NtfsAttributeReference reference;
            std::uint16_t entryLength = 0U;
            std::uint64_t fileReference = 0U;
            if (!readLe(value, cursor, reference.type)
                || !readLe(
                    value,
                    cursor + 4U,
                    entryLength)
                || !readLe(
                    value,
                    cursor + 8U,
                    reference.lowestVcn)
                || !readLe(
                    value,
                    cursor + 16U,
                    fileReference)
                || !readLe(
                    value,
                    cursor + 24U,
                    reference.attributeId))
            {
                errorTextOut = QStringLiteral(
                    "NTFS $ATTRIBUTE_LIST 项字段被截断。");
                return false;
            }
            const unsigned int kNameLength =
                static_cast<unsigned char>(
                    value.at(static_cast<qsizetype>(
                        cursor + 6U)));
            const unsigned int kNameOffset =
                static_cast<unsigned char>(
                    value.at(static_cast<qsizetype>(
                        cursor + 7U)));
            if (reference.type == 0U
                || reference.type == 0xFFFFFFFFU
                || entryLength < 26U
                || (entryLength & 7U) != 0U
                || entryLength > kRemaining
                || (kNameLength != 0U
                    && (kNameOffset < 26U
                        || static_cast<std::uint64_t>(kNameOffset)
                                + static_cast<std::uint64_t>(
                                    kNameLength) * 2U
                            > entryLength)))
            {
                errorTextOut = QStringLiteral(
                    "NTFS $ATTRIBUTE_LIST 项的长度、类型或名称范围无效。");
                return false;
            }
            if (kNameLength != 0U)
            {
                reference.name = QString::fromUtf16(
                    reinterpret_cast<const char16_t*>(
                        value.constData()
                        + static_cast<qsizetype>(
                            cursor + kNameOffset)),
                    static_cast<qsizetype>(kNameLength));
            }
            reference.recordNumber =
                ntfsReferenceNumber(fileReference);
            reference.sequenceNumber =
                static_cast<std::uint16_t>(
                    fileReference >> 48U);
            if (reference.sequenceNumber == 0U)
            {
                errorTextOut = QStringLiteral(
                    "NTFS $ATTRIBUTE_LIST 使用了保留的零序列号。");
                return false;
            }

            const auto kExactDuplicate = std::find_if(
                referencesOut.cbegin(),
                referencesOut.cend(),
                [&reference](
                    const NtfsAttributeReference& existing)
                {
                    return existing.type == reference.type
                        && existing.name == reference.name
                        && existing.lowestVcn
                            == reference.lowestVcn
                        && existing.recordNumber
                            == reference.recordNumber
                        && existing.sequenceNumber
                            == reference.sequenceNumber
                        && existing.attributeId
                            == reference.attributeId;
                });
            if (kExactDuplicate
                == referencesOut.cend())
            {
                const auto kConflictingSegment =
                    std::find_if(
                        referencesOut.cbegin(),
                        referencesOut.cend(),
                        [&reference](
                            const NtfsAttributeReference& existing)
                        {
                            return (reference.type == 0x20U
                                    || reference.type == 0x80U)
                                && existing.type
                                    == reference.type
                                && existing.name
                                    == reference.name
                                && existing.lowestVcn
                                    == reference.lowestVcn;
                        });
                if (kConflictingSegment
                    != referencesOut.cend())
                {
                    errorTextOut = QStringLiteral(
                        "NTFS $ATTRIBUTE_LIST 包含指向不同记录的重复属性键。");
                    return false;
                }
                const auto kSameRecordAttribute =
                    std::find_if(
                        referencesOut.cbegin(),
                        referencesOut.cend(),
                        [&reference](
                            const NtfsAttributeReference& existing)
                        {
                            return existing.recordNumber
                                    == reference.recordNumber
                                && existing.sequenceNumber
                                    == reference.sequenceNumber
                                && existing.attributeId
                                    == reference.attributeId;
                        });
                if (kSameRecordAttribute != referencesOut.cend())
                {
                    errorTextOut = QStringLiteral(
                        "NTFS $ATTRIBUTE_LIST 复用了同一记录属性 ID。");
                    return false;
                }
                referencesOut.push_back(reference);
                if (referencesOut.size()
                    > kNtfsAttributeListEntryLimit)
                {
                    errorTextOut = QStringLiteral(
                        "NTFS $ATTRIBUTE_LIST 超过 4096 项取证上限。");
                    return false;
                }
            }
            cursor += entryLength;
        }
        if (referencesOut.empty())
        {
            errorTextOut = QStringLiteral(
                "NTFS $ATTRIBUTE_LIST 不含可验证的属性引用。");
            return false;
        }
        return true;
    }

    bool readNtfsAttributeListValue(
        const ks::misc::rawfs::VolumeReader& reader,
        const NtfsGeometry& geometry,
        const NtfsRecord& record,
        QByteArray& valueOut,
        QString& errorTextOut)
    {
        valueOut.clear();
        if (record.attributeListSegments.empty())
        {
            errorTextOut = QStringLiteral(
                "NTFS 记录声明了 $ATTRIBUTE_LIST，"
                "但没有可解析的值属性。");
            return false;
        }
        std::vector<NtfsDataStream> assembled;
        for (const NtfsDataStream& segment :
             record.attributeListSegments)
        {
            if (!segment.name.isEmpty())
            {
                errorTextOut = QStringLiteral(
                    "NTFS $ATTRIBUTE_LIST 出现了非空属性名称。");
                return false;
            }
            if (!mergeNtfsStreamSegment(
                    assembled,
                    segment,
                    QStringLiteral("$ATTRIBUTE_LIST"),
                    errorTextOut))
            {
                return false;
            }
        }
        if (assembled.size() != 1U)
        {
            errorTextOut = QStringLiteral(
                "NTFS $ATTRIBUTE_LIST 无法合并为唯一值流。");
            return false;
        }
        NtfsDataStream stream = assembled.front();
        if (stream.realSize > kNtfsAttributeListReadLimit)
        {
            errorTextOut = QStringLiteral(
                "NTFS $ATTRIBUTE_LIST 超过 16 MiB 取证读取上限。");
            return false;
        }
        if (!stream.resident
            && !normalizeNtfsRuns(
                stream,
                true,
                QStringLiteral("$ATTRIBUTE_LIST"),
                errorTextOut))
        {
            return false;
        }
        if (!stream.resident && stream.realSize != 0U)
        {
            const NtfsRun& finalRun = stream.runs.back();
            std::uint64_t coveredBytes = 0U;
            if (finalRun.clusterCount
                    > std::numeric_limits<std::uint64_t>::max()
                        - finalRun.vcn
                || !multiplyChecked(
                    finalRun.vcn + finalRun.clusterCount,
                    geometry.clusterBytes,
                    coveredBytes)
                || coveredBytes < stream.realSize)
            {
                errorTextOut = QStringLiteral(
                    "NTFS $ATTRIBUTE_LIST 的 VCN 区间未覆盖完整逻辑值。");
                return false;
            }
        }
        std::vector<ks::misc::RawFileExtent> ignored;
        if (!readNtfsStream(
                reader,
                geometry,
                stream,
                0U,
                static_cast<std::uint32_t>(stream.realSize),
                valueOut,
                ignored,
                errorTextOut)
            || static_cast<std::uint64_t>(valueOut.size())
                != stream.realSize)
        {
            if (errorTextOut.isEmpty())
            {
                errorTextOut = QStringLiteral(
                    "NTFS $ATTRIBUTE_LIST 逻辑值读取被截断。");
            }
            return false;
        }
        return true;
    }

    const NtfsDataStream* findReferencedNtfsStream(
        const std::vector<NtfsDataStream>& streams,
        const NtfsAttributeReference& reference)
    {
        const auto kFound = std::find_if(
            streams.cbegin(),
            streams.cend(),
            [&reference](const NtfsDataStream& stream)
            {
                return stream.name == reference.name
                    && stream.firstVcn == reference.lowestVcn
                    && stream.attributeId
                        == reference.attributeId;
            });
        if (kFound == streams.cend())
        {
            return nullptr;
        }
        const auto kDuplicate = std::find_if(
            std::next(kFound),
            streams.cend(),
            [&reference](const NtfsDataStream& stream)
            {
                return stream.name == reference.name
                    && stream.firstVcn == reference.lowestVcn
                    && stream.attributeId
                        == reference.attributeId;
            });
        return kDuplicate == streams.cend() ? &*kFound : nullptr;
    }

    bool validateCompleteNtfsStream(
        NtfsDataStream& stream,
        const NtfsGeometry& geometry,
        const QString& diagnosticName,
        QString& errorTextOut)
    {
        if (stream.resident)
        {
            if (stream.realSize
                    != static_cast<std::uint64_t>(
                        stream.residentBytes.size()))
            {
                errorTextOut = QStringLiteral(
                    "NTFS 驻留 %1 的长度字段与值不一致。")
                    .arg(diagnosticName);
                return false;
            }
            return true;
        }
        if (!normalizeNtfsRuns(
                stream,
                true,
                diagnosticName,
                errorTextOut))
        {
            return false;
        }
        if (stream.realSize == 0U)
        {
            if (!stream.runs.empty())
            {
                errorTextOut = QStringLiteral(
                    "NTFS %1 的零长度逻辑值仍包含 runlist。")
                    .arg(diagnosticName);
                return false;
            }
            return true;
        }
        const NtfsRun& finalRun = stream.runs.back();
        std::uint64_t logicalBytes = 0U;
        if (finalRun.clusterCount
                > std::numeric_limits<std::uint64_t>::max()
                    - finalRun.vcn
            || !multiplyChecked(
                finalRun.vcn + finalRun.clusterCount,
                geometry.clusterBytes,
                logicalBytes)
            || logicalBytes < stream.realSize)
        {
            errorTextOut = QStringLiteral(
                "NTFS %1 的 VCN 区间未覆盖完整逻辑长度。")
                .arg(diagnosticName);
            return false;
        }
        return true;
    }

    bool sameNtfsAttributeReferenceSet(
        const std::vector<NtfsAttributeReference>& left,
        const std::vector<NtfsAttributeReference>& right)
    {
        if (left.size() != right.size())
        {
            return false;
        }
        return std::all_of(
            left.cbegin(),
            left.cend(),
            [&right](const NtfsAttributeReference& item)
            {
                return std::any_of(
                    right.cbegin(),
                    right.cend(),
                    [&item](
                        const NtfsAttributeReference& other)
                    {
                        return item.type == other.type
                            && item.name == other.name
                            && item.lowestVcn == other.lowestVcn
                            && item.recordNumber
                                == other.recordNumber
                            && item.sequenceNumber
                                == other.sequenceNumber
                            && item.attributeId
                                == other.attributeId;
                    });
            });
    }

    bool resolveNtfsAttributeList(
        const ks::misc::rawfs::VolumeReader& reader,
        const NtfsGeometry& geometry,
        NtfsRecord& baseRecord,
        QString& errorTextOut)
    {
        baseRecord.attributeListResolved = false;
        baseRecord.attributeReferences.clear();
        if (!baseRecord.hasAttributeList)
        {
            baseRecord.attributeListResolved = true;
            return true;
        }
        if (baseRecord.hasBaseRecordReference)
        {
            errorTextOut = QStringLiteral(
                "NTFS 扩展 FILE 记录不能作为 $ATTRIBUTE_LIST 基记录解析。");
            return false;
        }
        std::vector<NtfsDataStream> assembledStreams;
        for (const NtfsDataStream& segment :
             baseRecord.streams)
        {
            if (!mergeNtfsStreamSegment(
                    assembledStreams,
                    segment,
                    QStringLiteral("$DATA"),
                    errorTextOut))
            {
                return false;
            }
        }
        baseRecord.streams = std::move(assembledStreams);

        struct CachedExtension
        {
            std::uint64_t recordNumber = 0U;
            NtfsRecord record;
        };
        std::vector<CachedExtension> extensions;
        constexpr std::size_t kMaximumExpansionRounds = 4U;
        std::vector<NtfsAttributeReference> references;

        for (std::size_t round = 0U;
             round < kMaximumExpansionRounds;
             ++round)
        {
            QByteArray listValue;
            if (!readNtfsAttributeListValue(
                    reader,
                    geometry,
                    baseRecord,
                    listValue,
                    errorTextOut)
                || !parseNtfsAttributeListValue(
                    listValue,
                    references,
                    errorTextOut))
            {
                return false;
            }
            baseRecord.attributeReferences = references;

            for (const NtfsAttributeReference& reference :
                 references)
            {
                NtfsRecord* sourceRecord = nullptr;
                if (reference.recordNumber
                    == baseRecord.recordNumber)
                {
                    if (reference.sequenceNumber != 0U
                        && reference.sequenceNumber
                            != baseRecord.sequenceNumber)
                    {
                        errorTextOut = QStringLiteral(
                            "NTFS $ATTRIBUTE_LIST 的基记录序列号不匹配。");
                        return false;
                    }
                    sourceRecord = &baseRecord;
                }
                else
                {
                    auto cached = std::find_if(
                        extensions.begin(),
                        extensions.end(),
                        [&reference](
                            const CachedExtension& item)
                        {
                            return item.recordNumber
                                == reference.recordNumber;
                        });
                    if (cached == extensions.end())
                    {
                        if (extensions.size()
                            >= kNtfsAttributeExtensionRecordLimit)
                        {
                            errorTextOut = QStringLiteral(
                                "NTFS $ATTRIBUTE_LIST 超过 128 条扩展记录上限。");
                            return false;
                        }
                        NtfsRecord extension;
                        QString extensionError;
                        if (!readNtfsRecordBase(
                                reader,
                                geometry,
                                reference.recordNumber,
                                extension,
                                extensionError)
                            || !extension.valid
                            || !extension.inUse)
                        {
                            errorTextOut = QStringLiteral(
                                "NTFS $ATTRIBUTE_LIST 引用的扩展记录 %1 "
                                "无法验证：%2")
                                .arg(reference.recordNumber)
                                .arg(
                                    extensionError.isEmpty()
                                        ? QStringLiteral(
                                            "记录无效或未使用")
                                        : extensionError);
                            return false;
                        }
                        if (extension.recordNumber
                                != reference.recordNumber
                            || !extension
                                .hasBaseRecordReference
                            || extension.baseRecordNumber
                                != baseRecord.recordNumber
                            || extension.baseRecordSequenceNumber
                                != baseRecord.sequenceNumber
                            || extension.recordNumber
                                == extension.baseRecordNumber)
                        {
                            errorTextOut = QStringLiteral(
                                "NTFS 属性扩展记录的基记录引用或序列号无效。");
                            return false;
                        }
                        extensions.push_back(
                            {reference.recordNumber,
                             std::move(extension)});
                        cached = std::prev(extensions.end());
                    }
                    if (reference.sequenceNumber != 0U
                        && cached->record.sequenceNumber
                            != reference.sequenceNumber)
                    {
                        errorTextOut = QStringLiteral(
                            "NTFS $ATTRIBUTE_LIST 引用的扩展记录序列号不匹配。");
                        return false;
                    }
                    sourceRecord = &cached->record;
                }

                const auto kIdentity = std::find_if(
                    sourceRecord->attributes.cbegin(),
                    sourceRecord->attributes.cend(),
                    [&reference](
                        const NtfsAttributeIdentity& candidate)
                    {
                        return ntfsAttributeReferenceMatches(
                            candidate,
                            reference);
                    });
                if (kIdentity == sourceRecord->attributes.cend())
                {
                    errorTextOut = QStringLiteral(
                        "NTFS $ATTRIBUTE_LIST 的类型、名称、lowestVCN "
                        "或属性 ID 与目标记录不一致。");
                    return false;
                }

                if (reference.recordNumber
                    == baseRecord.recordNumber)
                {
                    continue;
                }
                if (reference.type == 0x80U)
                {
                    const NtfsDataStream* stream =
                        findReferencedNtfsStream(
                            sourceRecord->streams,
                            reference);
                    if (stream == nullptr
                        || !mergeNtfsStreamSegment(
                            baseRecord.streams,
                            *stream,
                            QStringLiteral("$DATA"),
                            errorTextOut))
                    {
                        if (errorTextOut.isEmpty())
                        {
                            errorTextOut = QStringLiteral(
                                "NTFS $ATTRIBUTE_LIST 的 $DATA "
                                "引用不是唯一可验证的属性段。");
                        }
                        return false;
                    }
                }
                else if (reference.type == 0x20U)
                {
                    const NtfsDataStream* segment =
                        findReferencedNtfsStream(
                            sourceRecord
                                ->attributeListSegments,
                            reference);
                    if (segment == nullptr
                        || !mergeNtfsStreamSegment(
                            baseRecord.attributeListSegments,
                            *segment,
                            QStringLiteral("$ATTRIBUTE_LIST"),
                            errorTextOut))
                    {
                        if (errorTextOut.isEmpty())
                        {
                            errorTextOut = QStringLiteral(
                                "NTFS $ATTRIBUTE_LIST 自身的扩展段"
                                "不是唯一可验证的属性段。");
                        }
                        return false;
                    }
                }
                else if (reference.type == 0x30U)
                {
                    const auto kMatchingLink = std::find_if(
                        sourceRecord->links.cbegin(),
                        sourceRecord->links.cend(),
                        [&reference](
                            const NtfsFileLink& link)
                        {
                            return link.attributeId
                                == reference.attributeId;
                        });
                    if (kMatchingLink
                        == sourceRecord->links.cend())
                    {
                        errorTextOut = QStringLiteral(
                            "NTFS $ATTRIBUTE_LIST 的 $FILE_NAME "
                            "属性 ID 没有对应的链接值。");
                        return false;
                    }
                    const auto kDuplicate = std::find_if(
                        baseRecord.links.cbegin(),
                        baseRecord.links.cend(),
                        [kMatchingLink](
                            const NtfsFileLink& existing)
                        {
                            return existing.parentRecord
                                    == kMatchingLink->parentRecord
                                && existing.parentSequence
                                    == kMatchingLink->parentSequence
                                && existing.name
                                    == kMatchingLink->name
                                && existing.nameSpace
                                    == kMatchingLink->nameSpace;
                        });
                    if (kDuplicate == baseRecord.links.cend())
                    {
                        baseRecord.links.push_back(
                            *kMatchingLink);
                    }
                }
            }

            QByteArray expandedValue;
            std::vector<NtfsAttributeReference>
                expandedReferences;
            if (!readNtfsAttributeListValue(
                    reader,
                    geometry,
                    baseRecord,
                    expandedValue,
                    errorTextOut)
                || !parseNtfsAttributeListValue(
                    expandedValue,
                    expandedReferences,
                    errorTextOut))
            {
                return false;
            }
            if (sameNtfsAttributeReferenceSet(
                    references,
                    expandedReferences))
            {
                references = std::move(expandedReferences);
                break;
            }
            if (round + 1U == kMaximumExpansionRounds)
            {
                errorTextOut = QStringLiteral(
                    "NTFS $ATTRIBUTE_LIST 扩展引用未在 4 轮内收敛，"
                    "可能存在循环或持续变化的重复证据。");
                return false;
            }
            references = std::move(expandedReferences);
        }

        for (NtfsDataStream& stream : baseRecord.streams)
        {
            const QString kStreamLabel = stream.name.isEmpty()
                ? QStringLiteral("$DATA")
                : QStringLiteral("$DATA:%1").arg(stream.name);
            if (!validateCompleteNtfsStream(
                    stream,
                    geometry,
                    kStreamLabel,
                    errorTextOut))
            {
                return false;
            }
        }
        baseRecord.attributeReferences = std::move(references);
        baseRecord.attributeListResolved = true;
        return true;
    }

    bool readNtfsRecord(
        const ks::misc::rawfs::VolumeReader& reader,
        const NtfsGeometry& geometry,
        const std::uint64_t recordNumber,
        NtfsRecord& recordOut,
        QString& errorTextOut)
    {
        NtfsRecord baseRecord;
        if (!readNtfsRecordBase(
                reader,
                geometry,
                recordNumber,
                baseRecord,
                errorTextOut))
        {
            return false;
        }
        if (baseRecord.valid
            && baseRecord.hasAttributeList
            && !resolveNtfsAttributeList(
                reader,
                geometry,
                baseRecord,
                errorTextOut))
        {
            return false;
        }
        recordOut = std::move(baseRecord);
        return true;
    }

    bool scanNtfsRecords(
        const ks::misc::rawfs::VolumeReader& reader,
        const NtfsGeometry& geometry,
        const std::function<bool(const NtfsRecord&)>& visitor,
        std::uint64_t& scannedOut,
        bool& truncatedOut,
        QString& errorTextOut)
    {
        scannedOut = 0U;
        truncatedOut = false;
        const std::uint64_t kAvailableRecords =
            geometry.mftStream.realSize / geometry.recordBytes;
        const std::uint64_t kRecordLimit =
            std::min(kAvailableRecords, kNtfsRecordScanLimit);
        const std::uint32_t kRecordsPerChunk = std::max(
            1U,
            kNtfsScanChunkBytes / geometry.recordBytes);
        for (std::uint64_t first = 0U;
             first < kRecordLimit;
             first += kRecordsPerChunk)
        {
            const std::uint32_t kCount =
                static_cast<std::uint32_t>(
                    std::min<std::uint64_t>(
                        kRecordsPerChunk,
                        kRecordLimit - first));
            const std::uint64_t kByteOffset =
                first * geometry.recordBytes;
            const std::uint32_t kByteLength =
                kCount * geometry.recordBytes;
            QByteArray chunk;
            std::vector<ks::misc::RawFileExtent> ignored;
            if (!readNtfsStream(
                    reader,
                    geometry,
                    geometry.mftStream,
                    kByteOffset,
                    kByteLength,
                    chunk,
                    ignored,
                    errorTextOut))
            {
                return false;
            }
            for (std::uint32_t index = 0U;
                 index < kCount;
                 ++index)
            {
                const std::uint64_t kRecordNumber =
                    first + index;
                NtfsRecord record;
                QString parseError;
                if (!parseNtfsRecord(
                        chunk.mid(
                            static_cast<qsizetype>(
                                index * geometry.recordBytes),
                            static_cast<qsizetype>(
                                geometry.recordBytes)),
                        geometry,
                        kRecordNumber,
                        ntfsStreamPhysicalOffset(
                            reader,
                            geometry,
                            geometry.mftStream,
                            kRecordNumber
                                * geometry.recordBytes),
                        record,
                        parseError))
                {
                    continue;
                }
                if (record.valid
                    && record.inUse
                    && !record.hasBaseRecordReference
                    && record.hasAttributeList)
                {
                    QString resolutionError;
                    if (!resolveNtfsAttributeList(
                            reader,
                            geometry,
                            record,
                            resolutionError))
                    {
                        record.attributeListResolved = false;
                    }
                }
                ++scannedOut;
                if (record.valid && visitor(record))
                {
                    truncatedOut =
                        kAvailableRecords > kRecordLimit;
                    return true;
                }
            }
        }
        truncatedOut = kAvailableRecords > kRecordLimit;
        return true;
    }

    bool findNtfsChild(
        const ks::misc::rawfs::VolumeReader& reader,
        const NtfsGeometry& geometry,
        const std::uint64_t parentRecord,
        const std::uint16_t parentSequence,
        const QString& name,
        NtfsRecord& recordOut,
        QString& errorTextOut)
    {
        bool found = false;
        NtfsFileLink foundLink;
        std::uint64_t scanned = 0U;
        bool truncated = false;
        if (!scanNtfsRecords(
                reader,
                geometry,
                [&found,
                    &foundLink,
                    &recordOut,
                    parentRecord,
                    parentSequence,
                    &name](
                    const NtfsRecord& record)
                {
                    if (!record.inUse
                        || record.hasBaseRecordReference)
                    {
                        return false;
                    }
                    const auto kMatchingLink = std::find_if(
                        record.links.cbegin(),
                        record.links.cend(),
                        [parentRecord,
                         parentSequence,
                         &name](
                            const NtfsFileLink& link)
                        {
                            return link.parentRecord
                                    == parentRecord
                                && link.parentSequence
                                    == parentSequence
                                && link.name.compare(
                                    name,
                                    Qt::CaseInsensitive) == 0;
                        });
                    if (kMatchingLink == record.links.cend())
                    {
                        return false;
                    }
                    foundLink = *kMatchingLink;
                    recordOut = record;
                    found = true;
                    return true;
                },
                scanned,
                truncated,
                errorTextOut))
        {
            return false;
        }
        if (!found)
        {
            errorTextOut = truncated
                ? QStringLiteral(
                    "NTFS 路径组件未在前 1048576 条 MFT 记录中找到：%1")
                    .arg(name)
                : QStringLiteral(
                    "NTFS 路径组件不存在：%1").arg(name);
            return false;
        }
        recordOut.name = foundLink.name;
        recordOut.parentRecord = foundLink.parentRecord;
        recordOut.fileAttributes = foundLink.fileAttributes;
        return true;
    }

    bool resolveNtfsPath(
        const ks::misc::rawfs::VolumeReader& reader,
        const NtfsGeometry& geometry,
        const QString& path,
        NtfsRecord& recordOut,
        QString& streamNameOut,
        QString& errorTextOut)
    {
        QStringList components = pathComponents(path);
        streamNameOut.clear();
        NtfsRecord current;
        if (!readNtfsRecord(
                reader,
                geometry,
                5U,
                current,
                errorTextOut)
            || !current.valid
            || !current.directory)
        {
            if (errorTextOut.isEmpty())
            {
                errorTextOut = QStringLiteral(
                    "NTFS 根目录记录无法解析。");
            }
            return false;
        }
        if (components.isEmpty())
        {
            recordOut = std::move(current);
            return true;
        }
        QString leaf = components.takeLast();
        const qsizetype kSeparator = leaf.indexOf(QChar(':'));
        if (kSeparator >= 0)
        {
            streamNameOut = leaf.mid(kSeparator + 1);
            leaf = leaf.left(kSeparator);
            if (leaf.isEmpty() || streamNameOut.isEmpty())
            {
                errorTextOut = QStringLiteral(
                    "NTFS 命名流路径格式无效。");
                return false;
            }
        }
        components.push_back(leaf);
        for (qsizetype index = 0;
             index < components.size();
             ++index)
        {
            if (!findNtfsChild(
                    reader,
                    geometry,
                    current.recordNumber,
                    current.sequenceNumber,
                    components.at(index),
                    current,
                    errorTextOut))
            {
                return false;
            }
            if (index + 1 < components.size()
                && !current.directory)
            {
                errorTextOut = QStringLiteral(
                    "NTFS 路径中间组件不是目录：%1")
                    .arg(current.name);
                return false;
            }
        }
        recordOut = std::move(current);
        return true;
    }

    const NtfsDataStream* selectNtfsStream(
        const NtfsRecord& record,
        const QString& streamName)
    {
        const auto kFound = std::find_if(
            record.streams.cbegin(),
            record.streams.cend(),
            [&streamName](const NtfsDataStream& stream)
            {
                return stream.name.compare(
                    streamName,
                    Qt::CaseInsensitive) == 0;
            });
        return kFound == record.streams.cend()
            ? nullptr
            : &*kFound;
    }

    ks::misc::RawFileEntry ntfsEntryFromRecord(
        const ks::misc::rawfs::VolumeReader& reader,
        const NtfsGeometry& geometry,
        const NtfsRecord& record,
        const QString& parentPath,
        const NtfsDataStream* stream,
        QString& errorTextOut)
    {
        ks::misc::RawFileEntry entry;
        const bool kNamedStream =
            stream != nullptr && !stream->name.isEmpty();
        entry.name = kNamedStream
            ? record.name + QChar(':') + stream->name
            : record.name;
        entry.streamName =
            kNamedStream ? stream->name : QString();
        entry.fullPath =
            ks::misc::rawfs::childPath(parentPath, entry.name);
        entry.type = kNamedStream
            ? ks::misc::RawFileObjectType::kNamedStream
            : record.directory
                ? ks::misc::RawFileObjectType::kDirectory
                : ks::misc::RawFileObjectType::kRegularFile;
        entry.objectId = record.recordNumber;
        entry.parentObjectId = record.parentRecord;
        entry.metadataOffset = record.metadataOffset;
        entry.modeOrFlags = record.fileAttributes;
        entry.extentsTruncated =
            record.hasAttributeList
            && !record.attributeListResolved;
        const NtfsDataStream* selected = stream != nullptr
            ? stream
            : selectNtfsStream(record, QString());
        if (selected != nullptr)
        {
            entry.fileSizeBytes = selected->realSize;
            entry.allocatedSizeBytes = selected->allocatedSize;
            ntfsStreamExtents(
                reader,
                geometry,
                *selected,
                entry.extents,
                errorTextOut);
        }
        return entry;
    }
}

namespace ks::misc::rawfs
{
    RawDirectoryResult listFat(
        const VolumeReader& reader,
        const ForensicFileSystemKind expectedKind,
        const QString& path,
        const std::uint32_t maximumEntries)
    {
        RawDirectoryResult result;
        result.fileSystem = expectedKind;
        result.fileSystemName =
            DiskFileSystemForensics::fileSystemName(expectedKind);
        result.requestedPath = normalizePath(path);
        FatGeometry geometry;
        if (!loadFatGeometry(
                reader,
                expectedKind,
                geometry,
                result.errorText))
        {
            return result;
        }
        RawFileEntry directory;
        bool root = false;
        if (!resolveFatPath(
                reader,
                geometry,
                result.requestedPath,
                directory,
                root,
                result.errorText))
        {
            return result;
        }
        if (!root && directory.type != RawFileObjectType::kDirectory)
        {
            result.errorText = QStringLiteral(
                "请求的 FAT 路径不是目录。");
            return result;
        }
        std::vector<RawFileEntry> entries;
        if (!enumerateFatDirectory(
                reader,
                geometry,
                root
                    ? geometry.rootCluster
                    : static_cast<std::uint32_t>(
                        directory.objectId),
                root,
                result.requestedPath,
                entries,
                result.scannedRecords,
                result.errorText))
        {
            return result;
        }
        result.directoryObjectId = root
            ? geometry.rootCluster
            : directory.objectId;
        result.canonicalPath = result.requestedPath;
        result.truncated = entries.size() > maximumEntries;
        if (result.truncated)
        {
            entries.resize(maximumEntries);
        }
        result.entries = std::move(entries);
        result.success = true;
        return result;
    }

    RawFileReadResult readFat(
        const VolumeReader& reader,
        const ForensicFileSystemKind expectedKind,
        const QString& path,
        const std::uint64_t offset,
        const std::uint32_t length)
    {
        RawFileReadResult result;
        result.fileSystem = expectedKind;
        result.fileSystemName =
            DiskFileSystemForensics::fileSystemName(expectedKind);
        result.filePath = normalizePath(path);
        result.requestedOffset = offset;
        FatGeometry geometry;
        if (!loadFatGeometry(
                reader,
                expectedKind,
                geometry,
                result.errorText))
        {
            return result;
        }
        RawFileEntry entry;
        bool root = false;
        if (!resolveFatPath(
                reader,
                geometry,
                result.filePath,
                entry,
                root,
                result.errorText))
        {
            return result;
        }
        if (root || entry.type == RawFileObjectType::kDirectory)
        {
            result.errorText = QStringLiteral(
                "FAT 目录不能作为普通文件读取。");
            return result;
        }
        result.fileSizeBytes = entry.fileSizeBytes;
        result.extents = entry.extents;
        if (!readMappedExtents(
                reader,
                entry.extents,
                entry.fileSizeBytes,
                offset,
                length,
                result.bytes,
                result.errorText))
        {
            return result;
        }
        result.endOfFile =
            offset >= entry.fileSizeBytes
            || static_cast<std::uint64_t>(result.bytes.size())
                >= entry.fileSizeBytes - offset;
        result.success = true;
        return result;
    }

    RawDirectoryResult listExFat(
        const VolumeReader& reader,
        const QString& path,
        const std::uint32_t maximumEntries)
    {
        RawDirectoryResult result;
        result.fileSystem = ForensicFileSystemKind::kExFat;
        result.fileSystemName = QStringLiteral("exFAT");
        result.requestedPath = normalizePath(path);
        ExFatGeometry geometry;
        if (!loadExFatGeometry(reader, geometry, result.errorText))
        {
            return result;
        }
        RawFileEntry directory;
        bool root = false;
        if (!resolveExFatPath(
                reader,
                geometry,
                result.requestedPath,
                directory,
                root,
                result.errorText))
        {
            return result;
        }
        if (!root && directory.type != RawFileObjectType::kDirectory)
        {
            result.errorText = QStringLiteral(
                "请求的 exFAT 路径不是目录。");
            return result;
        }
        std::vector<RawFileEntry> entries;
        if (!enumerateExFatDirectory(
                reader,
                geometry,
                root
                    ? geometry.rootCluster
                    : static_cast<std::uint32_t>(
                        directory.objectId),
                root ? 0U : directory.allocatedSizeBytes,
                !root
                    && (directory.modeOrFlags & 0x80000000U) != 0U,
                result.requestedPath,
                entries,
                result.scannedRecords,
                result.errorText))
        {
            return result;
        }
        result.directoryObjectId = root
            ? geometry.rootCluster
            : directory.objectId;
        result.canonicalPath = result.requestedPath;
        result.truncated = entries.size() > maximumEntries;
        if (result.truncated)
        {
            entries.resize(maximumEntries);
        }
        result.entries = std::move(entries);
        result.success = true;
        return result;
    }

    RawFileReadResult readExFat(
        const VolumeReader& reader,
        const QString& path,
        const std::uint64_t offset,
        const std::uint32_t length)
    {
        RawFileReadResult result;
        result.fileSystem = ForensicFileSystemKind::kExFat;
        result.fileSystemName = QStringLiteral("exFAT");
        result.filePath = normalizePath(path);
        result.requestedOffset = offset;
        ExFatGeometry geometry;
        if (!loadExFatGeometry(reader, geometry, result.errorText))
        {
            return result;
        }
        RawFileEntry entry;
        bool root = false;
        if (!resolveExFatPath(
                reader,
                geometry,
                result.filePath,
                entry,
                root,
                result.errorText))
        {
            return result;
        }
        if (root || entry.type == RawFileObjectType::kDirectory)
        {
            result.errorText = QStringLiteral(
                "exFAT 目录不能作为普通文件读取。");
            return result;
        }
        result.fileSizeBytes = entry.fileSizeBytes;
        result.extents = entry.extents;
        if (!readMappedExtents(
                reader,
                entry.extents,
                entry.fileSizeBytes,
                offset,
                length,
                result.bytes,
                result.errorText))
        {
            return result;
        }
        result.endOfFile =
            offset >= entry.fileSizeBytes
            || static_cast<std::uint64_t>(result.bytes.size())
                >= entry.fileSizeBytes - offset;
        result.success = true;
        return result;
    }

    RawDirectoryResult listNtfs(
        const VolumeReader& reader,
        const QString& path,
        const std::uint32_t maximumEntries)
    {
        RawDirectoryResult result;
        result.fileSystem = ForensicFileSystemKind::kNtfs;
        result.fileSystemName = QStringLiteral("NTFS");
        result.requestedPath = normalizePath(path);
        NtfsGeometry geometry;
        if (!loadNtfsGeometry(reader, geometry, result.errorText))
        {
            return result;
        }
        NtfsRecord directory;
        QString streamName;
        if (!resolveNtfsPath(
                reader,
                geometry,
                result.requestedPath,
                directory,
                streamName,
                result.errorText))
        {
            return result;
        }
        if (!streamName.isEmpty() || !directory.directory)
        {
            result.errorText = QStringLiteral(
                "请求的 NTFS 路径不是目录。");
            return result;
        }
        std::vector<RawFileEntry> entries;
        bool scanTruncated = false;
        if (!scanNtfsRecords(
                reader,
                geometry,
                [&entries,
                    &reader,
                    &geometry,
                    &result,
                    &directory,
                    maximumEntries](
                    const NtfsRecord& record)
                {
                    if (!record.inUse
                        || record.hasBaseRecordReference)
                    {
                        return false;
                    }
                    const bool kHasPreferredLink =
                        std::any_of(
                            record.links.cbegin(),
                            record.links.cend(),
                            [&directory](
                                const NtfsFileLink& link)
                            {
                                return link.parentRecord
                                        == directory.recordNumber
                                    && link.parentSequence
                                        == directory.sequenceNumber
                                    && link.nameSpace != 2U
                                    && !link.name.isEmpty();
                            });
                    for (const NtfsFileLink& link :
                         record.links)
                    {
                        if (link.parentRecord
                                != directory.recordNumber
                            || link.parentSequence
                                != directory.sequenceNumber
                            || link.name.isEmpty()
                            || (link.nameSpace == 2U
                                && kHasPreferredLink))
                        {
                            continue;
                        }
                        NtfsRecord linkedRecord =
                            record;
                        linkedRecord.name = link.name;
                        linkedRecord.parentRecord =
                            link.parentRecord;
                        linkedRecord.fileAttributes =
                            link.fileAttributes;
                        QString mappingError;
                        entries.push_back(ntfsEntryFromRecord(
                            reader,
                            geometry,
                            linkedRecord,
                            result.requestedPath,
                            nullptr,
                            mappingError));
                        for (const NtfsDataStream& stream :
                             linkedRecord.streams)
                        {
                            if (!stream.name.isEmpty())
                            {
                                entries.push_back(
                                    ntfsEntryFromRecord(
                                        reader,
                                        geometry,
                                        linkedRecord,
                                        result.requestedPath,
                                        &stream,
                                        mappingError));
                            }
                        }
                        if (entries.size() >= maximumEntries)
                        {
                            return true;
                        }
                    }
                    return false;
                },
                result.scannedRecords,
                scanTruncated,
                result.errorText))
        {
            return result;
        }
        result.directoryObjectId = directory.recordNumber;
        result.canonicalPath = result.requestedPath;
        result.truncated =
            scanTruncated || entries.size() >= maximumEntries;
        if (entries.size() > maximumEntries)
        {
            entries.resize(maximumEntries);
        }
        result.entries = std::move(entries);
        result.success = true;
        return result;
    }

    RawFileReadResult readNtfs(
        const VolumeReader& reader,
        const QString& path,
        const std::uint64_t offset,
        const std::uint32_t length)
    {
        RawFileReadResult result;
        result.fileSystem = ForensicFileSystemKind::kNtfs;
        result.fileSystemName = QStringLiteral("NTFS");
        result.filePath = normalizePath(path);
        result.requestedOffset = offset;
        NtfsGeometry geometry;
        if (!loadNtfsGeometry(reader, geometry, result.errorText))
        {
            return result;
        }
        NtfsRecord record;
        QString streamName;
        if (!resolveNtfsPath(
                reader,
                geometry,
                result.filePath,
                record,
                streamName,
                result.errorText))
        {
            return result;
        }
        if (record.hasAttributeList
            && !record.attributeListResolved)
        {
            result.errorText =
                record.nonResidentAttributeList
                ? QStringLiteral(
                    "目标 NTFS 对象使用非驻留 $ATTRIBUTE_LIST；"
                    "其扩展记录或 VCN 证据未能完整验证，"
                    "因此拒绝返回可能缺段的数据。")
                : QStringLiteral(
                    "目标 NTFS 对象的 $ATTRIBUTE_LIST 未能完整验证；"
                    "因此拒绝返回不完整的命名流或普通数据。");
            return result;
        }
        if (record.directory && streamName.isEmpty())
        {
            result.errorText = QStringLiteral(
                "NTFS 目录不能作为未命名普通文件读取。");
            return result;
        }
        const NtfsDataStream* stream =
            selectNtfsStream(record, streamName);
        if (stream == nullptr)
        {
            result.errorText = streamName.isEmpty()
                ? QStringLiteral(
                    "NTFS 文件没有未命名 $DATA。")
                : QStringLiteral(
                    "NTFS 命名流不存在：%1").arg(streamName);
            return result;
        }
        result.fileSizeBytes = stream->realSize;
        if (!readNtfsStream(
                reader,
                geometry,
                *stream,
                offset,
                length,
                result.bytes,
                result.extents,
                result.errorText))
        {
            return result;
        }
        result.endOfFile =
            offset >= stream->realSize
            || static_cast<std::uint64_t>(result.bytes.size())
                >= stream->realSize - offset;
        result.success = true;
        return result;
    }
}
