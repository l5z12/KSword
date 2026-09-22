#include "DiskRawFileSystemInternal.h"

#include <QByteArray>
#include <QStringList>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <vector>

namespace
{
    constexpr std::uint16_t kHfsSignature = 0x4244U;
    constexpr std::uint16_t kHfsPlusSignature = 0x482BU;
    constexpr std::uint16_t kHfsXSignature = 0x4858U;
    constexpr std::uint32_t kRootFolderId = 2U;
    constexpr std::uint32_t kExtentsFileId = 3U;
    constexpr std::uint8_t kDataForkType = 0U;
    constexpr std::int8_t kLeafNodeKind = -1;
    constexpr std::uint32_t kMaximumBTreeNodes = 1U << 20U;
    constexpr std::uint32_t kMaximumCatalogRecords = 4U * 1024U * 1024U;

    std::uint16_t be16(const unsigned char* bytes)
    {
        return (static_cast<std::uint16_t>(bytes[0]) << 8U)
            | static_cast<std::uint16_t>(bytes[1]);
    }

    std::uint32_t be32(const unsigned char* bytes)
    {
        return (static_cast<std::uint32_t>(bytes[0]) << 24U)
            | (static_cast<std::uint32_t>(bytes[1]) << 16U)
            | (static_cast<std::uint32_t>(bytes[2]) << 8U)
            | static_cast<std::uint32_t>(bytes[3]);
    }

    std::uint64_t be64(const unsigned char* bytes)
    {
        return (static_cast<std::uint64_t>(be32(bytes)) << 32U)
            | static_cast<std::uint64_t>(be32(bytes + 4U));
    }

    const unsigned char* dataPointer(const QByteArray& bytes)
    {
        return reinterpret_cast<const unsigned char*>(bytes.constData());
    }

    bool isPowerOfTwo(const std::uint32_t value)
    {
        return value != 0U && (value & (value - 1U)) == 0U;
    }

    bool checkedMultiply(
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

    std::uint32_t alignEven(const std::uint32_t value)
    {
        return (value + 1U) & ~1U;
    }

    QString decodeHfsPlusName(
        const unsigned char* bytes,
        const std::uint16_t characterCount)
    {
        QString result;
        result.reserve(characterCount);
        for (std::uint16_t index = 0; index < characterCount; ++index)
        {
            result.append(QChar(be16(bytes + index * 2U)));
        }
        return result;
    }

    QString decodeMacRoman(
        const unsigned char* bytes,
        const std::uint8_t byteCount)
    {
        static constexpr std::array<std::uint16_t, 128U> kHighCharacters{
            0x00C4U, 0x00C5U, 0x00C7U, 0x00C9U, 0x00D1U, 0x00D6U,
            0x00DCU, 0x00E1U, 0x00E0U, 0x00E2U, 0x00E4U, 0x00E3U,
            0x00E5U, 0x00E7U, 0x00E9U, 0x00E8U, 0x00EAU, 0x00EBU,
            0x00EDU, 0x00ECU, 0x00EEU, 0x00EFU, 0x00F1U, 0x00F3U,
            0x00F2U, 0x00F4U, 0x00F6U, 0x00F5U, 0x00FAU, 0x00F9U,
            0x00FBU, 0x00FCU, 0x2020U, 0x00B0U, 0x00A2U, 0x00A3U,
            0x00A7U, 0x2022U, 0x00B6U, 0x00DFU, 0x00AEU, 0x00A9U,
            0x2122U, 0x00B4U, 0x00A8U, 0x2260U, 0x00C6U, 0x00D8U,
            0x221EU, 0x00B1U, 0x2264U, 0x2265U, 0x00A5U, 0x00B5U,
            0x2202U, 0x2211U, 0x220FU, 0x03C0U, 0x222BU, 0x00AAU,
            0x00BAU, 0x03A9U, 0x00E6U, 0x00F8U, 0x00BFU, 0x00A1U,
            0x00ACU, 0x221AU, 0x0192U, 0x2248U, 0x2206U, 0x00ABU,
            0x00BBU, 0x2026U, 0x00A0U, 0x00C0U, 0x00C3U, 0x00D5U,
            0x0152U, 0x0153U, 0x2013U, 0x2014U, 0x201CU, 0x201DU,
            0x2018U, 0x2019U, 0x00F7U, 0x25CAU, 0x00FFU, 0x0178U,
            0x2044U, 0x20ACU, 0x2039U, 0x203AU, 0xFB01U, 0xFB02U,
            0x2021U, 0x00B7U, 0x201AU, 0x201EU, 0x2030U, 0x00C2U,
            0x00CAU, 0x00C1U, 0x00CBU, 0x00C8U, 0x00CDU, 0x00CEU,
            0x00CFU, 0x00CCU, 0x00D3U, 0x00D4U, 0xF8FFU, 0x00D2U,
            0x00DAU, 0x00DBU, 0x00D9U, 0x0131U, 0x02C6U, 0x02DCU,
            0x00AFU, 0x02D8U, 0x02D9U, 0x02DAU, 0x00B8U, 0x02DDU,
            0x02DBU, 0x02C7U
        };

        QString result;
        result.reserve(byteCount);
        for (std::uint8_t index = 0; index < byteCount; ++index)
        {
            const std::uint8_t kValue = bytes[index];
            result.append(
                kValue < 0x80U
                    ? QChar(kValue)
                    : QChar(kHighCharacters[kValue - 0x80U]));
        }
        return result;
    }

    struct HfsExtent
    {
        std::uint64_t logicalBlock = 0;
        std::uint32_t startBlock = 0;
        std::uint32_t blockCount = 0;
    };

    struct HfsFork
    {
        std::uint32_t fileId = 0;
        std::uint8_t forkType = kDataForkType;
        std::uint64_t logicalSize = 0;
        std::uint64_t totalBlocks = 0;
        std::vector<HfsExtent> extents;
        bool overflowApplied = false;
    };

    struct HfsTreeHeader
    {
        std::uint32_t rootNode = 0;
        std::uint32_t leafRecords = 0;
        std::uint32_t firstLeafNode = 0;
        std::uint32_t lastLeafNode = 0;
        std::uint32_t totalNodes = 0;
        std::uint16_t nodeSize = 0;
        std::uint8_t keyCompareType = 0;
    };

    struct HfsCatalogRecord
    {
        QString name;
        std::uint32_t parentId = 0;
        std::uint32_t objectId = 0;
        std::uint32_t valence = 0;
        std::uint32_t modeOrFlags = 0;
        std::uint64_t metadataOffset = 0;
        ks::misc::RawFileObjectType type =
            ks::misc::RawFileObjectType::kUnknown;
        HfsFork dataFork;
    };

    struct HfsOverflowRecord
    {
        std::uint32_t fileId = 0;
        std::uint8_t forkType = 0;
        std::uint64_t logicalBlock = 0;
        std::vector<HfsExtent> extents;
    };

    class HfsVolume final
    {
    public:
        HfsVolume(
            const ks::misc::rawfs::VolumeReader& reader,
            const ks::misc::ForensicFileSystemKind expectedKind)
            : reader_(reader),
              expectedKind_(expectedKind)
        {
        }

        bool mount(QString& errorText)
        {
            QByteArray header;
            if (!reader_.read(1024U, 512U, header, errorText))
            {
                return false;
            }
            const unsigned char* const kBytes = dataPointer(header);
            const std::uint16_t kSignature = be16(kBytes);
            if (kSignature == kHfsPlusSignature
                || kSignature == kHfsXSignature)
            {
                if (expectedKind_ !=
                    ks::misc::ForensicFileSystemKind::kHfsPlus)
                {
                    errorText = QStringLiteral(
                        "卷签名为 HFS+，与请求的文件系统类型不匹配。");
                    return false;
                }
                plus_ = true;
                caseSensitive_ = kSignature == kHfsXSignature;
                if (!mountPlus(kBytes, errorText))
                {
                    return false;
                }
            }
            else if (kSignature == kHfsSignature)
            {
                if (expectedKind_ !=
                    ks::misc::ForensicFileSystemKind::kHfs)
                {
                    errorText = QStringLiteral(
                        "卷签名为经典 HFS，与请求的文件系统类型不匹配。");
                    return false;
                }
                if (!mountClassic(kBytes, errorText))
                {
                    return false;
                }
            }
            else
            {
                errorText = QStringLiteral("HFS 卷头签名不匹配。");
                return false;
            }

            if (!readTreeHeader(extentsFork_, extentsTree_, errorText))
            {
                errorText = QStringLiteral(
                    "无法读取 HFS Extents Overflow B-tree：%1")
                    .arg(errorText);
                return false;
            }
            if (!loadOverflowIndex(errorText))
            {
                return false;
            }
            applyOverflowExtents(catalogFork_);
            if (!readTreeHeader(catalogFork_, catalogTree_, errorText))
            {
                errorText = QStringLiteral(
                    "无法读取 HFS Catalog B-tree：%1").arg(errorText);
                return false;
            }
            return true;
        }

        bool resolvePath(
            const QString& path,
            HfsCatalogRecord& recordOut,
            QString& canonicalPathOut,
            QString& errorText)
        {
            HfsCatalogRecord current;
            current.objectId = kRootFolderId;
            current.type = ks::misc::RawFileObjectType::kDirectory;
            current.name = QStringLiteral("\\");
            canonicalPathOut = QStringLiteral("\\");

            const QStringList kComponents =
                ks::misc::rawfs::normalizePath(path).split(
                    QChar('\\'),
                    Qt::SkipEmptyParts);
            for (const QString& component : kComponents)
            {
                if (current.type !=
                    ks::misc::RawFileObjectType::kDirectory)
                {
                    errorText = QStringLiteral(
                        "路径中间对象不是 HFS 目录：%1")
                        .arg(canonicalPathOut);
                    return false;
                }
                HfsCatalogRecord child;
                if (!findCatalogChild(
                        current.objectId,
                        component,
                        child,
                        errorText))
                {
                    return false;
                }
                current = child;
                canonicalPathOut = ks::misc::rawfs::childPath(
                    canonicalPathOut,
                    current.name);
            }

            recordOut = current;
            return true;
        }

        bool listDirectory(
            const HfsCatalogRecord& directory,
            const QString& canonicalPath,
            const std::uint32_t maximumEntries,
            ks::misc::RawDirectoryResult& result)
        {
            if (directory.type !=
                ks::misc::RawFileObjectType::kDirectory)
            {
                result.errorText = QStringLiteral("目标对象不是 HFS 目录。");
                return false;
            }

            QString errorText;
            bool stopped = false;
            const bool kScanned = scanCatalog(
                [&](HfsCatalogRecord& record)
                {
                    if (record.parentId != directory.objectId)
                    {
                        return true;
                    }
                    if (result.entries.size() >= maximumEntries)
                    {
                        result.truncated = true;
                        stopped = true;
                        return false;
                    }
                    if (record.type !=
                        ks::misc::RawFileObjectType::kDirectory)
                    {
                        applyOverflowExtents(record.dataFork);
                    }
                    ks::misc::RawFileEntry entry;
                    fillEntry(
                        record,
                        canonicalPath,
                        entry);
                    result.entries.push_back(std::move(entry));
                    return true;
                },
                result.scannedRecords,
                errorText);
            if (!kScanned && !stopped)
            {
                result.errorText = errorText;
                return false;
            }
            return true;
        }

        bool readFile(
            HfsCatalogRecord& record,
            const std::uint64_t offset,
            const std::uint32_t length,
            ks::misc::RawFileReadResult& result)
        {
            if (record.type == ks::misc::RawFileObjectType::kDirectory)
            {
                result.errorText = QStringLiteral("目标对象是目录，不能按文件读取。");
                return false;
            }
            if (offset >= record.dataFork.logicalSize)
            {
                result.endOfFile = true;
                return true;
            }

            applyOverflowExtents(record.dataFork);
            const std::uint32_t kBoundedLength =
                static_cast<std::uint32_t>(
                    std::min<std::uint64_t>(
                        length,
                        record.dataFork.logicalSize - offset));
            QString errorText;
            if (!readForkBytes(
                    record.dataFork,
                    offset,
                    kBoundedLength,
                    result.bytes,
                    errorText))
            {
                result.errorText = errorText;
                return false;
            }
            result.endOfFile =
                offset + kBoundedLength >= record.dataFork.logicalSize;
            result.extents = describeFork(record.dataFork);
            result.extentsTruncated =
                record.dataFork.extents.size()
                > ks::misc::rawfs::kMaximumExtentCount;
            return true;
        }

    private:
        bool mountPlus(
            const unsigned char* header,
            QString& errorText)
        {
            blockSize_ = be32(header + 0x28U);
            totalBlocks_ = be32(header + 0x2CU);
            if (!validateGeometry(errorText))
            {
                return false;
            }
            extentsFork_ =
                parsePlusFork(header + 0xC0U, kExtentsFileId);
            catalogFork_ =
                parsePlusFork(header + 0x110U, 4U);
            if (!validateMetadataFork(extentsFork_, errorText)
                || !validateMetadataFork(catalogFork_, errorText))
            {
                return false;
            }
            return true;
        }

        bool mountClassic(
            const unsigned char* header,
            QString& errorText)
        {
            const std::uint16_t kAllocationBlockCount =
                be16(header + 0x12U);
            blockSize_ = be32(header + 0x14U);
            totalBlocks_ = kAllocationBlockCount;
            allocationStart_ =
                static_cast<std::uint64_t>(be16(header + 0x1CU))
                * 512U;
            if (!validateGeometry(errorText)
                || allocationStart_ >= reader_.partitionLength())
            {
                errorText = QStringLiteral("经典 HFS 分配区几何参数无效。");
                return false;
            }

            extentsFork_.fileId = kExtentsFileId;
            extentsFork_.logicalSize = be32(header + 0x7EU);
            parseClassicExtentArray(
                header + 0x82U,
                0U,
                extentsFork_.extents);
            extentsFork_.totalBlocks =
                countExtentBlocks(extentsFork_.extents);

            catalogFork_.fileId = 4U;
            catalogFork_.logicalSize = be32(header + 0x8EU);
            parseClassicExtentArray(
                header + 0x92U,
                0U,
                catalogFork_.extents);
            catalogFork_.totalBlocks =
                countExtentBlocks(catalogFork_.extents);
            if (!validateMetadataFork(extentsFork_, errorText)
                || !validateMetadataFork(catalogFork_, errorText))
            {
                return false;
            }
            return true;
        }

        bool validateGeometry(QString& errorText) const
        {
            if (!isPowerOfTwo(blockSize_)
                || blockSize_ < 512U
                || blockSize_ > 1024U * 1024U
                || totalBlocks_ == 0U)
            {
                errorText = QStringLiteral("HFS 分配块大小或块总数无效。");
                return false;
            }
            std::uint64_t volumeBytes = 0;
            if (!checkedMultiply(
                    totalBlocks_,
                    blockSize_,
                    volumeBytes)
                || volumeBytes
                    > reader_.partitionLength() - allocationStart_)
            {
                errorText = QStringLiteral("HFS 卷几何范围越过所选分区。");
                return false;
            }
            return true;
        }

        bool validateMetadataFork(
            const HfsFork& fork,
            QString& errorText) const
        {
            if (fork.logicalSize == 0U || fork.extents.empty())
            {
                errorText = QStringLiteral("HFS 元数据分支为空。");
                return false;
            }
            for (const HfsExtent& extent : fork.extents)
            {
                if (extent.blockCount == 0U
                    || extent.startBlock >= totalBlocks_
                    || extent.blockCount
                        > totalBlocks_ - extent.startBlock)
                {
                    errorText = QStringLiteral(
                        "HFS 元数据分支包含越界区段。");
                    return false;
                }
            }
            return true;
        }

        HfsFork parsePlusFork(
            const unsigned char* bytes,
            const std::uint32_t fileId) const
        {
            HfsFork fork;
            fork.fileId = fileId;
            fork.logicalSize = be64(bytes);
            fork.totalBlocks = be32(bytes + 0x0CU);
            std::uint64_t logicalBlock = 0;
            for (std::uint32_t index = 0; index < 8U; ++index)
            {
                const std::uint32_t kStartBlock =
                    be32(bytes + 0x10U + index * 8U);
                const std::uint32_t kBlockCount =
                    be32(bytes + 0x14U + index * 8U);
                if (kBlockCount == 0U)
                {
                    continue;
                }
                fork.extents.push_back(
                    HfsExtent{
                        logicalBlock,
                        kStartBlock,
                        kBlockCount});
                logicalBlock += kBlockCount;
            }
            return fork;
        }

        static void parseClassicExtentArray(
            const unsigned char* bytes,
            const std::uint64_t firstLogicalBlock,
            std::vector<HfsExtent>& extentsOut)
        {
            std::uint64_t logicalBlock = firstLogicalBlock;
            for (std::uint32_t index = 0; index < 3U; ++index)
            {
                const std::uint32_t kStartBlock =
                    be16(bytes + index * 4U);
                const std::uint32_t kBlockCount =
                    be16(bytes + index * 4U + 2U);
                if (kBlockCount == 0U)
                {
                    continue;
                }
                extentsOut.push_back(
                    HfsExtent{
                        logicalBlock,
                        kStartBlock,
                        kBlockCount});
                logicalBlock += kBlockCount;
            }
        }

        static std::uint64_t countExtentBlocks(
            const std::vector<HfsExtent>& extents)
        {
            std::uint64_t total = 0;
            for (const HfsExtent& extent : extents)
            {
                total += extent.blockCount;
            }
            return total;
        }

        bool logicalBlockToRelativeOffset(
            const HfsFork& fork,
            const std::uint64_t logicalBlock,
            std::uint64_t& relativeOffsetOut,
            std::uint64_t& contiguousBytesOut) const
        {
            for (const HfsExtent& extent : fork.extents)
            {
                if (logicalBlock < extent.logicalBlock
                    || logicalBlock
                        >= extent.logicalBlock + extent.blockCount)
                {
                    continue;
                }
                const std::uint64_t kWithin =
                    logicalBlock - extent.logicalBlock;
                const std::uint64_t kPhysicalBlock =
                    static_cast<std::uint64_t>(extent.startBlock)
                    + kWithin;
                std::uint64_t blockOffset = 0;
                if (!checkedMultiply(
                        kPhysicalBlock,
                        blockSize_,
                        blockOffset)
                    || blockOffset
                        > std::numeric_limits<std::uint64_t>::max()
                            - allocationStart_)
                {
                    return false;
                }
                relativeOffsetOut = allocationStart_ + blockOffset;
                contiguousBytesOut =
                    (static_cast<std::uint64_t>(extent.blockCount)
                        - kWithin)
                    * blockSize_;
                return true;
            }
            return false;
        }

        bool readForkBytes(
            const HfsFork& fork,
            const std::uint64_t logicalOffset,
            const std::uint32_t length,
            QByteArray& bytesOut,
            QString& errorText) const
        {
            bytesOut.clear();
            if (length == 0U)
            {
                return true;
            }
            if (logicalOffset > fork.logicalSize
                || length > fork.logicalSize - logicalOffset)
            {
                errorText = QStringLiteral("HFS 分支读取范围越过逻辑末尾。");
                return false;
            }

            bytesOut.resize(static_cast<qsizetype>(length));
            std::uint64_t completed = 0;
            while (completed < length)
            {
                const std::uint64_t kCurrent = logicalOffset + completed;
                const std::uint64_t kLogicalBlock = kCurrent / blockSize_;
                const std::uint64_t kWithinBlock = kCurrent % blockSize_;
                std::uint64_t relativeOffset = 0;
                std::uint64_t contiguousBytes = 0;
                if (!logicalBlockToRelativeOffset(
                        fork,
                        kLogicalBlock,
                        relativeOffset,
                        contiguousBytes)
                    || contiguousBytes <= kWithinBlock)
                {
                    bytesOut.clear();
                    errorText = QStringLiteral(
                        "HFS 分支的区段映射不完整，无法安全读取。");
                    return false;
                }
                const std::uint32_t kChunkLength =
                    static_cast<std::uint32_t>(
                        std::min<std::uint64_t>(
                            length - completed,
                            contiguousBytes - kWithinBlock));
                QByteArray chunk;
                if (!reader_.read(
                        relativeOffset + kWithinBlock,
                        kChunkLength,
                        chunk,
                        errorText))
                {
                    bytesOut.clear();
                    return false;
                }
                std::copy(
                    chunk.cbegin(),
                    chunk.cend(),
                    bytesOut.begin()
                        + static_cast<qsizetype>(completed));
                completed += kChunkLength;
            }
            return true;
        }

        bool readTreeHeader(
            const HfsFork& fork,
            HfsTreeHeader& headerOut,
            QString& errorText) const
        {
            QByteArray prefix;
            if (!readForkBytes(fork, 0U, 64U, prefix, errorText))
            {
                return false;
            }
            const unsigned char* const kBytes = dataPointer(prefix);
            if (static_cast<std::int8_t>(kBytes[8U]) != 1)
            {
                errorText = QStringLiteral("HFS B-tree 头节点类型无效。");
                return false;
            }
            const unsigned char* const kRecord = kBytes + 14U;
            HfsTreeHeader header;
            header.rootNode = be32(kRecord + 2U);
            header.leafRecords = be32(kRecord + 6U);
            header.firstLeafNode = be32(kRecord + 10U);
            header.lastLeafNode = be32(kRecord + 14U);
            header.nodeSize = be16(kRecord + 18U);
            header.totalNodes = be32(kRecord + 22U);
            header.keyCompareType = kRecord[37U];
            if (!isPowerOfTwo(header.nodeSize)
                || header.nodeSize < 512U
                || header.nodeSize > 65536U
                || header.totalNodes == 0U
                || header.totalNodes > kMaximumBTreeNodes
                || header.firstLeafNode >= header.totalNodes
                || header.lastLeafNode >= header.totalNodes)
            {
                errorText = QStringLiteral("HFS B-tree 几何参数无效。");
                return false;
            }
            std::uint64_t treeBytes = 0;
            if (!checkedMultiply(
                    header.totalNodes,
                    header.nodeSize,
                    treeBytes)
                || treeBytes > fork.logicalSize)
            {
                errorText = QStringLiteral("HFS B-tree 节点范围越过分支。");
                return false;
            }
            headerOut = header;
            return true;
        }

        bool readTreeNode(
            const HfsFork& fork,
            const HfsTreeHeader& tree,
            const std::uint32_t nodeNumber,
            QByteArray& nodeOut,
            QString& errorText) const
        {
            if (nodeNumber >= tree.totalNodes)
            {
                errorText = QStringLiteral("HFS B-tree 节点号越界。");
                return false;
            }
            const std::uint64_t kOffset =
                static_cast<std::uint64_t>(nodeNumber) * tree.nodeSize;
            return readForkBytes(
                fork,
                kOffset,
                tree.nodeSize,
                nodeOut,
                errorText);
        }

        static bool nodeRecordRanges(
            const QByteArray& node,
            std::vector<std::pair<std::uint16_t, std::uint16_t>>& rangesOut,
            QString& errorText)
        {
            rangesOut.clear();
            if (node.size() < 16)
            {
                errorText = QStringLiteral("HFS B-tree 节点被截断。");
                return false;
            }
            const unsigned char* const kBytes = dataPointer(node);
            const std::uint16_t kRecordCount = be16(kBytes + 10U);
            const std::uint32_t kTableBytes =
                (static_cast<std::uint32_t>(kRecordCount) + 1U) * 2U;
            if (kTableBytes > static_cast<std::uint32_t>(node.size()) - 14U)
            {
                errorText = QStringLiteral("HFS B-tree 记录表越界。");
                return false;
            }

            std::vector<std::uint16_t> offsets;
            offsets.reserve(static_cast<std::size_t>(kRecordCount) + 1U);
            for (std::uint32_t index = 0;
                 index <= kRecordCount;
                 ++index)
            {
                const std::uint32_t kTableOffset =
                    static_cast<std::uint32_t>(node.size())
                    - (index + 1U) * 2U;
                offsets.push_back(be16(kBytes + kTableOffset));
            }
            for (std::uint32_t index = 0; index < kRecordCount; ++index)
            {
                const std::uint16_t kBegin = offsets[index];
                const std::uint16_t kEnd = offsets[index + 1U];
                if (kBegin < 14U || kEnd <= kBegin
                    || kEnd
                        > static_cast<std::uint32_t>(node.size())
                            - kTableBytes)
                {
                    errorText = QStringLiteral(
                        "HFS B-tree 记录边界无效。");
                    rangesOut.clear();
                    return false;
                }
                rangesOut.emplace_back(kBegin, kEnd);
            }
            return true;
        }

        bool loadOverflowIndex(QString& errorText)
        {
            overflowRecords_.clear();
            std::uint32_t nodeNumber = extentsTree_.firstLeafNode;
            std::vector<std::uint32_t> visited;
            while (nodeNumber != 0U)
            {
                if (visited.size() >= extentsTree_.totalNodes
                    || std::find(
                        visited.cbegin(),
                        visited.cend(),
                        nodeNumber) != visited.cend())
                {
                    errorText = QStringLiteral(
                        "HFS Extents Overflow 叶链包含循环。");
                    return false;
                }
                visited.push_back(nodeNumber);

                QByteArray node;
                if (!readTreeNode(
                        extentsFork_,
                        extentsTree_,
                        nodeNumber,
                        node,
                        errorText))
                {
                    return false;
                }
                const unsigned char* const kBytes = dataPointer(node);
                if (static_cast<std::int8_t>(kBytes[8U])
                    != kLeafNodeKind)
                {
                    errorText = QStringLiteral(
                        "HFS Extents Overflow 叶链指向非叶节点。");
                    return false;
                }

                std::vector<std::pair<std::uint16_t, std::uint16_t>> ranges;
                if (!nodeRecordRanges(node, ranges, errorText))
                {
                    return false;
                }
                for (const auto& [begin, end] : ranges)
                {
                    HfsOverflowRecord record;
                    if (parseOverflowRecord(
                            kBytes + begin,
                            end - begin,
                            record))
                    {
                        overflowRecords_.push_back(std::move(record));
                    }
                }
                nodeNumber = be32(kBytes);
            }
            std::sort(
                overflowRecords_.begin(),
                overflowRecords_.end(),
                [](const HfsOverflowRecord& left,
                   const HfsOverflowRecord& right)
                {
                    if (left.fileId != right.fileId)
                    {
                        return left.fileId < right.fileId;
                    }
                    if (left.forkType != right.forkType)
                    {
                        return left.forkType < right.forkType;
                    }
                    return left.logicalBlock < right.logicalBlock;
                });
            return true;
        }

        bool parseOverflowRecord(
            const unsigned char* record,
            const std::uint32_t recordLength,
            HfsOverflowRecord& recordOut) const
        {
            if (plus_)
            {
                if (recordLength < 12U)
                {
                    return false;
                }
                const std::uint16_t kKeyLength = be16(record);
                const std::uint32_t kDataOffset =
                    alignEven(static_cast<std::uint32_t>(kKeyLength) + 2U);
                if (kKeyLength < 10U
                    || kDataOffset + 64U > recordLength)
                {
                    return false;
                }
                HfsOverflowRecord parsed;
                parsed.forkType = record[2U];
                parsed.fileId = be32(record + 4U);
                parsed.logicalBlock = be32(record + 8U);
                std::uint64_t logical = parsed.logicalBlock;
                for (std::uint32_t index = 0; index < 8U; ++index)
                {
                    const std::uint32_t kStartBlock =
                        be32(record + kDataOffset + index * 8U);
                    const std::uint32_t kBlockCount =
                        be32(record + kDataOffset + index * 8U + 4U);
                    if (kBlockCount == 0U)
                    {
                        continue;
                    }
                    parsed.extents.push_back(
                        HfsExtent{logical, kStartBlock, kBlockCount});
                    logical += kBlockCount;
                }
                if (parsed.extents.empty())
                {
                    return false;
                }
                recordOut = std::move(parsed);
                return true;
            }

            if (recordLength < 20U)
            {
                return false;
            }
            const std::uint8_t kKeyLength = record[0U];
            const std::uint32_t kDataOffset =
                alignEven(static_cast<std::uint32_t>(kKeyLength) + 1U);
            if (kKeyLength < 7U || kDataOffset + 12U > recordLength)
            {
                return false;
            }
            HfsOverflowRecord parsed;
            parsed.forkType = record[1U];
            parsed.fileId = be32(record + 2U);
            parsed.logicalBlock = be16(record + 6U);
            parseClassicExtentArray(
                record + kDataOffset,
                parsed.logicalBlock,
                parsed.extents);
            if (parsed.extents.empty())
            {
                return false;
            }
            recordOut = std::move(parsed);
            return true;
        }

        void applyOverflowExtents(HfsFork& fork) const
        {
            if (fork.overflowApplied)
            {
                return;
            }
            for (const HfsOverflowRecord& record : overflowRecords_)
            {
                if (record.fileId != fork.fileId
                    || record.forkType != fork.forkType)
                {
                    continue;
                }
                for (const HfsExtent& candidate : record.extents)
                {
                    const bool kDuplicate = std::any_of(
                        fork.extents.cbegin(),
                        fork.extents.cend(),
                        [&](const HfsExtent& existing)
                        {
                            return existing.logicalBlock
                                    == candidate.logicalBlock
                                && existing.startBlock
                                    == candidate.startBlock
                                && existing.blockCount
                                    == candidate.blockCount;
                        });
                    if (!kDuplicate)
                    {
                        fork.extents.push_back(candidate);
                    }
                }
            }
            std::sort(
                fork.extents.begin(),
                fork.extents.end(),
                [](const HfsExtent& left, const HfsExtent& right)
                {
                    return left.logicalBlock < right.logicalBlock;
                });
            fork.overflowApplied = true;
        }

        template<typename Callback>
        bool scanCatalog(
            Callback&& callback,
            std::uint64_t& scannedRecordsOut,
            QString& errorText)
        {
            scannedRecordsOut = 0;
            std::uint32_t nodeNumber = catalogTree_.firstLeafNode;
            std::vector<std::uint32_t> visited;
            while (nodeNumber != 0U)
            {
                if (visited.size() >= catalogTree_.totalNodes
                    || std::find(
                        visited.cbegin(),
                        visited.cend(),
                        nodeNumber) != visited.cend())
                {
                    errorText = QStringLiteral(
                        "HFS Catalog 叶链包含循环。");
                    return false;
                }
                visited.push_back(nodeNumber);

                QByteArray node;
                if (!readTreeNode(
                        catalogFork_,
                        catalogTree_,
                        nodeNumber,
                        node,
                        errorText))
                {
                    return false;
                }
                const unsigned char* const kBytes = dataPointer(node);
                if (static_cast<std::int8_t>(kBytes[8U])
                    != kLeafNodeKind)
                {
                    errorText = QStringLiteral(
                        "HFS Catalog 叶链指向非叶节点。");
                    return false;
                }
                std::vector<std::pair<std::uint16_t, std::uint16_t>> ranges;
                if (!nodeRecordRanges(node, ranges, errorText))
                {
                    return false;
                }
                for (const auto& [begin, end] : ranges)
                {
                    if (++scannedRecordsOut > kMaximumCatalogRecords)
                    {
                        errorText = QStringLiteral(
                            "HFS Catalog 记录数超过安全上限。");
                        return false;
                    }
                    HfsCatalogRecord record;
                    if (!parseCatalogRecord(
                            kBytes + begin,
                            end - begin,
                            static_cast<std::uint64_t>(nodeNumber)
                                * catalogTree_.nodeSize
                                + begin,
                            record))
                    {
                        continue;
                    }
                    if (!callback(record))
                    {
                        return false;
                    }
                }
                nodeNumber = be32(kBytes);
            }
            return true;
        }

        bool parseCatalogRecord(
            const unsigned char* record,
            const std::uint32_t recordLength,
            const std::uint64_t catalogLogicalOffset,
            HfsCatalogRecord& recordOut) const
        {
            if (plus_)
            {
                return parsePlusCatalogRecord(
                    record,
                    recordLength,
                    catalogLogicalOffset,
                    recordOut);
            }
            return parseClassicCatalogRecord(
                record,
                recordLength,
                catalogLogicalOffset,
                recordOut);
        }

        bool parsePlusCatalogRecord(
            const unsigned char* record,
            const std::uint32_t recordLength,
            const std::uint64_t catalogLogicalOffset,
            HfsCatalogRecord& recordOut) const
        {
            if (recordLength < 10U)
            {
                return false;
            }
            const std::uint16_t kKeyLength = be16(record);
            const std::uint32_t kDataOffset =
                alignEven(static_cast<std::uint32_t>(kKeyLength) + 2U);
            const std::uint16_t kCharacterCount = be16(record + 6U);
            if (kKeyLength < 6U
                || static_cast<std::uint32_t>(kCharacterCount) * 2U
                    > kKeyLength - 6U
                || kDataOffset + 2U > recordLength)
            {
                return false;
            }

            const unsigned char* const kData = record + kDataOffset;
            const std::uint16_t kRecordType = be16(kData);
            if (kRecordType != 1U && kRecordType != 2U)
            {
                return false;
            }
            const std::uint32_t kRequired =
                kRecordType == 1U ? 88U : 248U;
            if (kDataOffset + kRequired > recordLength)
            {
                return false;
            }

            HfsCatalogRecord parsed;
            parsed.parentId = be32(record + 2U);
            parsed.name =
                decodeHfsPlusName(record + 8U, kCharacterCount);
            parsed.objectId = be32(kData + 8U);
            parsed.modeOrFlags =
                static_cast<std::uint32_t>(be16(kData + 2U)) << 16U;
            parsed.modeOrFlags |= be16(kData + 0x2AU);
            parsed.valence = kRecordType == 1U ? be32(kData + 4U) : 0U;
            parsed.metadataOffset =
                catalogRecordAbsoluteOffset(catalogLogicalOffset);
            if (kRecordType == 1U)
            {
                parsed.type = ks::misc::RawFileObjectType::kDirectory;
            }
            else
            {
                const std::uint16_t kMode = be16(kData + 0x2AU);
                parsed.type = objectTypeForMode(kMode);
                parsed.dataFork =
                    parsePlusFork(kData + 0x58U, parsed.objectId);
            }
            recordOut = std::move(parsed);
            return true;
        }

        bool parseClassicCatalogRecord(
            const unsigned char* record,
            const std::uint32_t recordLength,
            const std::uint64_t catalogLogicalOffset,
            HfsCatalogRecord& recordOut) const
        {
            if (recordLength < 8U)
            {
                return false;
            }
            const std::uint8_t kKeyLength = record[0U];
            const std::uint32_t kDataOffset =
                alignEven(static_cast<std::uint32_t>(kKeyLength) + 1U);
            const std::uint8_t kNameLength = record[6U];
            if (kKeyLength < 6U || kNameLength > kKeyLength - 6U
                || kDataOffset + 1U > recordLength)
            {
                return false;
            }

            const unsigned char* const kData = record + kDataOffset;
            std::uint8_t recordType = kData[0U] >> 4U;
            if (recordType != 1U && recordType != 2U)
            {
                recordType = kData[0U];
            }
            const std::uint32_t kRequired =
                recordType == 1U ? 70U : 102U;
            if ((recordType != 1U && recordType != 2U)
                || kDataOffset + kRequired > recordLength)
            {
                return false;
            }

            HfsCatalogRecord parsed;
            parsed.parentId = be32(record + 2U);
            parsed.name = decodeMacRoman(record + 7U, kNameLength);
            parsed.metadataOffset =
                catalogRecordAbsoluteOffset(catalogLogicalOffset);
            if (recordType == 1U)
            {
                parsed.type = ks::misc::RawFileObjectType::kDirectory;
                parsed.valence = be16(kData + 4U);
                parsed.objectId = be32(kData + 6U);
            }
            else
            {
                parsed.type = ks::misc::RawFileObjectType::kRegularFile;
                parsed.objectId = be32(kData + 0x14U);
                parsed.dataFork.fileId = parsed.objectId;
                parsed.dataFork.logicalSize = be32(kData + 0x1AU);
                parsed.dataFork.totalBlocks =
                    (static_cast<std::uint64_t>(be32(kData + 0x1EU))
                        + blockSize_ - 1U)
                    / blockSize_;
                parseClassicExtentArray(
                    kData + 0x4EU,
                    0U,
                    parsed.dataFork.extents);
            }
            recordOut = std::move(parsed);
            return true;
        }

        std::uint64_t catalogRecordAbsoluteOffset(
            const std::uint64_t logicalOffset) const
        {
            const std::uint64_t kLogicalBlock = logicalOffset / blockSize_;
            const std::uint64_t kWithinBlock = logicalOffset % blockSize_;
            std::uint64_t relativeOffset = 0;
            std::uint64_t contiguousBytes = 0;
            if (!logicalBlockToRelativeOffset(
                    catalogFork_,
                    kLogicalBlock,
                    relativeOffset,
                    contiguousBytes)
                || contiguousBytes <= kWithinBlock)
            {
                return 0U;
            }
            return reader_.partitionOffset()
                + relativeOffset + kWithinBlock;
        }

        bool findCatalogChild(
            const std::uint32_t parentId,
            const QString& requestedName,
            HfsCatalogRecord& childOut,
            QString& errorText)
        {
            bool found = false;
            bool stopped = false;
            std::uint64_t scannedRecords = 0;
            const bool kScanned = scanCatalog(
                [&](HfsCatalogRecord& record)
                {
                    if (record.parentId == parentId
                        && namesEqual(record.name, requestedName))
                    {
                        childOut = record;
                        found = true;
                        stopped = true;
                        return false;
                    }
                    return true;
                },
                scannedRecords,
                errorText);
            if (!kScanned && !stopped)
            {
                return false;
            }
            if (!found)
            {
                errorText = QStringLiteral(
                    "HFS 目录中不存在对象：%1").arg(requestedName);
                return false;
            }
            return true;
        }

        bool namesEqual(
            const QString& left,
            const QString& right) const
        {
            return QString::compare(
                left,
                right,
                caseSensitive_
                    ? Qt::CaseSensitive
                    : Qt::CaseInsensitive) == 0;
        }

        static ks::misc::RawFileObjectType objectTypeForMode(
            const std::uint16_t mode)
        {
            switch (mode & 0xF000U)
            {
            case 0x4000U:
                return ks::misc::RawFileObjectType::kDirectory;
            case 0x8000U:
                return ks::misc::RawFileObjectType::kRegularFile;
            case 0xA000U:
                return ks::misc::RawFileObjectType::kSymbolicLink;
            default:
                return ks::misc::RawFileObjectType::kSpecial;
            }
        }

        std::vector<ks::misc::RawFileExtent> describeFork(
            const HfsFork& fork) const
        {
            std::vector<ks::misc::RawFileExtent> extents;
            extents.reserve(
                std::min<std::size_t>(
                    fork.extents.size(),
                    ks::misc::rawfs::kMaximumExtentCount));
            for (const HfsExtent& source : fork.extents)
            {
                if (extents.size()
                    >= ks::misc::rawfs::kMaximumExtentCount)
                {
                    break;
                }
                const std::uint64_t kLogicalOffset =
                    source.logicalBlock * blockSize_;
                if (kLogicalOffset >= fork.logicalSize)
                {
                    continue;
                }
                ks::misc::RawFileExtent extent;
                extent.logicalOffset = kLogicalOffset;
                extent.absoluteOffset =
                    reader_.partitionOffset()
                    + allocationStart_
                    + static_cast<std::uint64_t>(source.startBlock)
                        * blockSize_;
                extent.lengthBytes = std::min<std::uint64_t>(
                    static_cast<std::uint64_t>(source.blockCount)
                        * blockSize_,
                    fork.logicalSize - kLogicalOffset);
                extent.physicalMappingExact = true;
                extents.push_back(extent);
            }
            return extents;
        }

        void fillEntry(
            const HfsCatalogRecord& record,
            const QString& parentPath,
            ks::misc::RawFileEntry& entry) const
        {
            entry.name = record.name;
            entry.fullPath =
                ks::misc::rawfs::childPath(parentPath, record.name);
            entry.type = record.type;
            entry.objectId = record.objectId;
            entry.parentObjectId = record.parentId;
            entry.fileSizeBytes = record.dataFork.logicalSize;
            entry.allocatedSizeBytes =
                record.dataFork.totalBlocks * blockSize_;
            entry.metadataOffset = record.metadataOffset;
            entry.modeOrFlags = record.modeOrFlags;
            entry.extents = describeFork(record.dataFork);
            entry.extentsTruncated =
                record.dataFork.extents.size()
                > ks::misc::rawfs::kMaximumExtentCount;
        }

        const ks::misc::rawfs::VolumeReader& reader_;
        ks::misc::ForensicFileSystemKind expectedKind_ =
            ks::misc::ForensicFileSystemKind::kUnknown;
        bool plus_ = false;
        bool caseSensitive_ = false;
        std::uint32_t blockSize_ = 0;
        std::uint64_t totalBlocks_ = 0;
        std::uint64_t allocationStart_ = 0;
        HfsFork extentsFork_;
        HfsFork catalogFork_;
        HfsTreeHeader extentsTree_;
        HfsTreeHeader catalogTree_;
        std::vector<HfsOverflowRecord> overflowRecords_;
    };

    ks::misc::RawDirectoryResult makeDirectoryResult(
        const ks::misc::ForensicFileSystemKind kind,
        const QString& path)
    {
        ks::misc::RawDirectoryResult result;
        result.fileSystem = kind;
        result.fileSystemName =
            ks::misc::DiskFileSystemForensics::fileSystemName(kind);
        result.requestedPath = path;
        return result;
    }

    ks::misc::RawFileReadResult makeFileResult(
        const ks::misc::ForensicFileSystemKind kind,
        const QString& path,
        const std::uint64_t offset)
    {
        ks::misc::RawFileReadResult result;
        result.fileSystem = kind;
        result.fileSystemName =
            ks::misc::DiskFileSystemForensics::fileSystemName(kind);
        result.filePath = path;
        result.requestedOffset = offset;
        return result;
    }
}

namespace ks::misc::rawfs
{
    RawDirectoryResult listHfs(
        const VolumeReader& reader,
        const ForensicFileSystemKind expectedKind,
        const QString& path,
        const std::uint32_t maximumEntries)
    {
        RawDirectoryResult result =
            makeDirectoryResult(expectedKind, path);
        HfsVolume volume(reader, expectedKind);
        if (!volume.mount(result.errorText))
        {
            return result;
        }

        HfsCatalogRecord directory;
        if (!volume.resolvePath(
                path,
                directory,
                result.canonicalPath,
                result.errorText))
        {
            return result;
        }
        result.directoryObjectId = directory.objectId;
        if (!volume.listDirectory(
                directory,
                result.canonicalPath,
                maximumEntries,
                result))
        {
            return result;
        }
        result.success = true;
        return result;
    }

    RawFileReadResult readHfs(
        const VolumeReader& reader,
        const ForensicFileSystemKind expectedKind,
        const QString& path,
        const std::uint64_t offset,
        const std::uint32_t length)
    {
        RawFileReadResult result =
            makeFileResult(expectedKind, path, offset);
        HfsVolume volume(reader, expectedKind);
        if (!volume.mount(result.errorText))
        {
            return result;
        }

        HfsCatalogRecord record;
        QString canonicalPath;
        if (!volume.resolvePath(
                path,
                record,
                canonicalPath,
                result.errorText))
        {
            return result;
        }
        result.filePath = canonicalPath;
        result.fileSizeBytes = record.dataFork.logicalSize;
        if (!volume.readFile(record, offset, length, result))
        {
            return result;
        }
        result.success = true;
        return result;
    }
}
