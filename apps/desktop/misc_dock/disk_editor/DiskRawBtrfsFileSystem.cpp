#include "DiskRawFileSystemInternal.h"

#include <QByteArray>
#include <QStringList>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <limits>
#include <vector>

namespace
{
    constexpr std::uint64_t kSuperblockOffset = 64U * 1024U;
    constexpr std::uint32_t kSuperblockSize = 4096U;
    constexpr std::uint32_t kSystemChunkArrayOffset = 0x32BU;
    constexpr std::uint32_t kSystemChunkArrayCapacity = 2048U;
    constexpr std::uint32_t kTreeHeaderSize = 101U;
    constexpr std::uint32_t kLeafItemSize = 25U;
    constexpr std::uint32_t kNodePointerSize = 33U;
    constexpr std::uint32_t kChunkHeaderSize = 48U;
    constexpr std::uint32_t kChunkStripeSize = 32U;
    constexpr std::uint32_t kDirItemHeaderSize = 30U;
    constexpr std::uint32_t kFileExtentHeaderSize = 21U;
    constexpr std::uint32_t kFileExtentRegularSize = 53U;
    constexpr std::uint64_t kFsTreeObjectId = 5U;
    constexpr std::uint64_t kRootDirectoryObjectId = 256U;
    constexpr std::uint8_t kInodeItemKey = 1U;
    constexpr std::uint8_t kDirectoryIndexKey = 96U;
    constexpr std::uint8_t kFileExtentDataKey = 108U;
    constexpr std::uint8_t kRootItemKey = 132U;
    constexpr std::uint8_t kChunkItemKey = 228U;
    constexpr std::uint64_t kBlockGroupRaid0 = 0x08U;
    constexpr std::uint64_t kBlockGroupRaid10 = 0x40U;
    constexpr std::uint64_t kBlockGroupRaid5 = 0x80U;
    constexpr std::uint64_t kBlockGroupRaid6 = 0x100U;
    constexpr std::uint8_t kExtentInline = 0U;
    constexpr std::uint8_t kExtentRegular = 1U;
    constexpr std::uint8_t kExtentPreallocated = 2U;
    constexpr std::uint32_t kMaximumVisitedTreeBlocks = 1U << 20U;
    constexpr std::uint32_t kMaximumDirectoryRecords = 1U << 20U;

    std::uint16_t le16(const unsigned char* bytes)
    {
        return static_cast<std::uint16_t>(bytes[0])
            | (static_cast<std::uint16_t>(bytes[1]) << 8U);
    }

    std::uint32_t le32(const unsigned char* bytes)
    {
        return static_cast<std::uint32_t>(bytes[0])
            | (static_cast<std::uint32_t>(bytes[1]) << 8U)
            | (static_cast<std::uint32_t>(bytes[2]) << 16U)
            | (static_cast<std::uint32_t>(bytes[3]) << 24U);
    }

    std::uint64_t le64(const unsigned char* bytes)
    {
        return static_cast<std::uint64_t>(le32(bytes))
            | (static_cast<std::uint64_t>(le32(bytes + 4U)) << 32U);
    }

    const unsigned char* dataPointer(const QByteArray& bytes)
    {
        return reinterpret_cast<const unsigned char*>(bytes.constData());
    }

    bool isPowerOfTwo(const std::uint32_t value)
    {
        return value != 0U && (value & (value - 1U)) == 0U;
    }

    bool checkedAdd(
        const std::uint64_t left,
        const std::uint64_t right,
        std::uint64_t& resultOut)
    {
        if (right > std::numeric_limits<std::uint64_t>::max() - left)
        {
            return false;
        }
        resultOut = left + right;
        return true;
    }

    struct BtrfsKey
    {
        std::uint64_t objectId = 0;
        std::uint8_t type = 0;
        std::uint64_t offset = 0;
    };

    int compareKey(const BtrfsKey& left, const BtrfsKey& right)
    {
        if (left.objectId != right.objectId)
        {
            return left.objectId < right.objectId ? -1 : 1;
        }
        if (left.type != right.type)
        {
            return left.type < right.type ? -1 : 1;
        }
        if (left.offset != right.offset)
        {
            return left.offset < right.offset ? -1 : 1;
        }
        return 0;
    }

    BtrfsKey parseKey(const unsigned char* bytes)
    {
        return BtrfsKey{
            le64(bytes),
            bytes[8U],
            le64(bytes + 9U)};
    }

    struct BtrfsChunk
    {
        std::uint64_t logical = 0;
        std::uint64_t length = 0;
        std::uint64_t physical = 0;
        std::uint64_t type = 0;
        std::uint64_t deviceId = 0;
    };

    struct BtrfsInode
    {
        std::uint64_t number = 0;
        std::uint64_t size = 0;
        std::uint64_t allocated = 0;
        std::uint64_t flags = 0;
        std::uint64_t metadataOffset = 0;
        std::uint32_t mode = 0;
    };

    struct BtrfsDirectoryChild
    {
        QString name;
        std::uint64_t inode = 0;
        std::uint8_t type = 0;
    };

    struct BtrfsFileSegment
    {
        std::uint64_t logicalOffset = 0;
        std::uint64_t logicalLength = 0;
        std::uint64_t diskLogical = 0;
        std::uint64_t diskLength = 0;
        std::uint64_t inlineAbsolute = 0;
        QByteArray inlineBytes;
        std::uint8_t compression = 0;
        std::uint8_t encryption = 0;
        std::uint16_t otherEncoding = 0;
        bool sparse = false;
        bool preallocated = false;
    };

    struct BtrfsLeafItem
    {
        BtrfsKey key;
        const unsigned char* data = nullptr;
        std::uint32_t size = 0;
        std::uint64_t absoluteOffset = 0;
    };

    class BtrfsVolume final
    {
    public:
        explicit BtrfsVolume(
            const ks::misc::rawfs::VolumeReader& reader)
            : reader_(reader)
        {
        }

        bool mount(QString& errorText)
        {
            QByteArray superblock;
            if (!reader_.read(
                    kSuperblockOffset,
                    kSuperblockSize,
                    superblock,
                    errorText))
            {
                return false;
            }
            const unsigned char* const kBytes = dataPointer(superblock);
            if (QByteArray(
                    reinterpret_cast<const char*>(kBytes + 0x40U),
                    8) != QByteArrayLiteral("_BHRfS_M"))
            {
                errorText = QStringLiteral("Btrfs 超级块魔数不匹配。");
                return false;
            }

            totalBytes_ = le64(kBytes + 0x70U);
            deviceCount_ = le64(kBytes + 0x88U);
            sectorSize_ = le32(kBytes + 0x90U);
            nodeSize_ = le32(kBytes + 0x94U);
            rootTreeLogical_ = le64(kBytes + 0x50U);
            chunkTreeLogical_ = le64(kBytes + 0x58U);
            currentDeviceId_ = le64(kBytes + 0xC9U);
            const std::uint32_t kSystemArraySize =
                le32(kBytes + 0xA0U);
            if (!isPowerOfTwo(sectorSize_)
                || !isPowerOfTwo(nodeSize_)
                || sectorSize_ < 512U
                || sectorSize_ > 65536U
                || nodeSize_ < 1024U
                || nodeSize_ > 65536U
                || totalBytes_ == 0U
                || totalBytes_ > reader_.partitionLength()
                || deviceCount_ == 0U
                || kSystemArraySize > kSystemChunkArrayCapacity)
            {
                errorText = QStringLiteral("Btrfs 超级块几何参数无效。");
                return false;
            }

            if (!parseSystemChunkArray(
                    kBytes + kSystemChunkArrayOffset,
                    kSystemArraySize,
                    errorText))
            {
                return false;
            }
            if (chunks_.empty())
            {
                errorText = QStringLiteral("Btrfs 系统块组映射为空。");
                return false;
            }

            std::vector<std::uint64_t> visited;
            walkStopRequested_ = false;
            if (!walkTreeRange(
                    chunkTreeLogical_,
                    BtrfsKey{0U, 0U, 0U},
                    BtrfsKey{
                        std::numeric_limits<std::uint64_t>::max(),
                        std::numeric_limits<std::uint8_t>::max(),
                        std::numeric_limits<std::uint64_t>::max()},
                    [&](const BtrfsLeafItem& item)
                    {
                        if (item.key.type == kChunkItemKey)
                        {
                            if (!parseChunk(
                                item.key.offset,
                                item.data,
                                item.size,
                                errorText))
                            {
                                return false;
                            }
                        }
                        return true;
                    },
                    visited,
                    errorText)
                || !errorText.isEmpty())
            {
                errorText = QStringLiteral(
                    "无法遍历 Btrfs Chunk tree：%1").arg(errorText);
                return false;
            }
            normalizeChunkMap();

            bool foundFsTree = false;
            visited.clear();
            walkStopRequested_ = false;
            if (!walkTreeRange(
                    rootTreeLogical_,
                    BtrfsKey{kFsTreeObjectId, kRootItemKey, 0U},
                    BtrfsKey{
                        kFsTreeObjectId,
                        kRootItemKey,
                        std::numeric_limits<std::uint64_t>::max()},
                    [&](const BtrfsLeafItem& item)
                    {
                        if (item.key.objectId != kFsTreeObjectId
                            || item.key.type != kRootItemKey
                            || item.size < 239U)
                        {
                            return true;
                        }
                        fsTreeLogical_ = le64(item.data + 0xB0U);
                        foundFsTree = fsTreeLogical_ != 0U;
                        return !foundFsTree;
                    },
                    visited,
                    errorText))
            {
                return false;
            }
            if (!foundFsTree)
            {
                errorText = QStringLiteral(
                    "Btrfs Root tree 中不存在默认文件系统树。");
                return false;
            }
            return true;
        }

        bool resolvePath(
            const QString& path,
            BtrfsInode& inodeOut,
            QString& canonicalPathOut,
            QString& errorText)
        {
            BtrfsInode current;
            if (!loadInode(
                    kRootDirectoryObjectId,
                    current,
                    errorText))
            {
                return false;
            }
            canonicalPathOut = QStringLiteral("\\");
            const QStringList kComponents =
                ks::misc::rawfs::normalizePath(path).split(
                    QChar('\\'),
                    Qt::SkipEmptyParts);
            for (const QString& component : kComponents)
            {
                if ((current.mode & 0xF000U) != 0x4000U)
                {
                    errorText = QStringLiteral(
                        "路径中间对象不是 Btrfs 目录：%1")
                        .arg(canonicalPathOut);
                    return false;
                }
                BtrfsDirectoryChild child;
                if (!findDirectoryChild(
                        current.number,
                        component,
                        child,
                        errorText)
                    || !loadInode(child.inode, current, errorText))
                {
                    return false;
                }
                canonicalPathOut =
                    ks::misc::rawfs::childPath(
                        canonicalPathOut,
                        child.name);
            }
            inodeOut = current;
            return true;
        }

        bool listDirectory(
            const BtrfsInode& directory,
            const QString& canonicalPath,
            const std::uint32_t maximumEntries,
            ks::misc::RawDirectoryResult& result)
        {
            if ((directory.mode & 0xF000U) != 0x4000U)
            {
                result.errorText = QStringLiteral("目标对象不是 Btrfs 目录。");
                return false;
            }

            std::vector<BtrfsDirectoryChild> children;
            if (!enumerateDirectory(
                    directory.number,
                    maximumEntries,
                    children,
                    result.scannedRecords,
                    result.truncated,
                    result.errorText))
            {
                return false;
            }
            result.entries.reserve(children.size());
            for (const BtrfsDirectoryChild& child : children)
            {
                BtrfsInode inode;
                if (!loadInode(child.inode, inode, result.errorText))
                {
                    return false;
                }
                std::vector<BtrfsFileSegment> segments;
                if ((inode.mode & 0xF000U) != 0x4000U
                    && !loadFileSegments(
                        inode.number,
                        segments,
                        result.errorText))
                {
                    return false;
                }
                ks::misc::RawFileEntry entry;
                fillEntry(
                    inode,
                    directory.number,
                    child.name,
                    ks::misc::rawfs::childPath(
                        canonicalPath,
                        child.name),
                    segments,
                    entry);
                result.entries.push_back(std::move(entry));
            }
            return true;
        }

        bool readFile(
            const BtrfsInode& inode,
            const std::uint64_t offset,
            const std::uint32_t length,
            ks::misc::RawFileReadResult& result)
        {
            if ((inode.mode & 0xF000U) == 0x4000U)
            {
                result.errorText = QStringLiteral(
                    "目标对象是目录，不能按文件读取。");
                return false;
            }
            if (offset >= inode.size)
            {
                result.endOfFile = true;
                return true;
            }

            std::vector<BtrfsFileSegment> segments;
            if (!loadFileSegments(
                    inode.number,
                    segments,
                    result.errorText))
            {
                return false;
            }
            result.extents = describeSegments(inode.size, segments);
            result.extentsTruncated =
                segments.size() > ks::misc::rawfs::kMaximumExtentCount;

            const std::uint32_t kBounded =
                static_cast<std::uint32_t>(
                    std::min<std::uint64_t>(
                        length,
                        inode.size - offset));
            result.bytes = QByteArray(
                static_cast<qsizetype>(kBounded),
                '\0');
            const std::uint64_t kRequestEnd = offset + kBounded;
            for (const BtrfsFileSegment& segment : segments)
            {
                const std::uint64_t kSegmentEnd =
                    segment.logicalOffset + segment.logicalLength;
                const std::uint64_t kOverlapStart =
                    std::max(offset, segment.logicalOffset);
                const std::uint64_t kOverlapEnd =
                    std::min(kRequestEnd, kSegmentEnd);
                if (kOverlapStart >= kOverlapEnd
                    || segment.sparse
                    || segment.preallocated)
                {
                    continue;
                }
                if (segment.compression != 0U
                    || segment.encryption != 0U
                    || segment.otherEncoding != 0U)
                {
                    result.bytes.clear();
                    result.errorText = QStringLiteral(
                        "文件包含压缩、加密或未知编码的 Btrfs extent，"
                        "原始读取已安全拒绝。");
                    return false;
                }

                const std::uint64_t kWithin =
                    kOverlapStart - segment.logicalOffset;
                const std::uint32_t kCopyLength =
                    static_cast<std::uint32_t>(
                        kOverlapEnd - kOverlapStart);
                const qsizetype kDestination =
                    static_cast<qsizetype>(kOverlapStart - offset);
                if (!segment.inlineBytes.isEmpty())
                {
                    if (kWithin + kCopyLength
                        > static_cast<std::uint64_t>(
                            segment.inlineBytes.size()))
                    {
                        result.bytes.clear();
                        result.errorText = QStringLiteral(
                            "Btrfs 内联 extent 数据被截断。");
                        return false;
                    }
                    std::copy_n(
                        segment.inlineBytes.cbegin()
                            + static_cast<qsizetype>(kWithin),
                        kCopyLength,
                        result.bytes.begin() + kDestination);
                    continue;
                }

                if (!readLogicalData(
                        segment.diskLogical + kWithin,
                        kCopyLength,
                        result.bytes,
                        kDestination,
                        result.errorText))
                {
                    result.bytes.clear();
                    return false;
                }
            }
            result.endOfFile = kRequestEnd >= inode.size;
            return true;
        }

    private:
        bool parseSystemChunkArray(
            const unsigned char* array,
            const std::uint32_t length,
            QString& errorText)
        {
            std::uint32_t cursor = 0;
            while (cursor < length)
            {
                if (length - cursor < 17U + kChunkHeaderSize)
                {
                    errorText = QStringLiteral(
                        "Btrfs system chunk array 被截断。");
                    return false;
                }
                const BtrfsKey kKey = parseKey(array + cursor);
                if (kKey.type != kChunkItemKey)
                {
                    errorText = QStringLiteral(
                        "Btrfs system chunk array 包含非块组键。");
                    return false;
                }
                const unsigned char* const kChunkData =
                    array + cursor + 17U;
                const std::uint16_t kStripeCount =
                    le16(kChunkData + 44U);
                const std::uint64_t kRecordLength =
                    17U + kChunkHeaderSize
                    + static_cast<std::uint64_t>(kStripeCount)
                        * kChunkStripeSize;
                if (kRecordLength > length - cursor)
                {
                    errorText = QStringLiteral(
                        "Btrfs system chunk 条带数组越界。");
                    return false;
                }
                if (!parseChunk(
                        kKey.offset,
                        kChunkData,
                        static_cast<std::uint32_t>(
                            kRecordLength - 17U),
                        errorText))
                {
                    return false;
                }
                cursor += static_cast<std::uint32_t>(kRecordLength);
            }
            normalizeChunkMap();
            return true;
        }

        bool parseChunk(
            const std::uint64_t logical,
            const unsigned char* data,
            const std::uint32_t size,
            QString& errorText)
        {
            if (size < kChunkHeaderSize)
            {
                errorText = QStringLiteral("Btrfs chunk item 被截断。");
                return false;
            }
            const std::uint64_t kLength = le64(data);
            const std::uint64_t kType = le64(data + 24U);
            const std::uint16_t kStripeCount = le16(data + 44U);
            const std::uint64_t kRequired =
                kChunkHeaderSize
                + static_cast<std::uint64_t>(kStripeCount)
                    * kChunkStripeSize;
            if (kLength == 0U || kStripeCount == 0U || kRequired > size)
            {
                errorText = QStringLiteral("Btrfs chunk item 几何参数无效。");
                return false;
            }
            if ((kType & (kBlockGroupRaid0
                    | kBlockGroupRaid10
                    | kBlockGroupRaid5
                    | kBlockGroupRaid6)) != 0U)
            {
                return true;
            }

            const unsigned char* selectedStripe = nullptr;
            for (std::uint16_t index = 0; index < kStripeCount; ++index)
            {
                const unsigned char* const kStripe =
                    data + kChunkHeaderSize
                    + static_cast<std::uint32_t>(index)
                        * kChunkStripeSize;
                const std::uint64_t kDeviceId = le64(kStripe);
                if (kDeviceId == currentDeviceId_
                    || (deviceCount_ == 1U && index == 0U))
                {
                    selectedStripe = kStripe;
                    break;
                }
            }
            if (selectedStripe == nullptr)
            {
                return true;
            }

            const std::uint64_t kPhysical = le64(selectedStripe + 8U);
            if (kPhysical > reader_.partitionLength()
                || kLength > reader_.partitionLength() - kPhysical)
            {
                errorText = QStringLiteral(
                    "Btrfs chunk item 的物理范围越过所选分区。");
                return false;
            }
            chunks_.push_back(
                BtrfsChunk{
                    logical,
                    kLength,
                    kPhysical,
                    kType,
                    le64(selectedStripe)});
            return true;
        }

        void normalizeChunkMap()
        {
            std::sort(
                chunks_.begin(),
                chunks_.end(),
                [](const BtrfsChunk& left, const BtrfsChunk& right)
                {
                    if (left.logical != right.logical)
                    {
                        return left.logical < right.logical;
                    }
                    return left.length > right.length;
                });
            chunks_.erase(
                std::unique(
                    chunks_.begin(),
                    chunks_.end(),
                    [](const BtrfsChunk& left, const BtrfsChunk& right)
                    {
                        return left.logical == right.logical
                            && left.length == right.length
                            && left.physical == right.physical;
                    }),
                chunks_.end());
        }

        bool logicalToPhysical(
            const std::uint64_t logical,
            std::uint64_t& physicalOut,
            std::uint64_t& contiguousOut,
            QString& errorText) const
        {
            for (auto iterator = chunks_.crbegin();
                 iterator != chunks_.crend();
                 ++iterator)
            {
                const BtrfsChunk& chunk = *iterator;
                if (logical < chunk.logical
                    || logical - chunk.logical >= chunk.length)
                {
                    continue;
                }
                if ((chunk.type & (kBlockGroupRaid0
                        | kBlockGroupRaid10
                        | kBlockGroupRaid5
                        | kBlockGroupRaid6)) != 0U)
                {
                    errorText = QStringLiteral(
                        "当前 Btrfs 逻辑地址位于不支持的条带或奇偶校验块组。");
                    return false;
                }
                const std::uint64_t kWithin = logical - chunk.logical;
                if (!checkedAdd(chunk.physical, kWithin, physicalOut))
                {
                    errorText = QStringLiteral("Btrfs 物理地址发生溢出。");
                    return false;
                }
                contiguousOut = chunk.length - kWithin;
                return true;
            }
            errorText = QStringLiteral("Btrfs 逻辑地址缺少块组映射。");
            return false;
        }

        bool readLogical(
            const std::uint64_t logical,
            const std::uint32_t length,
            QByteArray& bytesOut,
            QString& errorText) const
        {
            bytesOut.resize(static_cast<qsizetype>(length));
            std::uint64_t completed = 0;
            while (completed < length)
            {
                std::uint64_t physical = 0;
                std::uint64_t contiguous = 0;
                if (!logicalToPhysical(
                        logical + completed,
                        physical,
                        contiguous,
                        errorText))
                {
                    bytesOut.clear();
                    return false;
                }
                const std::uint32_t kChunkLength =
                    static_cast<std::uint32_t>(
                        std::min<std::uint64_t>(
                            length - completed,
                            contiguous));
                QByteArray chunk;
                if (!reader_.read(
                        physical,
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

        bool readLogicalData(
            const std::uint64_t logical,
            const std::uint32_t length,
            QByteArray& destination,
            const qsizetype destinationOffset,
            QString& errorText) const
        {
            QByteArray bytes;
            if (!readLogical(logical, length, bytes, errorText))
            {
                return false;
            }
            std::copy(
                bytes.cbegin(),
                bytes.cend(),
                destination.begin() + destinationOffset);
            return true;
        }

        bool readTreeBlock(
            const std::uint64_t logical,
            QByteArray& blockOut,
            std::uint64_t& physicalOut,
            QString& errorText) const
        {
            std::uint64_t contiguous = 0;
            if (!logicalToPhysical(
                    logical,
                    physicalOut,
                    contiguous,
                    errorText)
                || contiguous < nodeSize_
                || !readLogical(
                    logical,
                    nodeSize_,
                    blockOut,
                    errorText))
            {
                return false;
            }
            const unsigned char* const kBytes = dataPointer(blockOut);
            if (le64(kBytes + 0x30U) != logical
                || kBytes[0x64U] > ks::misc::rawfs::kMaximumTreeDepth)
            {
                errorText = QStringLiteral("Btrfs tree block 头部无效。");
                return false;
            }
            const std::uint32_t kItemCount = le32(kBytes + 0x60U);
            const std::uint64_t kTableBytes =
                static_cast<std::uint64_t>(kItemCount)
                * (kBytes[0x64U] == 0U
                    ? kLeafItemSize
                    : kNodePointerSize);
            if (kTableBytes > nodeSize_ - kTreeHeaderSize)
            {
                errorText = QStringLiteral("Btrfs tree block 项目表越界。");
                return false;
            }
            return true;
        }

        template<typename Callback>
        bool walkTreeRange(
            const std::uint64_t logical,
            const BtrfsKey& minimum,
            const BtrfsKey& maximum,
            Callback&& callback,
            std::vector<std::uint64_t>& visited,
            QString& errorText)
        {
            if (walkStopRequested_)
            {
                return true;
            }
            if (visited.size() >= kMaximumVisitedTreeBlocks
                || std::find(
                    visited.cbegin(),
                    visited.cend(),
                    logical) != visited.cend())
            {
                errorText = QStringLiteral(
                    "Btrfs tree 包含循环或节点数超过安全上限。");
                return false;
            }
            visited.push_back(logical);

            QByteArray block;
            std::uint64_t physical = 0;
            if (!readTreeBlock(
                    logical,
                    block,
                    physical,
                    errorText))
            {
                return false;
            }
            const unsigned char* const kBytes = dataPointer(block);
            const std::uint32_t kCount = le32(kBytes + 0x60U);
            const std::uint8_t kLevel = kBytes[0x64U];
            if (kLevel == 0U)
            {
                for (std::uint32_t index = 0; index < kCount; ++index)
                {
                    const unsigned char* const kItem =
                        kBytes + kTreeHeaderSize
                        + index * kLeafItemSize;
                    const BtrfsKey kKey = parseKey(kItem);
                    if (compareKey(kKey, minimum) < 0
                        || compareKey(kKey, maximum) > 0)
                    {
                        continue;
                    }
                    const std::uint32_t kDataOffset =
                        kTreeHeaderSize + le32(kItem + 17U);
                    const std::uint32_t kDataSize = le32(kItem + 21U);
                    if (kDataOffset > nodeSize_
                        || kDataSize > nodeSize_ - kDataOffset)
                    {
                        errorText = QStringLiteral(
                            "Btrfs leaf item 数据范围越界。");
                        return false;
                    }
                    if (!callback(
                            BtrfsLeafItem{
                                kKey,
                                kBytes + kDataOffset,
                                kDataSize,
                                reader_.partitionOffset()
                                    + physical + kDataOffset}))
                    {
                        walkStopRequested_ = true;
                        return true;
                    }
                }
                return true;
            }

            for (std::uint32_t index = 0; index < kCount; ++index)
            {
                const unsigned char* const kPointer =
                    kBytes + kTreeHeaderSize
                    + index * kNodePointerSize;
                const BtrfsKey kLower = parseKey(kPointer);
                if (compareKey(kLower, maximum) > 0)
                {
                    break;
                }
                if (index + 1U < kCount)
                {
                    const BtrfsKey kNext = parseKey(
                        kPointer + kNodePointerSize);
                    if (compareKey(kNext, minimum) <= 0)
                    {
                        continue;
                    }
                }
                const std::uint64_t kChildLogical =
                    le64(kPointer + 17U);
                if (!walkTreeRange(
                        kChildLogical,
                        minimum,
                        maximum,
                        callback,
                        visited,
                        errorText))
                {
                    return false;
                }
                if (walkStopRequested_)
                {
                    return true;
                }
            }
            return true;
        }

        bool loadInode(
            const std::uint64_t inodeNumber,
            BtrfsInode& inodeOut,
            QString& errorText)
        {
            bool found = false;
            std::vector<std::uint64_t> visited;
            walkStopRequested_ = false;
            if (!walkTreeRange(
                    fsTreeLogical_,
                    BtrfsKey{inodeNumber, kInodeItemKey, 0U},
                    BtrfsKey{inodeNumber, kInodeItemKey, 0U},
                    [&](const BtrfsLeafItem& item)
                    {
                        if (item.size < 160U)
                        {
                            return true;
                        }
                        BtrfsInode inode;
                        inode.number = inodeNumber;
                        inode.size = le64(item.data + 16U);
                        inode.allocated = le64(item.data + 24U);
                        inode.mode = le32(item.data + 52U);
                        inode.flags = le64(item.data + 64U);
                        inode.metadataOffset = item.absoluteOffset;
                        inodeOut = inode;
                        found = true;
                        return false;
                    },
                    visited,
                    errorText))
            {
                return false;
            }
            if (!found)
            {
                errorText = QStringLiteral(
                    "Btrfs inode 不存在：%1").arg(inodeNumber);
                return false;
            }
            return true;
        }

        bool enumerateDirectory(
            const std::uint64_t inodeNumber,
            const std::uint32_t maximumEntries,
            std::vector<BtrfsDirectoryChild>& childrenOut,
            std::uint64_t& scannedRecordsOut,
            bool& truncatedOut,
            QString& errorText)
        {
            childrenOut.clear();
            scannedRecordsOut = 0;
            truncatedOut = false;
            std::vector<std::uint64_t> visited;
            walkStopRequested_ = false;
            const bool kWalked = walkTreeRange(
                fsTreeLogical_,
                BtrfsKey{inodeNumber, kDirectoryIndexKey, 0U},
                BtrfsKey{
                    inodeNumber,
                    kDirectoryIndexKey,
                    std::numeric_limits<std::uint64_t>::max()},
                [&](const BtrfsLeafItem& item)
                {
                    std::uint32_t cursor = 0;
                    while (cursor < item.size)
                    {
                        if (item.size - cursor < kDirItemHeaderSize)
                        {
                            errorText = QStringLiteral(
                                "Btrfs 目录项记录被截断。");
                            return false;
                        }
                        const unsigned char* const kEntry =
                            item.data + cursor;
                        const std::uint16_t kDataLength =
                            le16(kEntry + 25U);
                        const std::uint16_t kNameLength =
                            le16(kEntry + 27U);
                        const std::uint64_t kRecordLength =
                            kDirItemHeaderSize
                            + static_cast<std::uint64_t>(kNameLength)
                            + kDataLength;
                        if (kRecordLength > item.size - cursor)
                        {
                            errorText = QStringLiteral(
                                "Btrfs 目录项名称范围越界。");
                            return false;
                        }
                        if (++scannedRecordsOut
                            > kMaximumDirectoryRecords)
                        {
                            errorText = QStringLiteral(
                                "Btrfs 目录记录数超过安全上限。");
                            return false;
                        }
                        if (childrenOut.size() >= maximumEntries)
                        {
                            truncatedOut = true;
                            return false;
                        }
                        BtrfsDirectoryChild child;
                        child.inode = le64(kEntry);
                        child.type = kEntry[29U];
                        child.name = QString::fromUtf8(
                            reinterpret_cast<const char*>(
                                kEntry + kDirItemHeaderSize),
                            kNameLength);
                        childrenOut.push_back(std::move(child));
                        cursor += static_cast<std::uint32_t>(kRecordLength);
                    }
                    return true;
                },
                visited,
                errorText);
            return kWalked && errorText.isEmpty();
        }

        bool findDirectoryChild(
            const std::uint64_t parentInode,
            const QString& requestedName,
            BtrfsDirectoryChild& childOut,
            QString& errorText)
        {
            std::vector<BtrfsDirectoryChild> children;
            std::uint64_t scanned = 0;
            bool truncated = false;
            if (!enumerateDirectory(
                    parentInode,
                    kMaximumDirectoryRecords,
                    children,
                    scanned,
                    truncated,
                    errorText))
            {
                return false;
            }
            const auto kIterator = std::find_if(
                children.cbegin(),
                children.cend(),
                [&](const BtrfsDirectoryChild& child)
                {
                    return child.name == requestedName;
                });
            if (kIterator == children.cend())
            {
                errorText = QStringLiteral(
                    "Btrfs 目录中不存在对象：%1")
                    .arg(requestedName);
                return false;
            }
            childOut = *kIterator;
            return true;
        }

        bool loadFileSegments(
            const std::uint64_t inodeNumber,
            std::vector<BtrfsFileSegment>& segmentsOut,
            QString& errorText)
        {
            segmentsOut.clear();
            std::vector<std::uint64_t> visited;
            walkStopRequested_ = false;
            if (!walkTreeRange(
                    fsTreeLogical_,
                    BtrfsKey{inodeNumber, kFileExtentDataKey, 0U},
                    BtrfsKey{
                        inodeNumber,
                        kFileExtentDataKey,
                        std::numeric_limits<std::uint64_t>::max()},
                    [&](const BtrfsLeafItem& item)
                    {
                        if (item.size < kFileExtentHeaderSize)
                        {
                            errorText = QStringLiteral(
                                "Btrfs file extent item 被截断。");
                            return false;
                        }
                        BtrfsFileSegment segment;
                        segment.logicalOffset = item.key.offset;
                        segment.compression = item.data[16U];
                        segment.encryption = item.data[17U];
                        segment.otherEncoding = le16(item.data + 18U);
                        const std::uint8_t kExtentType = item.data[20U];
                        if (kExtentType == kExtentInline)
                        {
                            segment.inlineBytes = QByteArray(
                                reinterpret_cast<const char*>(
                                    item.data + kFileExtentHeaderSize),
                                static_cast<qsizetype>(
                                    item.size - kFileExtentHeaderSize));
                            const std::uint64_t kRamBytes =
                                le64(item.data + 8U);
                            segment.logicalLength =
                                segment.compression == 0U
                                    ? std::min<std::uint64_t>(
                                        kRamBytes,
                                        segment.inlineBytes.size())
                                    : kRamBytes;
                            segment.inlineAbsolute =
                                item.absoluteOffset
                                + kFileExtentHeaderSize;
                        }
                        else if (kExtentType == kExtentRegular
                            || kExtentType == kExtentPreallocated)
                        {
                            if (item.size < kFileExtentRegularSize)
                            {
                                errorText = QStringLiteral(
                                    "Btrfs regular extent item 被截断。");
                                return false;
                            }
                            const std::uint64_t kDiskBytenr =
                                le64(item.data + 21U);
                            segment.diskLength =
                                le64(item.data + 29U);
                            const std::uint64_t kExtentOffset =
                                le64(item.data + 37U);
                            segment.logicalLength =
                                le64(item.data + 45U);
                            segment.sparse = kDiskBytenr == 0U;
                            segment.preallocated =
                                kExtentType == kExtentPreallocated;
                            if (!segment.sparse
                                && !checkedAdd(
                                    kDiskBytenr,
                                    kExtentOffset,
                                    segment.diskLogical))
                            {
                                errorText = QStringLiteral(
                                    "Btrfs extent 逻辑地址发生溢出。");
                                return false;
                            }
                        }
                        else
                        {
                            errorText = QStringLiteral(
                                "Btrfs file extent 类型未知。");
                            return false;
                        }
                        if (segment.logicalLength != 0U)
                        {
                            segmentsOut.push_back(std::move(segment));
                        }
                        if (segmentsOut.size()
                            > ks::misc::rawfs::kMaximumExtentCount * 16U)
                        {
                            errorText = QStringLiteral(
                                "Btrfs 文件 extent 数量超过安全上限。");
                            return false;
                        }
                        return true;
                    },
                    visited,
                    errorText))
            {
                return false;
            }
            if (!errorText.isEmpty())
            {
                return false;
            }
            std::sort(
                segmentsOut.begin(),
                segmentsOut.end(),
                [](const BtrfsFileSegment& left,
                   const BtrfsFileSegment& right)
                {
                    return left.logicalOffset < right.logicalOffset;
                });
            return true;
        }

        std::vector<ks::misc::RawFileExtent> describeSegments(
            const std::uint64_t fileSize,
            const std::vector<BtrfsFileSegment>& segments) const
        {
            std::vector<ks::misc::RawFileExtent> extents;
            for (const BtrfsFileSegment& segment : segments)
            {
                if (extents.size()
                        >= ks::misc::rawfs::kMaximumExtentCount
                    || segment.logicalOffset >= fileSize)
                {
                    break;
                }
                ks::misc::RawFileExtent extent;
                extent.logicalOffset = segment.logicalOffset;
                extent.lengthBytes = std::min<std::uint64_t>(
                    segment.logicalLength,
                    fileSize - segment.logicalOffset);
                extent.sparse = segment.sparse;
                extent.unwritten = segment.preallocated;
                extent.compressed = segment.compression != 0U;
                if (!segment.inlineBytes.isEmpty())
                {
                    extent.absoluteOffset = segment.inlineAbsolute;
                    extent.physicalMappingExact = true;
                }
                else if (!segment.sparse)
                {
                    std::uint64_t physical = 0;
                    std::uint64_t contiguous = 0;
                    QString ignored;
                    if (logicalToPhysical(
                            segment.diskLogical,
                            physical,
                            contiguous,
                            ignored))
                    {
                        extent.absoluteOffset =
                            reader_.partitionOffset() + physical;
                        extent.physicalMappingExact =
                            contiguous >= extent.lengthBytes;
                    }
                }
                extents.push_back(extent);
            }
            return extents;
        }

        static ks::misc::RawFileObjectType objectType(
            const std::uint32_t mode)
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

        void fillEntry(
            const BtrfsInode& inode,
            const std::uint64_t parentInode,
            const QString& name,
            const QString& fullPath,
            const std::vector<BtrfsFileSegment>& segments,
            ks::misc::RawFileEntry& entry) const
        {
            entry.name = name;
            entry.fullPath = fullPath;
            entry.type = objectType(inode.mode);
            entry.objectId = inode.number;
            entry.parentObjectId = parentInode;
            entry.fileSizeBytes = inode.size;
            entry.allocatedSizeBytes = inode.allocated;
            entry.metadataOffset = inode.metadataOffset;
            entry.modeOrFlags =
                static_cast<std::uint32_t>(inode.flags)
                | inode.mode;
            entry.extents = describeSegments(inode.size, segments);
            entry.extentsTruncated =
                segments.size() > ks::misc::rawfs::kMaximumExtentCount;
        }

        const ks::misc::rawfs::VolumeReader& reader_;
        std::uint32_t sectorSize_ = 0;
        std::uint32_t nodeSize_ = 0;
        std::uint64_t totalBytes_ = 0;
        std::uint64_t deviceCount_ = 0;
        std::uint64_t currentDeviceId_ = 0;
        std::uint64_t rootTreeLogical_ = 0;
        std::uint64_t chunkTreeLogical_ = 0;
        std::uint64_t fsTreeLogical_ = 0;
        std::vector<BtrfsChunk> chunks_;
        bool walkStopRequested_ = false;
    };

    ks::misc::RawDirectoryResult makeDirectoryResult(
        const QString& path)
    {
        ks::misc::RawDirectoryResult result;
        result.fileSystem =
            ks::misc::ForensicFileSystemKind::kBtrfs;
        result.fileSystemName =
            ks::misc::DiskFileSystemForensics::fileSystemName(
                result.fileSystem);
        result.requestedPath = path;
        return result;
    }

    ks::misc::RawFileReadResult makeFileResult(
        const QString& path,
        const std::uint64_t offset)
    {
        ks::misc::RawFileReadResult result;
        result.fileSystem =
            ks::misc::ForensicFileSystemKind::kBtrfs;
        result.fileSystemName =
            ks::misc::DiskFileSystemForensics::fileSystemName(
                result.fileSystem);
        result.filePath = path;
        result.requestedOffset = offset;
        return result;
    }
}

namespace ks::misc::rawfs
{
    RawDirectoryResult listBtrfs(
        const VolumeReader& reader,
        const QString& path,
        const std::uint32_t maximumEntries)
    {
        RawDirectoryResult result = makeDirectoryResult(path);
        BtrfsVolume volume(reader);
        if (!volume.mount(result.errorText))
        {
            return result;
        }
        BtrfsInode directory;
        if (!volume.resolvePath(
                path,
                directory,
                result.canonicalPath,
                result.errorText))
        {
            return result;
        }
        result.directoryObjectId = directory.number;
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

    RawFileReadResult readBtrfs(
        const VolumeReader& reader,
        const QString& path,
        const std::uint64_t offset,
        const std::uint32_t length)
    {
        RawFileReadResult result = makeFileResult(path, offset);
        BtrfsVolume volume(reader);
        if (!volume.mount(result.errorText))
        {
            return result;
        }
        BtrfsInode inode;
        QString canonicalPath;
        if (!volume.resolvePath(
                path,
                inode,
                canonicalPath,
                result.errorText))
        {
            return result;
        }
        result.filePath = canonicalPath;
        result.fileSizeBytes = inode.size;
        if (!volume.readFile(inode, offset, length, result))
        {
            return result;
        }
        result.success = true;
        return result;
    }
}
