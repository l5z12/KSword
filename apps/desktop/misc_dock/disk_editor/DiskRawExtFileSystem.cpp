#include "DiskRawFileSystemInternal.h"

#include <QByteArray>
#include <QStringList>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <vector>

namespace
{
    constexpr std::uint16_t kExtMagic = 0xEF53U;
    constexpr std::uint16_t kExtentMagic = 0xF30AU;
    constexpr std::uint32_t kExtentsFlag = 0x00080000U;
    constexpr std::uint32_t kFileTypeMask = 0xF000U;
    constexpr std::uint32_t kRegularFileMode = 0x8000U;
    constexpr std::uint32_t kDirectoryMode = 0x4000U;
    constexpr std::uint32_t kSymbolicLinkMode = 0xA000U;
    constexpr std::uint32_t kMaximumLogicalBlocks = 2U * 1024U * 1024U;

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

    std::uint64_t combine32(
        const std::uint32_t low,
        const std::uint32_t high)
    {
        return static_cast<std::uint64_t>(low)
            | (static_cast<std::uint64_t>(high) << 32U);
    }

    const unsigned char* dataPointer(const QByteArray& bytes)
    {
        return reinterpret_cast<const unsigned char*>(bytes.constData());
    }

    struct ExtInode
    {
        std::uint64_t number = 0;
        std::uint64_t metadataOffset = 0;
        std::uint64_t sizeBytes = 0;
        std::uint64_t allocatedBytes = 0;
        std::uint32_t flags = 0;
        std::uint16_t mode = 0;
        std::array<unsigned char, 60U> blockData{};
    };

    struct ExtBlockMapping
    {
        bool mapped = false;
        bool unwritten = false;
        std::uint64_t physicalBlock = 0;
    };

    struct ExtLogicalRun
    {
        std::uint64_t logicalBlock = 0;
        std::uint64_t physicalBlock = 0;
        std::uint64_t blockCount = 0;
        bool sparse = false;
        bool unwritten = false;
    };

    class ExtVolume final
    {
    public:
        explicit ExtVolume(const ks::misc::rawfs::VolumeReader& reader)
            : reader_(reader)
        {
        }

        bool mount(QString& errorText)
        {
            QByteArray superblock;
            if (!reader_.read(1024U, 1024U, superblock, errorText))
            {
                return false;
            }
            const unsigned char* const kBytes = dataPointer(superblock);
            if (le16(kBytes + 0x38U) != kExtMagic)
            {
                errorText = QStringLiteral("Ext 超级块魔数不匹配。");
                return false;
            }

            const std::uint32_t kLogarithm = le32(kBytes + 0x18U);
            if (kLogarithm > 6U)
            {
                errorText = QStringLiteral("Ext 块大小指数无效。");
                return false;
            }
            blockSize_ = 1024U << kLogarithm;
            firstDataBlock_ = le32(kBytes + 0x14U);
            blocksPerGroup_ = le32(kBytes + 0x20U);
            inodesPerGroup_ = le32(kBytes + 0x28U);
            inodeCount_ = le32(kBytes + 0x00U);
            incompatFeatures_ = le32(kBytes + 0x60U);
            inodeSize_ = le16(kBytes + 0x58U);
            if (inodeSize_ == 0U)
            {
                inodeSize_ = 128U;
            }
            descriptorSize_ = le16(kBytes + 0xFEU);
            if (descriptorSize_ < 32U)
            {
                descriptorSize_ = 32U;
            }
            if (descriptorSize_ > blockSize_ || inodeSize_ > blockSize_
                || inodeSize_ < 128U || blocksPerGroup_ == 0U
                || inodesPerGroup_ == 0U)
            {
                errorText = QStringLiteral("Ext 几何参数超出安全边界。");
                return false;
            }

            const std::uint32_t kBlocksHigh =
                (incompatFeatures_ & 0x80U) != 0U
                ? le32(kBytes + 0x150U)
                : 0U;
            blockCount_ = combine32(le32(kBytes + 0x04U), kBlocksHigh);
            if (blockCount_ <= firstDataBlock_
                || blockCount_
                    > reader_.partitionLength()
                        / static_cast<std::uint64_t>(blockSize_))
            {
                errorText = QStringLiteral("Ext 块总数越过所选分区。");
                return false;
            }

            const std::uint64_t kDataBlocks =
                blockCount_ - firstDataBlock_;
            groupCount_ =
                (kDataBlocks + blocksPerGroup_ - 1U) / blocksPerGroup_;
            if (groupCount_ == 0U || groupCount_ > 0x1000000ULL)
            {
                errorText = QStringLiteral("Ext 块组数量无效。");
                return false;
            }
            return true;
        }

        bool resolvePath(
            const QString& path,
            ExtInode& inodeOut,
            QString& canonicalPathOut,
            QString& errorText)
        {
            ExtInode current;
            if (!loadInode(2U, current, errorText))
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
                if ((current.mode & kFileTypeMask) != kDirectoryMode)
                {
                    errorText = QStringLiteral(
                        "路径中间对象不是目录：%1").arg(canonicalPathOut);
                    return false;
                }
                std::uint64_t childInode = 0;
                if (!findDirectoryChild(
                        current,
                        component,
                        childInode,
                        errorText))
                {
                    return false;
                }
                if (!loadInode(childInode, current, errorText))
                {
                    return false;
                }
                canonicalPathOut =
                    ks::misc::rawfs::childPath(
                        canonicalPathOut,
                        component);
            }
            inodeOut = current;
            return true;
        }

        bool listDirectory(
            const ExtInode& directory,
            const QString& canonicalPath,
            const std::uint32_t maximumEntries,
            ks::misc::RawDirectoryResult& result)
        {
            if ((directory.mode & kFileTypeMask) != kDirectoryMode)
            {
                result.errorText = QStringLiteral("目标对象不是 Ext 目录。");
                return false;
            }

            const std::uint64_t kLogicalBlocks =
                (directory.sizeBytes + blockSize_ - 1U) / blockSize_;
            const std::uint64_t kBoundedBlocks =
                std::min<std::uint64_t>(
                    kLogicalBlocks,
                    kMaximumLogicalBlocks);
            QString errorText;
            for (std::uint64_t blockIndex = 0;
                 blockIndex < kBoundedBlocks;
                 ++blockIndex)
            {
                ExtBlockMapping mapping;
                if (!mapBlock(directory, blockIndex, mapping, errorText))
                {
                    result.errorText = errorText;
                    return false;
                }
                if (!mapping.mapped || mapping.unwritten)
                {
                    continue;
                }

                QByteArray block;
                if (!readBlock(mapping.physicalBlock, block, errorText))
                {
                    result.errorText = errorText;
                    return false;
                }
                const unsigned char* const kBytes = dataPointer(block);
                std::uint32_t offset = 0;
                while (offset + 8U <= blockSize_)
                {
                    const std::uint32_t kInodeNumber =
                        le32(kBytes + offset);
                    const std::uint16_t kRecordLength =
                        le16(kBytes + offset + 4U);
                    const std::uint8_t kNameLength =
                        kBytes[offset + 6U];
                    if (kRecordLength < 8U
                        || (kRecordLength & 3U) != 0U
                        || offset + kRecordLength > blockSize_)
                    {
                        break;
                    }
                    ++result.scannedRecords;
                    if (kInodeNumber != 0U
                        && kNameLength != 0U
                        && kNameLength <= kRecordLength - 8U)
                    {
                        const QString kName = QString::fromUtf8(
                            reinterpret_cast<const char*>(
                                kBytes + offset + 8U),
                            kNameLength);
                        if (kName != QStringLiteral(".")
                            && kName != QStringLiteral(".."))
                        {
                            if (result.entries.size() >= maximumEntries)
                            {
                                result.truncated = true;
                                return true;
                            }
                            ExtInode child;
                            if (!loadInode(
                                    kInodeNumber,
                                    child,
                                    errorText))
                            {
                                result.errorText = errorText;
                                return false;
                            }
                            ks::misc::RawFileEntry entry;
                            fillEntry(
                                child,
                                directory.number,
                                kName,
                                ks::misc::rawfs::childPath(
                                    canonicalPath,
                                    kName),
                                entry);
                            if (!collectExtents(
                                    child,
                                    entry.extents,
                                    entry.extentsTruncated,
                                    errorText))
                            {
                                result.errorText = errorText;
                                return false;
                            }
                            for (const auto& extent : entry.extents)
                            {
                                if (!extent.sparse)
                                {
                                    entry.allocatedSizeBytes +=
                                        extent.lengthBytes;
                                }
                            }
                            result.entries.push_back(std::move(entry));
                        }
                    }
                    offset += kRecordLength;
                }
            }
            result.truncated = kLogicalBlocks > kBoundedBlocks;
            return true;
        }

        bool readFile(
            const ExtInode& inode,
            const std::uint64_t offset,
            const std::uint32_t requestedLength,
            ks::misc::RawFileReadResult& result)
        {
            const std::uint32_t kType = inode.mode & kFileTypeMask;
            if (kType != kRegularFileMode && kType != kSymbolicLinkMode)
            {
                result.errorText = QStringLiteral(
                    "目标 Ext 对象不是可读取的文件或符号链接。");
                return false;
            }
            result.fileSizeBytes = inode.sizeBytes;
            result.requestedOffset = offset;
            if (offset >= inode.sizeBytes)
            {
                result.success = true;
                result.endOfFile = true;
                return collectExtents(
                    inode,
                    result.extents,
                    result.extentsTruncated,
                    result.errorText);
            }

            const std::uint64_t kAvailable = inode.sizeBytes - offset;
            const std::uint32_t kLength = static_cast<std::uint32_t>(
                std::min<std::uint64_t>(
                    kAvailable,
                    requestedLength));
            result.bytes = QByteArray(
                static_cast<qsizetype>(kLength),
                '\0');

            if (kType == kSymbolicLinkMode
                && inode.sizeBytes <= inode.blockData.size()
                && (inode.flags & kExtentsFlag) == 0U)
            {
                std::memcpy(
                    result.bytes.data(),
                    inode.blockData.data()
                        + static_cast<std::size_t>(offset),
                    kLength);
            }
            else
            {
                std::uint64_t completed = 0;
                QString errorText;
                while (completed < kLength)
                {
                    const std::uint64_t kFileOffset = offset + completed;
                    const std::uint64_t kLogicalBlock =
                        kFileOffset / blockSize_;
                    const std::uint32_t kOffsetInBlock =
                        static_cast<std::uint32_t>(
                            kFileOffset % blockSize_);
                    const std::uint32_t kTake =
                        static_cast<std::uint32_t>(
                            std::min<std::uint64_t>(
                                kLength - completed,
                                blockSize_ - kOffsetInBlock));
                    ExtBlockMapping mapping;
                    if (!mapBlock(
                            inode,
                            kLogicalBlock,
                            mapping,
                            errorText))
                    {
                        result.errorText = errorText;
                        return false;
                    }
                    if (mapping.mapped && !mapping.unwritten)
                    {
                        QByteArray bytes;
                        if (!reader_.read(
                                mapping.physicalBlock * blockSize_
                                    + kOffsetInBlock,
                                kTake,
                                bytes,
                                errorText))
                        {
                            result.errorText = errorText;
                            return false;
                        }
                        std::copy(
                            bytes.cbegin(),
                            bytes.cend(),
                            result.bytes.begin()
                                + static_cast<qsizetype>(completed));
                    }
                    completed += kTake;
                }
            }

            if (!collectExtents(
                    inode,
                    result.extents,
                    result.extentsTruncated,
                    result.errorText))
            {
                return false;
            }
            result.endOfFile =
                offset + static_cast<std::uint64_t>(kLength)
                >= inode.sizeBytes;
            result.success = true;
            return true;
        }

    private:
        bool readBlock(
            const std::uint64_t block,
            QByteArray& bytes,
            QString& errorText) const
        {
            if (block >= blockCount_)
            {
                errorText = QStringLiteral("Ext 块号越过文件系统边界。");
                return false;
            }
            return reader_.read(
                block * blockSize_,
                blockSize_,
                bytes,
                errorText);
        }

        bool loadInode(
            const std::uint64_t inodeNumber,
            ExtInode& inodeOut,
            QString& errorText)
        {
            if (inodeNumber == 0U || inodeNumber > inodeCount_)
            {
                errorText = QStringLiteral("Ext inode 编号越界。");
                return false;
            }
            const std::uint64_t kZeroBased = inodeNumber - 1U;
            const std::uint64_t kGroup = kZeroBased / inodesPerGroup_;
            const std::uint64_t kIndex = kZeroBased % inodesPerGroup_;
            if (kGroup >= groupCount_)
            {
                errorText = QStringLiteral("Ext inode 块组越界。");
                return false;
            }

            const std::uint64_t kDescriptorTableBlock =
                static_cast<std::uint64_t>(firstDataBlock_) + 1U;
            const std::uint64_t kDescriptorOffset =
                kDescriptorTableBlock * blockSize_
                + kGroup * descriptorSize_;
            QByteArray descriptor;
            if (!reader_.read(
                    kDescriptorOffset,
                    descriptorSize_,
                    descriptor,
                    errorText))
            {
                return false;
            }
            const unsigned char* const kDescriptorBytes =
                dataPointer(descriptor);
            const std::uint32_t kInodeTableLow =
                le32(kDescriptorBytes + 8U);
            const std::uint32_t kInodeTableHigh =
                descriptorSize_ >= 64U
                ? le32(kDescriptorBytes + 40U)
                : 0U;
            const std::uint64_t kInodeTable =
                combine32(kInodeTableLow, kInodeTableHigh);
            if (kInodeTable == 0U || kInodeTable >= blockCount_)
            {
                errorText = QStringLiteral("Ext inode 表块号无效。");
                return false;
            }

            const std::uint64_t kInodeOffset =
                kInodeTable * blockSize_ + kIndex * inodeSize_;
            QByteArray inodeBytes;
            if (!reader_.read(
                    kInodeOffset,
                    inodeSize_,
                    inodeBytes,
                    errorText))
            {
                return false;
            }
            const unsigned char* const kBytes = dataPointer(inodeBytes);
            ExtInode inode;
            inode.number = inodeNumber;
            inode.metadataOffset =
                reader_.partitionOffset() + kInodeOffset;
            inode.mode = le16(kBytes + 0U);
            inode.flags = le32(kBytes + 32U);
            const std::uint32_t kSizeHigh =
                (inode.mode & kFileTypeMask) == kRegularFileMode
                || (inode.mode & kFileTypeMask) == kSymbolicLinkMode
                ? le32(kBytes + 108U)
                : 0U;
            inode.sizeBytes = combine32(le32(kBytes + 4U), kSizeHigh);
            inode.allocatedBytes =
                static_cast<std::uint64_t>(le32(kBytes + 28U)) * 512U;
            std::copy_n(
                kBytes + 40U,
                inode.blockData.size(),
                inode.blockData.begin());
            inodeOut = inode;
            return true;
        }

        bool findDirectoryChild(
            const ExtInode& directory,
            const QString& wantedName,
            std::uint64_t& inodeOut,
            QString& errorText)
        {
            const std::uint64_t kLogicalBlocks =
                (directory.sizeBytes + blockSize_ - 1U) / blockSize_;
            if (kLogicalBlocks > kMaximumLogicalBlocks)
            {
                errorText = QStringLiteral(
                    "Ext 目录数据超过安全扫描上限。");
                return false;
            }
            for (std::uint64_t blockIndex = 0;
                 blockIndex < kLogicalBlocks;
                 ++blockIndex)
            {
                ExtBlockMapping mapping;
                if (!mapBlock(directory, blockIndex, mapping, errorText))
                {
                    return false;
                }
                if (!mapping.mapped || mapping.unwritten)
                {
                    continue;
                }
                QByteArray block;
                if (!readBlock(mapping.physicalBlock, block, errorText))
                {
                    return false;
                }
                const unsigned char* const kBytes = dataPointer(block);
                std::uint32_t offset = 0;
                while (offset + 8U <= blockSize_)
                {
                    const std::uint32_t kChild = le32(kBytes + offset);
                    const std::uint16_t kRecordLength =
                        le16(kBytes + offset + 4U);
                    const std::uint8_t kNameLength =
                        kBytes[offset + 6U];
                    if (kRecordLength < 8U
                        || (kRecordLength & 3U) != 0U
                        || offset + kRecordLength > blockSize_)
                    {
                        break;
                    }
                    if (kChild != 0U && kNameLength != 0U
                        && kNameLength <= kRecordLength - 8U)
                    {
                        const QString kName = QString::fromUtf8(
                            reinterpret_cast<const char*>(
                                kBytes + offset + 8U),
                            kNameLength);
                        if (kName == wantedName)
                        {
                            inodeOut = kChild;
                            return true;
                        }
                    }
                    offset += kRecordLength;
                }
            }
            errorText = QStringLiteral("Ext 路径不存在：%1")
                .arg(wantedName);
            return false;
        }

        bool mapExtentNode(
            const QByteArray& node,
            const std::uint64_t logicalBlock,
            const std::uint32_t recursionDepth,
            ExtBlockMapping& mapping,
            QString& errorText)
        {
            if (node.size() < 12 || recursionDepth > 8U)
            {
                errorText = QStringLiteral("Ext extent 树深度无效。");
                return false;
            }
            const unsigned char* const kBytes = dataPointer(node);
            if (le16(kBytes) != kExtentMagic)
            {
                errorText = QStringLiteral("Ext extent 节点魔数无效。");
                return false;
            }
            const std::uint16_t kEntries = le16(kBytes + 2U);
            const std::uint16_t kMaximum = le16(kBytes + 4U);
            const std::uint16_t kDepth = le16(kBytes + 6U);
            if (kEntries > kMaximum
                || 12U + static_cast<std::uint32_t>(kEntries) * 12U
                    > static_cast<std::uint32_t>(node.size()))
            {
                errorText = QStringLiteral("Ext extent 节点记录越界。");
                return false;
            }

            if (kDepth == 0U)
            {
                for (std::uint16_t index = 0; index < kEntries; ++index)
                {
                    const unsigned char* const kExtent =
                        kBytes + 12U + index * 12U;
                    const std::uint64_t kLogical = le32(kExtent);
                    const std::uint16_t kEncodedLength =
                        le16(kExtent + 4U);
                    const bool kUnwritten =
                        (kEncodedLength & 0x8000U) != 0U;
                    std::uint64_t blockCount =
                        kEncodedLength & 0x7FFFU;
                    if (blockCount == 0U)
                    {
                        blockCount = 32768U;
                    }
                    if (logicalBlock >= kLogical
                        && logicalBlock - kLogical < blockCount)
                    {
                        const std::uint64_t kPhysical =
                            static_cast<std::uint64_t>(
                                le16(kExtent + 6U)) << 32U
                            | le32(kExtent + 8U);
                        if (kPhysical + logicalBlock - kLogical
                            >= blockCount_)
                        {
                            errorText = QStringLiteral(
                                "Ext extent 物理块越界。");
                            return false;
                        }
                        mapping.mapped = true;
                        mapping.unwritten = kUnwritten;
                        mapping.physicalBlock =
                            kPhysical + logicalBlock - kLogical;
                        return true;
                    }
                }
                return true;
            }

            const unsigned char* selected = nullptr;
            for (std::uint16_t index = 0; index < kEntries; ++index)
            {
                const unsigned char* const kEntry =
                    kBytes + 12U + index * 12U;
                if (le32(kEntry) > logicalBlock)
                {
                    break;
                }
                selected = kEntry;
            }
            if (selected == nullptr)
            {
                return true;
            }
            const std::uint64_t kChildBlock =
                static_cast<std::uint64_t>(
                    le16(selected + 8U)) << 32U
                | le32(selected + 4U);
            QByteArray child;
            if (!readBlock(kChildBlock, child, errorText))
            {
                return false;
            }
            return mapExtentNode(
                child,
                logicalBlock,
                recursionDepth + 1U,
                mapping,
                errorText);
        }

        bool readIndirectPointer(
            const std::uint64_t block,
            const std::uint64_t index,
            std::uint64_t& pointerOut,
            QString& errorText)
        {
            const std::uint64_t kPointersPerBlock = blockSize_ / 4U;
            if (block == 0U)
            {
                pointerOut = 0U;
                return true;
            }
            if (block >= blockCount_ || index >= kPointersPerBlock)
            {
                errorText = QStringLiteral("Ext 间接块索引越界。");
                return false;
            }
            QByteArray pointerBytes;
            if (!reader_.read(
                    block * blockSize_ + index * 4U,
                    4U,
                    pointerBytes,
                    errorText))
            {
                return false;
            }
            pointerOut = le32(dataPointer(pointerBytes));
            if (pointerOut >= blockCount_ && pointerOut != 0U)
            {
                errorText = QStringLiteral("Ext 间接块指针越界。");
                return false;
            }
            return true;
        }

        bool mapIndirectBlock(
            const ExtInode& inode,
            const std::uint64_t logicalBlock,
            ExtBlockMapping& mapping,
            QString& errorText)
        {
            const unsigned char* const kPointers =
                inode.blockData.data();
            if (logicalBlock < 12U)
            {
                mapping.physicalBlock =
                    le32(kPointers + logicalBlock * 4U);
                mapping.mapped = mapping.physicalBlock != 0U;
                return mapping.physicalBlock < blockCount_;
            }

            const std::uint64_t kPerBlock = blockSize_ / 4U;
            std::uint64_t relative = logicalBlock - 12U;
            std::uint64_t current = 0;
            if (relative < kPerBlock)
            {
                return readIndirectPointer(
                    le32(kPointers + 12U * 4U),
                    relative,
                    current,
                    errorText)
                    && ((mapping.physicalBlock = current),
                        (mapping.mapped = current != 0U),
                        true);
            }

            relative -= kPerBlock;
            if (kPerBlock != 0U
                && relative < kPerBlock * kPerBlock)
            {
                if (!readIndirectPointer(
                        le32(kPointers + 13U * 4U),
                        relative / kPerBlock,
                        current,
                        errorText)
                    || !readIndirectPointer(
                        current,
                        relative % kPerBlock,
                        current,
                        errorText))
                {
                    return false;
                }
                mapping.physicalBlock = current;
                mapping.mapped = current != 0U;
                return true;
            }

            const std::uint64_t kDoubleCapacity =
                kPerBlock * kPerBlock;
            relative -= kDoubleCapacity;
            if (kPerBlock == 0U
                || relative / kPerBlock / kPerBlock >= kPerBlock)
            {
                errorText = QStringLiteral(
                    "Ext 逻辑块超过三级间接块范围。");
                return false;
            }
            if (!readIndirectPointer(
                    le32(kPointers + 14U * 4U),
                    relative / kDoubleCapacity,
                    current,
                    errorText))
            {
                return false;
            }
            const std::uint64_t kSecondIndex =
                (relative % kDoubleCapacity) / kPerBlock;
            if (!readIndirectPointer(
                    current,
                    kSecondIndex,
                    current,
                    errorText)
                || !readIndirectPointer(
                    current,
                    relative % kPerBlock,
                    current,
                    errorText))
            {
                return false;
            }
            mapping.physicalBlock = current;
            mapping.mapped = current != 0U;
            return true;
        }

        bool mapBlock(
            const ExtInode& inode,
            const std::uint64_t logicalBlock,
            ExtBlockMapping& mapping,
            QString& errorText)
        {
            mapping = {};
            if ((inode.flags & kExtentsFlag) != 0U)
            {
                const QByteArray kRoot(
                    reinterpret_cast<const char*>(
                        inode.blockData.data()),
                    static_cast<qsizetype>(inode.blockData.size()));
                return mapExtentNode(
                    kRoot,
                    logicalBlock,
                    0U,
                    mapping,
                    errorText);
            }
            return mapIndirectBlock(
                inode,
                logicalBlock,
                mapping,
                errorText);
        }

        bool collectExtentNode(
            const QByteArray& node,
            const std::uint32_t recursionDepth,
            std::vector<ExtLogicalRun>& runs,
            bool& truncated,
            QString& errorText)
        {
            if (node.size() < 12 || recursionDepth > 8U)
            {
                errorText = QStringLiteral("Ext extent 树深度无效。");
                return false;
            }
            const unsigned char* const kBytes = dataPointer(node);
            if (le16(kBytes) != kExtentMagic)
            {
                errorText = QStringLiteral("Ext extent 节点魔数无效。");
                return false;
            }
            const std::uint16_t kEntries = le16(kBytes + 2U);
            const std::uint16_t kMaximum = le16(kBytes + 4U);
            const std::uint16_t kDepth = le16(kBytes + 6U);
            if (kEntries > kMaximum
                || 12U + static_cast<std::uint32_t>(kEntries) * 12U
                    > static_cast<std::uint32_t>(node.size()))
            {
                errorText = QStringLiteral("Ext extent 节点记录越界。");
                return false;
            }
            for (std::uint16_t index = 0; index < kEntries; ++index)
            {
                if (runs.size() >= ks::misc::rawfs::kMaximumExtentCount)
                {
                    truncated = true;
                    return true;
                }
                const unsigned char* const kEntry =
                    kBytes + 12U + index * 12U;
                if (kDepth == 0U)
                {
                    const std::uint16_t kEncodedLength =
                        le16(kEntry + 4U);
                    std::uint64_t blockCount =
                        kEncodedLength & 0x7FFFU;
                    if (blockCount == 0U)
                    {
                        blockCount = 32768U;
                    }
                    ExtLogicalRun run;
                    run.logicalBlock = le32(kEntry);
                    run.physicalBlock =
                        static_cast<std::uint64_t>(
                            le16(kEntry + 6U)) << 32U
                        | le32(kEntry + 8U);
                    run.blockCount = blockCount;
                    run.unwritten =
                        (kEncodedLength & 0x8000U) != 0U;
                    if (run.physicalBlock >= blockCount_
                        || run.blockCount
                            > blockCount_ - run.physicalBlock)
                    {
                        errorText = QStringLiteral(
                            "Ext extent 物理范围越界。");
                        return false;
                    }
                    runs.push_back(run);
                }
                else
                {
                    const std::uint64_t kChildBlock =
                        static_cast<std::uint64_t>(
                            le16(kEntry + 8U)) << 32U
                        | le32(kEntry + 4U);
                    QByteArray child;
                    if (!readBlock(kChildBlock, child, errorText)
                        || !collectExtentNode(
                            child,
                            recursionDepth + 1U,
                            runs,
                            truncated,
                            errorText))
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        static void appendRun(
            const ExtLogicalRun& run,
            std::vector<ExtLogicalRun>& runs)
        {
            if (!runs.empty())
            {
                ExtLogicalRun& previous = runs.back();
                const bool kLogicalContiguous =
                    previous.logicalBlock + previous.blockCount
                    == run.logicalBlock;
                const bool kPhysicalContiguous =
                    previous.sparse
                    || previous.physicalBlock + previous.blockCount
                        == run.physicalBlock;
                if (kLogicalContiguous && kPhysicalContiguous
                    && previous.sparse == run.sparse
                    && previous.unwritten == run.unwritten)
                {
                    previous.blockCount += run.blockCount;
                    return;
                }
            }
            runs.push_back(run);
        }

        bool collectExtents(
            const ExtInode& inode,
            std::vector<ks::misc::RawFileExtent>& extents,
            bool& truncated,
            QString& errorText)
        {
            extents.clear();
            truncated = false;
            const std::uint64_t kLogicalBlockCount =
                (inode.sizeBytes + blockSize_ - 1U) / blockSize_;
            if (kLogicalBlockCount == 0U)
            {
                return true;
            }

            std::vector<ExtLogicalRun> mappedRuns;
            if ((inode.flags & kExtentsFlag) != 0U)
            {
                const QByteArray kRoot(
                    reinterpret_cast<const char*>(
                        inode.blockData.data()),
                    static_cast<qsizetype>(inode.blockData.size()));
                if (!collectExtentNode(
                        kRoot,
                        0U,
                        mappedRuns,
                        truncated,
                        errorText))
                {
                    return false;
                }
                std::sort(
                    mappedRuns.begin(),
                    mappedRuns.end(),
                    [](const ExtLogicalRun& left,
                       const ExtLogicalRun& right)
                    {
                        return left.logicalBlock < right.logicalBlock;
                    });
            }
            else
            {
                const std::uint64_t kBoundedBlocks =
                    std::min<std::uint64_t>(
                        kLogicalBlockCount,
                        kMaximumLogicalBlocks);
                for (std::uint64_t logical = 0;
                     logical < kBoundedBlocks;
                     ++logical)
                {
                    ExtBlockMapping mapping;
                    if (!mapIndirectBlock(
                            inode,
                            logical,
                            mapping,
                            errorText))
                    {
                        return false;
                    }
                    ExtLogicalRun run;
                    run.logicalBlock = logical;
                    run.blockCount = 1U;
                    run.physicalBlock = mapping.physicalBlock;
                    run.sparse = !mapping.mapped;
                    appendRun(run, mappedRuns);
                    if (mappedRuns.size()
                        >= ks::misc::rawfs::kMaximumExtentCount)
                    {
                        truncated = true;
                        break;
                    }
                }
                truncated = truncated
                    || kLogicalBlockCount > kBoundedBlocks;
            }

            std::uint64_t cursor = 0;
            for (const ExtLogicalRun& mapped : mappedRuns)
            {
                if (mapped.logicalBlock >= kLogicalBlockCount)
                {
                    break;
                }
                if (mapped.logicalBlock > cursor)
                {
                    ExtLogicalRun hole;
                    hole.logicalBlock = cursor;
                    hole.blockCount = mapped.logicalBlock - cursor;
                    hole.sparse = true;
                    appendRawExtent(
                        hole,
                        inode.sizeBytes,
                        extents);
                }
                appendRawExtent(
                    mapped,
                    inode.sizeBytes,
                    extents);
                cursor = std::max(
                    cursor,
                    mapped.logicalBlock + mapped.blockCount);
                if (extents.size()
                    >= ks::misc::rawfs::kMaximumExtentCount)
                {
                    truncated = true;
                    break;
                }
            }
            if (!truncated && cursor < kLogicalBlockCount)
            {
                ExtLogicalRun hole;
                hole.logicalBlock = cursor;
                hole.blockCount = kLogicalBlockCount - cursor;
                hole.sparse = true;
                appendRawExtent(hole, inode.sizeBytes, extents);
            }
            return true;
        }

        void appendRawExtent(
            const ExtLogicalRun& run,
            const std::uint64_t fileSize,
            std::vector<ks::misc::RawFileExtent>& extents) const
        {
            const std::uint64_t kLogicalOffset =
                run.logicalBlock * blockSize_;
            if (kLogicalOffset >= fileSize)
            {
                return;
            }
            ks::misc::RawFileExtent extent;
            extent.logicalOffset = kLogicalOffset;
            extent.lengthBytes = std::min<std::uint64_t>(
                run.blockCount * blockSize_,
                fileSize - kLogicalOffset);
            extent.sparse = run.sparse;
            extent.unwritten = run.unwritten;
            extent.physicalMappingExact = !run.sparse;
            if (!run.sparse)
            {
                extent.absoluteOffset =
                    reader_.partitionOffset()
                    + run.physicalBlock * blockSize_;
            }
            extents.push_back(extent);
        }

        static ks::misc::RawFileObjectType objectType(
            const std::uint16_t mode)
        {
            switch (mode & kFileTypeMask)
            {
            case kRegularFileMode:
                return ks::misc::RawFileObjectType::kRegularFile;
            case kDirectoryMode:
                return ks::misc::RawFileObjectType::kDirectory;
            case kSymbolicLinkMode:
                return ks::misc::RawFileObjectType::kSymbolicLink;
            default:
                return ks::misc::RawFileObjectType::kSpecial;
            }
        }

        static void fillEntry(
            const ExtInode& inode,
            const std::uint64_t parent,
            const QString& name,
            const QString& fullPath,
            ks::misc::RawFileEntry& entry)
        {
            entry.name = name;
            entry.fullPath = fullPath;
            entry.type = objectType(inode.mode);
            entry.objectId = inode.number;
            entry.parentObjectId = parent;
            entry.fileSizeBytes = inode.sizeBytes;
            entry.allocatedSizeBytes = inode.allocatedBytes;
            entry.metadataOffset = inode.metadataOffset;
            entry.modeOrFlags =
                static_cast<std::uint32_t>(inode.mode)
                | inode.flags;
        }

        const ks::misc::rawfs::VolumeReader& reader_;
        std::uint32_t blockSize_ = 0;
        std::uint32_t firstDataBlock_ = 0;
        std::uint32_t blocksPerGroup_ = 0;
        std::uint32_t inodesPerGroup_ = 0;
        std::uint32_t inodeCount_ = 0;
        std::uint32_t incompatFeatures_ = 0;
        std::uint16_t inodeSize_ = 0;
        std::uint16_t descriptorSize_ = 0;
        std::uint64_t blockCount_ = 0;
        std::uint64_t groupCount_ = 0;
    };
}

namespace ks::misc::rawfs
{
    RawDirectoryResult listExt(
        const VolumeReader& reader,
        const ForensicFileSystemKind expectedKind,
        const QString& path,
        const std::uint32_t maximumEntries)
    {
        RawDirectoryResult result;
        result.fileSystem = expectedKind;
        result.fileSystemName =
            DiskFileSystemForensics::fileSystemName(expectedKind);
        result.requestedPath = path;

        ExtVolume volume(reader);
        if (!volume.mount(result.errorText))
        {
            return result;
        }
        ExtInode directory;
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

    RawFileReadResult readExt(
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
        result.filePath = path;

        ExtVolume volume(reader);
        if (!volume.mount(result.errorText))
        {
            return result;
        }
        ExtInode inode;
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
        volume.readFile(inode, offset, length, result);
        return result;
    }
}
