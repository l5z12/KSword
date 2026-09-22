#include "DiskRawFileSystemBrowser.h"

#include "DiskEditorBackend.h"
#include "DiskRawFileSystemInternal.h"

#include <QFileInfo>
#include <QSaveFile>

#include <algorithm>
#include <limits>

namespace
{
    constexpr std::uint32_t kBackendTransferBytes = 256U * 1024U;

    std::uint64_t alignDown(
        const std::uint64_t value,
        const std::uint32_t alignment)
    {
        return value - (value % static_cast<std::uint64_t>(alignment));
    }

    bool alignUp(
        const std::uint64_t value,
        const std::uint32_t alignment,
        std::uint64_t& alignedOut)
    {
        const std::uint64_t kRemainder =
            value % static_cast<std::uint64_t>(alignment);
        if (kRemainder == 0U)
        {
            alignedOut = value;
            return true;
        }
        const std::uint64_t kIncrement =
            static_cast<std::uint64_t>(alignment) - kRemainder;
        if (value > std::numeric_limits<std::uint64_t>::max() - kIncrement)
        {
            return false;
        }
        alignedOut = value + kIncrement;
        return true;
    }

    ks::misc::RawDirectoryResult unsupportedDirectoryResult(
        const ks::misc::ForensicFileSystemKind kind,
        const QString& path)
    {
        ks::misc::RawDirectoryResult result;
        result.fileSystem = kind;
        result.fileSystemName =
            ks::misc::DiskFileSystemForensics::fileSystemName(kind);
        result.requestedPath = path;
        result.errorText = QStringLiteral(
            "该文件系统的原始目录解析器未能建立可验证的挂载状态。");
        return result;
    }

    ks::misc::RawFileReadResult unsupportedFileResult(
        const ks::misc::ForensicFileSystemKind kind,
        const QString& path)
    {
        ks::misc::RawFileReadResult result;
        result.fileSystem = kind;
        result.fileSystemName =
            ks::misc::DiskFileSystemForensics::fileSystemName(kind);
        result.filePath = path;
        result.errorText = QStringLiteral(
            "该文件系统的原始文件读取器未能建立可验证的挂载状态。");
        return result;
    }
}

namespace ks::misc::rawfs
{
    VolumeReader::VolumeReader(
        const int diskIndex,
        const unsigned long backend,
        const std::uint64_t partitionOffset,
        const std::uint64_t partitionLength,
        const std::uint32_t logicalSectorSize)
        : diskIndex_(diskIndex),
          backend_(backend),
          partitionOffset_(partitionOffset),
          partitionLength_(partitionLength),
          logicalSectorSize_(
              logicalSectorSize == 0U ? 512U : logicalSectorSize)
    {
    }

    bool VolumeReader::rangeIsValid(
        const std::uint64_t relativeOffset,
        const std::uint64_t length) const
    {
        return length != 0U
            && relativeOffset <= partitionLength_
            && length <= partitionLength_ - relativeOffset;
    }

    bool VolumeReader::read(
        const std::uint64_t relativeOffset,
        const std::uint32_t length,
        QByteArray& bytesOut,
        QString& errorTextOut) const
    {
        bytesOut.clear();
        errorTextOut.clear();
        if (length == 0U)
        {
            return true;
        }
        if (!rangeIsValid(relativeOffset, length))
        {
            errorTextOut = QStringLiteral("读取范围越过所选分区边界。");
            return false;
        }

        const std::uint64_t kAlignedStart =
            alignDown(relativeOffset, logicalSectorSize_);
        const std::uint64_t kPrefix = relativeOffset - kAlignedStart;
        if (kPrefix > std::numeric_limits<std::uint64_t>::max() - length)
        {
            errorTextOut = QStringLiteral("读取范围发生整数溢出。");
            return false;
        }

        std::uint64_t alignedLength = 0;
        if (!alignUp(
                kPrefix + static_cast<std::uint64_t>(length),
                logicalSectorSize_,
                alignedLength)
            || !rangeIsValid(kAlignedStart, alignedLength)
            || partitionOffset_
                > std::numeric_limits<std::uint64_t>::max()
                    - kAlignedStart
                    - alignedLength
            || alignedLength
                > static_cast<std::uint64_t>(
                    std::numeric_limits<int>::max()))
        {
            errorTextOut = QStringLiteral("扇区对齐后的读取范围无效。");
            return false;
        }

        QByteArray alignedBytes(
            static_cast<qsizetype>(alignedLength),
            Qt::Uninitialized);
        std::uint64_t completed = 0;
        while (completed < alignedLength)
        {
            const std::uint64_t kRemaining = alignedLength - completed;
            const std::uint32_t kChunkLength = static_cast<std::uint32_t>(
                std::min<std::uint64_t>(
                    kRemaining,
                    kBackendTransferBytes));
            QByteArray chunk;
            if (!DiskEditorBackend::readBytesWithBackend(
                    diskIndex_,
                    backend_,
                    partitionOffset_ + kAlignedStart + completed,
                    kChunkLength,
                    chunk,
                    errorTextOut))
            {
                bytesOut.clear();
                return false;
            }
            if (chunk.size() != static_cast<qsizetype>(kChunkLength))
            {
                bytesOut.clear();
                errorTextOut = QStringLiteral("磁盘后端返回了截断的数据。");
                return false;
            }
            std::copy(
                chunk.cbegin(),
                chunk.cend(),
                alignedBytes.begin() + static_cast<qsizetype>(completed));
            completed += kChunkLength;
        }

        bytesOut = alignedBytes.mid(
            static_cast<qsizetype>(kPrefix),
            static_cast<qsizetype>(length));
        return true;
    }

    std::uint64_t VolumeReader::partitionOffset() const
    {
        return partitionOffset_;
    }

    std::uint64_t VolumeReader::partitionLength() const
    {
        return partitionLength_;
    }

    QString normalizePath(const QString& path)
    {
        QString normalized = path.trimmed();
        normalized.replace(QChar('/'), QChar('\\'));
        if (normalized.isEmpty())
        {
            return QStringLiteral("\\");
        }
        if (!normalized.startsWith(QChar('\\')))
        {
            normalized.prepend(QChar('\\'));
        }
        while (normalized.contains(QStringLiteral("\\\\")))
        {
            normalized.replace(QStringLiteral("\\\\"), QStringLiteral("\\"));
        }
        if (normalized.size() > 1 && normalized.endsWith(QChar('\\')))
        {
            normalized.chop(1);
        }
        return normalized;
    }

    QString childPath(const QString& parent, const QString& name)
    {
        const QString kNormalizedParent = normalizePath(parent);
        return kNormalizedParent == QStringLiteral("\\")
            ? QStringLiteral("\\") + name
            : kNormalizedParent + QStringLiteral("\\") + name;
    }
}

namespace ks::misc
{
    RawDirectoryResult DiskRawFileSystemBrowser::listDirectory(
        const int diskIndex,
        const unsigned long backend,
        const std::uint64_t partitionOffset,
        const std::uint64_t partitionLength,
        const std::uint32_t logicalSectorSize,
        const ForensicFileSystemKind fileSystem,
        const QString& path,
        const std::uint32_t maximumEntries)
    {
        const rawfs::VolumeReader kReader(
            diskIndex,
            backend,
            partitionOffset,
            partitionLength,
            logicalSectorSize);
        const QString kNormalized = rawfs::normalizePath(path);
        const std::uint32_t kBounded =
            std::clamp(maximumEntries, 1U, 65536U);

        switch (fileSystem)
        {
        case ForensicFileSystemKind::kNtfs:
            return rawfs::listNtfs(kReader, kNormalized, kBounded);
        case ForensicFileSystemKind::kFat12:
        case ForensicFileSystemKind::kFat16:
        case ForensicFileSystemKind::kFat32:
            return rawfs::listFat(
                kReader,
                fileSystem,
                kNormalized,
                kBounded);
        case ForensicFileSystemKind::kExFat:
            return rawfs::listExFat(
                kReader,
                kNormalized,
                kBounded);
        case ForensicFileSystemKind::kExt2:
        case ForensicFileSystemKind::kExt3:
        case ForensicFileSystemKind::kExt4:
            return rawfs::listExt(kReader, fileSystem, kNormalized, kBounded);
        case ForensicFileSystemKind::kBtrfs:
            return rawfs::listBtrfs(kReader, kNormalized, kBounded);
        case ForensicFileSystemKind::kApfs:
            return rawfs::listApfs(kReader, kNormalized, kBounded);
        case ForensicFileSystemKind::kHfs:
        case ForensicFileSystemKind::kHfsPlus:
            return rawfs::listHfs(kReader, fileSystem, kNormalized, kBounded);
        case ForensicFileSystemKind::kReFs:
            return rawfs::listRefs(kReader, kNormalized, kBounded);
        default:
            return unsupportedDirectoryResult(fileSystem, kNormalized);
        }
    }

    RawFileReadResult DiskRawFileSystemBrowser::readFile(
        const int diskIndex,
        const unsigned long backend,
        const std::uint64_t partitionOffset,
        const std::uint64_t partitionLength,
        const std::uint32_t logicalSectorSize,
        const ForensicFileSystemKind fileSystem,
        const QString& path,
        const std::uint64_t offset,
        const std::uint32_t length)
    {
        const QString kNormalized = rawfs::normalizePath(path);
        if (length == 0U || length > rawfs::kMaximumSingleReadBytes)
        {
            RawFileReadResult result =
                unsupportedFileResult(fileSystem, kNormalized);
            result.errorText = QStringLiteral(
                "单次文件读取长度必须在 1 字节到 16 MiB 之间。");
            return result;
        }
        const rawfs::VolumeReader kReader(
            diskIndex,
            backend,
            partitionOffset,
            partitionLength,
            logicalSectorSize);

        switch (fileSystem)
        {
        case ForensicFileSystemKind::kNtfs:
            return rawfs::readNtfs(
                kReader,
                kNormalized,
                offset,
                length);
        case ForensicFileSystemKind::kFat12:
        case ForensicFileSystemKind::kFat16:
        case ForensicFileSystemKind::kFat32:
            return rawfs::readFat(
                kReader,
                fileSystem,
                kNormalized,
                offset,
                length);
        case ForensicFileSystemKind::kExFat:
            return rawfs::readExFat(
                kReader,
                kNormalized,
                offset,
                length);
        case ForensicFileSystemKind::kExt2:
        case ForensicFileSystemKind::kExt3:
        case ForensicFileSystemKind::kExt4:
            return rawfs::readExt(
                kReader, fileSystem, kNormalized, offset, length);
        case ForensicFileSystemKind::kBtrfs:
            return rawfs::readBtrfs(kReader, kNormalized, offset, length);
        case ForensicFileSystemKind::kApfs:
            return rawfs::readApfs(kReader, kNormalized, offset, length);
        case ForensicFileSystemKind::kHfs:
        case ForensicFileSystemKind::kHfsPlus:
            return rawfs::readHfs(
                kReader, fileSystem, kNormalized, offset, length);
        case ForensicFileSystemKind::kReFs:
            return rawfs::readRefs(kReader, kNormalized, offset, length);
        default:
            return unsupportedFileResult(fileSystem, kNormalized);
        }
    }

    RawFileExportResult DiskRawFileSystemBrowser::exportFile(
        const int diskIndex,
        const unsigned long backend,
        const std::uint64_t partitionOffset,
        const std::uint64_t partitionLength,
        const std::uint32_t logicalSectorSize,
        const ForensicFileSystemKind fileSystem,
        const QString& sourcePath,
        const QString& destinationPath)
    {
        RawFileExportResult result;
        result.filePath = rawfs::normalizePath(sourcePath);
        result.destinationPath = QFileInfo(destinationPath).absoluteFilePath();
        if (destinationPath.trimmed().isEmpty())
        {
            result.errorText = QStringLiteral("导出目标路径为空。");
            return result;
        }

        QSaveFile destination(result.destinationPath);
        if (!destination.open(QIODevice::WriteOnly))
        {
            result.errorText = QStringLiteral("无法创建导出文件：%1")
                .arg(destination.errorString());
            return result;
        }

        std::uint64_t offset = 0;
        for (;;)
        {
            const RawFileReadResult kChunk = readFile(
                diskIndex,
                backend,
                partitionOffset,
                partitionLength,
                logicalSectorSize,
                fileSystem,
                result.filePath,
                offset,
                rawfs::kExportChunkBytes);
            if (!kChunk.success)
            {
                destination.cancelWriting();
                result.errorText = kChunk.errorText;
                return result;
            }

            result.fileSizeBytes = kChunk.fileSizeBytes;
            if (!kChunk.bytes.isEmpty())
            {
                const qint64 kWritten = destination.write(kChunk.bytes);
                if (kWritten != static_cast<qint64>(kChunk.bytes.size()))
                {
                    destination.cancelWriting();
                    result.errorText = QStringLiteral(
                        "写入导出文件失败：%1")
                        .arg(destination.errorString());
                    return result;
                }
                offset += static_cast<std::uint64_t>(kChunk.bytes.size());
                result.bytesWritten = offset;
            }
            if (kChunk.endOfFile || kChunk.bytes.isEmpty())
            {
                break;
            }
        }

        if (!destination.commit())
        {
            result.errorText = QStringLiteral("提交导出文件失败：%1")
                .arg(destination.errorString());
            return result;
        }
        result.success = true;
        return result;
    }

    QString DiskRawFileSystemBrowser::objectTypeText(
        const RawFileObjectType type)
    {
        switch (type)
        {
        case RawFileObjectType::kRegularFile:
            return QStringLiteral("文件");
        case RawFileObjectType::kDirectory:
            return QStringLiteral("目录");
        case RawFileObjectType::kSymbolicLink:
            return QStringLiteral("符号链接");
        case RawFileObjectType::kSpecial:
            return QStringLiteral("特殊对象");
        case RawFileObjectType::kNamedStream:
            return QStringLiteral("NTFS 命名流");
        default:
            return QStringLiteral("未知");
        }
    }
}
