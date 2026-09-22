#include "DriverFileSystemParser.h"

// ============================================================
// DriverFileSystemParser.cpp
// Purpose:
// 1) Convert Win32 paths to NT paths accessible by the driver;
// 2) Invoke ArkDriverClient to merge R0 page directory snapshots;
// 3) Map name, attributes, size, time, and FileId to the FileDock tile model.
// ============================================================

#include "../../../shared/ark_client/ArkDriverClient.h"

#include <QDir>
#include <QFileInfo>
#include <QTimeZone>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <utility>

namespace
{
    // buildDriverNtPath purpose: convert common Win32/long/UNC paths to \??\ namespace paths.
    QString buildDriverNtPath(const QString& pathText)
    {
        QString nativePath = QDir::toNativeSeparators(pathText.trimmed());
        if (nativePath.isEmpty())
        {
            return {};
        }
        if (nativePath.startsWith(QStringLiteral("\\??\\")))
        {
            return nativePath;
        }
        if (nativePath.startsWith(
            QStringLiteral("\\\\?\\UNC\\"),
            Qt::CaseInsensitive))
        {
            return QStringLiteral("\\??\\UNC\\") + nativePath.mid(8);
        }
        if (nativePath.startsWith(QStringLiteral("\\\\?\\")))
        {
            return QStringLiteral("\\??\\") + nativePath.mid(4);
        }
        if (nativePath.startsWith(QStringLiteral("\\\\")))
        {
            return QStringLiteral("\\??\\UNC\\") + nativePath.mid(2);
        }
        return QStringLiteral("\\??\\") + nativePath;
    }

    // manualFsTypeFromDriverName: Purpose: Map R0 FileFsAttributeInformation names to existing parser enums.
    ks::file::ManualFsType manualFsTypeFromDriverName(
        const std::wstring& fileSystemName)
    {
        const QString kNormalized =
            QString::fromStdWString(fileSystemName).trimmed().toUpper();
        if (kNormalized == QStringLiteral("NTFS"))
        {
            return ks::file::ManualFsType::kNtfs;
        }
        if (kNormalized == QStringLiteral("FAT32") ||
            kNormalized == QStringLiteral("FAT"))
        {
            return ks::file::ManualFsType::kFat32;
        }
        if (kNormalized == QStringLiteral("EXFAT"))
        {
            return ks::file::ManualFsType::kExFat;
        }
        return ks::file::ManualFsType::kUnknown;
    }

    // fileTimeToLocal: Converts the NT 100ns timestamp returned by the driver to a local QDateTime.
    QDateTime fileTimeToLocal(const std::int64_t fileTime100ns)
    {
        if (fileTime100ns <= 0)
        {
            return {};
        }
        constexpr qint64 kEpochDeltaMsec = 11644473600000LL;
        const std::uint64_t kTicks =
            static_cast<std::uint64_t>(fileTime100ns);
        if (kTicks / 10000ULL >
            static_cast<std::uint64_t>(
                std::numeric_limits<qint64>::max()))
        {
            return {};
        }
        const qint64 kUnixMsec =
            static_cast<qint64>(kTicks / 10000ULL) - kEpochDeltaMsec;
        return QDateTime::fromMSecsSinceEpoch(
            kUnixMsec,
            QTimeZone::UTC).toLocalTime();
    }

    // buildTypeText purpose: Generates file type text (e.g., 'Directory/Extension File') consistent with manual parsing mode.
    QString buildTypeText(
        const QString& fileName,
        const bool isDirectory)
    {
        if (isDirectory)
        {
            return QStringLiteral("目录");
        }
        const QString kSuffixText = QFileInfo(fileName).suffix().trimmed();
        return kSuffixText.isEmpty()
            ? QStringLiteral("文件")
            : kSuffixText.toUpper() + QStringLiteral(" 文件");
    }

    // statusHex purpose: Uniformly formats NTSTATUS into a fixed eight-digit hexadecimal diagnostic string.
    QString statusHex(const long statusValue)
    {
        return QStringLiteral("0x%1")
            .arg(
                static_cast<qulonglong>(
                    static_cast<unsigned long>(statusValue)),
                8,
                16,
                QChar('0'))
            .toUpper();
    }
}

bool ks::file::DriverFileSystemParser::enumerateDirectory(
    const QString& pathText,
    std::vector<ManualDirectoryEntry>& entriesOut,
    ManualFsType& fsTypeOut,
    QString& errorTextOut,
    bool* partialOut,
    QString* sourceDetailOut)
{
    entriesOut.clear();
    fsTypeOut = ManualFsType::kUnknown;
    errorTextOut.clear();
    if (partialOut != nullptr)
    {
        *partialOut = false;
    }
    if (sourceDetailOut != nullptr)
    {
        sourceDetailOut->clear();
    }

    const QString kDriverPath = buildDriverNtPath(pathText);
    if (kDriverPath.isEmpty())
    {
        errorTextOut = QStringLiteral("目录路径为空，无法执行 R0 驱动解析。");
        return false;
    }

    const ksword::ark::DirectoryEnumerationResult kDriverResult =
        ksword::ark::DriverClient().enumerateDirectory(
            kDriverPath.toStdWString());
    if (!kDriverResult.io.ok)
    {
        errorTextOut = kDriverResult.unsupported
            ? QStringLiteral("当前 KswordARK 驱动不支持 R0 目录枚举，请重新部署本次构建的驱动。")
            : QStringLiteral("R0 目录枚举通信失败：Win32=%1；%2")
                .arg(kDriverResult.io.win32Error)
                .arg(QString::fromStdString(kDriverResult.io.message));
        return false;
    }

    const bool kSemanticSuccess =
        kDriverResult.queryStatus ==
            KSWORD_ARK_DIRECTORY_ENUM_STATUS_OK ||
        kDriverResult.queryStatus ==
            KSWORD_ARK_DIRECTORY_ENUM_STATUS_PARTIAL;
    if (!kSemanticSuccess)
    {
        errorTextOut = QStringLiteral(
            "R0 无法枚举目录：queryStatus=%1；open=%2；last=%3。")
            .arg(kDriverResult.queryStatus)
            .arg(statusHex(kDriverResult.openStatus))
            .arg(statusHex(kDriverResult.lastStatus));
        return false;
    }

    fsTypeOut = manualFsTypeFromDriverName(
        kDriverResult.fileSystemName);
    bool partialResult = kDriverResult.capped ||
        kDriverResult.queryStatus ==
            KSWORD_ARK_DIRECTORY_ENUM_STATUS_PARTIAL;
    const QString kCurrentPath =
        QDir::toNativeSeparators(QDir::cleanPath(pathText));
    entriesOut.reserve(kDriverResult.entries.size());
    for (const ksword::ark::DirectoryEntryRecord& source :
        kDriverResult.entries)
    {
        const QString kName = QString::fromStdWString(source.name);
        if (kName.isEmpty())
        {
            partialResult = true;
            continue;
        }

        ManualDirectoryEntry entry{};
        entry.name = kName;
        entry.absolutePath = QDir(kCurrentPath).filePath(kName);
        entry.isDirectory =
            (source.flags &
                KSWORD_ARK_DIRECTORY_ENTRY_FLAG_DIRECTORY) != 0U;
        entry.sizeBytes = source.endOfFile > 0
            ? static_cast<std::uint64_t>(source.endOfFile)
            : 0U;
        entry.modifiedTime = fileTimeToLocal(source.lastWriteTime);
        entry.typeText = buildTypeText(kName, entry.isDirectory);
        entry.ntfsFileReference = source.fileId;
        entriesOut.push_back(std::move(entry));

        if ((source.flags &
                KSWORD_ARK_DIRECTORY_ENTRY_FLAG_NAME_TRUNCATED) != 0U)
        {
            partialResult = true;
        }
    }

    std::sort(
        entriesOut.begin(),
        entriesOut.end(),
        [](const ManualDirectoryEntry& left,
           const ManualDirectoryEntry& right)
        {
            if (left.isDirectory != right.isDirectory)
            {
                return left.isDirectory && !right.isDirectory;
            }
            return QString::compare(
                left.name,
                right.name,
                Qt::CaseInsensitive) < 0;
        });

    if (partialOut != nullptr)
    {
        *partialOut = partialResult;
    }
    if (sourceDetailOut != nullptr)
    {
        const QString kFsName = kDriverResult.fileSystemName.empty()
            ? QStringLiteral("未知")
            : QString::fromStdWString(kDriverResult.fileSystemName);
        *sourceDetailOut = partialResult
            ? QStringLiteral("R0 驱动解析（部分结果）；文件系统=%1；条目=%2")
                .arg(kFsName)
                .arg(entriesOut.size())
            : QStringLiteral("R0 驱动解析；文件系统=%1；条目=%2")
                .arg(kFsName)
                .arg(entriesOut.size());
    }
    return true;
}
