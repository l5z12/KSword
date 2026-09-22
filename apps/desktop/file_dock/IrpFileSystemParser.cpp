#include "IrpFileSystemParser.h"

// ============================================================
// IrpFileSystemParser.cpp
// Purpose:
// 1) Convert Win32 paths to NT paths accessible by the driver;
// 2) Invoke ArkDriverClient's custom IRP directory enumeration to bypass layer views.
// 3) Fetch the stack top view again for comparison and report the difference set as suspected hidden entries.
// ============================================================

#include "../../../shared/ark_client/ArkDriverClient.h"

#include <QDir>
#include <QFileInfo>
#include <QSet>
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
        const std::uint64_t kTicks = static_cast<std::uint64_t>(fileTime100ns);
        if (kTicks / 10000ULL >
            static_cast<std::uint64_t>(std::numeric_limits<qint64>::max()))
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
    QString buildTypeText(const QString& fileName, const bool isDirectory)
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
                static_cast<qulonglong>(static_cast<unsigned long>(statusValue)),
                8,
                16,
                QChar('0'))
            .toUpper();
    }

    // convertRows purpose: Map protocol rows to the FileDock tiling model and report truncation information.
    void convertRows(
        const std::vector<ksword::ark::DirectoryEntryRecord>& sourceRows,
        const QString& currentPath,
        std::vector<ks::file::ManualDirectoryEntry>& entriesOut,
        bool& partialResult)
    {
        entriesOut.reserve(sourceRows.size());
        for (const ksword::ark::DirectoryEntryRecord& source : sourceRows)
        {
            const QString kName = QString::fromStdWString(source.name);
            if (kName.isEmpty())
            {
                partialResult = true;
                continue;
            }

            ks::file::ManualDirectoryEntry entry{};
            entry.name = kName;
            entry.absolutePath = QDir(currentPath).filePath(kName);
            entry.isDirectory =
                (source.flags & KSWORD_ARK_DIRECTORY_ENTRY_FLAG_DIRECTORY) != 0U;
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
    }

    // sortEntries purpose: Sort by directory priority first, then by case-insensitive name ascending, to remain consistent with other parsers.
    void sortEntries(std::vector<ks::file::ManualDirectoryEntry>& entriesOut)
    {
        std::sort(
            entriesOut.begin(),
            entriesOut.end(),
            [](const ks::file::ManualDirectoryEntry& left,
               const ks::file::ManualDirectoryEntry& right)
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
    }
}

QString ks::file::IrpFileSystemParser::layerDisplayText(
    const unsigned long layerValue)
{
    switch (layerValue)
    {
    case KSWORD_ARK_FILE_IRP_LAYER_RELATED:
        return QStringLiteral("设备栈顶");
    case KSWORD_ARK_FILE_IRP_LAYER_BASE_FS:
        return QStringLiteral("基础文件系统设备");
    case KSWORD_ARK_FILE_IRP_LAYER_VPB_FS:
        return QStringLiteral("VPB 挂载文件系统");
    case KSWORD_ARK_FILE_IRP_LAYER_DEVICE:
        return QStringLiteral("卷设备");
    default:
        return QStringLiteral("未知层(%1)").arg(layerValue);
    }
}

bool ks::file::IrpFileSystemParser::enumerateDirectory(
    const QString& pathText,
    std::vector<ManualDirectoryEntry>& entriesOut,
    ManualFsType& fsTypeOut,
    QString& errorTextOut,
    bool* partialOut,
    QString* sourceDetailOut,
    IrpScanDiagnostics* diagnosticsOut)
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
    if (diagnosticsOut != nullptr)
    {
        *diagnosticsOut = IrpScanDiagnostics{};
    }

    const QString kDriverPath = buildDriverNtPath(pathText);
    if (kDriverPath.isEmpty())
    {
        errorTextOut = QStringLiteral("目录路径为空，无法执行 R0 IRP 解析。");
        return false;
    }

    const ksword::ark::DriverClient kClient;
    // Note: The main view fixedly requests the base file system device; this is the purpose of this mode. The
    // difference between the request layer and the effective layer will be reported truthfully in diagnostics.
    const ksword::ark::FileIrpDirectoryResult kBypassResult =
        kClient.enumerateDirectoryByIrp(
            kDriverPath.toStdWString(),
            KSWORD_ARK_FILE_IRP_LAYER_BASE_FS);
    if (!kBypassResult.io.ok)
    {
        errorTextOut = kBypassResult.unsupported
            ? QStringLiteral("当前 KswordARK 驱动不支持 R0 IRP 目录枚举，请重新部署本次构建的驱动。")
            : QStringLiteral("R0 IRP 目录枚举通信失败：Win32=%1；%2")
                .arg(kBypassResult.io.win32Error)
                .arg(QString::fromStdString(kBypassResult.io.message));
        return false;
    }

    const bool kSemanticSuccess =
        kBypassResult.queryStatus == KSWORD_ARK_DIRECTORY_ENUM_STATUS_OK ||
        kBypassResult.queryStatus == KSWORD_ARK_DIRECTORY_ENUM_STATUS_PARTIAL;
    if (!kSemanticSuccess)
    {
        errorTextOut = QStringLiteral(
            "R0 无法用自建 IRP 枚举目录：queryStatus=%1；create=%2；last=%3。")
            .arg(kBypassResult.queryStatus)
            .arg(statusHex(kBypassResult.openStatus))
            .arg(statusHex(kBypassResult.lastStatus));
        return false;
    }

    fsTypeOut = manualFsTypeFromDriverName(kBypassResult.fileSystemName);
    bool partialResult = kBypassResult.capped ||
        kBypassResult.queryStatus == KSWORD_ARK_DIRECTORY_ENUM_STATUS_PARTIAL;
    const QString kCurrentPath =
        QDir::toNativeSeparators(QDir::cleanPath(pathText));
    convertRows(kBypassResult.entries, kCurrentPath, entriesOut, partialResult);
    sortEntries(entriesOut);

    const bool kLayerBypassed =
        kBypassResult.resolvedLayer != KSWORD_ARK_FILE_IRP_LAYER_RELATED;

    if (diagnosticsOut != nullptr)
    {
        diagnosticsOut->requestedLayer = kBypassResult.requestedLayer;
        diagnosticsOut->resolvedLayer = kBypassResult.resolvedLayer;
        diagnosticsOut->layerBypassed = kLayerBypassed;
        diagnosticsOut->bypassEntryCount = static_cast<int>(entriesOut.size());
        diagnosticsOut->bypassDriverName =
            QString::fromStdWString(kBypassResult.driverName);

        /*
         * The stack-top reference is only meaningful when truly dispatched to a deeper layer: if R0 is unavailable at the target layer, it falls back to the stack top. In
         * this case, the two requests share the same source, so their difference set is necessarily empty; treating this as 'no hidden items' is an incorrect conclusion.
         */
        if (kLayerBypassed)
        {
            const ksword::ark::FileIrpDirectoryResult kTopResult =
                kClient.enumerateDirectoryByIrp(
                    kDriverPath.toStdWString(),
                    KSWORD_ARK_FILE_IRP_LAYER_RELATED);
            const bool kTopSemanticOk = kTopResult.io.ok &&
                (kTopResult.queryStatus == KSWORD_ARK_DIRECTORY_ENUM_STATUS_OK ||
                 kTopResult.queryStatus == KSWORD_ARK_DIRECTORY_ENUM_STATUS_PARTIAL);
            if (kTopSemanticOk)
            {
                std::vector<ManualDirectoryEntry> topEntries;
                bool topPartial = false;
                convertRows(kTopResult.entries, kCurrentPath, topEntries, topPartial);

                diagnosticsOut->comparisonAvailable = true;
                diagnosticsOut->topLayerEntryCount =
                    static_cast<int>(topEntries.size());
                diagnosticsOut->topLayerDriverName =
                    QString::fromStdWString(kTopResult.driverName);

                QSet<QString> bypassNameSet;
                bypassNameSet.reserve(static_cast<int>(entriesOut.size()) + 16);
                for (const ManualDirectoryEntry& itemValue : entriesOut)
                {
                    bypassNameSet.insert(itemValue.name.toCaseFolded());
                }
                QSet<QString> topNameSet;
                topNameSet.reserve(static_cast<int>(topEntries.size()) + 16);
                for (const ManualDirectoryEntry& itemValue : topEntries)
                {
                    topNameSet.insert(itemValue.name.toCaseFolded());
                }

                for (const ManualDirectoryEntry& itemValue : entriesOut)
                {
                    if (!topNameSet.contains(itemValue.name.toCaseFolded()))
                    {
                        diagnosticsOut->bypassOnlyNames.append(itemValue.name);
                    }
                }
                for (const ManualDirectoryEntry& itemValue : topEntries)
                {
                    if (!bypassNameSet.contains(itemValue.name.toCaseFolded()))
                    {
                        diagnosticsOut->topLayerOnlyNames.append(itemValue.name);
                    }
                }
            }
        }
    }

    if (partialOut != nullptr)
    {
        *partialOut = partialResult;
    }
    if (sourceDetailOut != nullptr)
    {
        const QString kFsName = kBypassResult.fileSystemName.empty()
            ? QStringLiteral("未知")
            : QString::fromStdWString(kBypassResult.fileSystemName);
        const QString kDriverText = kBypassResult.driverName.empty()
            ? QStringLiteral("未知驱动")
            : QString::fromStdWString(kBypassResult.driverName);
        QString detailText =
            QStringLiteral("R0 IRP 解析%1；目标层=%2；接收驱动=%3；文件系统=%4；条目=%5")
                .arg(partialResult ? QStringLiteral("（部分结果）") : QString())
                .arg(layerDisplayText(kBypassResult.resolvedLayer))
                .arg(kDriverText)
                .arg(kFsName)
                .arg(entriesOut.size());
        if (!kLayerBypassed)
        {
            detailText += QStringLiteral("；已回退到栈顶，本次未绕过过滤层");
        }
        else if (diagnosticsOut != nullptr &&
            diagnosticsOut->comparisonAvailable &&
            !diagnosticsOut->bypassOnlyNames.isEmpty())
        {
            detailText += QStringLiteral("；栈顶不可见条目=%1")
                .arg(diagnosticsOut->bypassOnlyNames.size());
        }
        *sourceDetailOut = detailText;
    }
    return true;
}
