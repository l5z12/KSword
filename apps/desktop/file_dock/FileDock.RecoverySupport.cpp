#include "FileDock.Support.h"

namespace ksword::ui::file_dock
{
    // isDeletedFileSafelyRecoverable:
    // - Uniformly determine if scan results allow entry into the recovery flow.
    // - Non-resident data returns true only if both completeness and runlist pass scan validation.
    bool isDeletedFileSafelyRecoverable(
        const ks::file::NtfsDeletedFileEntry& entryValue)
    {
        return entryValue.recoveryCapability ==
                ks::file::NtfsRecoveryCapability::kResident ||
            entryValue.recoveryCapability ==
                ks::file::NtfsRecoveryCapability::kNonResidentIntact;
    }

    // deletedFileRecoveryCapabilityText:
    // - Convert underlying recovery capability to table-readable text.
    // - Text explicitly states that non-resident data must be exported to another volume.
    QString deletedFileRecoveryCapabilityText(
        const ks::file::NtfsDeletedFileEntry& entryValue)
    {
        switch (entryValue.recoveryCapability)
        {
        case ks::file::NtfsRecoveryCapability::kResident:
            return QStringLiteral("Resident 可恢复");
        case ks::file::NtfsRecoveryCapability::kNonResidentIntact:
            return QStringLiteral("非驻留完整可恢复（需其它卷）");
        case ks::file::NtfsRecoveryCapability::kNonResidentAtRisk:
            return QStringLiteral("非驻留簇已复用或完整度未知");
        case ks::file::NtfsRecoveryCapability::kUnsupportedStream:
            return QStringLiteral("压缩、加密或跨记录流暂不支持");
        case ks::file::NtfsRecoveryCapability::kMetadataOnly:
        default:
            return QStringLiteral("仅元数据");
        }
    }

    // localVolumeRootForPath:
    // - Extract the volume root in 'C:\' format from a local absolute path.
    // - UNC/network paths return an empty string and will not be mistakenly identified as the source volume.
    QString localVolumeRootForPath(const QString& pathText)
    {
        const QString kNativePath =
            QDir::toNativeSeparators(QDir::cleanPath(pathText.trimmed()));
        if (kNativePath.size() < 2 || kNativePath[1] != QChar(':'))
        {
            return QString();
        }
        return kNativePath.left(2).toUpper() + QStringLiteral("\\");
    }

    // safeRecoveryFileName:
    // - Convert raw names from MFT to leaf names creatable by standard Win32 file APIs.
    // - Filters path separators, ADS colons, control characters, trailing dots/spaces, and DOS reserved device names;
    // - Return: Empty string indicates the caller should use the placeholder name deleted_<MFT>.bin.
    QString safeRecoveryFileName(const QString& requestedFileName)
    {
        QString safeFileName = requestedFileName.trimmed();
        constexpr qsizetype kMaximumRecoveryFileNameLength = 180;
        const QString kInvalidCharacterSet =
            QStringLiteral("<>:\"/\\|?*");
        for (qsizetype characterIndex = 0;
             characterIndex < safeFileName.size();
             ++characterIndex)
        {
            const QChar kCharacterValue = safeFileName.at(characterIndex);
            if (kCharacterValue.unicode() < 0x20U ||
                kInvalidCharacterSet.contains(kCharacterValue))
            {
                safeFileName[characterIndex] = QChar('_');
            }
        }

        while (safeFileName.endsWith(QChar('.')) ||
               safeFileName.endsWith(QChar(' ')))
        {
            safeFileName.chop(1);
        }
        if (safeFileName.size() > kMaximumRecoveryFileNameLength)
        {
            safeFileName.truncate(kMaximumRecoveryFileNameLength);
            if (!safeFileName.isEmpty() &&
                safeFileName.back().isHighSurrogate())
            {
                safeFileName.chop(1);
            }
        }

        const QString kDeviceBaseName =
            safeFileName.section(QChar('.'), 0, 0).toUpper();
        const bool kIsReservedDeviceName =
            kDeviceBaseName == QStringLiteral("CON") ||
            kDeviceBaseName == QStringLiteral("PRN") ||
            kDeviceBaseName == QStringLiteral("AUX") ||
            kDeviceBaseName == QStringLiteral("NUL") ||
            (kDeviceBaseName.size() == 4 &&
             (kDeviceBaseName.startsWith(QStringLiteral("COM")) ||
              kDeviceBaseName.startsWith(QStringLiteral("LPT"))) &&
             kDeviceBaseName.back() >= QChar('1') &&
             kDeviceBaseName.back() <= QChar('9'));
        if (kIsReservedDeviceName)
        {
            safeFileName.prepend(QChar('_'));
        }
        if (safeFileName == QStringLiteral(".") ||
            safeFileName == QStringLiteral(".."))
        {
            safeFileName.clear();
        }
        return safeFileName;
    }

    // uniqueRecoveryTargetPath:
    // - Generate non-overlapping output paths for batch recovery that do not overwrite existing files or conflict with each other;
    // - Append MFT record number and incrementing sequence number to the extension name in case of conflict.
    QString uniqueRecoveryTargetPath(
        const QString& outputDirectory,
        const QString& requestedFileName,
        const std::uint64_t fileReference,
        QSet<QString>& reservedPathSet)
    {
        QString safeFileName = safeRecoveryFileName(requestedFileName);
        if (safeFileName.isEmpty() ||
            safeFileName == QStringLiteral(".") ||
            safeFileName == QStringLiteral(".."))
        {
            safeFileName = QStringLiteral("deleted_%1.bin")
                .arg(static_cast<qulonglong>(fileReference));
        }

        const QFileInfo kNameInfo(safeFileName);
        const QString kBaseName = kNameInfo.completeBaseName().isEmpty()
            ? safeFileName
            : kNameInfo.completeBaseName();
        const QString kSuffixText = kNameInfo.completeSuffix();
        QString candidatePath = QDir(outputDirectory).filePath(safeFileName);
        int collisionIndex = 0;
        while (QFileInfo::exists(candidatePath) ||
               reservedPathSet.contains(candidatePath.toCaseFolded()))
        {
            ++collisionIndex;
            const QString kCollisionName = kSuffixText.isEmpty()
                ? QStringLiteral("%1_mft%2_%3")
                    .arg(kBaseName)
                    .arg(static_cast<qulonglong>(fileReference))
                    .arg(collisionIndex)
                : QStringLiteral("%1_mft%2_%3.%4")
                    .arg(kBaseName)
                    .arg(static_cast<qulonglong>(fileReference))
                    .arg(collisionIndex)
                    .arg(kSuffixText);
            candidatePath = QDir(outputDirectory).filePath(kCollisionName);
        }
        reservedPathSet.insert(candidatePath.toCaseFolded());
        return candidatePath;
    }

    // collectNtfsVolumeRootList:
    // - Purpose: enumerate NTFS volume roots currently available for accidental deletion scanning; must be called from a background thread.
    // - Input: none; internally enumerate logical drives.
    // - Returns: List of NTFS volume root paths (native separators, e.g., C:\).
    // Note: GetVolumeInformationW blocks waiting for media readiness on empty optical drives and waits for SMB session timeouts on disconnected network
    // mapped drives. First, use GetDriveTypeW to filter out optical drives, network mappings, and devices without roots. Additionally, use SetThreadErrorMode
    // to disable the 'Please insert disk' system modal dialog for this thread, preventing background probing from popping up a modal box in the user's face.
    QVector<QString> collectNtfsVolumeRootList()
    {
        QVector<QString> ntfsVolumeRootList;

        DWORD previousThreadErrorMode = 0;
        const bool kThreadErrorModeChanged =
            ::SetThreadErrorMode(SEM_FAILCRITICALERRORS, &previousThreadErrorMode) != FALSE;

        const QFileInfoList kDriveInfoList = QDir::drives();
        for (const QFileInfo& driveInfo : kDriveInfoList)
        {
            const QString kVolumeRootPath = QDir::toNativeSeparators(driveInfo.absoluteFilePath());
            const UINT kDriveTypeValue = ::GetDriveTypeW(kVolumeRootPath.toStdWString().c_str());
            if (kDriveTypeValue == DRIVE_CDROM
                || kDriveTypeValue == DRIVE_REMOTE
                || kDriveTypeValue == DRIVE_NO_ROOT_DIR
                || kDriveTypeValue == DRIVE_UNKNOWN)
            {
                // These types are either definitely not local volumes suitable for accidental deletion scanning, or they are the
                // cause of GetVolumeInformationW taking seconds to tens of seconds. Skip them directly without further probing.
                continue;
            }

            const ks::file::ManualFsType kFileSystemType =
                ks::file::ManualFileSystemParser::detectFileSystemType(kVolumeRootPath);
            if (kFileSystemType != ks::file::ManualFsType::kNtfs)
            {
                continue;
            }

            ntfsVolumeRootList.push_back(kVolumeRootPath);
        }

        if (kThreadErrorModeChanged)
        {
            ::SetThreadErrorMode(previousThreadErrorMode, nullptr);
        }
        return ntfsVolumeRootList;
    }
}
