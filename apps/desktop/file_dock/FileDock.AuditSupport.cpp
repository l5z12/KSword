#include "FileDock.Support.h"

namespace ksword::ui::file_dock
{
    // VolumePathFromAnyPath: Compresses any local path to the volume root (e.g., C:\).
    QString volumePathFromAnyPath(const QString& pathText)
    {
        const QString kNormalizedPath = QDir::toNativeSeparators(pathText).trimmed();
        if (kNormalizedPath.isEmpty())
        {
            return QString();
        }

        std::array<wchar_t, MAX_PATH + 4U> buffer{};
        const BOOL kOk = ::GetVolumePathNameW(
            kNormalizedPath.toStdWString().c_str(),
            buffer.data(),
            static_cast<DWORD>(buffer.size()));
        if (kOk == FALSE)
        {
            return QString();
        }
        return QString::fromWCharArray(buffer.data());
    }

    // buildMountPointsText: Reads the DOS mount point list corresponding to the volume; returns an empty string on failure.
    QString buildMountPointsText(const QString& volumeRoot)
    {
        if (volumeRoot.trimmed().isEmpty())
        {
            return QString();
        }

        DWORD requiredChars = 0;
        ::GetVolumePathNamesForVolumeNameW(
            volumeRoot.toStdWString().c_str(),
            nullptr,
            0,
            &requiredChars);
        if (requiredChars == 0)
        {
            return QString();
        }

        std::vector<wchar_t> buffer(static_cast<std::size_t>(requiredChars) + 2U, L'\0');
        if (::GetVolumePathNamesForVolumeNameW(
            volumeRoot.toStdWString().c_str(),
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &requiredChars) == FALSE)
        {
            return QString();
        }

        QStringList paths;
        const wchar_t* cursor = buffer.data();
        while (cursor != nullptr && *cursor != L'\0')
        {
            const QString kPathText = QString::fromWCharArray(cursor);
            if (!kPathText.isEmpty())
            {
                paths << kPathText;
            }
            cursor += kPathText.size() + 1;
        }
        return paths.join(QStringLiteral(", "));
    }

    // buildVolumeDevicePathText: Parses a volume name into a device path (e.g., \Device\HarddiskVolumeX).
    QString buildVolumeDevicePathText(const QString& volumeRoot)
    {
        if (volumeRoot.trimmed().isEmpty())
        {
            return QString();
        }

        QString dosName = volumeRoot;
        if (dosName.endsWith(QChar('\\')))
        {
            dosName.chop(1);
        }

        std::array<wchar_t, 1024U> buffer{};
        const DWORD kChars = ::QueryDosDeviceW(
            dosName.toStdWString().c_str(),
            buffer.data(),
            static_cast<DWORD>(buffer.size()));
        if (kChars == 0)
        {
            return QString();
        }
        return QString::fromWCharArray(buffer.data());
    }

    // buildVolumeInfoText: Reads volume label, file system, and basic attributes.
    QString buildVolumeInfoText(const QString& volumeRoot)
    {
        if (volumeRoot.trimmed().isEmpty())
        {
            return QString();
        }

        std::array<wchar_t, MAX_PATH + 1U> labelBuffer{};
        std::array<wchar_t, MAX_PATH + 1U> fsBuffer{};
        DWORD serialNumber = 0;
        DWORD maxComponentLength = 0;
        DWORD fsFlags = 0;
        if (::GetVolumeInformationW(
            volumeRoot.toStdWString().c_str(),
            labelBuffer.data(),
            static_cast<DWORD>(labelBuffer.size()),
            &serialNumber,
            &maxComponentLength,
            &fsFlags,
            fsBuffer.data(),
            static_cast<DWORD>(fsBuffer.size())) == FALSE)
        {
            return QString();
        }

        return QStringLiteral("Label=%1 | FS=%2 | Serial=0x%3 | Flags=0x%4")
            .arg(QString::fromWCharArray(labelBuffer.data()))
            .arg(QString::fromWCharArray(fsBuffer.data()))
            .arg(serialNumber, 8, 16, QChar('0'))
            .arg(fsFlags, 8, 16, QChar('0'))
            .toUpper();
    }

    // queryVolumeLabelAndFileSystemText: Reads only the volume label and file system name for reuse by the Storage/FVE page.
    // Input: volumeRoot is the volume root path (e.g., C:\); labelOut/fileSystemOut receive the read results.
    // Return: true on success; on failure, the output remains empty.
    bool queryVolumeLabelAndFileSystemText(
        const QString& volumeRoot,
        QString& labelOut,
        QString& fileSystemOut)
    {
        labelOut.clear();
        fileSystemOut.clear();
        if (volumeRoot.trimmed().isEmpty())
        {
            return false;
        }

        std::array<wchar_t, MAX_PATH + 1U> labelBuffer{};
        std::array<wchar_t, MAX_PATH + 1U> fsBuffer{};
        DWORD serialNumber = 0;
        DWORD maxComponentLength = 0;
        DWORD fsFlags = 0;
        if (::GetVolumeInformationW(
            volumeRoot.toStdWString().c_str(),
            labelBuffer.data(),
            static_cast<DWORD>(labelBuffer.size()),
            &serialNumber,
            &maxComponentLength,
            &fsFlags,
            fsBuffer.data(),
            static_cast<DWORD>(fsBuffer.size())) == FALSE)
        {
            return false;
        }

        labelOut = QString::fromWCharArray(labelBuffer.data()).trimmed();
        fileSystemOut = QString::fromWCharArray(fsBuffer.data()).trimmed();
        return true;
    }

    // buildStorageDescriptorText: Reads the storage device descriptor.
    QString buildStorageDescriptorText(const QString& volumeRoot)
    {
        if (volumeRoot.trimmed().isEmpty())
        {
            return QString();
        }

        HANDLE handleValue = ::CreateFileW(
            volumeRoot.toStdWString().c_str(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (handleValue == INVALID_HANDLE_VALUE)
        {
            return QStringLiteral("CreateFile=%1").arg(::GetLastError());
        }

        QString result;
        STORAGE_PROPERTY_QUERY query{};
        query.PropertyId = StorageDeviceProperty;
        query.QueryType = PropertyStandardQuery;
        std::array<std::uint8_t, 1024U> buffer{};
        DWORD returnedBytes = 0;
        if (::DeviceIoControl(
            handleValue,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &query,
            static_cast<DWORD>(sizeof(query)),
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &returnedBytes,
            nullptr) != FALSE
            && returnedBytes >= sizeof(STORAGE_DEVICE_DESCRIPTOR))
        {
            const auto* descriptor = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buffer.data());
            result = QStringLiteral("BusType=%1 | Removable=%2 | RawSize=%3")
                .arg(static_cast<unsigned long>(descriptor->BusType))
                .arg(descriptor->RemovableMedia ? QStringLiteral("是") : QStringLiteral("否"))
                .arg(returnedBytes);
        }
        ::CloseHandle(handleValue);
        return result;
    }

    // buildVolumeStackText: Construct a stable, read-only 'volume stack' summary from volume root, device path, and file system.
    // Input: volumeRoot, devicePathText, and fsText are all optional visible status strings.
    // Return: Single-line or multi-line chain summary suitable for UI display.
    QString buildVolumeStackText(
        const QString& volumeRoot,
        const QString& devicePathText,
        const QString& fsText,
        const QString& mountPointsText)
    {
        QStringList parts;
        appendUniqueText(parts, volumeRoot);
        appendUniqueText(parts, devicePathText);
        appendUniqueText(parts, fsText);
        appendUniqueText(parts, mountPointsText);
        if (parts.isEmpty())
        {
            return QString();
        }
        return parts.join(QStringLiteral(" -> "));
    }

    // buildBitLockerStatusText: Read-only query BitLocker visible status; provide a fallback explanation on failure.
    QString buildBitLockerStatusText(const QString& volumeRoot)
    {
        if (volumeRoot.trimmed().isEmpty())
        {
            return QStringLiteral("BitLocker: <unknown>");
        }

        return queryBitLockerVolumeText(volumeRoot.left(2));
    }

    // queryFileVolumeAuditSnapshot: Aggregates the volume/storage/FVE views required by the three new FileDock tabs.
    FileVolumeAuditSnapshot queryFileVolumeAuditSnapshot(const QString& filePath)
    {
        FileVolumeAuditSnapshot snapshot{};
        snapshot.volumeRoot = volumePathFromAnyPath(filePath);
        if (snapshot.volumeRoot.isEmpty())
        {
            return snapshot;
        }

        snapshot.mountPointsText = buildMountPointsText(snapshot.volumeRoot);
        snapshot.devicePathText = buildVolumeDevicePathText(snapshot.volumeRoot);
        QString volumeLabelText;
        QString fileSystemText;
        if (queryVolumeLabelAndFileSystemText(snapshot.volumeRoot, volumeLabelText, fileSystemText))
        {
            snapshot.labelText = volumeLabelText;
            snapshot.fsNameText = fileSystemText;
        }
        snapshot.volumeStackText = buildVolumeStackText(
            snapshot.volumeRoot,
            snapshot.devicePathText,
            snapshot.fsNameText,
            snapshot.mountPointsText);
        const QString kVolumeInfoText = buildVolumeInfoText(snapshot.volumeRoot);
        const QString kStorageDescriptorText = buildStorageDescriptorText(snapshot.volumeRoot);
        snapshot.storageText = QStringList{ kVolumeInfoText, kStorageDescriptorText }.join(QStringLiteral(" | "));
        snapshot.bitLockerText = buildBitLockerStatusText(snapshot.volumeRoot);
        snapshot.filterText = QStringLiteral("仅只读枚举，不做卸载/绕过/修改。");
        return snapshot;
    }

    // openReadOnlyFileHandle: Opens a file or directory in read-only mode with maximum sharing.
    HANDLE openReadOnlyFileHandle(const QString& pathText, const bool directoryHint)
    {
        const QString kNormalizedPath = QDir::toNativeSeparators(pathText).trimmed();
        if (kNormalizedPath.isEmpty())
        {
            return INVALID_HANDLE_VALUE;
        }

        DWORD flags = FILE_ATTRIBUTE_NORMAL;
        if (directoryHint)
        {
            flags |= FILE_FLAG_BACKUP_SEMANTICS;
        }

        return ::CreateFileW(
            kNormalizedPath.toStdWString().c_str(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            flags,
            nullptr);
    }

    // queryFileStandardInfoText: Reads standard information such as DeletePending, file size, and link count.
    bool queryFileStandardInfoText(
        HANDLE fileHandle,
        QString& detailsOut,
        QString& statusOut)
    {
        detailsOut.clear();
        statusOut.clear();
        if (fileHandle == nullptr || fileHandle == INVALID_HANDLE_VALUE)
        {
            statusOut = QStringLiteral("句柄无效");
            return false;
        }

        FILE_STANDARD_INFO standardInfo{};
        if (::GetFileInformationByHandleEx(
            fileHandle,
            FileStandardInfo,
            &standardInfo,
            static_cast<DWORD>(sizeof(standardInfo))) == FALSE)
        {
            statusOut = QStringLiteral("GetFileInformationByHandleEx(FileStandardInfo) 失败，Win32=%1")
                .arg(::GetLastError());
            return false;
        }

        detailsOut = QStringLiteral("DeletePending: %1\n")
            .arg(standardInfo.DeletePending ? QStringLiteral("是") : QStringLiteral("否"));
        detailsOut += QStringLiteral("Directory: %1\n")
            .arg(standardInfo.Directory ? QStringLiteral("是") : QStringLiteral("否"));
        detailsOut += QStringLiteral("AllocationSize: %1\n")
            .arg(static_cast<qlonglong>(standardInfo.AllocationSize.QuadPart));
        detailsOut += QStringLiteral("EndOfFile: %1\n")
            .arg(static_cast<qlonglong>(standardInfo.EndOfFile.QuadPart));
        detailsOut += QStringLiteral("NumberOfLinks: %1\n")
            .arg(static_cast<unsigned long>(standardInfo.NumberOfLinks));
        detailsOut += QStringLiteral("采集句柄 ShareAccess: READ|WRITE|DELETE\n");
        statusOut = QStringLiteral("OK");
        return true;
    }

    // createReadOnlyAuditTextPage: Creates a read-only text page with unified text selection and layout styles.
    // Input: parent is the page's parent object, content is the page text.
    // Returns: A QWidget page hosting the CodeEditorWidget; no side effects other than the return value.
    QWidget* createReadOnlyAuditTextPage(QWidget* parent, const QString& content)
    {
        QWidget* page = new QWidget(parent);
        QVBoxLayout* layout = new QVBoxLayout(page);
        CodeEditorWidget* editor = new CodeEditorWidget(page);
        editor->setReadOnly(true);
        editor->setLocalizedText(content);
        layout->addWidget(editor, 1);
        return page;
    }

    // readUtf16FieldAtOffset: Reads a UTF-16 offset field from the returned buffer for FltLib enumeration structure parsing.
    // Input: buffer/bytesReturned point to the complete returned buffer; fieldOffset/fieldLength are byte-level field positions.
    // Returns: the string with trailing whitespace removed on success; an empty string on failure.
    QString readUtf16FieldAtOffset(
        const void* buffer,
        const std::size_t bytesReturned,
        const USHORT fieldOffset,
        const USHORT fieldLength)
    {
        if (buffer == nullptr || bytesReturned == 0U || fieldLength == 0U)
        {
            return QString();
        }
        const std::size_t kStartOffset = static_cast<std::size_t>(fieldOffset);
        const std::size_t kLengthBytes = static_cast<std::size_t>(fieldLength);
        if (kStartOffset >= bytesReturned || (kStartOffset + kLengthBytes) > bytesReturned)
        {
            return QString();
        }
        const auto* charBuffer = reinterpret_cast<const wchar_t*>(
            static_cast<const std::uint8_t*>(buffer) + kStartOffset);
        return QString::fromWCharArray(charBuffer, static_cast<int>(kLengthBytes / sizeof(wchar_t))).trimmed();
    }

    // filterFilesystemTypeToText: Converts the FLT_FILESYSTEM_TYPE enum to human-readable text.
    // Input: Filesystem type returned by FltUser for filesystemType.
    // Returns the corresponding file system name; preserves the numeric value for unknown enums.
    QString filterFilesystemTypeToText(const FLT_FILESYSTEM_TYPE filesystemType)
    {
        switch (filesystemType)
        {
        case FLT_FSTYPE_UNKNOWN: return QStringLiteral("Unknown");
        case FLT_FSTYPE_RAW: return QStringLiteral("RAW");
        case FLT_FSTYPE_NTFS: return QStringLiteral("NTFS");
        case FLT_FSTYPE_FAT: return QStringLiteral("FAT");
        case FLT_FSTYPE_CDFS: return QStringLiteral("CDFS");
        case FLT_FSTYPE_UDFS: return QStringLiteral("UDFS");
        case FLT_FSTYPE_LANMAN: return QStringLiteral("LANMAN");
        case FLT_FSTYPE_WEBDAV: return QStringLiteral("WebDAV");
        case FLT_FSTYPE_RDPDR: return QStringLiteral("RDPDR");
        case FLT_FSTYPE_NFS: return QStringLiteral("NFS");
        case FLT_FSTYPE_MS_NETWARE: return QStringLiteral("MS_NETWARE");
        case FLT_FSTYPE_NETWARE: return QStringLiteral("NETWARE");
        case FLT_FSTYPE_BSUDF: return QStringLiteral("BsUDF");
        case FLT_FSTYPE_MUP: return QStringLiteral("MUP");
        case FLT_FSTYPE_RSFX: return QStringLiteral("RsFx");
        case FLT_FSTYPE_ROXIO_UDF1: return QStringLiteral("RoxioUDF1");
        case FLT_FSTYPE_ROXIO_UDF2: return QStringLiteral("RoxioUDF2");
        case FLT_FSTYPE_ROXIO_UDF3: return QStringLiteral("RoxioUDF3");
        case FLT_FSTYPE_TACIT: return QStringLiteral("Tacit");
        case FLT_FSTYPE_FS_REC: return QStringLiteral("FsRec");
        case FLT_FSTYPE_INCD: return QStringLiteral("InCD");
        case FLT_FSTYPE_INCD_FAT: return QStringLiteral("InCDFat");
        case FLT_FSTYPE_EXFAT: return QStringLiteral("exFAT");
        case FLT_FSTYPE_PSFS: return QStringLiteral("PSFS");
        case FLT_FSTYPE_GPFS: return QStringLiteral("GPFS");
        case FLT_FSTYPE_NPFS: return QStringLiteral("NPFS");
        case FLT_FSTYPE_MSFS: return QStringLiteral("MSFS");
        case FLT_FSTYPE_CSVFS: return QStringLiteral("CSVFS");
        case FLT_FSTYPE_REFS: return QStringLiteral("ReFS");
        case FLT_FSTYPE_OPENAFS: return QStringLiteral("OpenAFS");
        case FLT_FSTYPE_CIMFS: return QStringLiteral("CIMFS");
        default:
            return QStringLiteral("Type=%1").arg(static_cast<int>(filesystemType));
        }
    }

    // appendMinifilterRecordText: Compresses a single Filter enumeration record into readable text.
    // Input: buffer/bytesReturned contain data returned by FilterFindFirst/Next.
    // Returns: None; directly appends to content.
    void appendMinifilterRecordText(
        QString& content,
        const void* buffer,
        const std::size_t bytesReturned)
    {
        if (buffer == nullptr || bytesReturned < sizeof(FILTER_AGGREGATE_STANDARD_INFORMATION))
        {
            return;
        }

        const auto* record = reinterpret_cast<const FILTER_AGGREGATE_STANDARD_INFORMATION*>(buffer);
        const bool kIsMinifilter = (record->Flags & FLTFL_ASI_IS_MINIFILTER) != 0;
        const QString kFilterName = kIsMinifilter
            ? readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.MiniFilter.FilterNameBufferOffset, record->Type.MiniFilter.FilterNameLength)
            : readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.LegacyFilter.FilterNameBufferOffset, record->Type.LegacyFilter.FilterNameLength);
        const QString kAltitude = kIsMinifilter
            ? readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.MiniFilter.FilterAltitudeBufferOffset, record->Type.MiniFilter.FilterAltitudeLength)
            : readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.LegacyFilter.FilterAltitudeBufferOffset, record->Type.LegacyFilter.FilterAltitudeLength);
        const QString kRecordKind = kIsMinifilter ? QStringLiteral("Minifilter") : QStringLiteral("LegacyFilter");

        content += QStringLiteral("名称: %1\n").arg(kFilterName.isEmpty() ? QStringLiteral("<unknown>") : kFilterName);
        content += QStringLiteral("类型: %1\n").arg(kRecordKind);
        content += QStringLiteral("Flags: 0x%1\n").arg(record->Flags, 8, 16, QChar('0')).toUpper();
        if (kIsMinifilter)
        {
            content += QStringLiteral("FrameID: %1\n").arg(record->Type.MiniFilter.FrameID);
            content += QStringLiteral("NumberOfInstances: %1\n").arg(record->Type.MiniFilter.NumberOfInstances);
        }
        content += QStringLiteral("Altitude: %1\n").arg(kAltitude.isEmpty() ? QStringLiteral("<unknown>") : kAltitude);
    }

    // enumerateMinifilterText: Read-only enumeration of the Filter list to generate summary text.
    // Inputs: None.
    // Returns: Visible text containing Filter name, Altitude, FrameID, and instance count.
    QString enumerateMinifilterText()
    {
        QString content;
        content += QStringLiteral("[Minifilter]\n");
        content += QStringLiteral("枚举来源: FilterFindFirst / FilterFindNext\n");
        content += QStringLiteral("展示字段: FilterName, Altitude, FrameID, NumberOfInstances, Flags\n");

        std::vector<std::uint8_t> buffer(16U * 1024U, 0U);
        DWORD bytesReturned = 0;
        HANDLE enumHandle = nullptr;
        HRESULT hr = E_FAIL;
        for (;;)
        {
            hr = ::FilterFindFirst(
                FilterAggregateStandardInformation,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytesReturned,
                &enumHandle);
            if (SUCCEEDED(hr))
            {
                break;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
            {
                buffer.resize(buffer.size() * 2U);
                continue;
            }
            content += QStringLiteral("状态: 枚举失败 HRESULT=0x%1\n")
                .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
            return content;
        }

        auto appendRecord = [&](const QString& prefixText)
        {
            content += prefixText;
            appendMinifilterRecordText(content, buffer.data(), bytesReturned);
            content += QStringLiteral("\n");
        };

        appendRecord(QStringLiteral("\n"));

        for (;;)
        {
            bytesReturned = 0;
            hr = ::FilterFindNext(
                enumHandle,
                FilterAggregateStandardInformation,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytesReturned);
            if (SUCCEEDED(hr))
            {
                appendRecord(QStringLiteral(""));
                continue;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
            {
                break;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
            {
                buffer.resize(buffer.size() * 2U);
                continue;
            }
            content += QStringLiteral("继续枚举失败 HRESULT=0x%1\n")
                .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
            break;
        }

        if (enumHandle != nullptr)
        {
            ::FilterFindClose(enumHandle);
        }
        return content;
    }

    // appendInstanceRecordText: Compresses a single Instance enumeration record into readable text.
    // Input: buffer/bytesReturned contain data returned by FilterInstanceFindFirst/Next.
    // Returns: None; directly appends to content.
    void appendInstanceRecordText(
        QString& content,
        const void* buffer,
        const std::size_t bytesReturned)
    {
        if (buffer == nullptr || bytesReturned < sizeof(INSTANCE_AGGREGATE_STANDARD_INFORMATION))
        {
            return;
        }

        const auto* record = reinterpret_cast<const INSTANCE_AGGREGATE_STANDARD_INFORMATION*>(buffer);
        const bool kIsMinifilter = (record->Flags & FLTFL_IASI_IS_MINIFILTER) != 0;
        const QString kInstanceName = kIsMinifilter
            ? readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.MiniFilter.InstanceNameBufferOffset, record->Type.MiniFilter.InstanceNameLength)
            : readUtf16FieldAtOffset(buffer, bytesReturned, 0, 0);
        const QString kAltitude = kIsMinifilter
            ? readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.MiniFilter.AltitudeBufferOffset, record->Type.MiniFilter.AltitudeLength)
            : readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.LegacyFilter.AltitudeBufferOffset, record->Type.LegacyFilter.AltitudeLength);
        const QString kVolumeName = kIsMinifilter
            ? readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.MiniFilter.VolumeNameBufferOffset, record->Type.MiniFilter.VolumeNameLength)
            : readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.LegacyFilter.VolumeNameBufferOffset, record->Type.LegacyFilter.VolumeNameLength);
        const QString kFilterName = kIsMinifilter
            ? readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.MiniFilter.FilterNameBufferOffset, record->Type.MiniFilter.FilterNameLength)
            : readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.LegacyFilter.FilterNameBufferOffset, record->Type.LegacyFilter.FilterNameLength);

        content += QStringLiteral("实例名: %1\n").arg(kInstanceName.isEmpty() ? QStringLiteral("<unknown>") : kInstanceName);
        content += QStringLiteral("类型: %1\n").arg(kIsMinifilter ? QStringLiteral("Minifilter") : QStringLiteral("LegacyFilter"));
        content += QStringLiteral("Flags: 0x%1\n").arg(record->Flags, 8, 16, QChar('0')).toUpper();
        if (kIsMinifilter)
        {
            content += QStringLiteral("FrameID: %1\n").arg(record->Type.MiniFilter.FrameID);
            content += QStringLiteral("VolumeFileSystemType: %1\n")
                .arg(filterFilesystemTypeToText(record->Type.MiniFilter.VolumeFileSystemType));
        }
        content += QStringLiteral("Altitude: %1\n").arg(kAltitude.isEmpty() ? QStringLiteral("<unknown>") : kAltitude);
        content += QStringLiteral("VolumeName: %1\n").arg(kVolumeName.isEmpty() ? QStringLiteral("<unknown>") : kVolumeName);
        content += QStringLiteral("FilterName: %1\n").arg(kFilterName.isEmpty() ? QStringLiteral("<unknown>") : kFilterName);
    }

    // enumerateInstanceText: Enumerates all minifilter/legacy instances and provides a volume association summary.
    // Inputs: None.
    // Returns: Read-only text of the instance list.
    QString enumerateInstanceText()
    {
        QString content;
        content += QStringLiteral("[Instance]\n");
        content += QStringLiteral("枚举来源: FilterInstanceFindFirst / FilterInstanceFindNext\n");
        content += QStringLiteral("展示字段: InstanceName, Altitude, VolumeName, FilterName, VolumeFileSystemType\n");

        std::vector<std::uint8_t> buffer(16U * 1024U, 0U);
        DWORD bytesReturned = 0;
        HANDLE findHandle = nullptr;
        HRESULT hr = E_FAIL;
        for (;;)
        {
            hr = ::FilterFindFirst(
                FilterAggregateStandardInformation,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytesReturned,
                &findHandle);
            if (SUCCEEDED(hr))
            {
                break;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
            {
                buffer.resize(buffer.size() * 2U);
                continue;
            }
            content += QStringLiteral("状态: 无法先枚举 Filter 列表 HRESULT=0x%1\n")
                .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
            return content;
        }

        for (;;)
        {
            const auto* filterRecord = reinterpret_cast<const FILTER_AGGREGATE_STANDARD_INFORMATION*>(buffer.data());
            const bool kIsMinifilter = (filterRecord->Flags & FLTFL_ASI_IS_MINIFILTER) != 0;
            const QString kFilterName = kIsMinifilter
                ? readUtf16FieldAtOffset(buffer.data(), bytesReturned, filterRecord->Type.MiniFilter.FilterNameBufferOffset, filterRecord->Type.MiniFilter.FilterNameLength)
                : readUtf16FieldAtOffset(buffer.data(), bytesReturned, filterRecord->Type.LegacyFilter.FilterNameBufferOffset, filterRecord->Type.LegacyFilter.FilterNameLength);
            if (!kFilterName.isEmpty())
            {
                content += QStringLiteral("\n[Filter] %1\n").arg(kFilterName);
            }

            HANDLE instanceHandle = nullptr;
            std::vector<std::uint8_t> instanceBuffer(16U * 1024U, 0U);
            DWORD instanceBytesReturned = 0;
            if (!kFilterName.isEmpty())
            {
                for (;;)
                {
                    hr = ::FilterInstanceFindFirst(
                        kFilterName.toStdWString().c_str(),
                        InstanceAggregateStandardInformation,
                        instanceBuffer.data(),
                        static_cast<DWORD>(instanceBuffer.size()),
                        &instanceBytesReturned,
                        &instanceHandle);
                    if (SUCCEEDED(hr))
                    {
                        break;
                    }
                    if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
                    {
                        instanceBuffer.resize(instanceBuffer.size() * 2U);
                        continue;
                    }
                    break;
                }
                if (SUCCEEDED(hr))
                {
                    for (;;)
                    {
                        content += QStringLiteral("  - ");
                        appendInstanceRecordText(content, instanceBuffer.data(), instanceBytesReturned);
                        content += QStringLiteral("\n");

                        instanceBytesReturned = 0;
                        hr = ::FilterInstanceFindNext(
                            instanceHandle,
                            InstanceAggregateStandardInformation,
                            instanceBuffer.data(),
                            static_cast<DWORD>(instanceBuffer.size()),
                            &instanceBytesReturned);
                        if (SUCCEEDED(hr))
                        {
                            continue;
                        }
                        if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
                        {
                            break;
                        }
                        if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
                        {
                            instanceBuffer.resize(instanceBuffer.size() * 2U);
                            continue;
                        }
                        content += QStringLiteral("  ! 继续枚举实例失败 HRESULT=0x%1\n")
                            .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
                        break;
                    }
                }
                else
                {
                    content += QStringLiteral("  ! FilterInstanceFindFirst 失败 HRESULT=0x%1\n")
                        .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
                }
            }

            bytesReturned = 0;
            hr = ::FilterFindNext(
                findHandle,
                FilterAggregateStandardInformation,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytesReturned);
            if (SUCCEEDED(hr))
            {
                continue;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
            {
                break;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
            {
                buffer.resize(buffer.size() * 2U);
                continue;
            }
            content += QStringLiteral("继续枚举 Filter 失败 HRESULT=0x%1\n")
                .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
            break;
        }

        if (findHandle != nullptr)
        {
            ::FilterFindClose(findHandle);
        }
        return content;
    }

    // appendVolumeRecordText: Converts a single Volume enumeration record into readable text.
    // Input: buffer/bytesReturned are the data returned by FilterVolumeFindFirst/Next.
    // Returns: None; directly appends to content.
    void appendVolumeRecordText(
        QString& content,
        const void* buffer,
        const std::size_t bytesReturned)
    {
        if (buffer == nullptr || bytesReturned < sizeof(FILTER_VOLUME_STANDARD_INFORMATION))
        {
            return;
        }

        const auto* record = reinterpret_cast<const FILTER_VOLUME_STANDARD_INFORMATION*>(buffer);
        const QString kVolumeName = readUtf16FieldAtOffset(
            buffer,
            bytesReturned,
            offsetof(FILTER_VOLUME_STANDARD_INFORMATION, FilterVolumeName),
            record->FilterVolumeNameLength);
        content += QStringLiteral("卷名: %1\n").arg(kVolumeName.isEmpty() ? QStringLiteral("<unknown>") : kVolumeName);
        content += QStringLiteral("Flags: 0x%1\n").arg(record->Flags, 8, 16, QChar('0')).toUpper();
        content += QStringLiteral("FrameID: %1\n").arg(record->FrameID);
        content += QStringLiteral("FileSystemType: %1\n").arg(filterFilesystemTypeToText(record->FileSystemType));
    }

    // enumerateVolumeText: Enumerates the Volume list exposed by FilterManager and provides a summary of volume stack associations.
    // Inputs: None.
    // Returns: Volume list and visibility status text.
    QString enumerateVolumeText()
    {
        QString content;
        content += QStringLiteral("[Volume]\n");
        content += QStringLiteral("枚举来源: FilterVolumeFindFirst / FilterVolumeFindNext\n");
        content += QStringLiteral("展示字段: VolumeName, FileSystemType, FrameID, Flags, AttachedInstances\n");

        std::vector<std::uint8_t> buffer(16U * 1024U, 0U);
        DWORD bytesReturned = 0;
        HANDLE volumeHandle = nullptr;
        HRESULT hr = E_FAIL;
        for (;;)
        {
            hr = ::FilterVolumeFindFirst(
                FilterVolumeStandardInformation,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytesReturned,
                &volumeHandle);
            if (SUCCEEDED(hr))
            {
                break;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
            {
                buffer.resize(buffer.size() * 2U);
                continue;
            }
            content += QStringLiteral("状态: 枚举失败 HRESULT=0x%1\n")
                .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
            return content;
        }

        for (;;)
        {
            content += QStringLiteral("\n");
            appendVolumeRecordText(content, buffer.data(), bytesReturned);

            const auto* volumeRecord = reinterpret_cast<const FILTER_VOLUME_STANDARD_INFORMATION*>(buffer.data());
            const QString kVolumeName = readUtf16FieldAtOffset(
                buffer.data(),
                bytesReturned,
                offsetof(FILTER_VOLUME_STANDARD_INFORMATION, FilterVolumeName),
                volumeRecord->FilterVolumeNameLength);
            if (!kVolumeName.isEmpty())
            {
                HANDLE instanceHandle = nullptr;
                std::vector<std::uint8_t> instanceBuffer(16U * 1024U, 0U);
                DWORD instanceBytesReturned = 0;
                if (!kVolumeName.isEmpty())
                {
                    for (;;)
                    {
                        hr = ::FilterVolumeInstanceFindFirst(
                            kVolumeName.toStdWString().c_str(),
                            InstanceAggregateStandardInformation,
                            instanceBuffer.data(),
                            static_cast<DWORD>(instanceBuffer.size()),
                            &instanceBytesReturned,
                            &instanceHandle);
                        if (SUCCEEDED(hr))
                        {
                            break;
                        }
                        if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
                        {
                            instanceBuffer.resize(instanceBuffer.size() * 2U);
                            continue;
                        }
                        break;
                    }
                    if (SUCCEEDED(hr))
                    {
                        content += QStringLiteral("AttachedInstances:\n");
                        for (;;)
                        {
                            content += QStringLiteral("  - ");
                            appendInstanceRecordText(content, instanceBuffer.data(), instanceBytesReturned);
                            content += QStringLiteral("\n");

                            instanceBytesReturned = 0;
                            hr = ::FilterVolumeInstanceFindNext(
                                instanceHandle,
                                InstanceAggregateStandardInformation,
                                instanceBuffer.data(),
                                static_cast<DWORD>(instanceBuffer.size()),
                                &instanceBytesReturned);
                            if (SUCCEEDED(hr))
                            {
                                continue;
                            }
                            if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
                            {
                                break;
                            }
                            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
                            {
                                instanceBuffer.resize(instanceBuffer.size() * 2U);
                                continue;
                            }
                            content += QStringLiteral("  ! 继续枚举卷实例失败 HRESULT=0x%1\n")
                                .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
                            break;
                        }
                    }
                    else
                    {
                        content += QStringLiteral("AttachedInstances: FilterVolumeInstanceFindFirst 失败 HRESULT=0x%1\n")
                            .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
                    }
                }
            }

            bytesReturned = 0;
            hr = ::FilterVolumeFindNext(
                volumeHandle,
                FilterVolumeStandardInformation,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytesReturned);
            if (SUCCEEDED(hr))
            {
                continue;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
            {
                break;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
            {
                buffer.resize(buffer.size() * 2U);
                continue;
            }
            content += QStringLiteral("继续枚举 Volume 失败 HRESULT=0x%1\n")
                .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
            break;
        }

        if (volumeHandle != nullptr)
        {
            ::FilterVolumeFindClose(volumeHandle);
        }
        return content;
    }

    // queryBitLockerVolumeText:
    // - Purpose: Provide BitLocker read-only status text from the Win32_EncryptableVolume perspective.
    // - Input driveLetter: Target drive letter (e.g., C:);
    // - Returns: Status text ready for display.
    // Note: This originally involved CoInitializeEx + CoCreateInstance(CLSID_WbemLocator) +
    // ConnectServer(ROOT\CIMV2\Security\MicrosoftVolumeEncryption) + CoSetProxyBlanket，
    // However, after constructing the SELECT statement, ExecQuery is never called, so it ultimately only outputs the following fallback text;
    // In other words, the entire WMI connection chain (which requires starting the provider host on cold boot, costing hundreds of milliseconds to several seconds) is an unnecessary cost.
    // Return the same degraded text directly before the actual ExecQuery implementation, avoiding WMI connections.
    // The actual visible state of BitLocker is provided in the 'R0 Audit Supplement / BitLocker FVE' section of the Storage page.
    QString queryBitLockerVolumeText(const QString& driveLetter)
    {
        if (driveLetter.trimmed().isEmpty())
        {
            return QStringLiteral("BitLocker: <无盘符>");
        }

        return QStringLiteral("BitLocker WMI: 查询语句已准备，当前版本保留降级文本展示。");
    }
}
