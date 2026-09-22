#include "DiskEditorBackend.h"
#include "../../../../shared/ark_client/ArkDriverClient.h"
#include "../../Theme.h"

// ============================================================
// DiskEditorBackend.cpp
// Purpose:
// 1) Use Win32 API to read physical disk geometry, length, descriptors, and partition tables;
// 2) Provide a unified entry point for reading and writing bytes by offset.
// 3) The UI layer only consumes DiskDeviceInfo and does not directly process underlying Windows structures.
// ============================================================

#include <QColor>
#include <QStringList>
#include <QVariantMap>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winioctl.h>

#include <algorithm>
#include <array>
#include <string>

namespace
{
    using ks::misc::DiskDeviceInfo;
    using ks::misc::DiskPartitionInfo;
    using ks::misc::DiskPartitionKind;
    using ks::misc::DiskPartitionStyle;

    // Common GPT partition type GUIDs:
    // - Some SDK header files unstablely expose these constants;
    // - The locally defined const GUID is used only for comparison and does not pollute global symbols.
    constexpr GUID kGptBasicDataGuid =
        { 0xEBD0A0A2, 0xB9E5, 0x4433, { 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7 } };
    constexpr GUID kGptEfiSystemGuid =
        { 0xC12A7328, 0xF81F, 0x11D2, { 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B } };
    constexpr GUID kGptMsReservedGuid =
        { 0xE3C9E316, 0x0B5C, 0x4DB8, { 0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE } };
    constexpr GUID kGptRecoveryGuid =
        { 0xDE94BBA4, 0x06D1, 0x4D40, { 0xA1, 0x6A, 0xBF, 0xD5, 0x01, 0x79, 0xD6, 0xAC } };

    // kMaxPhysicalDriveProbeCount：
    // - Enumerates the probe limit for PhysicalDrive.
    // - Windows desktop environments are typically much smaller than this value.
    constexpr int kMaxPhysicalDriveProbeCount = 64;

    // toWide：
    // - Convert QString to Win32 wide string.
    // - text: Qt string
    // - Returns a std::wstring.
    std::wstring toWide(const QString& text)
    {
        return std::wstring(reinterpret_cast<const wchar_t*>(text.utf16()));
    }

    // lastWin32ErrorText：
    // - Format the most recent Win32 error code;
    // - prefix: operation description.
    // - Returns Chinese diagnostic text.
    QString lastWin32ErrorText(const QString& prefix)
    {
        return QStringLiteral("%1失败，Win32错误码=%2").arg(prefix).arg(::GetLastError());
    }

    // guidToText：
    // - Converts GUID to standard string format;
    // - guidValue: input GUID.
    // - Returns the text in {xxxxxxxx-...} format;
    // - Uses pure formatting to avoid the additional ole32 link dependency of StringFromGUID2.
    QString guidToText(const GUID& guidValue)
    {
        return QStringLiteral("{%1-%2-%3-%4%5-%6%7%8%9%10%11}")
            .arg(static_cast<qulonglong>(guidValue.Data1), 8, 16, QChar('0'))
            .arg(static_cast<unsigned int>(guidValue.Data2), 4, 16, QChar('0'))
            .arg(static_cast<unsigned int>(guidValue.Data3), 4, 16, QChar('0'))
            .arg(static_cast<unsigned int>(guidValue.Data4[0]), 2, 16, QChar('0'))
            .arg(static_cast<unsigned int>(guidValue.Data4[1]), 2, 16, QChar('0'))
            .arg(static_cast<unsigned int>(guidValue.Data4[2]), 2, 16, QChar('0'))
            .arg(static_cast<unsigned int>(guidValue.Data4[3]), 2, 16, QChar('0'))
            .arg(static_cast<unsigned int>(guidValue.Data4[4]), 2, 16, QChar('0'))
            .arg(static_cast<unsigned int>(guidValue.Data4[5]), 2, 16, QChar('0'))
            .arg(static_cast<unsigned int>(guidValue.Data4[6]), 2, 16, QChar('0'))
            .arg(static_cast<unsigned int>(guidValue.Data4[7]), 2, 16, QChar('0'))
            .toUpper();
    }

    // trimStorageString：
    // - Clean up ASCII fields in STORAGE_DEVICE_DESCRIPTOR.
    // - text: original string
    // - Returns the text with control characters and extra spaces removed.
    QString trimStorageString(const QString& text)
    {
        QString result = text;
        result.replace(QChar('\0'), QChar(' '));
        result = result.simplified();
        return result == QStringLiteral(".") ? QString() : result;
    }

    // storageBusTypeText：
    // - Convert STORAGE_BUS_TYPE to a user-friendly bus name;
    // - busType is a Win32 bus enumeration value;
    // - Returns text for SATA/NVMe/USB, etc.
    QString storageBusTypeText(const STORAGE_BUS_TYPE busType)
    {
        const int kRawBusType = static_cast<int>(busType);
        switch (kRawBusType)
        {
        case 0x01: return QStringLiteral("SCSI");
        case 0x02: return QStringLiteral("ATAPI");
        case 0x03: return QStringLiteral("ATA");
        case 0x04: return QStringLiteral("IEEE1394");
        case 0x05: return QStringLiteral("SSA");
        case 0x06: return QStringLiteral("Fibre");
        case 0x07: return QStringLiteral("USB");
        case 0x08: return QStringLiteral("RAID");
        case 0x09: return QStringLiteral("iSCSI");
        case 0x0A: return QStringLiteral("SAS");
        case 0x0B: return QStringLiteral("SATA");
        case 0x0C: return QStringLiteral("SD");
        case 0x0D: return QStringLiteral("MMC");
        case 0x0E: return QStringLiteral("Virtual");
        case 0x0F: return QStringLiteral("FileBackedVirtual");
        case 0x10: return QStringLiteral("Storage Spaces");
        case 0x11: return QStringLiteral("NVMe");
        case 0x12: return QStringLiteral("SCM");
        case 0x13: return QStringLiteral("UFS");
        default: break;
        }
        return QStringLiteral("未知");
    }

    // diskStyleFromWin32：
    // Convert PARTITION_STYLE to the project enum.
    // - style is a Win32 style.
    // - Returns DiskPartitionStyle.
    DiskPartitionStyle diskStyleFromWin32(const int style)
    {
        switch (static_cast<int>(style))
        {
        case 0: return DiskPartitionStyle::kMbr;
        case 1: return DiskPartitionStyle::kGpt;
        case 2: return DiskPartitionStyle::kRaw;
        default: break;
        }
        return DiskPartitionStyle::kUnknown;
    }

    // isGuidEqual：
    // - Compare whether two GUIDs are equal;
    // - left/right are input GUIDs.
    // - Returns true if they are exactly equal.
    bool isGuidEqual(const GUID& left, const GUID& right)
    {
        return ::IsEqualGUID(left, right) != FALSE;
    }

    // partitionKindFromGptType：
    // - Classify based on GPT type GUID.
    // - typeGuid is the GPT PartitionType;
    // - Returns the classification used for UI coloring.
    DiskPartitionKind partitionKindFromGptType(const GUID& typeGuid)
    {
        if (isGuidEqual(typeGuid, kGptEfiSystemGuid))
        {
            return DiskPartitionKind::kSystem;
        }
        if (isGuidEqual(typeGuid, kGptMsReservedGuid))
        {
            return DiskPartitionKind::kReserved;
        }
        if (isGuidEqual(typeGuid, kGptRecoveryGuid))
        {
            return DiskPartitionKind::kRecovery;
        }
        if (isGuidEqual(typeGuid, kGptBasicDataGuid))
        {
            return DiskPartitionKind::kBasicData;
        }
        return DiskPartitionKind::kUnknown;
    }

    // partitionTypeTextFromGpt：
    // - Convert GPT type GUID to Chinese description;
    // - typeGuid is the GPT PartitionType;
    // - Returns displayable text.
    QString partitionTypeTextFromGpt(const GUID& typeGuid)
    {
        if (isGuidEqual(typeGuid, kGptBasicDataGuid))
        {
            return QStringLiteral("GPT 基本数据");
        }
        if (isGuidEqual(typeGuid, kGptEfiSystemGuid))
        {
            return QStringLiteral("EFI 系统分区");
        }
        if (isGuidEqual(typeGuid, kGptMsReservedGuid))
        {
            return QStringLiteral("Microsoft 保留分区");
        }
        if (isGuidEqual(typeGuid, kGptRecoveryGuid))
        {
            return QStringLiteral("Windows 恢复分区");
        }
        return QStringLiteral("GPT %1").arg(guidToText(typeGuid));
    }

    // partitionKindFromMbrType：
    // - Classify based on the MBR type byte;
    // - typeByte: MBR PartitionType.
    // - Returns the classification used for UI coloring.
    DiskPartitionKind partitionKindFromMbrType(const BYTE typeByte)
    {
        switch (typeByte)
        {
        case 0x01:
        case 0x04:
        case 0x06:
        case 0x07:
        case 0x0B:
        case 0x0C:
        case 0x0E:
        case 0x0F:
            return DiskPartitionKind::kBasicData;
        case 0xEF:
            return DiskPartitionKind::kSystem;
        case 0x27:
            return DiskPartitionKind::kRecovery;
        case 0x42:
            return DiskPartitionKind::kReserved;
        case 0x82:
        case 0x83:
        case 0x8E:
            return DiskPartitionKind::kLinux;
        default:
            break;
        }
        return DiskPartitionKind::kUnknown;
    }

    // partitionTypeTextFromMbr：
    // - Convert MBR type byte to text.
    // - typeByte: MBR PartitionType.
    // - Returns displayable text.
    QString partitionTypeTextFromMbr(const BYTE typeByte)
    {
        switch (typeByte)
        {
        case 0x01: return QStringLiteral("MBR FAT12 (0x01)");
        case 0x04: return QStringLiteral("MBR FAT16 (0x04)");
        case 0x06: return QStringLiteral("MBR FAT16 扩展 (0x06)");
        case 0x07: return QStringLiteral("MBR NTFS/exFAT/HPFS (0x07)");
        case 0x0B: return QStringLiteral("MBR FAT32 (0x0B)");
        case 0x0C: return QStringLiteral("MBR FAT32 LBA (0x0C)");
        case 0x0E: return QStringLiteral("MBR FAT16 LBA (0x0E)");
        case 0x0F: return QStringLiteral("MBR 扩展 LBA (0x0F)");
        case 0xEF: return QStringLiteral("MBR EFI 系统 (0xEF)");
        case 0x27: return QStringLiteral("MBR 恢复/OEM (0x27)");
        case 0x82: return QStringLiteral("MBR Linux Swap (0x82)");
        case 0x83: return QStringLiteral("MBR Linux 文件系统 (0x83)");
        case 0x8E: return QStringLiteral("MBR Linux LVM (0x8E)");
        default: break;
        }
        return QStringLiteral("MBR 类型 0x%1").arg(static_cast<unsigned int>(typeByte), 2, 16, QChar('0')).toUpper();
    }

    // partitionColor：
    // - Return bar chart color based on partition type;
    // - kind is a semantic classification;
    // - Returns a QColor.
    QColor partitionColor(const DiskPartitionKind kind)
    {
        switch (kind)
        {
        case DiskPartitionKind::kBasicData:
            return ksword_theme::accentColor(ksword_theme::AccentRole::kBlue);
        case DiskPartitionKind::kSystem:
            return ksword_theme::successColor();
        case DiskPartitionKind::kReserved:
            return ksword_theme::accentColor(ksword_theme::AccentRole::kSlate);
        case DiskPartitionKind::kRecovery:
            return ksword_theme::warningColor();
        case DiskPartitionKind::kLinux:
            return ksword_theme::accentColor(ksword_theme::AccentRole::kPurple);
        case DiskPartitionKind::kUnallocated:
            return ksword_theme::textSecondaryColor();
        default: break;
        }
        return ksword_theme::accentColor(ksword_theme::AccentRole::kTeal);
    }

    // openDiskHandle：
    // - Open physical disk;
    // - writeAccess: Controls whether write access is requested;
    // - errorTextOut returns the failure diagnosis.
    // - Returns a Win32 HANDLE; returns INVALID_HANDLE_VALUE on failure.
    HANDLE openDiskHandle(
        const QString& devicePath,
        const bool writeAccess,
        QString& errorTextOut)
    {
        const DWORD kDesiredAccess = writeAccess
            ? (GENERIC_READ | GENERIC_WRITE)
            : GENERIC_READ;
        const std::wstring kDevicePathWide = toWide(devicePath);
        HANDLE handleValue = ::CreateFileW(
            kDevicePathWide.c_str(),
            kDesiredAccess,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (handleValue == INVALID_HANDLE_VALUE)
        {
            errorTextOut = lastWin32ErrorText(QStringLiteral("打开 %1").arg(devicePath));
        }
        return handleValue;
    }

    // readStorageDescriptor：
    // - Read the STORAGE_DEVICE_DESCRIPTOR and populate the model, manufacturer, serial number, and bus.
    // - handleValue is an opened disk handle;
    // - diskInfo is the structure to be populated;
    // - No return value; fields remain empty on failure.
    void readStorageDescriptor(const HANDLE handleValue, DiskDeviceInfo& diskInfo)
    {
        STORAGE_PROPERTY_QUERY query{};
        query.PropertyId = StorageDeviceProperty;
        query.QueryType = PropertyStandardQuery;

        STORAGE_DESCRIPTOR_HEADER header{};
        DWORD returnedBytes = 0;
        if (::DeviceIoControl(
            handleValue,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &query,
            static_cast<DWORD>(sizeof(query)),
            &header,
            static_cast<DWORD>(sizeof(header)),
            &returnedBytes,
            nullptr) == FALSE
            || header.Size < sizeof(STORAGE_DEVICE_DESCRIPTOR))
        {
            return;
        }

        std::vector<std::uint8_t> buffer(header.Size + 8ULL);
        returnedBytes = 0;
        if (::DeviceIoControl(
            handleValue,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &query,
            static_cast<DWORD>(sizeof(query)),
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &returnedBytes,
            nullptr) == FALSE)
        {
            return;
        }

        const STORAGE_DEVICE_DESCRIPTOR* descriptor =
            reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buffer.data());
        const char* basePtr = reinterpret_cast<const char*>(buffer.data());
        const auto kReadOffsetString = [&](const DWORD offsetValue) -> QString
        {
            if (offsetValue == 0 || offsetValue >= returnedBytes)
            {
                return QString();
            }

            const char* textStart = basePtr + offsetValue;
            const DWORD kRemainingBytes = returnedBytes - offsetValue;
            DWORD textLength = 0;
            while (textLength < kRemainingBytes && textStart[textLength] != '\0')
            {
                ++textLength;
            }
            return trimStorageString(QString::fromLatin1(textStart, static_cast<int>(textLength)));
        };

        diskInfo.vendor = kReadOffsetString(descriptor->VendorIdOffset);
        diskInfo.model = kReadOffsetString(descriptor->ProductIdOffset);
        diskInfo.serial = kReadOffsetString(descriptor->SerialNumberOffset);
        diskInfo.busType = storageBusTypeText(descriptor->BusType);
        diskInfo.removable = descriptor->RemovableMedia != FALSE;
    }

    // readDiskGeometry：
    // - Read disk geometry and sector size.
    // - handleValue is the disk handle;
    // - diskInfo is the structure to be populated;
    // - No return value.
    void readDiskGeometry(const HANDLE handleValue, DiskDeviceInfo& diskInfo)
    {
        DISK_GEOMETRY_EX geometry{};
        DWORD returnedBytes = 0;
        if (::DeviceIoControl(
            handleValue,
            IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
            nullptr,
            0,
            &geometry,
            static_cast<DWORD>(sizeof(geometry)),
            &returnedBytes,
            nullptr) != FALSE)
        {
            diskInfo.sizeBytes = static_cast<std::uint64_t>(geometry.DiskSize.QuadPart);
            diskInfo.bytesPerSector = geometry.Geometry.BytesPerSector == 0
                ? 512U
                : geometry.Geometry.BytesPerSector;
            switch (geometry.Geometry.MediaType)
            {
            case FixedMedia: diskInfo.mediaType = QStringLiteral("固定磁盘"); break;
            case RemovableMedia: diskInfo.mediaType = QStringLiteral("可移动磁盘"); break;
            default: diskInfo.mediaType = QStringLiteral("介质类型 %1").arg(static_cast<int>(geometry.Geometry.MediaType)); break;
            }
        }

        // Physical bytes per sector:
        // - different SDKs have inconsistent exposure conditions for STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR;
        // Write protection on the current page is based on logical sectors; physical sectors can be supplemented later in a dedicated compatibility layer.
        diskInfo.physicalBytesPerSector = diskInfo.bytesPerSector;
    }

    // appendUnallocatedRanges：
    // - Fill in unallocated regions based on partition usage ranges;
    // - diskInfo is the current disk information;
    // - No return value; directly appends to partitions.
    void appendUnallocatedRanges(DiskDeviceInfo& diskInfo)
    {
        if (diskInfo.sizeBytes == 0)
        {
            return;
        }

        std::sort(
            diskInfo.partitions.begin(),
            diskInfo.partitions.end(),
            [](const DiskPartitionInfo& left, const DiskPartitionInfo& right)
            {
                return left.offsetBytes < right.offsetBytes;
            });

        std::vector<DiskPartitionInfo> withGaps;
        std::uint64_t cursor = 0;
        int generatedIndex = 0;
        for (DiskPartitionInfo partition : diskInfo.partitions)
        {
            if (partition.offsetBytes > cursor)
            {
                DiskPartitionInfo gap;
                gap.tableIndex = generatedIndex++;
                gap.partitionNumber = 0;
                gap.style = diskInfo.partitionStyle;
                gap.kind = DiskPartitionKind::kUnallocated;
                gap.name = QStringLiteral("未分配");
                gap.typeText = QStringLiteral("未分配空间");
                gap.offsetBytes = cursor;
                gap.lengthBytes = partition.offsetBytes - cursor;
                gap.color = partitionColor(gap.kind);
                withGaps.push_back(gap);
            }

            partition.tableIndex = generatedIndex++;
            partition.color = partitionColor(partition.kind);
            withGaps.push_back(partition);
            const std::uint64_t kEndOffset = partition.offsetBytes + partition.lengthBytes;
            cursor = std::max(cursor, kEndOffset);
        }

        if (cursor < diskInfo.sizeBytes)
        {
            DiskPartitionInfo gap;
            gap.tableIndex = generatedIndex++;
            gap.partitionNumber = 0;
            gap.style = diskInfo.partitionStyle;
            gap.kind = DiskPartitionKind::kUnallocated;
            gap.name = QStringLiteral("未分配");
            gap.typeText = QStringLiteral("未分配空间");
            gap.offsetBytes = cursor;
            gap.lengthBytes = diskInfo.sizeBytes - cursor;
            gap.color = partitionColor(gap.kind);
            withGaps.push_back(gap);
        }

        diskInfo.partitions = std::move(withGaps);
    }

    // readDriveLayout：
    // - Read DRIVE_LAYOUT_INFORMATION_EX and convert to DiskPartitionInfo;
    // - handleValue is the disk handle;
    // - diskInfo is the structure to be populated;
    // - No return value; retains existing basic information on failure.
    void readDriveLayout(const HANDLE handleValue, DiskDeviceInfo& diskInfo)
    {
        DWORD bufferBytes = 64U * 1024U;
        for (int attempt = 0; attempt < 4; ++attempt)
        {
            std::vector<std::uint8_t> buffer(bufferBytes);
            DWORD returnedBytes = 0;
            const BOOL kLayoutOk = ::DeviceIoControl(
                handleValue,
                IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                nullptr,
                0,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &returnedBytes,
                nullptr);
            if (kLayoutOk == FALSE)
            {
                const DWORD kErrorCode = ::GetLastError();
                if (kErrorCode == ERROR_INSUFFICIENT_BUFFER || kErrorCode == ERROR_MORE_DATA)
                {
                    bufferBytes *= 2U;
                    continue;
                }
                return;
            }

            if (returnedBytes < sizeof(DRIVE_LAYOUT_INFORMATION_EX))
            {
                return;
            }

            const DRIVE_LAYOUT_INFORMATION_EX* layout =
                reinterpret_cast<const DRIVE_LAYOUT_INFORMATION_EX*>(buffer.data());
            diskInfo.partitionStyle = diskStyleFromWin32(static_cast<int>(layout->PartitionStyle));
            diskInfo.partitions.clear();
            diskInfo.partitions.reserve(layout->PartitionCount);

            for (DWORD index = 0; index < layout->PartitionCount; ++index)
            {
                const PARTITION_INFORMATION_EX& source = layout->PartitionEntry[index];
                if (source.PartitionLength.QuadPart <= 0)
                {
                    continue;
                }

                DiskPartitionInfo partition;
                partition.tableIndex = static_cast<int>(diskInfo.partitions.size());
                partition.partitionNumber = static_cast<int>(source.PartitionNumber);
                partition.style = diskStyleFromWin32(static_cast<int>(source.PartitionStyle));
                partition.offsetBytes = static_cast<std::uint64_t>(source.StartingOffset.QuadPart);
                partition.lengthBytes = static_cast<std::uint64_t>(source.PartitionLength.QuadPart);
                partition.name = QStringLiteral("分区 %1").arg(partition.partitionNumber);

                if (static_cast<int>(source.PartitionStyle) == 0)
                {
                    partition.kind = partitionKindFromMbrType(source.Mbr.PartitionType);
                    partition.typeText = partitionTypeTextFromMbr(source.Mbr.PartitionType);
                    partition.bootIndicator = source.Mbr.BootIndicator != FALSE;
                    partition.recognized = source.Mbr.RecognizedPartition != FALSE;
                    QStringList flags;
                    if (partition.bootIndicator)
                    {
                        flags << QStringLiteral("活动");
                    }
                    if (source.Mbr.HiddenSectors != 0)
                    {
                        flags << QStringLiteral("隐藏扇区=%1").arg(source.Mbr.HiddenSectors);
                    }
                    if (partition.recognized)
                    {
                        flags << QStringLiteral("已识别");
                    }
                    partition.flagsText = flags.join(QStringLiteral(", "));
                }
                else if (static_cast<int>(source.PartitionStyle) == 1)
                {
                    partition.kind = partitionKindFromGptType(source.Gpt.PartitionType);
                    partition.typeText = partitionTypeTextFromGpt(source.Gpt.PartitionType);
                    partition.uniqueIdText = guidToText(source.Gpt.PartitionId);
                    const QString kGptName = QString::fromWCharArray(source.Gpt.Name, 36).trimmed();
                    if (!kGptName.isEmpty())
                    {
                        partition.name = kGptName;
                    }
                    QStringList flags;
                    if (source.Gpt.Attributes != 0)
                    {
                        flags << QStringLiteral("属性=0x%1")
                            .arg(static_cast<qulonglong>(source.Gpt.Attributes), 16, 16, QChar('0'));
                    }
                    partition.flagsText = flags.join(QStringLiteral(", "));
                    partition.recognized = true;
                }

                partition.color = partitionColor(partition.kind);
                diskInfo.partitions.push_back(std::move(partition));
            }

            appendUnallocatedRanges(diskInfo);
            return;
        }
    }

    // buildDisplayName：
    // - Construct a friendly disk display name.
    // - diskInfo contains disk information;
    // - Return the text for the UI dropdown.
    QString buildDisplayName(const DiskDeviceInfo& diskInfo)
    {
        const QString kModelText = diskInfo.model.isEmpty()
            ? QStringLiteral("未知型号")
            : diskInfo.model;
        const QString kSizeText = ks::misc::DiskEditorBackend::formatBytes(diskInfo.sizeBytes);
        return QStringLiteral("PhysicalDrive%1  %2  %3")
            .arg(diskInfo.diskIndex)
            .arg(kModelText)
            .arg(kSizeText);
    }

    // openVolumeHandle：
    // - Open the volume handle corresponding to the \\?\Volume{...} path;
    // - volumeName comes from FindFirstVolumeW;
    // - errorTextOut returns the failure diagnosis.
    // - Returns a Win32 HANDLE.
    HANDLE openVolumeHandle(const QString& volumeName, QString& errorTextOut)
    {
        QString path = volumeName;
        if (path.endsWith(QChar('\\')))
        {
            path.chop(1);
        }
        HANDLE handleValue = ::CreateFileW(
            toWide(path).c_str(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (handleValue == INVALID_HANDLE_VALUE)
        {
            errorTextOut = lastWin32ErrorText(QStringLiteral("打开卷 %1").arg(volumeName));
        }
        return handleValue;
    }

    // collectMountPoints：
    // - Query volume mount points and drive letters;
    // - volumeName is \\?\Volume{GUID}\;
    // - Return the concatenated mount point text.
    QString collectMountPoints(const QString& volumeName)
    {
        DWORD requiredChars = 0;
        ::GetVolumePathNamesForVolumeNameW(
            toWide(volumeName).c_str(),
            nullptr,
            0,
            &requiredChars);
        if (requiredChars == 0)
        {
            return QString();
        }

        std::vector<wchar_t> buffer(requiredChars + 2U);
        if (::GetVolumePathNamesForVolumeNameW(
            toWide(volumeName).c_str(),
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &requiredChars) == FALSE)
        {
            return QString();
        }

        QStringList paths;
        const wchar_t* cursor = buffer.data();
        while (*cursor != L'\0')
        {
            const QString kPath = QString::fromWCharArray(cursor);
            if (!kPath.isEmpty())
            {
                paths << kPath;
            }
            cursor += kPath.size() + 1;
        }
        return paths.join(QStringLiteral(", "));
    }

    // collectVolumeInformation：
    // - Read volume label and file system name.
    // - volumeName is \\?\Volume{GUID}\;
    // - labelOut/fileSystemOut receive the results
    void collectVolumeInformation(const QString& volumeName, QString& labelOut, QString& fileSystemOut)
    {
        std::array<wchar_t, MAX_PATH + 1> labelBuffer{};
        std::array<wchar_t, MAX_PATH + 1> fsBuffer{};
        DWORD serialNumber = 0;
        DWORD maxComponentLength = 0;
        DWORD flags = 0;
        if (::GetVolumeInformationW(
            toWide(volumeName).c_str(),
            labelBuffer.data(),
            static_cast<DWORD>(labelBuffer.size()),
            &serialNumber,
            &maxComponentLength,
            &flags,
            fsBuffer.data(),
            static_cast<DWORD>(fsBuffer.size())) != FALSE)
        {
            labelOut = QString::fromWCharArray(labelBuffer.data());
            fileSystemOut = QString::fromWCharArray(fsBuffer.data());
        }
    }

    // collectVolumeDevicePath：
    // - Use QueryDosDevice to query the NT device path corresponding to the volume GUID.
    // - volumeName is \\?\Volume{GUID}\;
    // - Returns the text \Device\HarddiskVolumeX; returns empty on failure.
    QString collectVolumeDevicePath(const QString& volumeName)
    {
        QString dosName = volumeName;
        if (dosName.startsWith(QStringLiteral("\\\\?\\")))
        {
            dosName = dosName.mid(4);
        }
        if (dosName.endsWith(QChar('\\')))
        {
            dosName.chop(1);
        }

        std::array<wchar_t, 1024> targetBuffer{};
        const DWORD kChars = ::QueryDosDeviceW(
            toWide(dosName).c_str(),
            targetBuffer.data(),
            static_cast<DWORD>(targetBuffer.size()));
        if (kChars == 0)
        {
            return QString();
        }
        return QString::fromWCharArray(targetBuffer.data());
    }

    // boolText：
    // - Convert boolean values to Yes/No.
    // - value is the input boolean.
    // - Returns Chinese text.
    QString boolText(const bool value)
    {
        return value ? QStringLiteral("是") : QStringLiteral("否");
    }

    // addHealthMap：
    // - Appends a row to the QVariantMap health list;
    // - severity convention: 0=Information, 1=Warning, 2=Error;
    // - No return value.
    void addHealthMap(
        std::vector<QVariantMap>& items,
        const QString& category,
        const QString& name,
        const QString& value,
        const QString& detail,
        const int severity = 0)
    {
        QVariantMap item;
        item.insert(QStringLiteral("category"), category);
        item.insert(QStringLiteral("name"), name);
        item.insert(QStringLiteral("value"), value);
        item.insert(QStringLiteral("detail"), detail);
        item.insert(QStringLiteral("severity"), severity);
        items.push_back(std::move(item));
    }
}

namespace ks::misc
{
    bool DiskEditorBackend::enumerateDisks(
        std::vector<DiskDeviceInfo>& disksOut,
        QString& errorTextOut)
    {
        disksOut.clear();
        errorTextOut.clear();
        int missingStreak = 0;

        for (int diskIndex = 0; diskIndex < kMaxPhysicalDriveProbeCount; ++diskIndex)
        {
            DiskDeviceInfo diskInfo;
            diskInfo.diskIndex = diskIndex;
            diskInfo.devicePath = QStringLiteral("\\\\.\\PhysicalDrive%1").arg(diskIndex);

            QString openErrorText;
            HANDLE handleValue = openDiskHandle(diskInfo.devicePath, false, openErrorText);
            if (handleValue == INVALID_HANDLE_VALUE)
            {
                const DWORD kErrorCode = ::GetLastError();
                if (kErrorCode == ERROR_FILE_NOT_FOUND || kErrorCode == ERROR_PATH_NOT_FOUND)
                {
                    ++missingStreak;
                    if (missingStreak >= 8 && !disksOut.empty())
                    {
                        break;
                    }
                    continue;
                }

                diskInfo.openErrorText = openErrorText;
                diskInfo.displayName = QStringLiteral("PhysicalDrive%1  打开失败").arg(diskIndex);
                disksOut.push_back(std::move(diskInfo));
                missingStreak = 0;
                continue;
            }

            missingStreak = 0;
            diskInfo.canRead = true;
            readStorageDescriptor(handleValue, diskInfo);
            readDiskGeometry(handleValue, diskInfo);
            readDriveLayout(handleValue, diskInfo);
            const ksword::ark::RawDiskBackendResult kBackendResult =
                ksword::ark::DriverClient().queryRawDiskBackend(
                    static_cast<unsigned long>(diskIndex));
            if (kBackendResult.io.ok)
            {
                diskInfo.rawBackendMask = kBackendResult.response.availableBackendMask;
                diskInfo.rawCapabilityFlags = kBackendResult.response.capabilityFlags;
                diskInfo.rawBackendDetail = QString::fromWCharArray(kBackendResult.response.detail);
                if (kBackendResult.response.logicalSectorSize != 0U)
                {
                    diskInfo.bytesPerSector = kBackendResult.response.logicalSectorSize;
                }
                if (kBackendResult.response.physicalSectorSize != 0U)
                {
                    diskInfo.physicalBytesPerSector = kBackendResult.response.physicalSectorSize;
                }
            }
            else
            {
                diskInfo.rawBackendMask = 1U;
                diskInfo.rawBackendDetail = QStringLiteral("R0 后端不可用；仅保留 Windows 存储栈兼容读取。");
            }
            diskInfo.displayName = buildDisplayName(diskInfo);
            ::CloseHandle(handleValue);

            disksOut.push_back(std::move(diskInfo));
        }

        if (disksOut.empty())
        {
            errorTextOut = QStringLiteral("未枚举到 PhysicalDrive 设备。");
            return false;
        }
        return true;
    }

    bool DiskEditorBackend::readBytes(
        const QString& devicePath,
        const std::uint64_t offsetBytes,
        const std::uint32_t bytesToRead,
        QByteArray& bytesOut,
        QString& errorTextOut)
    {
        bytesOut.clear();
        errorTextOut.clear();
        if (devicePath.trimmed().isEmpty())
        {
            errorTextOut = QStringLiteral("磁盘设备路径为空。");
            return false;
        }
        if (bytesToRead == 0)
        {
            errorTextOut = QStringLiteral("读取长度为 0。");
            return false;
        }

        QString openErrorText;
        HANDLE handleValue = openDiskHandle(devicePath, false, openErrorText);
        if (handleValue == INVALID_HANDLE_VALUE)
        {
            errorTextOut = openErrorText;
            return false;
        }

        LARGE_INTEGER targetOffset{};
        targetOffset.QuadPart = static_cast<LONGLONG>(offsetBytes);
        if (::SetFilePointerEx(handleValue, targetOffset, nullptr, FILE_BEGIN) == FALSE)
        {
            errorTextOut = lastWin32ErrorText(QStringLiteral("设置读取偏移"));
            ::CloseHandle(handleValue);
            return false;
        }

        QByteArray buffer;
        buffer.resize(static_cast<int>(bytesToRead));
        DWORD readBytesValue = 0;
        if (::ReadFile(
            handleValue,
            buffer.data(),
            bytesToRead,
            &readBytesValue,
            nullptr) == FALSE)
        {
            errorTextOut = lastWin32ErrorText(QStringLiteral("读取磁盘字节"));
            ::CloseHandle(handleValue);
            return false;
        }
        ::CloseHandle(handleValue);

        buffer.resize(static_cast<int>(readBytesValue));
        bytesOut = buffer;
        return true;
    }

    bool DiskEditorBackend::readBytesWithBackend(
        const int diskIndex,
        const unsigned long backend,
        const std::uint64_t offsetBytes,
        const std::uint32_t bytesToRead,
        QByteArray& bytesOut,
        QString& errorTextOut)
    {
        bytesOut.clear();
        errorTextOut.clear();
        if (diskIndex < 0
            || backend < KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK
            || backend > KSWORD_ARK_RAW_DISK_BACKEND_CONTROLLER)
        {
            errorTextOut = QStringLiteral("磁盘号或访问层无效。");
            return false;
        }

        const ksword::ark::RawDiskReadResult kResult =
            ksword::ark::DriverClient().readRawDisk(
                static_cast<unsigned long>(diskIndex),
                backend,
                offsetBytes,
                bytesToRead,
                backend == KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK
                    ? 0UL
                    : KSWORD_ARK_RAW_DISK_FLAG_ALLOW_SYSTEM_DISK_READ);
        if (!kResult.io.ok)
        {
            if (backend == KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK
                && kResult.unsupported)
            {
                return readBytes(
                    QStringLiteral("\\\\.\\PhysicalDrive%1").arg(diskIndex),
                    offsetBytes,
                    bytesToRead,
                    bytesOut,
                    errorTextOut);
            }

            errorTextOut = QStringLiteral(
                "R0 磁盘读取失败：访问层=%1，协议状态=%2，NTSTATUS=0x%3，Win32=%4。")
                .arg(backend)
                .arg(kResult.status)
                .arg(static_cast<qulonglong>(
                    static_cast<unsigned long>(kResult.io.ntStatus)),
                    8,
                    16,
                    QChar('0'))
                .arg(kResult.io.win32Error)
                .toUpper();
            return false;
        }

        bytesOut = QByteArray(
            reinterpret_cast<const char*>(kResult.bytes.data()),
            static_cast<int>(kResult.bytes.size()));
        return true;
    }

    bool DiskEditorBackend::writeBytes(
        const QString& devicePath,
        const std::uint64_t offsetBytes,
        const QByteArray& bytes,
        const std::uint32_t bytesPerSector,
        const bool requireSectorAligned,
        QString& errorTextOut)
    {
        errorTextOut.clear();
        if (devicePath.trimmed().isEmpty())
        {
            errorTextOut = QStringLiteral("磁盘设备路径为空。");
            return false;
        }
        if (bytes.isEmpty())
        {
            errorTextOut = QStringLiteral("写入缓冲区为空。");
            return false;
        }

        const std::uint32_t kSectorSize = bytesPerSector == 0 ? 512U : bytesPerSector;
        if (requireSectorAligned)
        {
            if ((offsetBytes % kSectorSize) != 0
                || (static_cast<std::uint64_t>(bytes.size()) % kSectorSize) != 0)
            {
                errorTextOut = QStringLiteral("写入被拒绝：偏移和长度必须按 %1 字节扇区对齐。").arg(kSectorSize);
                return false;
            }
        }

        QString openErrorText;
        HANDLE handleValue = openDiskHandle(devicePath, true, openErrorText);
        if (handleValue == INVALID_HANDLE_VALUE)
        {
            errorTextOut = openErrorText;
            return false;
        }

        LARGE_INTEGER targetOffset{};
        targetOffset.QuadPart = static_cast<LONGLONG>(offsetBytes);
        if (::SetFilePointerEx(handleValue, targetOffset, nullptr, FILE_BEGIN) == FALSE)
        {
            errorTextOut = lastWin32ErrorText(QStringLiteral("设置写入偏移"));
            ::CloseHandle(handleValue);
            return false;
        }

        DWORD writtenBytes = 0;
        const DWORD kRequestedBytes = static_cast<DWORD>(bytes.size());
        if (::WriteFile(
            handleValue,
            bytes.constData(),
            kRequestedBytes,
            &writtenBytes,
            nullptr) == FALSE)
        {
            errorTextOut = lastWin32ErrorText(QStringLiteral("写入磁盘字节"));
            ::CloseHandle(handleValue);
            return false;
        }

        ::FlushFileBuffers(handleValue);
        ::CloseHandle(handleValue);

        if (writtenBytes != kRequestedBytes)
        {
            errorTextOut = QStringLiteral("写入长度不足：期望 %1 字节，实际 %2 字节。")
                .arg(kRequestedBytes)
                .arg(writtenBytes);
            return false;
        }
        return true;
    }

    bool DiskEditorBackend::writeBytesWithBackend(
        const int diskIndex,
        const unsigned long backend,
        const std::uint64_t offsetBytes,
        const QByteArray& bytes,
        const unsigned long callerFlags,
        QString& errorTextOut)
    {
        errorTextOut.clear();
        if (diskIndex < 0
            || backend < KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK
            || backend > KSWORD_ARK_RAW_DISK_BACKEND_CONTROLLER
            || bytes.isEmpty())
        {
            errorTextOut = QStringLiteral("磁盘号、访问层或写入数据无效。");
            return false;
        }

        std::vector<std::uint8_t> requestBytes(
            reinterpret_cast<const std::uint8_t*>(bytes.constData()),
            reinterpret_cast<const std::uint8_t*>(bytes.constData()) + bytes.size());
        const ksword::ark::RawDiskWriteResult kResult =
            ksword::ark::DriverClient().writeRawDisk(
                static_cast<unsigned long>(diskIndex),
                backend,
                offsetBytes,
                requestBytes,
                callerFlags);
        if (!kResult.io.ok
            || kResult.response.status != KSWORD_ARK_RAW_DISK_STATUS_OK
            || kResult.response.bytesTransferred != static_cast<unsigned long>(bytes.size()))
        {
            errorTextOut = QStringLiteral(
                "R0 磁盘写入失败：访问层=%1，协议状态=%2，完成=%3/%4，NTSTATUS=0x%5，Win32=%6。")
                .arg(backend)
                .arg(kResult.response.status)
                .arg(kResult.response.bytesTransferred)
                .arg(bytes.size())
                .arg(static_cast<qulonglong>(
                    static_cast<unsigned long>(kResult.io.ntStatus)),
                    8,
                    16,
                    QChar('0'))
                .arg(kResult.io.win32Error)
                .toUpper();
            return false;
        }
        return true;
    }

    std::vector<QVariantMap> DiskEditorBackend::queryVolumeMappings(
        const int diskIndex,
        QString& errorTextOut)
    {
        std::vector<QVariantMap> volumes;
        errorTextOut.clear();

        std::array<wchar_t, MAX_PATH> volumeNameBuffer{};
        HANDLE findHandle = ::FindFirstVolumeW(volumeNameBuffer.data(), static_cast<DWORD>(volumeNameBuffer.size()));
        if (findHandle == INVALID_HANDLE_VALUE)
        {
            errorTextOut = lastWin32ErrorText(QStringLiteral("枚举卷"));
            return volumes;
        }

        for (;;)
        {
            const QString kVolumeName = QString::fromWCharArray(volumeNameBuffer.data());
            QString openError;
            HANDLE volumeHandle = openVolumeHandle(kVolumeName, openError);
            if (volumeHandle != INVALID_HANDLE_VALUE)
            {
                DWORD returnedBytes = 0;
                constexpr DWORD kExtentBufferBytes = sizeof(VOLUME_DISK_EXTENTS) + sizeof(DISK_EXTENT) * 31U;
                std::array<unsigned char, kExtentBufferBytes> extentBuffer{};
                if (::DeviceIoControl(
                    volumeHandle,
                    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                    nullptr,
                    0,
                    extentBuffer.data(),
                    static_cast<DWORD>(extentBuffer.size()),
                    &returnedBytes,
                    nullptr) != FALSE
                    && returnedBytes >= sizeof(VOLUME_DISK_EXTENTS))
                {
                    const auto* extents = reinterpret_cast<const VOLUME_DISK_EXTENTS*>(extentBuffer.data());
                    QString label;
                    QString fileSystem;
                    collectVolumeInformation(kVolumeName, label, fileSystem);
                    const QString kMountPoints = collectMountPoints(kVolumeName);
                    const QString kDevicePath = collectVolumeDevicePath(kVolumeName);
                    for (DWORD index = 0; index < extents->NumberOfDiskExtents; ++index)
                    {
                        const DISK_EXTENT& extent = extents->Extents[index];
                        if (static_cast<int>(extent.DiskNumber) != diskIndex)
                        {
                            continue;
                        }

                        QVariantMap volume;
                        volume.insert(QStringLiteral("volumeName"), kVolumeName);
                        volume.insert(QStringLiteral("mountPoints"), kMountPoints);
                        volume.insert(QStringLiteral("devicePath"), kDevicePath);
                        volume.insert(QStringLiteral("fileSystem"), fileSystem);
                        volume.insert(QStringLiteral("label"), label);
                        volume.insert(QStringLiteral("diskNumber"), static_cast<int>(extent.DiskNumber));
                        volume.insert(QStringLiteral("offsetBytes"), static_cast<qulonglong>(extent.StartingOffset.QuadPart));
                        volume.insert(QStringLiteral("lengthBytes"), static_cast<qulonglong>(extent.ExtentLength.QuadPart));
                        volumes.push_back(std::move(volume));
                    }
                }
                ::CloseHandle(volumeHandle);
            }

            volumeNameBuffer.fill(L'\0');
            if (::FindNextVolumeW(findHandle, volumeNameBuffer.data(), static_cast<DWORD>(volumeNameBuffer.size())) == FALSE)
            {
                const DWORD kErrorCode = ::GetLastError();
                if (kErrorCode != ERROR_NO_MORE_FILES)
                {
                    errorTextOut = QStringLiteral("继续枚举卷失败，Win32错误码=%1").arg(kErrorCode);
                }
                break;
            }
        }

        ::FindVolumeClose(findHandle);
        return volumes;
    }

    std::vector<QVariantMap> DiskEditorBackend::queryHealthItems(
        const QString& devicePath,
        QString& errorTextOut)
    {
        std::vector<QVariantMap> items;
        errorTextOut.clear();

        HANDLE handleValue = ::CreateFileW(
            toWide(devicePath).c_str(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (handleValue == INVALID_HANDLE_VALUE)
        {
            errorTextOut = lastWin32ErrorText(QStringLiteral("打开磁盘做健康探测"));
            addHealthMap(items, QStringLiteral("探测"), QStringLiteral("只读句柄"), QStringLiteral("失败"), errorTextOut, 1);
            return items;
        }

        STORAGE_PROPERTY_QUERY query{};
        query.PropertyId = StorageDeviceTrimProperty;
        query.QueryType = PropertyStandardQuery;
        DEVICE_TRIM_DESCRIPTOR trimDescriptor{};
        DWORD returnedBytes = 0;
        if (::DeviceIoControl(
            handleValue,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &query,
            static_cast<DWORD>(sizeof(query)),
            &trimDescriptor,
            static_cast<DWORD>(sizeof(trimDescriptor)),
            &returnedBytes,
            nullptr) != FALSE)
        {
            addHealthMap(items, QStringLiteral("能力"), QStringLiteral("TRIM/UNMAP"), boolText(trimDescriptor.TrimEnabled != FALSE), QStringLiteral("StorageDeviceTrimProperty"));
        }
        else
        {
            addHealthMap(items, QStringLiteral("能力"), QStringLiteral("TRIM/UNMAP"), QStringLiteral("未知"), lastWin32ErrorText(QStringLiteral("查询 TRIM")), 1);
        }

        query = STORAGE_PROPERTY_QUERY{};
        query.PropertyId = StorageDeviceWriteCacheProperty;
        query.QueryType = PropertyStandardQuery;
        STORAGE_WRITE_CACHE_PROPERTY writeCache{};
        returnedBytes = 0;
        if (::DeviceIoControl(
            handleValue,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &query,
            static_cast<DWORD>(sizeof(query)),
            &writeCache,
            static_cast<DWORD>(sizeof(writeCache)),
            &returnedBytes,
            nullptr) != FALSE)
        {
            addHealthMap(items, QStringLiteral("缓存"), QStringLiteral("写缓存启用"), boolText(writeCache.WriteCacheEnabled != FALSE), QStringLiteral("WriteCacheType=%1").arg(static_cast<int>(writeCache.WriteCacheType)));
            addHealthMap(items, QStringLiteral("缓存"), QStringLiteral("Flush 支持"), boolText(writeCache.FlushCacheSupported != FALSE), QStringLiteral("WriteCacheChangeable=%1").arg(boolText(writeCache.WriteCacheChangeable != FALSE)));
        }
        else
        {
            addHealthMap(items, QStringLiteral("缓存"), QStringLiteral("写缓存状态"), QStringLiteral("未知"), lastWin32ErrorText(QStringLiteral("查询写缓存")), 1);
        }

        STORAGE_HOTPLUG_INFO hotplugInfo{};
        returnedBytes = 0;
        if (::DeviceIoControl(
            handleValue,
            IOCTL_STORAGE_GET_HOTPLUG_INFO,
            nullptr,
            0,
            &hotplugInfo,
            static_cast<DWORD>(sizeof(hotplugInfo)),
            &returnedBytes,
            nullptr) != FALSE)
        {
            addHealthMap(items, QStringLiteral("热插拔"), QStringLiteral("介质可移除"), boolText(hotplugInfo.MediaRemovable != FALSE), QStringLiteral("STORAGE_HOTPLUG_INFO"));
            addHealthMap(items, QStringLiteral("热插拔"), QStringLiteral("设备热插拔"), boolText(hotplugInfo.DeviceHotplug != FALSE), QStringLiteral("WriteCacheEnableOverride=%1").arg(boolText(hotplugInfo.WriteCacheEnableOverride != FALSE)));
        }
        else
        {
            addHealthMap(items, QStringLiteral("热插拔"), QStringLiteral("热插拔信息"), QStringLiteral("未知"), lastWin32ErrorText(QStringLiteral("查询热插拔")), 1);
        }

        GETVERSIONINPARAMS smartVersion{};
        returnedBytes = 0;
        if (::DeviceIoControl(
            handleValue,
            SMART_GET_VERSION,
            nullptr,
            0,
            &smartVersion,
            static_cast<DWORD>(sizeof(smartVersion)),
            &returnedBytes,
            nullptr) != FALSE)
        {
            addHealthMap(
                items,
                QStringLiteral("SMART"),
                QStringLiteral("SMART 接口"),
                (smartVersion.fCapabilities & CAP_SMART_CMD) ? QStringLiteral("可用") : QStringLiteral("驱动不声明 SMART"),
                QStringLiteral("capabilities=0x%1").arg(static_cast<unsigned int>(smartVersion.fCapabilities), 8, 16, QChar('0')).toUpper());
        }
        else
        {
            addHealthMap(items, QStringLiteral("SMART"), QStringLiteral("SMART 接口"), QStringLiteral("不可用/需权限"), lastWin32ErrorText(QStringLiteral("查询 SMART 版本")), 1);
        }

        ::CloseHandle(handleValue);
        return items;
    }

    QString DiskEditorBackend::formatBytes(const std::uint64_t bytes)
    {
        const double kValue = static_cast<double>(bytes);
        if (bytes >= 1024ULL * 1024ULL * 1024ULL * 1024ULL)
        {
            return QStringLiteral("%1 TB").arg(kValue / 1099511627776.0, 0, 'f', 2);
        }
        if (bytes >= 1024ULL * 1024ULL * 1024ULL)
        {
            return QStringLiteral("%1 GB").arg(kValue / 1073741824.0, 0, 'f', 2);
        }
        if (bytes >= 1024ULL * 1024ULL)
        {
            return QStringLiteral("%1 MB").arg(kValue / 1048576.0, 0, 'f', 2);
        }
        if (bytes >= 1024ULL)
        {
            return QStringLiteral("%1 KB").arg(kValue / 1024.0, 0, 'f', 2);
        }
        return QStringLiteral("%1 B").arg(static_cast<qulonglong>(bytes));
    }

    QString DiskEditorBackend::partitionStyleText(const DiskPartitionStyle style)
    {
        switch (style)
        {
        case DiskPartitionStyle::kRaw: return QStringLiteral("RAW");
        case DiskPartitionStyle::kMbr: return QStringLiteral("MBR");
        case DiskPartitionStyle::kGpt: return QStringLiteral("GPT");
        default: break;
        }
        return QStringLiteral("未知");
    }
}
