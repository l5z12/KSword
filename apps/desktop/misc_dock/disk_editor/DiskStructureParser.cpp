#include "DiskStructureParser.h"

// ============================================================
// DiskStructureParser.cpp
// Purpose:
// 1) Parse MBR, GPT, and boot sector key fields in pure read-only mode;
// 2) Converts volume mapping and health information returned by the basic backend into an advanced UI model;
// 3) Provide a tabular representation of structure fields that supports navigation and alerts.
// ============================================================

#include "DiskEditorBackend.h"

#include <QVariantMap>
#include <QStringList>

#include <algorithm>
#include <array>
#include <limits>

namespace
{
    using ks::misc::DiskDeviceInfo;
    using ks::misc::DiskHealthItem;
    using ks::misc::DiskPartitionInfo;
    using ks::misc::DiskStructureField;
    using ks::misc::DiskStructureReport;
    using ks::misc::DiskStructureSeverity;
    using ks::misc::DiskVolumeInfo;
    using ks::misc::DiskEditorBackend;

    // kMbrSignatureOffset: Fixed offset to the MBR end signature 0x55AA.
    constexpr std::uint32_t kMbrSignatureOffset = 510;

    // kMbrPartitionTableOffset: Fixed offset for the four primary partition table entries in MBR.
    constexpr std::uint32_t kMbrPartitionTableOffset = 446;

    // kMbrPartitionEntryBytes: Length of each MBR partition table entry.
    constexpr std::uint32_t kMbrPartitionEntryBytes = 16;

    // kGptHeaderLba: LBA where the primary GPT Header is located.
    constexpr std::uint64_t kGptHeaderLba = 1;

    // le16：
    // - Reads a little-endian 16-bit value from QByteArray;
    // - bytes is the data buffer, and offset is the offset within the buffer.
    // - Return 0 on out-of-bounds access.
    std::uint16_t le16(const QByteArray& bytes, const std::uint64_t offset)
    {
        if (offset + 2 > static_cast<std::uint64_t>(bytes.size()))
        {
            return 0;
        }
        const auto* p = reinterpret_cast<const unsigned char*>(bytes.constData() + offset);
        return static_cast<std::uint16_t>(p[0] | (p[1] << 8));
    }

    // le32：
    // - Reads a little-endian 32-bit value from QByteArray;
    // - bytes is the data buffer, and offset is the offset within the buffer.
    // - Return 0 on out-of-bounds access.
    std::uint32_t le32(const QByteArray& bytes, const std::uint64_t offset)
    {
        if (offset + 4 > static_cast<std::uint64_t>(bytes.size()))
        {
            return 0;
        }
        const auto* p = reinterpret_cast<const unsigned char*>(bytes.constData() + offset);
        return static_cast<std::uint32_t>(p[0])
            | (static_cast<std::uint32_t>(p[1]) << 8)
            | (static_cast<std::uint32_t>(p[2]) << 16)
            | (static_cast<std::uint32_t>(p[3]) << 24);
    }

    // le64：
    // - Reads a little-endian 64-bit value from QByteArray;
    // - bytes is the data buffer, and offset is the offset within the buffer.
    // - Return 0 on out-of-bounds access.
    std::uint64_t le64(const QByteArray& bytes, const std::uint64_t offset)
    {
        const std::uint64_t kLow = le32(bytes, offset);
        const std::uint64_t kHigh = le32(bytes, offset + 4);
        return kLow | (kHigh << 32);
    }

    // latinText：
    // - Read ASCII/OEM text from the byte buffer;
    // - offset/length specify the range.
    // - Returns the cleaned display string.
    QString latinText(const QByteArray& bytes, const std::uint64_t offset, const std::uint32_t length)
    {
        if (offset + length > static_cast<std::uint64_t>(bytes.size()))
        {
            return QString();
        }
        QString text = QString::fromLatin1(bytes.constData() + offset, static_cast<int>(length));
        text.replace(QChar('\0'), QChar(' '));
        return text.simplified();
    }

    // utf16Text：
    // - Read text from a fixed-length UTF-16LE field;
    // - offset/byteLength specify the range.
    // - Returns the string with NULs and whitespace removed.
    QString utf16Text(const QByteArray& bytes, const std::uint64_t offset, const std::uint32_t byteLength)
    {
        if (offset + byteLength > static_cast<std::uint64_t>(bytes.size()))
        {
            return QString();
        }
        QString text = QString::fromUtf16(
            reinterpret_cast<const char16_t*>(bytes.constData() + offset),
            static_cast<int>(byteLength / 2));
        const int kNulIndex = text.indexOf(QChar('\0'));
        if (kNulIndex >= 0)
        {
            text.truncate(kNulIndex);
        }
        return text.trimmed();
    }

    // hexValue：
    // - Format integers uniformly with a 0x prefix and uppercase hexadecimal digits.
    // - value is the input numeric value.
    // - width is the minimum bit width.
    QString hexValue(const std::uint64_t value, const int width = 0)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), width, 16, QChar('0'))
            .toUpper();
    }

    // bytesToHexText：
    // - Convert small byte segments to space-separated HEX.
    // - bytes is the buffer; offset/length specify the range.
    // - Automatically truncate on out-of-bounds access.
    QString bytesToHexText(const QByteArray& bytes, const std::uint64_t offset, const std::uint32_t length)
    {
        if (offset >= static_cast<std::uint64_t>(bytes.size()))
        {
            return QString();
        }
        const std::uint64_t kAvailable = std::min<std::uint64_t>(
            length,
            static_cast<std::uint64_t>(bytes.size()) - offset);
        QStringList parts;
        for (std::uint64_t index = 0; index < kAvailable; ++index)
        {
            const auto kValue = static_cast<unsigned char>(bytes.at(static_cast<int>(offset + index)));
            parts << QStringLiteral("%1").arg(static_cast<unsigned int>(kValue), 2, 16, QChar('0')).toUpper();
        }
        return parts.join(QChar(' '));
    }

    // guidFromBytes：
    // - Generates text from the GPT little-endian GUID field.
    // - bytes is the buffer, offset points to the 16-byte GUID;
    // - Returns standard GUID text without curly braces.
    QString guidFromBytes(const QByteArray& bytes, const std::uint64_t offset)
    {
        if (offset + 16 > static_cast<std::uint64_t>(bytes.size()))
        {
            return QString();
        }
        return QStringLiteral("%1-%2-%3-%4%5-%6%7%8%9%10%11")
            .arg(le32(bytes, offset + 0), 8, 16, QChar('0'))
            .arg(le16(bytes, offset + 4), 4, 16, QChar('0'))
            .arg(le16(bytes, offset + 6), 4, 16, QChar('0'))
            .arg(static_cast<unsigned int>(static_cast<unsigned char>(bytes.at(static_cast<int>(offset + 8)))), 2, 16, QChar('0'))
            .arg(static_cast<unsigned int>(static_cast<unsigned char>(bytes.at(static_cast<int>(offset + 9)))), 2, 16, QChar('0'))
            .arg(static_cast<unsigned int>(static_cast<unsigned char>(bytes.at(static_cast<int>(offset + 10)))), 2, 16, QChar('0'))
            .arg(static_cast<unsigned int>(static_cast<unsigned char>(bytes.at(static_cast<int>(offset + 11)))), 2, 16, QChar('0'))
            .arg(static_cast<unsigned int>(static_cast<unsigned char>(bytes.at(static_cast<int>(offset + 12)))), 2, 16, QChar('0'))
            .arg(static_cast<unsigned int>(static_cast<unsigned char>(bytes.at(static_cast<int>(offset + 13)))), 2, 16, QChar('0'))
            .arg(static_cast<unsigned int>(static_cast<unsigned char>(bytes.at(static_cast<int>(offset + 14)))), 2, 16, QChar('0'))
            .arg(static_cast<unsigned int>(static_cast<unsigned char>(bytes.at(static_cast<int>(offset + 15)))), 2, 16, QChar('0'))
            .toUpper();
    }

    // addField：
    // - Append a structure parsing result row to the field list.
    // - group/name/value/detail define the displayed content;
    // - offsetBytes/sizeBytes enable UI navigation;
    // - severity controls the alert level.
    void addField(
        std::vector<DiskStructureField>& fields,
        const QString& group,
        const QString& name,
        const QString& value,
        const QString& detail,
        const std::uint64_t offsetBytes,
        const std::uint32_t sizeBytes,
        const DiskStructureSeverity severity = DiskStructureSeverity::kInfo)
    {
        DiskStructureField field;
        field.group = group;
        field.name = name;
        field.value = value;
        field.detail = detail;
        field.offsetBytes = offsetBytes;
        field.sizeBytes = sizeBytes;
        field.severity = severity;
        fields.push_back(std::move(field));
    }

    // crc32Table：
    // - Generate the IEEE CRC32 table used by GPT.
    // - Returns a reference to the static array.
    const std::array<std::uint32_t, 256>& crc32Table()
    {
        static const std::array<std::uint32_t, 256> kTable = []()
        {
            std::array<std::uint32_t, 256> values{};
            for (std::uint32_t index = 0; index < 256; ++index)
            {
                std::uint32_t crc = index;
                for (int bit = 0; bit < 8; ++bit)
                {
                    crc = (crc & 1U) ? (0xEDB88320U ^ (crc >> 1)) : (crc >> 1);
                }
                values[index] = crc;
            }
            return values;
        }();
        return kTable;
    }

    // computeCrc32：
    // - Compute the CRC32 used for the GPT Header and Entry Array;
    // - data points to input bytes, size is length
    // - Returns the CRC32 value.
    std::uint32_t computeCrc32(const unsigned char* data, const std::size_t size)
    {
        std::uint32_t crc = 0xFFFFFFFFU;
        const auto& table = crc32Table();
        for (std::size_t index = 0; index < size; ++index)
        {
            crc = table[(crc ^ data[index]) & 0xFFU] ^ (crc >> 8);
        }
        return crc ^ 0xFFFFFFFFU;
    }

    // readBoundedSlice：
    // - Read a safe slice from leadingBytes;
    // - offset/length use offsets within the buffer;
    // - Returns the corresponding QByteArray on success; returns an empty one on failure.
    QByteArray readBoundedSlice(const QByteArray& leadingBytes, const std::uint64_t offset, const std::uint64_t length)
    {
        if (length == 0 || offset + length > static_cast<std::uint64_t>(leadingBytes.size()))
        {
            return QByteArray();
        }
        if (length > static_cast<std::uint64_t>(std::numeric_limits<int>::max()))
        {
            return QByteArray();
        }
        return leadingBytes.mid(static_cast<int>(offset), static_cast<int>(length));
    }

    // mbrTypeName：
    // - Converts an MBR type byte to a short description.
    // - typeByte: partition type;
    // - Returns display text.
    QString mbrTypeName(const std::uint8_t typeByte)
    {
        switch (typeByte)
        {
        case 0x00: return QStringLiteral("空槽");
        case 0x05: return QStringLiteral("扩展分区 CHS");
        case 0x07: return QStringLiteral("NTFS/exFAT/HPFS");
        case 0x0B: return QStringLiteral("FAT32 CHS");
        case 0x0C: return QStringLiteral("FAT32 LBA");
        case 0x0F: return QStringLiteral("扩展分区 LBA");
        case 0x27: return QStringLiteral("Windows Recovery/OEM");
        case 0x82: return QStringLiteral("Linux Swap");
        case 0x83: return QStringLiteral("Linux 文件系统");
        case 0x8E: return QStringLiteral("Linux LVM");
        case 0xEE: return QStringLiteral("GPT Protective MBR");
        case 0xEF: return QStringLiteral("EFI System");
        default: break;
        }
        return QStringLiteral("类型 %1").arg(hexValue(typeByte, 2));
    }

    // gptTypeName：
    // - Convert common GPT type GUIDs to Chinese descriptions.
    // - guidText: standard GUID text
    // - Returns display text.
    QString gptTypeName(const QString& guidText)
    {
        const QString kNormalized = guidText.toUpper();
        if (kNormalized == QStringLiteral("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"))
        {
            return QStringLiteral("Microsoft 基本数据");
        }
        if (kNormalized == QStringLiteral("C12A7328-F81F-11D2-BA4B-00A0C93EC93B"))
        {
            return QStringLiteral("EFI 系统分区");
        }
        if (kNormalized == QStringLiteral("E3C9E316-0B5C-4DB8-817D-F92DF00215AE"))
        {
            return QStringLiteral("Microsoft 保留分区");
        }
        if (kNormalized == QStringLiteral("DE94BBA4-06D1-4D40-A16A-BFD50179D6AC"))
        {
            return QStringLiteral("Windows 恢复分区");
        }
        if (kNormalized == QStringLiteral("0FC63DAF-8483-4772-8E79-3D69D8477DE4"))
        {
            return QStringLiteral("Linux 文件系统");
        }
        if (kNormalized == QStringLiteral("0657FD6D-A4AB-43C4-84E5-0933C84B4F4F"))
        {
            return QStringLiteral("Linux Swap");
        }
        return QStringLiteral("GPT %1").arg(guidText);
    }

    // parseMbr：
    // - Parse the MBR signature and four primary partition table entries at LBA0.
    // - report: receives fields and alerts;
    // - No return value.
    void parseMbr(const DiskDeviceInfo& disk, const QByteArray& leadingBytes, DiskStructureReport& report)
    {
        if (leadingBytes.size() < 512)
        {
            report.warnings << QStringLiteral("前部读取不足 512 字节，无法解析 MBR。");
            return;
        }

        const std::uint16_t kSignature = le16(leadingBytes, kMbrSignatureOffset);
        addField(
            report.fields,
            QStringLiteral("MBR"),
            QStringLiteral("结束签名"),
            hexValue(kSignature, 4),
            kSignature == 0xAA55U ? QStringLiteral("有效 0x55AA") : QStringLiteral("签名异常，磁盘可能为 RAW 或前部损坏"),
            kMbrSignatureOffset,
            2,
            kSignature == 0xAA55U ? DiskStructureSeverity::kInfo : DiskStructureSeverity::kError);

        const std::uint32_t kDiskSignature = le32(leadingBytes, 440);
        addField(
            report.fields,
            QStringLiteral("MBR"),
            QStringLiteral("磁盘签名"),
            hexValue(kDiskSignature, 8),
            QStringLiteral("Windows MBR 磁盘签名字段"),
            440,
            4);

        for (int slot = 0; slot < 4; ++slot)
        {
            const std::uint64_t kEntryOffset = kMbrPartitionTableOffset + slot * kMbrPartitionEntryBytes;
            const auto kBootFlag = static_cast<std::uint8_t>(leadingBytes.at(static_cast<int>(kEntryOffset)));
            const auto kTypeByte = static_cast<std::uint8_t>(leadingBytes.at(static_cast<int>(kEntryOffset + 4)));
            const std::uint32_t kFirstLba = le32(leadingBytes, kEntryOffset + 8);
            const std::uint32_t kSectorCount = le32(leadingBytes, kEntryOffset + 12);
            const QString kGroup = QStringLiteral("MBR 分区槽 %1").arg(slot + 1);
            const std::uint64_t kAbsoluteOffset = static_cast<std::uint64_t>(kFirstLba) * disk.bytesPerSector;
            const std::uint64_t kLengthBytes = static_cast<std::uint64_t>(kSectorCount) * disk.bytesPerSector;

            addField(
                report.fields,
                kGroup,
                QStringLiteral("启动标记"),
                hexValue(kBootFlag, 2),
                kBootFlag == 0x80U ? QStringLiteral("活动分区") : (kBootFlag == 0x00U ? QStringLiteral("非活动") : QStringLiteral("非标准启动标记")),
                kEntryOffset,
                1,
                (kBootFlag == 0x00U || kBootFlag == 0x80U) ? DiskStructureSeverity::kInfo : DiskStructureSeverity::kWarning);
            addField(
                report.fields,
                kGroup,
                QStringLiteral("分区类型"),
                QStringLiteral("%1 (%2)").arg(hexValue(kTypeByte, 2), mbrTypeName(kTypeByte)),
                kTypeByte == 0xEEU ? QStringLiteral("GPT Protective MBR 保护项") : QStringLiteral("传统 MBR 类型字节"),
                kEntryOffset + 4,
                1);
            addField(
                report.fields,
                kGroup,
                QStringLiteral("起始 LBA"),
                QString::number(kFirstLba),
                QStringLiteral("绝对偏移 %1").arg(hexValue(kAbsoluteOffset, 16)),
                kEntryOffset + 8,
                4,
                (kSectorCount > 0 && kAbsoluteOffset >= disk.sizeBytes) ? DiskStructureSeverity::kWarning : DiskStructureSeverity::kInfo);
            addField(
                report.fields,
                kGroup,
                QStringLiteral("扇区数量"),
                QString::number(kSectorCount),
                QStringLiteral("长度 %1").arg(DiskEditorBackend::formatBytes(kLengthBytes)),
                kEntryOffset + 12,
                4);
        }
    }

    // parseGpt：
    // - Parse the primary GPT Header and GPT Entries within the readable range;
    // - Calculate the Header CRC and Entry Array CRC;
    // - No return value.
    void parseGpt(const DiskDeviceInfo& disk, const QByteArray& leadingBytes, DiskStructureReport& report)
    {
        const std::uint32_t kSectorSize = disk.bytesPerSector == 0 ? 512U : disk.bytesPerSector;
        const std::uint64_t kHeaderOffset = kGptHeaderLba * kSectorSize;
        if (kHeaderOffset + 92 > static_cast<std::uint64_t>(leadingBytes.size()))
        {
            report.warnings << QStringLiteral("前部读取不足，无法完整解析主 GPT Header。");
            return;
        }

        const QString kSignature = latinText(leadingBytes, kHeaderOffset, 8);
        addField(
            report.fields,
            QStringLiteral("GPT Header"),
            QStringLiteral("签名"),
            kSignature,
            kSignature == QStringLiteral("EFI PART") ? QStringLiteral("有效 GPT Header 签名") : QStringLiteral("GPT 签名异常"),
            kHeaderOffset,
            8,
            kSignature == QStringLiteral("EFI PART") ? DiskStructureSeverity::kInfo : DiskStructureSeverity::kError);

        if (kSignature != QStringLiteral("EFI PART"))
        {
            return;
        }

        const std::uint32_t kRevision = le32(leadingBytes, kHeaderOffset + 8);
        const std::uint32_t kHeaderSize = le32(leadingBytes, kHeaderOffset + 12);
        const std::uint32_t kStoredHeaderCrc = le32(leadingBytes, kHeaderOffset + 16);
        const std::uint64_t kCurrentLba = le64(leadingBytes, kHeaderOffset + 24);
        const std::uint64_t kBackupLba = le64(leadingBytes, kHeaderOffset + 32);
        const std::uint64_t kFirstUsableLba = le64(leadingBytes, kHeaderOffset + 40);
        const std::uint64_t kLastUsableLba = le64(leadingBytes, kHeaderOffset + 48);
        const QString kDiskGuid = guidFromBytes(leadingBytes, kHeaderOffset + 56);
        const std::uint64_t kEntryArrayLba = le64(leadingBytes, kHeaderOffset + 72);
        const std::uint32_t kEntryCount = le32(leadingBytes, kHeaderOffset + 80);
        const std::uint32_t kEntrySize = le32(leadingBytes, kHeaderOffset + 84);
        const std::uint32_t kStoredEntryCrc = le32(leadingBytes, kHeaderOffset + 88);

        addField(report.fields, QStringLiteral("GPT Header"), QStringLiteral("版本"), hexValue(kRevision, 8), QStringLiteral("通常为 0x00010000"), kHeaderOffset + 8, 4);
        addField(report.fields, QStringLiteral("GPT Header"), QStringLiteral("Header 大小"), QString::number(kHeaderSize), QStringLiteral("用于 CRC 计算的头部长度"), kHeaderOffset + 12, 4);
        addField(report.fields, QStringLiteral("GPT Header"), QStringLiteral("当前 LBA"), QString::number(kCurrentLba), QStringLiteral("主 Header 通常为 LBA 1"), kHeaderOffset + 24, 8);
        addField(report.fields, QStringLiteral("GPT Header"), QStringLiteral("备份 LBA"), QString::number(kBackupLba), QStringLiteral("应位于磁盘末尾 LBA"), kHeaderOffset + 32, 8);
        addField(report.fields, QStringLiteral("GPT Header"), QStringLiteral("可用 LBA 范围"), QStringLiteral("%1 - %2").arg(kFirstUsableLba).arg(kLastUsableLba), QStringLiteral("分区不应越界到该范围外"), kHeaderOffset + 40, 16);
        addField(report.fields, QStringLiteral("GPT Header"), QStringLiteral("磁盘 GUID"), kDiskGuid, QStringLiteral("GPT Disk GUID"), kHeaderOffset + 56, 16);
        addField(report.fields, QStringLiteral("GPT Header"), QStringLiteral("Entry 起始 LBA"), QString::number(kEntryArrayLba), QStringLiteral("分区项数组起始位置"), kHeaderOffset + 72, 8);
        addField(report.fields, QStringLiteral("GPT Header"), QStringLiteral("Entry 数量/大小"), QStringLiteral("%1 x %2").arg(kEntryCount).arg(kEntrySize), QStringLiteral("Windows 常见为 128 x 128"), kHeaderOffset + 80, 8);

        if (kHeaderSize >= 92 && kHeaderOffset + kHeaderSize <= static_cast<std::uint64_t>(leadingBytes.size()))
        {
            QByteArray headerBytes = readBoundedSlice(leadingBytes, kHeaderOffset, kHeaderSize);
            if (!headerBytes.isEmpty())
            {
                for (int index = 16; index < 20; ++index)
                {
                    headerBytes[index] = '\0';
                }
                const std::uint32_t kComputedCrc = computeCrc32(
                    reinterpret_cast<const unsigned char*>(headerBytes.constData()),
                    static_cast<std::size_t>(headerBytes.size()));
                addField(
                    report.fields,
                    QStringLiteral("GPT Header"),
                    QStringLiteral("Header CRC32"),
                    QStringLiteral("存储 %1 / 计算 %2").arg(hexValue(kStoredHeaderCrc, 8), hexValue(kComputedCrc, 8)),
                    kComputedCrc == kStoredHeaderCrc ? QStringLiteral("Header CRC 匹配") : QStringLiteral("Header CRC 不匹配"),
                    kHeaderOffset + 16,
                    4,
                    kComputedCrc == kStoredHeaderCrc ? DiskStructureSeverity::kInfo : DiskStructureSeverity::kError);
            }
        }
        else
        {
            addField(
                report.fields,
                QStringLiteral("GPT Header"),
                QStringLiteral("Header CRC32"),
                hexValue(kStoredHeaderCrc, 8),
                QStringLiteral("Header 大小异常或读取不足，未计算 CRC"),
                kHeaderOffset + 16,
                4,
                DiskStructureSeverity::kWarning);
        }

        const std::uint64_t kEntryArrayOffset = kEntryArrayLba * kSectorSize;
        const std::uint64_t kEntryArrayBytes = static_cast<std::uint64_t>(kEntryCount) * kEntrySize;
        const QByteArray kEntryBytes = readBoundedSlice(leadingBytes, kEntryArrayOffset, kEntryArrayBytes);
        if (!kEntryBytes.isEmpty())
        {
            const std::uint32_t kComputedEntryCrc = computeCrc32(
                reinterpret_cast<const unsigned char*>(kEntryBytes.constData()),
                static_cast<std::size_t>(kEntryBytes.size()));
            addField(
                report.fields,
                QStringLiteral("GPT Entry Array"),
                QStringLiteral("Entry Array CRC32"),
                QStringLiteral("存储 %1 / 计算 %2").arg(hexValue(kStoredEntryCrc, 8), hexValue(kComputedEntryCrc, 8)),
                kComputedEntryCrc == kStoredEntryCrc ? QStringLiteral("Entry Array CRC 匹配") : QStringLiteral("Entry Array CRC 不匹配"),
                kHeaderOffset + 88,
                4,
                kComputedEntryCrc == kStoredEntryCrc ? DiskStructureSeverity::kInfo : DiskStructureSeverity::kError);
        }
        else
        {
            addField(
                report.fields,
                QStringLiteral("GPT Entry Array"),
                QStringLiteral("Entry Array CRC32"),
                hexValue(kStoredEntryCrc, 8),
                QStringLiteral("Entry Array 超出当前前部读取范围，未计算 CRC"),
                kHeaderOffset + 88,
                4,
                DiskStructureSeverity::kWarning);
        }

        const std::uint32_t kSafeEntrySize = kEntrySize == 0 ? 128U : kEntrySize;
        const std::uint32_t kEntriesToShow = std::min<std::uint32_t>(kEntryCount, 64U);
        for (std::uint32_t index = 0; index < kEntriesToShow; ++index)
        {
            const std::uint64_t kEntryOffset = kEntryArrayOffset + static_cast<std::uint64_t>(index) * kSafeEntrySize;
            if (kEntryOffset + std::min<std::uint32_t>(kSafeEntrySize, 128U) > static_cast<std::uint64_t>(leadingBytes.size()))
            {
                break;
            }

            const QString kTypeGuid = guidFromBytes(leadingBytes, kEntryOffset);
            const QString kUniqueGuid = guidFromBytes(leadingBytes, kEntryOffset + 16);
            const std::uint64_t kFirstLba = le64(leadingBytes, kEntryOffset + 32);
            const std::uint64_t kLastLba = le64(leadingBytes, kEntryOffset + 40);
            const std::uint64_t kAttributes = le64(leadingBytes, kEntryOffset + 48);
            const QString kName = utf16Text(leadingBytes, kEntryOffset + 56, std::min<std::uint32_t>(72U, kSafeEntrySize > 56 ? kSafeEntrySize - 56 : 0));
            const bool kEmptyEntry = kTypeGuid == QStringLiteral("00000000-0000-0000-0000-000000000000");
            if (kEmptyEntry)
            {
                continue;
            }

            const QString kGroup = QStringLiteral("GPT Entry %1").arg(index + 1);
            const std::uint64_t kPartitionOffset = kFirstLba * kSectorSize;
            const std::uint64_t kPartitionLength = kLastLba >= kFirstLba
                ? (kLastLba - kFirstLba + 1ULL) * kSectorSize
                : 0ULL;
            addField(report.fields, kGroup, QStringLiteral("类型 GUID"), kTypeGuid, gptTypeName(kTypeGuid), kEntryOffset, 16);
            addField(report.fields, kGroup, QStringLiteral("唯一 GUID"), kUniqueGuid, QStringLiteral("Partition GUID"), kEntryOffset + 16, 16);
            addField(report.fields, kGroup, QStringLiteral("LBA 范围"), QStringLiteral("%1 - %2").arg(kFirstLba).arg(kLastLba), QStringLiteral("偏移 %1，长度 %2").arg(hexValue(kPartitionOffset, 16), DiskEditorBackend::formatBytes(kPartitionLength)), kEntryOffset + 32, 16);
            addField(report.fields, kGroup, QStringLiteral("属性"), hexValue(kAttributes, 16), kAttributes == 0 ? QStringLiteral("无特殊属性") : QStringLiteral("GPT Attributes 位图"), kEntryOffset + 48, 8);
            addField(report.fields, kGroup, QStringLiteral("名称"), kName.isEmpty() ? QStringLiteral("<未命名>") : kName, QStringLiteral("UTF-16LE 分区名称"), kEntryOffset + 56, std::min<std::uint32_t>(72U, kSafeEntrySize > 56 ? kSafeEntrySize - 56 : 0));
        }
    }

    // BootSectorAnalysis:
    // - Cache the file system type and BPB fields of the boot sector;
    // - Avoid incorrect reads caused by field offset differences between NTFS and exFAT.
    struct BootSectorAnalysis
    {
        QString kind;                    // kind: NTFS/FAT32/exFAT/Unknown.
        std::uint16_t bytesPerSector = 0; // bytesPerSector: Bytes per sector.
        std::uint32_t sectorsPerCluster = 0; // sectorsPerCluster: number of sectors per cluster.
        std::uint64_t totalSectors = 0;  // totalSectors: Total number of sectors in the volume.
        bool hasFatBpb = false;          // hasFatBpb: Whether traditional BPB fields are available.
    };

    // analyzeBootSector：
    // - Identify the boot sector file system based on OEM name and field characteristics;
    // - bytes is the starting sector data;
    // - Returns the analysis result with key BPB fields.
    BootSectorAnalysis analyzeBootSector(const QByteArray& bytes)
    {
        BootSectorAnalysis analysis;
        const QString kOem = latinText(bytes, 3, 8).toUpper();
        if (kOem.contains(QStringLiteral("NTFS")))
        {
            const std::uint16_t kBps = le16(bytes, 11);
            const std::uint32_t kSpc = static_cast<std::uint8_t>(bytes.at(13));
            analysis.kind = QStringLiteral("NTFS");
            analysis.bytesPerSector = kBps;
            analysis.sectorsPerCluster = kSpc;
            analysis.totalSectors = le64(bytes, 40);
            analysis.hasFatBpb = (kBps == 512 || kBps == 1024 || kBps == 2048 || kBps == 4096) && kSpc != 0;
            return analysis;
        }
        if (kOem.contains(QStringLiteral("EXFAT")))
        {
            const auto kBytesPerSectorShift = static_cast<std::uint8_t>(bytes.at(108));
            const auto kSectorsPerClusterShift = static_cast<std::uint8_t>(bytes.at(109));
            analysis.kind = QStringLiteral("exFAT");
            analysis.bytesPerSector = kBytesPerSectorShift < 16
                ? static_cast<std::uint16_t>(1U << kBytesPerSectorShift)
                : 0;
            analysis.sectorsPerCluster = kSectorsPerClusterShift < 31
                ? static_cast<std::uint32_t>(1U << kSectorsPerClusterShift)
                : 0;
            analysis.totalSectors = le64(bytes, 72);
            analysis.hasFatBpb = false;
            return analysis;
        }
        const QString kFat16 = latinText(bytes, 54, 8).toUpper();
        const QString kFat32 = latinText(bytes, 82, 8).toUpper();
        if (kFat32.contains(QStringLiteral("FAT32")))
        {
            const std::uint16_t kBps = le16(bytes, 11);
            const std::uint32_t kSpc = static_cast<std::uint8_t>(bytes.at(13));
            analysis.kind = QStringLiteral("FAT32");
            analysis.bytesPerSector = kBps;
            analysis.sectorsPerCluster = kSpc;
            analysis.totalSectors = le16(bytes, 19) != 0 ? le16(bytes, 19) : le32(bytes, 32);
            analysis.hasFatBpb = (kBps == 512 || kBps == 1024 || kBps == 2048 || kBps == 4096) && kSpc != 0;
            return analysis;
        }
        if (kFat16.contains(QStringLiteral("FAT")))
        {
            const std::uint16_t kBps = le16(bytes, 11);
            const std::uint32_t kSpc = static_cast<std::uint8_t>(bytes.at(13));
            analysis.kind = QStringLiteral("FAT12/16");
            analysis.bytesPerSector = kBps;
            analysis.sectorsPerCluster = kSpc;
            analysis.totalSectors = le16(bytes, 19) != 0 ? le16(bytes, 19) : le32(bytes, 32);
            analysis.hasFatBpb = (kBps == 512 || kBps == 1024 || kBps == 2048 || kBps == 4096) && kSpc != 0;
            return analysis;
        }
        analysis.kind = QStringLiteral("未知/非标准");
        analysis.bytesPerSector = le16(bytes, 11);
        analysis.sectorsPerCluster = static_cast<std::uint8_t>(bytes.at(13));
        analysis.totalSectors = le16(bytes, 19) != 0 ? le16(bytes, 19) : le32(bytes, 32);
        analysis.hasFatBpb = false;
        return analysis;
    }

    // parseBootSectorAt：
    // - Parse common fields of the boot sector at a specified absolute offset.
    // - groupPrefix: Used to distinguish between full-disk LBA0 and specific partitions.
    // - No return value.
    void parseBootSectorAt(
        const DiskDeviceInfo& disk,
        const QByteArray& leadingBytes,
        const std::uint64_t baseOffset,
        const QString& groupPrefix,
        DiskStructureReport& report)
    {
        if (baseOffset + 512 > static_cast<std::uint64_t>(leadingBytes.size()))
        {
            return;
        }

        const QByteArray kSector = leadingBytes.mid(static_cast<int>(baseOffset), 512);
        const std::uint16_t kSignature = le16(kSector, 510);
        if (kSignature != 0xAA55U)
        {
            return;
        }

        const BootSectorAnalysis kAnalysis = analyzeBootSector(kSector);
        const QString kKind = kAnalysis.kind;
        const QString kGroup = QStringLiteral("%1 启动扇区").arg(groupPrefix);
        const std::uint16_t kBytesPerSector = kAnalysis.bytesPerSector;
        const std::uint32_t kSectorsPerCluster = kAnalysis.sectorsPerCluster;
        const std::uint16_t kReservedSectors = le16(kSector, 14);
        const auto kFatCount = static_cast<std::uint8_t>(kSector.at(16));
        const std::uint64_t kTotalSectors = kAnalysis.totalSectors;

        addField(report.fields, kGroup, QStringLiteral("文件系统识别"), kKind, QStringLiteral("依据 OEM 名称和 BPB 字段推断"), baseOffset + 3, 8);
        addField(report.fields, kGroup, QStringLiteral("OEM 名称"), latinText(kSector, 3, 8), QStringLiteral("启动扇区 OEM 字符串"), baseOffset + 3, 8);
        addField(report.fields, kGroup, QStringLiteral("每扇区字节"), QString::number(kBytesPerSector), kBytesPerSector == disk.bytesPerSector ? QStringLiteral("与磁盘逻辑扇区一致") : QStringLiteral("与磁盘逻辑扇区不同或为 0"), kAnalysis.hasFatBpb ? baseOffset + 11 : baseOffset + 108, kAnalysis.hasFatBpb ? 2 : 1, (kBytesPerSector == 0 || (disk.bytesPerSector != 0 && kBytesPerSector != disk.bytesPerSector)) ? DiskStructureSeverity::kWarning : DiskStructureSeverity::kInfo);
        addField(report.fields, kGroup, QStringLiteral("每簇扇区"), QString::number(kSectorsPerCluster), QStringLiteral("簇大小约 %1").arg(DiskEditorBackend::formatBytes(static_cast<std::uint64_t>(kBytesPerSector) * kSectorsPerCluster)), kAnalysis.hasFatBpb ? baseOffset + 13 : baseOffset + 109, 1);
        if (kAnalysis.hasFatBpb)
        {
            addField(report.fields, kGroup, QStringLiteral("保留扇区/FAT 数"), QStringLiteral("%1 / %2").arg(kReservedSectors).arg(kFatCount), QStringLiteral("FAT/NTFS BPB 传统字段"), baseOffset + 14, 3);
        }
        addField(report.fields, kGroup, QStringLiteral("总扇区"), QString::number(kTotalSectors), kTotalSectors == 0 ? QStringLiteral("总扇区字段为空") : QStringLiteral("约 %1").arg(DiskEditorBackend::formatBytes(kTotalSectors * kBytesPerSector)), kAnalysis.hasFatBpb ? baseOffset + 19 : baseOffset + 72, kAnalysis.hasFatBpb ? 4 : 8);

        if (kKind == QStringLiteral("NTFS"))
        {
            const std::uint64_t kTotalSectors64 = le64(kSector, 40);
            const std::uint64_t kMftCluster = le64(kSector, 48);
            const std::uint64_t kMirrorCluster = le64(kSector, 56);
            const auto kClustersPerFileRecord = static_cast<signed char>(kSector.at(64));
            addField(report.fields, kGroup, QStringLiteral("NTFS 总扇区"), QString::number(kTotalSectors64), QStringLiteral("NTFS BPB 64 位总扇区"), baseOffset + 40, 8);
            addField(report.fields, kGroup, QStringLiteral("$MFT 簇号"), QString::number(kMftCluster), QStringLiteral("$MFT 物理偏移约 %1").arg(hexValue(baseOffset + kMftCluster * kSectorsPerCluster * kBytesPerSector, 16)), baseOffset + 48, 8);
            addField(report.fields, kGroup, QStringLiteral("$MFTMirr 簇号"), QString::number(kMirrorCluster), QStringLiteral("MFT 镜像簇号"), baseOffset + 56, 8);
            addField(report.fields, kGroup, QStringLiteral("文件记录大小编码"), QString::number(kClustersPerFileRecord), kClustersPerFileRecord < 0 ? QStringLiteral("记录大小为 2^%1 字节").arg(-kClustersPerFileRecord) : QStringLiteral("记录大小为簇数倍数"), baseOffset + 64, 1);
        }
        else if (kKind == QStringLiteral("FAT32"))
        {
            const std::uint32_t kSectorsPerFat = le32(kSector, 36);
            const std::uint32_t kRootCluster = le32(kSector, 44);
            const std::uint16_t kFsInfoSector = le16(kSector, 48);
            addField(report.fields, kGroup, QStringLiteral("FAT32 每 FAT 扇区"), QString::number(kSectorsPerFat), QStringLiteral("FAT 表长度"), baseOffset + 36, 4);
            addField(report.fields, kGroup, QStringLiteral("FAT32 根目录簇"), QString::number(kRootCluster), QStringLiteral("根目录起始簇"), baseOffset + 44, 4);
            addField(report.fields, kGroup, QStringLiteral("FAT32 FSInfo 扇区"), QString::number(kFsInfoSector), QStringLiteral("通常为 1"), baseOffset + 48, 2);
        }
        else if (kKind == QStringLiteral("exFAT"))
        {
            const std::uint64_t kVolumeOffset = le64(kSector, 64);
            const std::uint64_t kVolumeLength = le64(kSector, 72);
            const std::uint32_t kFatOffset = le32(kSector, 80);
            const std::uint32_t kClusterHeapOffset = le32(kSector, 88);
            const auto kBytesPerSectorShift = static_cast<std::uint8_t>(kSector.at(108));
            const auto kSectorsPerClusterShift = static_cast<std::uint8_t>(kSector.at(109));
            addField(report.fields, kGroup, QStringLiteral("exFAT 卷偏移/长度"), QStringLiteral("%1 / %2").arg(kVolumeOffset).arg(kVolumeLength), QStringLiteral("以扇区为单位"), baseOffset + 64, 16);
            addField(report.fields, kGroup, QStringLiteral("exFAT FAT/簇堆偏移"), QStringLiteral("%1 / %2").arg(kFatOffset).arg(kClusterHeapOffset), QStringLiteral("以扇区为单位"), baseOffset + 80, 12);
            addField(report.fields, kGroup, QStringLiteral("exFAT 扇区/簇位移"), QStringLiteral("%1 / %2").arg(kBytesPerSectorShift).arg(kSectorsPerClusterShift), QStringLiteral("扇区大小=2^shift，簇扇区数=2^shift"), baseOffset + 108, 2);
        }
    }

    // severityFromMap：
    // - Convert the severity integer from the base backend QVariantMap to the advanced model enum;
    // - severityValue convention: 0=info, 1=warning, 2=error;
    // - Returns DiskStructureSeverity.
    DiskStructureSeverity severityFromMap(const int severityValue)
    {
        if (severityValue >= 2)
        {
            return DiskStructureSeverity::kError;
        }
        if (severityValue == 1)
        {
            return DiskStructureSeverity::kWarning;
        }
        return DiskStructureSeverity::kInfo;
    }

    // boolText：
    // - Convert boolean values to Yes/No.
    // - value is the input boolean.
    // - Returns Chinese text.
    QString boolText(const bool value)
    {
        return value ? QStringLiteral("是") : QStringLiteral("否");
    }

    // addHealth：
    // - Append a row of basic information to the advanced health item list.
    // - category/name/value/detail are for display content;
    // - severity: severity level
    void addHealth(
        std::vector<DiskHealthItem>& items,
        const QString& category,
        const QString& name,
        const QString& value,
        const QString& detail,
        const DiskStructureSeverity severity = DiskStructureSeverity::kInfo)
    {
        DiskHealthItem item;
        item.category = category;
        item.name = name;
        item.value = value;
        item.detail = detail;
        item.severity = severity;
        items.push_back(std::move(item));
    }
}

namespace ks::misc
{
    DiskStructureReport DiskStructureParser::buildReport(
        const DiskDeviceInfo& disk,
        const QByteArray& leadingBytes,
        QString& errorTextOut)
    {
        DiskStructureReport report;
        errorTextOut.clear();

        if (leadingBytes.isEmpty())
        {
            errorTextOut = QStringLiteral("前部扇区缓冲为空。");
            return report;
        }

        parseMbr(disk, leadingBytes, report);
        parseGpt(disk, leadingBytes, report);
        parseBootSectorAt(disk, leadingBytes, 0, QStringLiteral("LBA0"), report);

        int parsedBootSectors = 0;
        for (const DiskPartitionInfo& partition : disk.partitions)
        {
            if (partition.partitionNumber == 0 || partition.lengthBytes == 0)
            {
                continue;
            }
            parseBootSectorAt(
                disk,
                leadingBytes,
                partition.offsetBytes,
                partition.name.isEmpty() ? QStringLiteral("分区 %1").arg(partition.partitionNumber) : partition.name,
                report);
            ++parsedBootSectors;
            if (parsedBootSectors >= 16)
            {
                break;
            }
        }

        QString volumeError;
        report.volumes = collectVolumeMapping(disk.diskIndex, volumeError);
        if (!volumeError.isEmpty())
        {
            report.warnings << volumeError;
        }

        QString healthError;
        report.healthItems = collectHealthItems(disk, healthError);
        if (!healthError.isEmpty())
        {
            report.warnings << healthError;
        }

        if (report.fields.empty())
        {
            report.warnings << QStringLiteral("未解析到可识别结构字段，可能需要管理员权限或更大的前部读取范围。");
        }
        return report;
    }

    std::vector<DiskVolumeInfo> DiskStructureParser::collectVolumeMapping(
        const int diskIndex,
        QString& errorTextOut)
    {
        std::vector<DiskVolumeInfo> volumes;
        errorTextOut.clear();

        const std::vector<QVariantMap> kMaps = DiskEditorBackend::queryVolumeMappings(diskIndex, errorTextOut);
        volumes.reserve(kMaps.size());
        for (const QVariantMap& map : kMaps)
        {
            DiskVolumeInfo volume;
            volume.volumeName = map.value(QStringLiteral("volumeName")).toString();
            volume.mountPoints = map.value(QStringLiteral("mountPoints")).toString();
            volume.devicePath = map.value(QStringLiteral("devicePath")).toString();
            volume.fileSystem = map.value(QStringLiteral("fileSystem")).toString();
            volume.label = map.value(QStringLiteral("label")).toString();
            volume.diskNumber = map.value(QStringLiteral("diskNumber")).toInt();
            volume.offsetBytes = map.value(QStringLiteral("offsetBytes")).toULongLong();
            volume.lengthBytes = map.value(QStringLiteral("lengthBytes")).toULongLong();
            volumes.push_back(std::move(volume));
        }
        return volumes;
    }

    std::vector<DiskHealthItem> DiskStructureParser::collectHealthItems(
        const DiskDeviceInfo& disk,
        QString& errorTextOut)
    {
        std::vector<DiskHealthItem> items;
        errorTextOut.clear();

        addHealth(items, QStringLiteral("基础"), QStringLiteral("设备路径"), disk.devicePath, QStringLiteral("物理磁盘路径"));
        addHealth(items, QStringLiteral("基础"), QStringLiteral("型号"), disk.model.isEmpty() ? QStringLiteral("<未知>") : disk.model, QStringLiteral("STORAGE_DEVICE_DESCRIPTOR"));
        addHealth(items, QStringLiteral("基础"), QStringLiteral("序列号"), disk.serial.isEmpty() ? QStringLiteral("<未知>") : disk.serial, QStringLiteral("部分桥接器可能隐藏序列号"));
        addHealth(items, QStringLiteral("基础"), QStringLiteral("总线"), disk.busType.isEmpty() ? QStringLiteral("<未知>") : disk.busType, QStringLiteral("SATA/NVMe/USB 等"));
        addHealth(items, QStringLiteral("基础"), QStringLiteral("可移动介质"), boolText(disk.removable), QStringLiteral("RemovableMedia 标志"));
        addHealth(items, QStringLiteral("容量"), QStringLiteral("容量"), DiskEditorBackend::formatBytes(disk.sizeBytes), QStringLiteral("%1 字节").arg(static_cast<qulonglong>(disk.sizeBytes)));
        addHealth(items, QStringLiteral("容量"), QStringLiteral("逻辑/物理扇区"), QStringLiteral("%1 / %2").arg(disk.bytesPerSector).arg(disk.physicalBytesPerSector), QStringLiteral("写入保护以逻辑扇区为基准"));

        const std::vector<QVariantMap> kMaps = DiskEditorBackend::queryHealthItems(disk.devicePath, errorTextOut);
        for (const QVariantMap& map : kMaps)
        {
            DiskHealthItem item;
            item.category = map.value(QStringLiteral("category")).toString();
            item.name = map.value(QStringLiteral("name")).toString();
            item.value = map.value(QStringLiteral("value")).toString();
            item.detail = map.value(QStringLiteral("detail")).toString();
            item.severity = severityFromMap(map.value(QStringLiteral("severity")).toInt());
            items.push_back(std::move(item));
        }
        return items;
    }
}
