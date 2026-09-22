#include "KernelDockSsdtWorker.h"

#include "KernelCleanImageBaseline.h"
#include "../../../shared/ark_client/ArkDriverClient.h"

#include <algorithm>
#include <cstdint>
#include <vector>
#include <utility>

#include <QStringList>

namespace
{
    QString formatAddressHex(const std::uint64_t addressValue)
    {
        return QStringLiteral("0x%1")
            .arg(addressValue, 16, 16, QChar('0'))
            .toUpper();
    }

    std::vector<std::uint8_t> littleEndianBytes(
        const std::uint64_t value,
        const std::uint32_t byteCount)
    {
        std::vector<std::uint8_t> bytes;
        bytes.reserve(byteCount);
        for (std::uint32_t index = 0; index < byteCount; ++index)
        {
            bytes.push_back(static_cast<std::uint8_t>(
                (value >> (index * 8U)) & 0xFFU));
        }
        return bytes;
    }

    std::uint64_t littleEndianValue(
        const std::vector<std::uint8_t>& bytes)
    {
        std::uint64_t value = 0U;
        const std::size_t kCount = std::min<std::size_t>(
            bytes.size(),
            sizeof(value));
        for (std::size_t index = 0; index < kCount; ++index)
        {
            value |= static_cast<std::uint64_t>(bytes[index])
                << (index * 8U);
        }
        return value;
    }

    QString byteText(const std::vector<std::uint8_t>& bytes)
    {
        QStringList parts;
        parts.reserve(static_cast<int>(bytes.size()));
        for (const std::uint8_t kByte : bytes)
        {
            parts.push_back(QStringLiteral("%1")
                .arg(kByte, 2, 16, QChar('0')).toUpper());
        }
        return parts.join(QLatin1Char(' '));
    }

    // ssdtWorkerIoMessageText：
    // - Input: Raw message returned by ArkDriverClient::enumerateSsdt;
    // - Handling: Convert low-level logs such as DeviceIoControl/unsupported/DynData/buffer into human-readable descriptions.
    // - Return: Chinese short text for SSDT page error hints.
    QString ssdtWorkerIoMessageText(const QString& rawMessageText)
    {
        const QString kTrimmedText = rawMessageText.trimmed();
        if (kTrimmedText.isEmpty())
        {
            return QStringLiteral("驱动未返回额外说明。");
        }

        const QString kLowerText = kTrimmedText.toLower();
        if (kLowerText.contains(QStringLiteral("deviceiocontrol")))
        {
            return QStringLiteral("驱动 IOCTL 调用失败或当前驱动版本不匹配。");
        }
        if (kLowerText.contains(QStringLiteral("unsupported")) ||
            kLowerText.contains(QStringLiteral("not supported")) ||
            kLowerText.contains(QStringLiteral("status=0xc00000bb")))
        {
            return QStringLiteral("当前驱动暂不支持 SSDT 枚举接口。");
        }
        if (kLowerText.contains(QStringLiteral("dyndata")) ||
            kLowerText.contains(QStringLiteral("capability")))
        {
            return QStringLiteral("动态偏移能力未满足，SSDT 表地址或解析字段暂不可用。");
        }
        if (kLowerText.contains(QStringLiteral("buffer")) &&
            (kLowerText.contains(QStringLiteral("small")) || kLowerText.contains(QStringLiteral("trunc"))))
        {
            return QStringLiteral("驱动返回缓冲区不足，SSDT 结果可能被截断。");
        }
        return kTrimmedText;
    }
}

bool runSsdtSnapshotTask(std::vector<KernelSsdtEntry>& rowsOut, QString& errorTextOut)
{
    rowsOut.clear();
    errorTextOut.clear();

    // KernelDock only asks ArkDriverClient for the R0 SSDT snapshot. The worker
    // still owns UI row shaping, sorting, and localized error text.
    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::SsdtEnumResult kEnumResult = kDriverClient.enumerateSsdt(
        KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED);
    if (!kEnumResult.io.ok)
    {
        errorTextOut = QStringLiteral("查询 SSDT 失败，error=%1，detail=%2")
            .arg(kEnumResult.io.win32Error)
            .arg(ssdtWorkerIoMessageText(QString::fromStdString(kEnumResult.io.message)));
        return false;
    }

    std::uint32_t tableEntrySize = 0U;
    for (const ksword::ark::SsdtEntry& entry : kEnumResult.entries)
    {
        if (entry.tableEntrySize != 0U && entry.tableEntrySize <= sizeof(std::uint64_t))
        {
            tableEntrySize = entry.tableEntrySize;
            break;
        }
    }
    ks::kernel::CleanImageBaselineResult tableBaseline;
    if (kEnumResult.serviceTableBase != 0U
        && kEnumResult.serviceCountFromTable != 0U
        && tableEntrySize != 0U
        && static_cast<std::uint64_t>(kEnumResult.serviceCountFromTable)
            * tableEntrySize <= 64U * 1024U)
    {
        tableBaseline =
            ks::kernel::KernelCleanImageBaseline::compareAddress(
                kEnumResult.serviceTableBase,
                kEnumResult.serviceCountFromTable * tableEntrySize);
    }

    rowsOut.reserve(kEnumResult.entries.size());
    for (const ksword::ark::SsdtEntry& sourceEntry : kEnumResult.entries)
    {
        KernelSsdtEntry row{};
        row.serviceIndex = static_cast<std::uint32_t>(sourceEntry.serviceIndex);
        row.flags = static_cast<std::uint32_t>(sourceEntry.flags);
        row.zwRoutineAddress = static_cast<std::uint64_t>(sourceEntry.zwRoutineAddress);
        row.serviceRoutineAddress = static_cast<std::uint64_t>(sourceEntry.serviceRoutineAddress);
        row.serviceTableBase = static_cast<std::uint64_t>(kEnumResult.serviceTableBase);
        row.tableEntryAddress =
            static_cast<std::uint64_t>(sourceEntry.tableEntryAddress);
        row.currentTableValue =
            static_cast<std::uint64_t>(sourceEntry.currentTableValue);
        row.tableEntrySize =
            static_cast<std::uint32_t>(sourceEntry.tableEntrySize);
        row.currentTableBytes = littleEndianBytes(
            row.currentTableValue,
            row.tableEntrySize);
        row.cleanBaselineStatus = tableBaseline.statusText;
        row.cleanBaselinePath = tableBaseline.imagePath;
        if (tableBaseline.available
            && row.tableEntryAddress >= kEnumResult.serviceTableBase)
        {
            const std::uint64_t kByteOffset =
                row.tableEntryAddress - kEnumResult.serviceTableBase;
            if (kByteOffset <= tableBaseline.cleanBytes.size()
                && row.tableEntrySize
                    <= tableBaseline.cleanBytes.size() - kByteOffset)
            {
                const auto kFirst =
                    tableBaseline.cleanBytes.cbegin()
                    + static_cast<std::ptrdiff_t>(kByteOffset);
                row.cleanTableBytes.assign(
                    kFirst,
                    kFirst + row.tableEntrySize);
                row.cleanTableValue =
                    littleEndianValue(row.cleanTableBytes);
                row.cleanBaselineAvailable = true;
                row.cleanBaselineDiffers =
                    row.cleanTableBytes != row.currentTableBytes;
                row.cleanBaselineStatus = row.cleanBaselineDiffers
                    ? QStringLiteral("当前编码槽值与已验证磁盘映像不同")
                    : QStringLiteral("当前编码槽值与已验证磁盘映像一致");
            }
        }
        row.serviceNameText = QString::fromLocal8Bit(sourceEntry.serviceName.data(), static_cast<int>(sourceEntry.serviceName.size()));
        row.moduleNameText = QString::fromLocal8Bit(sourceEntry.moduleName.data(), static_cast<int>(sourceEntry.moduleName.size()));
        row.indexResolved = (row.flags & KSWORD_ARK_SSDT_ENTRY_FLAG_INDEX_RESOLVED) != 0U;
        const bool kTableAddressValid = (row.flags & KSWORD_ARK_SSDT_ENTRY_FLAG_TABLE_ADDRESS_VALID) != 0U;
        row.querySucceeded = true;

        QStringList statusParts;
        statusParts.push_back(row.indexResolved ? QStringLiteral("索引已解析") : QStringLiteral("索引未解析"));
        statusParts.push_back(kTableAddressValid ? QStringLiteral("表项地址已解析") : QStringLiteral("表项地址不可用"));
        statusParts.push_back(row.cleanBaselineAvailable
            ? (row.cleanBaselineDiffers
                ? QStringLiteral("磁盘基线差异")
                : QStringLiteral("磁盘基线一致"))
            : QStringLiteral("磁盘基线不可用"));
        row.statusText = statusParts.join(QStringLiteral(" | "));

        row.detailText = QStringLiteral(
            "协议版本: %1\n"
            "总条目: %2\n"
            "返回条目: %3\n"
            "服务名称: %4\n"
            "模块名称: %5\n"
            "服务索引: %6\n"
            "Zw导出地址: %7\n"
            "服务表基址: %8\n"
            "表项服务地址: %9\n"
            "表项槽位地址: %10\n"
            "当前编码槽值: 0x%11\n"
            "磁盘基线槽值: 0x%12\n"
            "当前槽字节: %13\n"
            "基线槽字节: %14\n"
            "槽位宽度: %15\n"
            "基线状态: %16\n"
            "基线映像: %17\n"
            "驱动标志: 0x%18")
            .arg(kEnumResult.version)
            .arg(kEnumResult.totalCount)
            .arg(kEnumResult.returnedCount)
            .arg(row.serviceNameText.isEmpty() ? QStringLiteral("<空>") : row.serviceNameText)
            .arg(row.moduleNameText.isEmpty() ? QStringLiteral("<空>") : row.moduleNameText)
            .arg(row.indexResolved ? QString::number(row.serviceIndex) : QStringLiteral("<未知>"))
            .arg(formatAddressHex(row.zwRoutineAddress))
            .arg(formatAddressHex(row.serviceTableBase))
            .arg(formatAddressHex(row.serviceRoutineAddress))
            .arg(formatAddressHex(row.tableEntryAddress))
            .arg(static_cast<qulonglong>(row.currentTableValue),
                0,
                16)
            .arg(static_cast<qulonglong>(row.cleanTableValue),
                0,
                16)
            .arg(byteText(row.currentTableBytes))
            .arg(byteText(row.cleanTableBytes))
            .arg(row.tableEntrySize)
            .arg(row.cleanBaselineStatus)
            .arg(row.cleanBaselinePath)
            .arg(static_cast<unsigned int>(row.flags), 8, 16, QChar('0'));

        rowsOut.push_back(std::move(row));
    }

    std::sort(rowsOut.begin(), rowsOut.end(), [](const KernelSsdtEntry& left, const KernelSsdtEntry& right) {
        if (left.indexResolved != right.indexResolved)
        {
            return left.indexResolved && !right.indexResolved;
        }
        if (left.serviceIndex != right.serviceIndex)
        {
            return left.serviceIndex < right.serviceIndex;
        }
        return QString::compare(left.serviceNameText, right.serviceNameText, Qt::CaseInsensitive) < 0;
    });

    return true;
}
