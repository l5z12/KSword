#include "MemoryDock.Internal.h"

// Note: Migrated from the original aggregated implementation to a standalone .cpp file; member function implementations remain unchanged.
using namespace ksword::memory_dock_internal;

// ============================================================
// MemoryDock.SearchParseAndFilter.cpp
// Purpose: Encapsulate search value parsing and scan region collection logic.
// ============================================================

// ============================================================
// MemoryDock.SearchParseAndFilter.cpp
// (split from original Search) purpose:
// - Responsible for initial scan, re-scan, background concurrent scan, and result table refresh.
// - Focus on 'scan rule parsing + scan task execution + scan state management'.
// ============================================================

bool MemoryDock::parseSearchPatternFromUi(
    ParsedSearchPattern& patternOut,
    QString& errorTextOut) const
{
    // Parse entry log: record the current type index and original input text to facilitate reproducing parse anomalies.
    KLogEvent parsePatternStartEvent;
    dbg << parsePatternStartEvent
        << "[MemoryDock] parseSearchPatternFromUi: 开始解析, typeIndex="
        << searchTypeCombo_->currentIndex()
        << ", rawText="
        << searchValueEdit_->text().trimmed().toStdString()
        << eol;

    // Clear the output structure before each parsing to prevent data from the previous round from contaminating the current matching rules.
    patternOut = ParsedSearchPattern{};

    // Data types come from the dropdown itemData, corresponding one-to-one with the SearchValueType enum.
    const int kTypeIndex = searchTypeCombo_->currentIndex();
    if (kTypeIndex < 0)
    {
        errorTextOut = "请选择有效的数据类型。";
        KLogEvent parsePatternTypeFailEvent;
        warn << parsePatternTypeFailEvent
            << "[MemoryDock] parseSearchPatternFromUi: 类型索引无效。"
            << eol;
        return false;
    }
    patternOut.valueType = static_cast<SearchValueType>(searchTypeCombo_->itemData(kTypeIndex).toInt());

    // The search value text is the core input for the initial scan; reject it immediately and prompt the user if empty.
    const QString kValueText = searchValueEdit_->text().trimmed();
    if (kValueText.isEmpty())
    {
        errorTextOut = "搜索值不能为空。";
        KLogEvent parsePatternEmptyValueEvent;
        warn << parsePatternEmptyValueEvent
            << "[MemoryDock] parseSearchPatternFromUi: 搜索值为空。"
            << eol;
        return false;
    }

    // Parse by data type, then unify into the 'exactBytes + wildcardMask' structure.
    switch (patternOut.valueType)
    {
    case SearchValueType::kByte:
    {
        std::uint64_t value = 0;
        if (!parseUnsignedNumber(kValueText, value) || value > 0xFF)
        {
            errorTextOut = "字节类型请输入 0~255（支持十进制或 0x 十六进制）。";
            KLogEvent parsePatternByteFailEvent;
            warn << parsePatternByteFailEvent
                << "[MemoryDock] parseSearchPatternFromUi: Byte 解析失败, text="
                << kValueText.toStdString()
                << eol;
            return false;
        }
        const std::uint8_t kByteValue = static_cast<std::uint8_t>(value);
        patternOut.exactBytes = QByteArray(reinterpret_cast<const char*>(&kByteValue), sizeof(kByteValue));
        patternOut.lowerBound = static_cast<double>(kByteValue);
        patternOut.upperBound = static_cast<double>(kByteValue);
        break;
    }
    case SearchValueType::kInt16:
    {
        bool parseOk = false;
        const qint16 kValue = static_cast<qint16>(kValueText.toLongLong(&parseOk, 0));
        if (!parseOk)
        {
            errorTextOut = "2字节整数解析失败。";
            KLogEvent parsePatternI16FailEvent;
            warn << parsePatternI16FailEvent
                << "[MemoryDock] parseSearchPatternFromUi: Int16 解析失败, text="
                << kValueText.toStdString()
                << eol;
            return false;
        }
        patternOut.exactBytes = QByteArray(reinterpret_cast<const char*>(&kValue), sizeof(kValue));
        patternOut.lowerBound = static_cast<double>(kValue);
        patternOut.upperBound = static_cast<double>(kValue);
        break;
    }
    case SearchValueType::kInt32:
    {
        bool parseOk = false;
        const qint32 kValue = static_cast<qint32>(kValueText.toLongLong(&parseOk, 0));
        if (!parseOk)
        {
            errorTextOut = "4字节整数解析失败。";
            KLogEvent parsePatternI32FailEvent;
            warn << parsePatternI32FailEvent
                << "[MemoryDock] parseSearchPatternFromUi: Int32 解析失败, text="
                << kValueText.toStdString()
                << eol;
            return false;
        }
        patternOut.exactBytes = QByteArray(reinterpret_cast<const char*>(&kValue), sizeof(kValue));
        patternOut.lowerBound = static_cast<double>(kValue);
        patternOut.upperBound = static_cast<double>(kValue);
        break;
    }
    case SearchValueType::kInt64:
    {
        bool parseOk = false;
        const qint64 kValue = static_cast<qint64>(kValueText.toLongLong(&parseOk, 0));
        if (!parseOk)
        {
            errorTextOut = "8字节整数解析失败。";
            KLogEvent parsePatternI64FailEvent;
            warn << parsePatternI64FailEvent
                << "[MemoryDock] parseSearchPatternFromUi: Int64 解析失败, text="
                << kValueText.toStdString()
                << eol;
            return false;
        }
        patternOut.exactBytes = QByteArray(reinterpret_cast<const char*>(&kValue), sizeof(kValue));
        patternOut.lowerBound = static_cast<double>(kValue);
        patternOut.upperBound = static_cast<double>(kValue);
        break;
    }
    case SearchValueType::kFloat32:
    {
        bool parseOk = false;
        const float kValue = kValueText.toFloat(&parseOk);
        if (!parseOk)
        {
            errorTextOut = "浮点数解析失败。";
            KLogEvent parsePatternF32FailEvent;
            warn << parsePatternF32FailEvent
                << "[MemoryDock] parseSearchPatternFromUi: Float32 解析失败, text="
                << kValueText.toStdString()
                << eol;
            return false;
        }
        patternOut.exactBytes = QByteArray(reinterpret_cast<const char*>(&kValue), sizeof(kValue));
        patternOut.lowerBound = static_cast<double>(kValue);
        patternOut.upperBound = static_cast<double>(kValue);
        patternOut.epsilon = 0.00001;
        break;
    }
    case SearchValueType::kFloat64:
    {
        bool parseOk = false;
        const double kValue = kValueText.toDouble(&parseOk);
        if (!parseOk)
        {
            errorTextOut = "双精度浮点数解析失败。";
            KLogEvent parsePatternF64FailEvent;
            warn << parsePatternF64FailEvent
                << "[MemoryDock] parseSearchPatternFromUi: Float64 解析失败, text="
                << kValueText.toStdString()
                << eol;
            return false;
        }
        patternOut.exactBytes = QByteArray(reinterpret_cast<const char*>(&kValue), sizeof(kValue));
        patternOut.lowerBound = kValue;
        patternOut.upperBound = kValue;
        patternOut.epsilon = 0.0000001;
        break;
    }
    case SearchValueType::kByteArray:
    {
        // Byte array supports mixed 'AA BB CC' and 'AA??CC' formats; here, unify tokenization by splitting on spaces.
        QString normalizedText = kValueText;
        normalizedText.replace(',', ' ');
        normalizedText.replace(';', ' ');
        const QStringList kTokens = normalizedText.split(' ', Qt::SkipEmptyParts);
        if (kTokens.isEmpty())
        {
            errorTextOut = "字节数组不能为空。示例：48 8B ?? ?? 89";
            KLogEvent parsePatternArrayEmptyEvent;
            warn << parsePatternArrayEmptyEvent
                << "[MemoryDock] parseSearchPatternFromUi: ByteArray token 为空。"
                << eol;
            return false;
        }

        for (const QString& tokenText : kTokens)
        {
            const QString kToken = tokenText.trimmed().toUpper();
            if (kToken == "??")
            {
                patternOut.exactBytes.push_back('\0');
                patternOut.wildcardMask.push_back('\0');
                continue;
            }

            std::uint8_t parsedByte = 0;
            if (!parseHexByte(kToken, parsedByte))
            {
                errorTextOut = QString("无效字节项：%1").arg(tokenText);
                KLogEvent parsePatternArrayTokenFailEvent;
                warn << parsePatternArrayTokenFailEvent
                    << "[MemoryDock] parseSearchPatternFromUi: ByteArray token 无效, token="
                    << tokenText.toStdString()
                    << eol;
                return false;
            }

            patternOut.exactBytes.push_back(static_cast<char>(parsedByte));
            patternOut.wildcardMask.push_back('\1');
        }
        break;
    }
    case SearchValueType::kStringAscii:
    {
        patternOut.exactBytes = kValueText.toLatin1();
        break;
    }
    case SearchValueType::kStringUnicode:
    {
        // QString stores UTF-16 internally; copying its underlying bytes directly produces an LE sequence.
        const QString kUnicodeText = kValueText;
        const auto* utf16Data = reinterpret_cast<const char*>(kUnicodeText.utf16());
        patternOut.exactBytes = QByteArray(utf16Data, kUnicodeText.size() * static_cast<int>(sizeof(char16_t)));
        break;
    }
    default:
        errorTextOut = "未知数据类型。";
        KLogEvent parsePatternUnknownTypeEvent;
        err << parsePatternUnknownTypeEvent
            << "[MemoryDock] parseSearchPatternFromUi: 未知类型, enum="
            << static_cast<int>(patternOut.valueType)
            << eol;
        return false;
    }

    // Any type must form a match pattern of at least 1 byte; otherwise, scanning cannot be performed.
    if (patternOut.exactBytes.isEmpty())
    {
        errorTextOut = "解析后匹配模式为空，请检查输入值。";
        KLogEvent parsePatternEmptyResultEvent;
        warn << parsePatternEmptyResultEvent
            << "[MemoryDock] parseSearchPatternFromUi: 解析后字节序列为空。"
            << eol;
        return false;
    }

    // Parse success log: record final type and pattern length.
    KLogEvent parsePatternFinishEvent;
    info << parsePatternFinishEvent
        << "[MemoryDock] parseSearchPatternFromUi: 解析成功, valueType="
        << static_cast<int>(patternOut.valueType)
        << ", exactBytesSize="
        << patternOut.exactBytes.size()
        << ", wildcardSize="
        << patternOut.wildcardMask.size()
        << eol;
    return true;
}

bool MemoryDock::collectSearchRegionsFromUi(
    std::vector<RegionEntry>& regionsOut,
    QString& errorTextOut)
{
    // Log entry for collecting scan regions: record range mode and filter switches.
    KLogEvent collectRegionStartEvent;
    info << collectRegionStartEvent
        << "[MemoryDock] collectSearchRegionsFromUi: 开始收集扫描区域, rangeModeIndex="
        << searchRangeCombo_->currentIndex()
        << ", imageOnly="
        << (searchImageOnlyCheck_->isChecked() ? "true" : "false")
        << ", heapOnly="
        << (searchHeapOnlyCheck_->isChecked() ? "true" : "false")
        << ", stackOnly="
        << (searchStackOnlyCheck_->isChecked() ? "true" : "false")
        << eol;

    // Target process must be attached before scanning; otherwise ReadProcessMemory cannot proceed.
    if (attachedProcessHandle_ == nullptr || attachedPid_ == 0)
    {
        errorTextOut = "请先附加目标进程。";
        KLogEvent collectRegionNoAttachEvent;
        warn << collectRegionNoAttachEvent
            << "[MemoryDock] collectSearchRegionsFromUi: 未附加进程。"
            << eol;
        return false;
    }

    // Proactively refresh once when the region cache is empty to avoid having no range data when first entering the scan page.
    if (regionCache_.empty())
    {
        refreshMemoryRegionList(true);
    }

    if (regionCache_.empty())
    {
        errorTextOut = "当前没有可用的内存区域，请先刷新区域列表。";
        KLogEvent collectRegionEmptyCacheEvent;
        warn << collectRegionEmptyCacheEvent
            << "[MemoryDock] collectSearchRegionsFromUi: 区域缓存为空。"
            << eol;
        return false;
    }

    // In custom range mode, the user-provided addresses must be parsed into a closed interval [start, end].
    bool useCustomRange = (searchRangeCombo_->currentIndex() == 1);
    std::uint64_t rangeStart = 0;
    std::uint64_t rangeEnd = std::numeric_limits<std::uint64_t>::max();
    if (useCustomRange)
    {
        if (!parseAddressText(searchRangeStartEdit_->text().trimmed(), rangeStart))
        {
            errorTextOut = "起始地址格式无效。";
            KLogEvent collectRegionStartParseFailEvent;
            warn << collectRegionStartParseFailEvent
                << "[MemoryDock] collectSearchRegionsFromUi: 起始地址解析失败, text="
                << searchRangeStartEdit_->text().trimmed().toStdString()
                << eol;
            return false;
        }
        if (!parseAddressText(searchRangeEndEdit_->text().trimmed(), rangeEnd))
        {
            errorTextOut = "结束地址格式无效。";
            KLogEvent collectRegionEndParseFailEvent;
            warn << collectRegionEndParseFailEvent
                << "[MemoryDock] collectSearchRegionsFromUi: 结束地址解析失败, text="
                << searchRangeEndEdit_->text().trimmed().toStdString()
                << eol;
            return false;
        }
        if (rangeEnd < rangeStart)
        {
            errorTextOut = "结束地址不能小于起始地址。";
            KLogEvent collectRegionRangeInvalidEvent;
            warn << collectRegionRangeInvalidEvent
                << "[MemoryDock] collectSearchRegionsFromUi: 自定义范围非法, start="
                << formatAddress(rangeStart).toStdString()
                << ", end="
                << formatAddress(rangeEnd).toStdString()
                << eol;
            return false;
        }
    }

    const bool kImageOnly = searchImageOnlyCheck_->isChecked();
    const bool kHeapOnly = searchHeapOnlyCheck_->isChecked();
    const bool kStackOnly = searchStackOnlyCheck_->isChecked();

    // Enabling both 'Heap Only' and 'Stack Only' has no clear business meaning; prompt the user to choose one.
    if (kHeapOnly && kStackOnly)
    {
        errorTextOut = "“仅堆”与“仅栈”不能同时启用。";
        KLogEvent collectRegionFilterConflictEvent;
        warn << collectRegionFilterConflictEvent
            << "[MemoryDock] collectSearchRegionsFromUi: heapOnly 与 stackOnly 同时启用。"
            << eol;
        return false;
    }

    regionsOut.clear();
    regionsOut.reserve(regionCache_.size());

    for (const RegionEntry& region : regionCache_)
    {
        // Scan only committed and readable regions to avoid excessive invalid accesses or NOACCESS errors.
        if (region.state != MEM_COMMIT || !isReadableProtect(region.protect))
        {
            continue;
        }

        // Filter by type: image only -> MEM_IMAGE; heap only -> MEM_PRIVATE (approximate).
        if (kImageOnly && region.type != MEM_IMAGE)
        {
            continue;
        }
        if (kHeapOnly && region.type != MEM_PRIVATE)
        {
            continue;
        }

        // Stack regions cannot be accurately identified by a single field; here we use an approximation of 'PRIVATE + GUARD or RW'.
        if (kStackOnly)
        {
            const bool kMaybeStack =
                (region.type == MEM_PRIVATE) &&
                (((region.protect & PAGE_GUARD) != 0) || ((region.protect & PAGE_READWRITE) != 0));
            if (!kMaybeStack)
            {
                continue;
            }
        }

        // If not using a custom range, include directly; if using a custom range, clip region boundaries by intersection.
        if (!useCustomRange)
        {
            regionsOut.push_back(region);
            continue;
        }

        if (region.regionSize == 0)
        {
            continue;
        }

        const std::uint64_t kRegionStart = region.baseAddress;
        const std::uint64_t kRegionEnd = region.baseAddress + region.regionSize - 1;
        if (kRegionEnd < rangeStart || kRegionStart > rangeEnd)
        {
            continue;
        }

        RegionEntry clippedRegion = region;
        clippedRegion.baseAddress = std::max(kRegionStart, rangeStart);
        const std::uint64_t kClippedEnd = std::min(kRegionEnd, rangeEnd);
        clippedRegion.regionSize = kClippedEnd - clippedRegion.baseAddress + 1;
        regionsOut.push_back(std::move(clippedRegion));
    }

    if (regionsOut.empty())
    {
        errorTextOut = "过滤后没有可扫描区域，请调整范围/过滤条件。";
        KLogEvent collectRegionEmptyResultEvent;
        warn << collectRegionEmptyResultEvent
            << "[MemoryDock] collectSearchRegionsFromUi: 过滤后区域为空。"
            << eol;
        return false;
    }

    // Log for successful collection: record the number of region entries.
    KLogEvent collectRegionFinishEvent;
    info << collectRegionFinishEvent
        << "[MemoryDock] collectSearchRegionsFromUi: 收集完成, regionCount="
        << regionsOut.size()
        << eol;

    return true;
}
