#include "MonitorDock.Support.h"

namespace ksword::ui::monitor_dock
{
    // decodeEtwPropertiesBySchema：
    // - Purpose: Parse UserData according to the cached schema order and record the offset for each field.
    // - Key point: Length/quantity reference attributes are read from preceding numeric fields, eliminating per-field TDH queries.
    bool decodeEtwPropertiesBySchema(
        const EVENT_RECORD* eventRecord,
        const EtwSchemaEntry& schemaEntry,
        std::vector<EtwDecodedPropertyEntry>* decodedPropertyListOut,
        ULONG* parsedBytesOut,
        QString* unparsedTailHexOut)
    {
        if (decodedPropertyListOut == nullptr || parsedBytesOut == nullptr)
        {
            return false;
        }

        decodedPropertyListOut->clear();
        *parsedBytesOut = 0;
        if (unparsedTailHexOut != nullptr)
        {
            unparsedTailHexOut->clear();
        }

        if (eventRecord == nullptr)
        {
            return false;
        }

        const unsigned char* userDataPointer = reinterpret_cast<const unsigned char*>(eventRecord->UserData);
        const ULONG kUserDataLength = eventRecord->UserDataLength;
        if (userDataPointer == nullptr || kUserDataLength == 0)
        {
            return true;
        }

        const ULONG kPointerSize = etwPointerSizeByHeader(eventRecord);
        ULONG cursorOffset = 0;
        std::unordered_map<ULONG, std::uint64_t> numericValueMap;
        decodedPropertyListOut->reserve(schemaEntry.propertyList.size());

        for (const EtwSchemaPropertyEntry& propertySchema : schemaEntry.propertyList)
        {
            EtwDecodedPropertyEntry decodedEntry;
            decodedEntry.propertyNameText = propertySchema.propertyNameText;
            decodedEntry.normalizedNameText = propertySchema.normalizedNameText;
            decodedEntry.meaningText = propertySchema.meaningText;
            decodedEntry.inTypeText = etwTypeText(propertySchema.inType);
            decodedEntry.beginOffset = cursorOffset;

            if (cursorOffset >= kUserDataLength)
            {
                decodedEntry.valueText = QStringLiteral("<无更多数据>");
                decodedEntry.parseFallback = true;
                decodedEntry.endOffset = cursorOffset;
                decodedPropertyListOut->push_back(std::move(decodedEntry));
                continue;
            }

            const ULONG kAvailableBytes = kUserDataLength - cursorOffset;
            const unsigned char* fieldDataPointer = userDataPointer + cursorOffset;

            ULONG resolvedLength = propertySchema.fixedLength;
            ULONG resolvedCount = propertySchema.fixedCount == 0 ? 1UL : static_cast<ULONG>(propertySchema.fixedCount);
            if (propertySchema.useLengthProperty)
            {
                const auto kFound = numericValueMap.find(propertySchema.lengthPropertyIndex);
                if (kFound != numericValueMap.end())
                {
                    resolvedLength = static_cast<ULONG>(std::min<std::uint64_t>(kFound->second, 0xFFFFFFFFULL));
                }
            }
            if (propertySchema.useCountProperty)
            {
                const auto kFound = numericValueMap.find(propertySchema.countPropertyIndex);
                if (kFound != numericValueMap.end())
                {
                    resolvedCount = static_cast<ULONG>(std::max<std::uint64_t>(1ULL, kFound->second));
                }
            }

            ULONG consumeBytes = 0;
            bool parsedAsKnownType = true;

            if (propertySchema.isStruct)
            {
                // The structure field has nested and dynamic layouts; retain a hexadecimal preview here.
                decodedEntry.valueText = QStringLiteral("<Struct: 当前版本未展开，已保留十六进制预览>");
                consumeBytes = std::min<ULONG>(kAvailableBytes, resolvedLength > 0 ? resolvedLength : 32UL);
                decodedEntry.parseFallback = true;
            }
            else
            {
                const ULONG kFixedTypeSize = etwFixedTypeSize(propertySchema.inType, kPointerSize);
                ULONG expectedBytes = 0;
                if (resolvedLength > 0)
                {
                    expectedBytes = resolvedLength * std::max<ULONG>(1, resolvedCount);
                }
                else if (kFixedTypeSize > 0)
                {
                    expectedBytes = kFixedTypeSize * std::max<ULONG>(1, resolvedCount);
                }

                switch (propertySchema.inType)
                {
                case TDH_INTYPE_UNICODESTRING:
                {
                    QString textValue;
                    if (tryConsumeUnicodeString(fieldDataPointer, kAvailableBytes, expectedBytes, &textValue, &consumeBytes))
                    {
                        decodedEntry.valueText = textValue;
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_ANSISTRING:
                {
                    QString textValue;
                    if (tryConsumeAnsiString(fieldDataPointer, kAvailableBytes, expectedBytes, &textValue, &consumeBytes))
                    {
                        decodedEntry.valueText = textValue;
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_GUID:
                {
                    GUID guidValue{};
                    consumeBytes = std::min<ULONG>(kAvailableBytes, 16);
                    if (etwReadScalar(fieldDataPointer, kAvailableBytes, &guidValue))
                    {
                        decodedEntry.valueText = guidToText(guidValue);
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_INT8:
                {
                    std::int8_t value = 0;
                    consumeBytes = 1;
                    if (etwReadScalar(fieldDataPointer, kAvailableBytes, &value))
                    {
                        decodedEntry.numericAvailable = true;
                        decodedEntry.numericValue = static_cast<std::uint64_t>(value);
                        decodedEntry.valueText = QString::number(value);
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_UINT8:
                {
                    std::uint8_t value = 0;
                    consumeBytes = 1;
                    if (etwReadScalar(fieldDataPointer, kAvailableBytes, &value))
                    {
                        decodedEntry.numericAvailable = true;
                        decodedEntry.numericValue = value;
                        decodedEntry.valueText = QString::number(value);
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_BOOLEAN:
                {
                    const ULONG kBoolBytes = expectedBytes > 0 ? std::min(expectedBytes, kAvailableBytes) : 4UL;
                    consumeBytes = std::max<ULONG>(1, kBoolBytes);

                    std::uint32_t value32 = 0;
                    if (consumeBytes >= 4 && etwReadScalar(fieldDataPointer, kAvailableBytes, &value32))
                    {
                        decodedEntry.numericAvailable = true;
                        decodedEntry.numericValue = value32;
                        decodedEntry.valueText = value32 == 0 ? QStringLiteral("false") : QStringLiteral("true");
                    }
                    else
                    {
                        std::uint8_t value8 = 0;
                        if (etwReadScalar(fieldDataPointer, kAvailableBytes, &value8))
                        {
                            decodedEntry.numericAvailable = true;
                            decodedEntry.numericValue = value8;
                            decodedEntry.valueText = value8 == 0 ? QStringLiteral("false") : QStringLiteral("true");
                        }
                        else
                        {
                            parsedAsKnownType = false;
                        }
                    }
                    break;
                }
                case TDH_INTYPE_INT16:
                {
                    std::int16_t value = 0;
                    consumeBytes = 2;
                    if (etwReadScalar(fieldDataPointer, kAvailableBytes, &value))
                    {
                        decodedEntry.numericAvailable = true;
                        decodedEntry.numericValue = static_cast<std::uint64_t>(value);
                        decodedEntry.valueText = QString::number(value);
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_UINT16:
                {
                    std::uint16_t value = 0;
                    consumeBytes = 2;
                    if (etwReadScalar(fieldDataPointer, kAvailableBytes, &value))
                    {
                        decodedEntry.numericAvailable = true;
                        decodedEntry.numericValue = value;
                        decodedEntry.valueText = QString::number(value);
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_INT32:
                {
                    std::int32_t value = 0;
                    consumeBytes = 4;
                    if (etwReadScalar(fieldDataPointer, kAvailableBytes, &value))
                    {
                        decodedEntry.numericAvailable = true;
                        decodedEntry.numericValue = static_cast<std::uint64_t>(value);
                        decodedEntry.valueText = QString::number(value);
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_UINT32:
                case TDH_INTYPE_HEXINT32:
                {
                    std::uint32_t value = 0;
                    consumeBytes = 4;
                    if (etwReadScalar(fieldDataPointer, kAvailableBytes, &value))
                    {
                        decodedEntry.numericAvailable = true;
                        decodedEntry.numericValue = value;
                        decodedEntry.valueText = propertySchema.inType == TDH_INTYPE_HEXINT32
                            ? QStringLiteral("0x%1").arg(value, 8, 16, QChar(u'0')).toUpper()
                            : QString::number(value);
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_INT64:
                {
                    std::int64_t value = 0;
                    consumeBytes = 8;
                    if (etwReadScalar(fieldDataPointer, kAvailableBytes, &value))
                    {
                        decodedEntry.numericAvailable = true;
                        decodedEntry.numericValue = static_cast<std::uint64_t>(value);
                        decodedEntry.valueText = QString::number(static_cast<qlonglong>(value));
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_FLOAT:
                {
                    float value = 0.0f;
                    consumeBytes = 4;
                    if (etwReadScalar(fieldDataPointer, kAvailableBytes, &value))
                    {
                        decodedEntry.valueText = QString::number(value, 'f', 6);
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_DOUBLE:
                {
                    double value = 0.0;
                    consumeBytes = 8;
                    if (etwReadScalar(fieldDataPointer, kAvailableBytes, &value))
                    {
                        decodedEntry.valueText = QString::number(value, 'f', 6);
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_UINT64:
                case TDH_INTYPE_HEXINT64:
                case TDH_INTYPE_POINTER:
                case TDH_INTYPE_FILETIME:
                {
                    std::uint64_t value = 0;
                    consumeBytes = propertySchema.inType == TDH_INTYPE_POINTER ? kPointerSize : 8;
                    if (consumeBytes == 4)
                    {
                        std::uint32_t value32 = 0;
                        if (etwReadScalar(fieldDataPointer, kAvailableBytes, &value32))
                        {
                            value = value32;
                        }
                    }
                    else
                    {
                        etwReadScalar(fieldDataPointer, kAvailableBytes, &value);
                    }

                    if (value == 0 && kAvailableBytes < consumeBytes)
                    {
                        parsedAsKnownType = false;
                        break;
                    }

                    decodedEntry.numericAvailable = true;
                    decodedEntry.numericValue = value;
                    if (propertySchema.inType == TDH_INTYPE_POINTER
                        || propertySchema.inType == TDH_INTYPE_HEXINT64)
                    {
                        decodedEntry.valueText = QStringLiteral("0x%1")
                            .arg(static_cast<qulonglong>(value), consumeBytes * 2, 16, QChar(u'0'))
                            .toUpper();
                    }
                    else
                    {
                        decodedEntry.valueText = QString::number(static_cast<qulonglong>(value));
                    }
                    break;
                }
                case TDH_INTYPE_SID:
                {
                    PSID sidPointer = reinterpret_cast<PSID>(const_cast<unsigned char*>(fieldDataPointer));
                    if (sidPointer != nullptr && ::IsValidSid(sidPointer) != FALSE)
                    {
                        consumeBytes = ::GetLengthSid(sidPointer);
                        consumeBytes = std::min(consumeBytes, kAvailableBytes);
                        LPWSTR sidTextPointer = nullptr;
                        if (::ConvertSidToStringSidW(sidPointer, &sidTextPointer) != FALSE && sidTextPointer != nullptr)
                        {
                            decodedEntry.valueText = QString::fromWCharArray(sidTextPointer);
                            ::LocalFree(sidTextPointer);
                        }
                        else
                        {
                            decodedEntry.valueText = QStringLiteral("<SID转换失败>");
                            decodedEntry.parseFallback = true;
                        }
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_SYSTEMTIME:
                {
                    SYSTEMTIME systemTimeValue{};
                    consumeBytes = static_cast<ULONG>(sizeof(SYSTEMTIME));
                    if (etwReadScalar(fieldDataPointer, kAvailableBytes, &systemTimeValue))
                    {
                        decodedEntry.valueText = QStringLiteral("%1-%2-%3 %4:%5:%6.%7")
                            .arg(systemTimeValue.wYear, 4, 10, QChar(u'0'))
                            .arg(systemTimeValue.wMonth, 2, 10, QChar(u'0'))
                            .arg(systemTimeValue.wDay, 2, 10, QChar(u'0'))
                            .arg(systemTimeValue.wHour, 2, 10, QChar(u'0'))
                            .arg(systemTimeValue.wMinute, 2, 10, QChar(u'0'))
                            .arg(systemTimeValue.wSecond, 2, 10, QChar(u'0'))
                            .arg(systemTimeValue.wMilliseconds, 3, 10, QChar(u'0'));
                    }
                    else
                    {
                        parsedAsKnownType = false;
                    }
                    break;
                }
                case TDH_INTYPE_BINARY:
                case TDH_INTYPE_HEXDUMP:
                {
                    consumeBytes = expectedBytes > 0
                        ? std::min(expectedBytes, kAvailableBytes)
                        : std::min<ULONG>(kAvailableBytes, 64);
                    decodedEntry.valueText = QStringLiteral("<二进制数据>");
                    decodedEntry.parseFallback = true;
                    break;
                }
                default:
                    parsedAsKnownType = false;
                    break;
                }
            }

            if (!parsedAsKnownType)
            {
                // When the type cannot be determined, use the 'length strategy > remaining entire' order as a fallback.
                ULONG fallbackBytes = 0;
                if (resolvedLength > 0)
                {
                    fallbackBytes = std::min<ULONG>(kAvailableBytes, resolvedLength * std::max<ULONG>(1, resolvedCount));
                }
                else if (propertySchema.fixedLength > 0)
                {
                    fallbackBytes = std::min<ULONG>(kAvailableBytes, propertySchema.fixedLength);
                }
                else
                {
                    fallbackBytes = std::min<ULONG>(kAvailableBytes, 32);
                }

                consumeBytes = std::max<ULONG>(1, fallbackBytes);
                decodedEntry.valueText = QStringLiteral("<未识别类型，已按十六进制保留>");
                decodedEntry.parseFallback = true;
            }

            consumeBytes = std::min(consumeBytes, kAvailableBytes);
            decodedEntry.endOffset = cursorOffset + consumeBytes;
            decodedEntry.hexPreviewText = etwHexPreview(fieldDataPointer, consumeBytes);

            if (decodedEntry.numericAvailable)
            {
                numericValueMap[propertySchema.propertyIndex] = decodedEntry.numericValue;
            }

            decodedPropertyListOut->push_back(std::move(decodedEntry));
            cursorOffset += consumeBytes;
        }

        *parsedBytesOut = cursorOffset;
        if (cursorOffset < kUserDataLength && unparsedTailHexOut != nullptr)
        {
            const unsigned char* tailPointer = userDataPointer + cursorOffset;
            *unparsedTailHexOut = etwHexDump(tailPointer, kUserDataLength - cursorOffset);
        }
        return true;
    }
}
